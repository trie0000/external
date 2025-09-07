# -*- coding: utf-8 -*-
"""
export_selected.py
選択範囲と交差する図形を JSON 化（図形テキスト取得強化 + デバッグ）
使い方:
    python export_selected.py --out ./diagram.json [--debug]
"""
import argparse
import json
import sys
import traceback
import win32com.client as win32

# mso constants (subset)
MSO_GROUP = 6
MSO_PICTURE = 13
MSO_TEXTBOX = 17

# マージン/閾値
SELECTION_MARGIN_PT = 30.0
CONTAIN_MARGIN_PT = 8.0
# ※ inside_texts は「完全内包のみ」を記録する運用に変更したため未使用
# OVERLAP_MIN_RATIO = 0.10  # 10%

# --------------------------
# ユーティリティ
# --------------------------
FW = "！＂＃＄％＆＇（）＊＋，－．／０１２３４５６７８９：；＜＝＞？" \
     "＠ＡＢＣＤＥＦＧＨＩＪＫＬＭＮＯＰＱＲＳＴＵＶＷＸＹＺ［＼］＾＿" \
     "｀ａｂｃｄｅｆｇｈｉｊｋｌｍｎｏｐｑｒｓｔｕｖｗｘｙｚ｛｜｝～"
HW = "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_" \
     "`abcdefghijklmnopqrstuvwxyz{|}~"
TRANS_FW2HW = str.maketrans({ord(f): h for f, h in zip(FW, HW)})

def norm_text(s: str) -> str:
    if not s:
        return ""
    s = s.translate(TRANS_FW2HW)
    s = (s.replace("\u3000", " ").replace("\xa0", " ")
           .replace("\r\n", "\n").replace("\r", "\n"))
    s = " ".join(s.split())
    return s.strip()

def get_excel():
    try:
        return win32.GetActiveObject("Excel.Application")
    except Exception:
        return win32.gencache.EnsureDispatch("Excel.Application")

def abs_offset(shape):
    offL = offT = 0.0
    sh = shape
    while True:
        try:
            pg = sh.ParentGroup
        except Exception:
            pg = None
        if not pg:
            break
        try:
            offL += float(pg.Left)
            offT += float(pg.Top)
        except Exception:
            pass
        sh = pg
    return offL, offT

def rect_abs(shape):
    L, T, W, H = shape.Left, shape.Top, shape.Width, shape.Height
    offL, offT = abs_offset(shape)
    return (float(L + offL), float(T + offT), float(L + offL + W), float(T + offT + H))

def rect_union(rects):
    L = min(r[0] for r in rects); T = min(r[1] for r in rects)
    R = max(r[2] for r in rects); B = max(r[3] for r in rects)
    return (L, T, R, B)

def rect_expand(r, m):
    L,T,R,B = r
    return (L-m, T-m, R+m, B+m)

def rect_intersects(a,b):
    L1,T1,R1,B1 = a; L2,T2,R2,B2 = b
    return not (R1 <= L2 or R2 <= L1 or B1 <= T2 or B2 <= T1)

def rect_contains_with_margin(outer, inner, margin=0.0):
    L1,T1,R1,B1 = outer; L2,T2,R2,B2 = inner
    L1 -= margin; T1 -= margin; R1 += margin; B1 += margin
    return (L1<=L2) and (T1<=T2) and (R1>=R2) and (B1>=B2)

def rect_area(r):
    L,T,R,B = r
    return max(0.0,(R-L))*max(0.0,(B-T))

def rect_intersection(a,b):
    L1,T1,R1,B1=a; L2,T2,R2,B2=b
    L=max(L1,L2); T=max(T1,T2); R=min(R1,R2); B=min(B1,B2)
    if R<=L or B<=T: return (0,0,0,0)
    return (L,T,R,B)

def overlap_ratio(a, b):
    inter = rect_intersection(a,b)
    ia = rect_area(inter); aa = rect_area(a)
    return (ia/aa) if aa>0 else 0.0

# --------------------------
# デバッグフラグ
# --------------------------
DEBUG = False

def debug_inspect(shape):
    info = {}
    def safe_attr(obj, name):
        try:
            return getattr(obj, name)
        except Exception as e:
            return f"<err:{e}>"
    try:
        info["id"] = safe_attr(shape, "Name")
        info["Type"] = safe_attr(shape, "Type")
        try:
            info["rect_ltrb"] = rect_abs(shape)
        except Exception:
            info["rect_ltrb"] = "<err>"
        tf2 = getattr(shape, "TextFrame2", None)
        info["has_TextFrame2"] = bool(tf2 is not None)
        if tf2 is not None:
            try:
                tr = getattr(tf2, "TextRange", None)
                info["TextFrame2.Text"] = getattr(tr, "Text", "<err>") if tr is not None else None
            except Exception as e:
                info["TextFrame2.Text"] = f"<err:{e}>"
        tf = getattr(shape, "TextFrame", None)
        info["has_TextFrame"] = bool(tf is not None)
        if tf is not None:
            try:
                txt = None
                try:
                    txt = tf.Characters().Text
                except Exception:
                    try:
                        cnt = int(getattr(tf.Characters, "Count", 0))
                        if cnt > 0:
                            txt = tf.Characters(1, cnt).Text
                    except Exception:
                        txt = None
                info["TextFrame.Characters.Text"] = txt
            except Exception as e:
                info["TextFrame.Characters.Text"] = f"<err:{e}>"
        te = getattr(shape, "TextEffect", None)
        info["has_TextEffect"] = bool(te is not None)
        if te is not None:
            try:
                info["TextEffect.Text"] = getattr(te, "Text", None)
            except Exception:
                info["TextEffect.Text"] = "<err>"
        info["AlternativeText"] = getattr(shape, "AlternativeText", None)
        info["Name"] = getattr(shape, "Name", None)
        try:
            info["Connector"] = bool(getattr(shape, "Connector", False))
        except Exception:
            info["Connector"] = "<err>"
        try:
            pg = getattr(shape, "ParentGroup", None)
            info["ParentGroup"] = getattr(pg, "Name", None) if pg is not None else None
        except Exception:
            info["ParentGroup"] = "<err>"
    except Exception as e:
        info["inspect_error"] = str(e)
    return info

# --------------------------
# テキスト抽出（堅牢版）
# --------------------------
def get_text_strict(shape) -> str:
    try:
        if DEBUG:
            print(f"DEBUG:get_text_strict START shape={getattr(shape,'Name',None)}", file=sys.stderr)
        # 1) TextFrame2.TextRange.Text
        try:
            tf2 = getattr(shape, "TextFrame2", None)
            if tf2 is not None:
                tr = None
                try:
                    tr = tf2.TextRange
                except Exception:
                    tr = None
                if tr is not None:
                    try:
                        t = getattr(tr, "Text", None)
                    except Exception:
                        t = None
                    if t and str(t).strip():
                        shape._text_source = "TextFrame2.TextRange"
                        out = norm_text(str(t))
                        if DEBUG:
                            print(f"DEBUG:get_text_strict => source=TextFrame2.TextRange text={out!r}", file=sys.stderr)
                        return out
                    # Paragraphs 列挙
                    try:
                        pcol = getattr(tr, "Paragraphs", None)
                        if pcol is not None:
                            paras = []
                            try:
                                cnt = int(getattr(pcol, "Count", 1))
                            except Exception:
                                cnt = 1
                            for i in range(1, cnt+1):
                                try:
                                    p = None
                                    try:
                                        p = pcol(i)
                                    except Exception:
                                        try:
                                            p = pcol.Item(i)
                                        except Exception:
                                            p = None
                                    if p is None:
                                        continue
                                    rng = getattr(p, "Range", None)
                                    if rng is not None:
                                        txt = getattr(rng, "Text", None)
                                        if txt:
                                            paras.append(str(txt))
                                    else:
                                        txt = getattr(p, "Text", None)
                                        if txt:
                                            paras.append(str(txt))
                                except Exception:
                                    continue
                            if paras:
                                shape._text_source = "TextFrame2.Paragraphs"
                                out = norm_text("\n".join(paras))
                                if DEBUG:
                                    print(f"DEBUG:get_text_strict => source=TextFrame2.Paragraphs text={out!r}", file=sys.stderr)
                                return out
                    except Exception:
                        pass
        except Exception:
            pass

        # 2) TextFrame.Characters
        try:
            tf = getattr(shape, "TextFrame", None)
            if tf is not None:
                try:
                    t = None
                    try:
                        t = tf.Characters().Text
                    except Exception:
                        t = None
                    if not t:
                        try:
                            cnt = int(getattr(tf.Characters, "Count", 0))
                            if cnt > 0:
                                try:
                                    t = tf.Characters(1, cnt).Text
                                except Exception:
                                    try:
                                        t = tf.Characters(1).Text
                                    except Exception:
                                        t = None
                        except Exception:
                            t = t
                    if t and str(t).strip():
                        shape._text_source = "TextFrame.Characters"
                        out = norm_text(str(t))
                        if DEBUG:
                            print(f"DEBUG:get_text_strict => source=TextFrame.Characters text={out!r}", file=sys.stderr)
                        return out
                except Exception:
                    pass
        except Exception:
            pass

        # 3) TextEffect (WordArt)
        try:
            te = getattr(shape, "TextEffect", None)
            if te is not None:
                try:
                    t = getattr(te, "Text", None)
                    if t and str(t).strip():
                        shape._text_source = "TextEffect"
                        out = norm_text(str(t))
                        if DEBUG:
                            print(f"DEBUG:get_text_strict => source=TextEffect text={out!r}", file=sys.stderr)
                        return out
                except Exception:
                    pass
        except Exception:
            pass

        # 4) AlternativeText
        try:
            t = getattr(shape, "AlternativeText", None)
            if t and str(t).strip():
                shape._text_source = "AlternativeText"
                out = norm_text(str(t))
                if DEBUG:
                    print(f"DEBUG:get_text_strict => source=AlternativeText text={out!r}", file=sys.stderr)
                return out
        except Exception:
            pass

        # 5) Name
        try:
            t = getattr(shape, "Name", None)
            if t and str(t).strip():
                shape._text_source = "Name"
                out = norm_text(str(t))
                if DEBUG:
                    print(f"DEBUG:get_text_strict => source=Name text={out!r}", file=sys.stderr)
                return out
        except Exception:
            pass

        if DEBUG:
            print(f"DEBUG:get_text_strict END shape={getattr(shape,'Name',None)} returning empty", file=sys.stderr)
        return ""
    except Exception:
        if DEBUG:
            traceback.print_exc()
        return ""

# --------------------------
# 収集
# --------------------------
def shape_basic_dict(shape) -> dict:
    # always collect a lightweight inspect result (used as a robust fallback)
    try:
        info = debug_inspect(shape)
    except Exception:
        info = {}
    if DEBUG:
        try:
            print("DEBUG: inspect:", json.dumps(info, ensure_ascii=False, indent=2))
        except Exception:
            print("DEBUG: inspect failed for shape", getattr(shape, "Name", "<unknown>"))

    try:
        text_val = get_text_strict(shape)
    except Exception:
        text_val = ""
    # if strict extractor failed, prefer values observed by debug_inspect
    if not (text_val and text_val.strip()):
        # TextFrame2.Text may be present as a direct property
        tf2_text = info.get("TextFrame2.Text") if isinstance(info, dict) else None
        tf_chars = info.get("TextFrame.Characters.Text") if isinstance(info, dict) else None
        te_text = info.get("TextEffect.Text") if isinstance(info, dict) else None
        # ignore error markers like '<err:...>' or None
        def valid(v):
            if not v:
                return False
            try:
                vs = str(v)
            except Exception:
                return False
            if vs.startswith("<err:"):
                return False
            return bool(vs.strip())

        if valid(tf2_text):
            text_val = norm_text(str(tf2_text))
            text_source = "TextFrame2.debug"
        elif valid(tf_chars):
            text_val = norm_text(str(tf_chars))
            text_source = "TextFrame.Characters.debug"
        elif valid(te_text):
            text_val = norm_text(str(te_text))
            text_source = "TextEffect.debug"
        else:
            text_source = ""
    else:
        # if get_text_strict returned something, try to read its recorded source safely
        try:
            text_source = getattr(shape, "_text_source")
        except Exception:
            text_source = ""
    d = {
        "id": getattr(shape, "Name", ""),
        "rect_ltrb": rect_abs(shape),
        # text は廃止。抽出テキストは text_orig のみに保持
        "text_orig": text_val or "",
        "text_source": text_source or "",
        "zorder": int(getattr(shape, "ZOrderPosition", 0)),
        "is_connector": False,
        "type_hint": int(getattr(shape, "AutoShapeType", 0)) if hasattr(shape, "AutoShapeType") else 0,
        "shape_type": int(getattr(shape, "Type", 0)),
        "group_path": []
    }
    d["is_picture"] = (d["shape_type"] == MSO_PICTURE)
    try:
        is_conn = bool(getattr(shape, "Connector", False))
    except Exception:
        is_conn = False
    d["is_connector"] = is_conn
    if is_conn:
        try:
            cf = shape.ConnectorFormat
            begin_connected = False
            end_connected = False
            b_name = ""
            e_name = ""
            try:
                begin_connected = bool(cf.BeginConnected)
            except Exception:
                begin_connected = False
            try:
                end_connected = bool(cf.EndConnected)
            except Exception:
                end_connected = False
            for attr in ("BeginConnectedShape", "BeginShape", "BeginConnectedTo", "BeginConnectedToShape"):
                try:
                    bs = getattr(cf, attr)
                    if bs is not None:
                        try:
                            b_name = bs.Name
                        except Exception:
                            b_name = str(bs)
                        break
                except Exception:
                    continue
            for attr in ("EndConnectedShape", "EndShape", "EndConnectedTo", "EndConnectedToShape"):
                try:
                    es = getattr(cf, attr)
                    if es is not None:
                        try:
                            e_name = es.Name
                        except Exception:
                            e_name = str(es)
                        break
                except Exception:
                    continue
            d["conn"] = {
                "begin_connected": begin_connected,
                "end_connected": end_connected,
                "begin_shape": b_name or "",
                "end_shape": e_name or ""
            }
            try:
                d["arrow"] = {"begin": int(cf.BeginType), "end": int(cf.EndType)}
            except Exception:
                d["arrow"] = {}
        except Exception:
            pass
    try:
        path = []
        sh = shape
        while True:
            try:
                pg = sh.ParentGroup
            except Exception:
                pg = None
            if not pg:
                break
            try:
                path.append(pg.Name)
            except Exception:
                try:
                    path.append(str(pg))
                except Exception:
                    path.append("")
            sh = pg
        d["group_path"] = list(reversed(path))
    except Exception:
        pass
    d["inside_texts"] = []
    return d

def iter_container(container):
    try:
        cnt = int(container.Count)
    except Exception:
        return []
    out = []
    for i in range(1, cnt+1):
        try:
            if hasattr(container, "Item"):
                sh = container.Item(i)
            else:
                sh = container(i)
            out.append(sh)
        except Exception:
            try:
                out.append(container[i-1])
            except Exception:
                continue
    return out

def walk_flatten(container, out_list):
    for sh in iter_container(container):
        st = int(getattr(sh, "Type", 0))
        if st == MSO_GROUP:
            try:
                walk_flatten(sh.GroupItems, out_list)
            except Exception:
                out_list.append(shape_basic_dict(sh))
        else:
            out_list.append(shape_basic_dict(sh))

def dump_with_compact_inside_texts(data, fp, indent=2, ensure_ascii=False):
    def _write(o, level):
        if isinstance(o, dict):
            fp.write('{\n')
            items = list(o.items())
            for i, (k, v) in enumerate(items):
                fp.write(' ' * (level * indent) + json.dumps(k, ensure_ascii=ensure_ascii) + ': ')
                if k == "inside_texts" and isinstance(v, list):
                    # 配列は複数行、要素は1行のコンパクト JSON
                    fp.write('[\n')
                    for j, elem in enumerate(v):
                        fp.write(' ' * ((level + 1) * indent))
                        fp.write(json.dumps(elem, ensure_ascii=ensure_ascii, separators=(',', ':')))
                        fp.write(',\n' if j != len(v) - 1 else '\n')
                    fp.write(' ' * (level * indent) + ']')
                else:
                    _write(v, level + 1)
                fp.write(',\n' if i != len(items) - 1 else '\n')
            fp.write(' ' * ((level - 1) * indent) + '}')
        elif isinstance(o, list):
            fp.write('[\n')
            for i, x in enumerate(o):
                fp.write(' ' * (level * indent))
                _write(x, level + 1)
                fp.write(',\n' if i != len(o) - 1 else '\n')
            fp.write(' ' * ((level - 1) * indent) + ']')
        else:
            fp.write(json.dumps(o, ensure_ascii=ensure_ascii))

    _write(data, 1)

# --------------------------
# main
# --------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True, help="出力先 JSON パス")
    ap.add_argument("--debug", action="store_true", help="デバッグ出力を有効化（図形のプロパティを出力）")
    args = ap.parse_args()

    global DEBUG
    DEBUG = bool(args.debug)

    excel = get_excel()
    sel = excel.Selection
    if sel is None:
        print("Excelで図形を選択してから実行してください。", file=sys.stderr)
        sys.exit(2)

    sel_rects = []
    try:
        sr = sel.ShapeRange
        for i in range(1, int(sr.Count) + 1):
            try:
                sh = sr.Item(i)
            except Exception:
                try:
                    sh = sr[i-1]
                except Exception:
                    continue
            try:
                sel_rects.append(rect_abs(sh))
            except Exception:
                try:
                    L = float(sh.Left); T = float(sh.Top); W = float(sh.Width); H = float(sh.Height)
                    sel_rects.append((L, T, L+W, T+H))
                except Exception:
                    continue
    except Exception:
        try:
            if hasattr(sel, "Left") and hasattr(sel, "Width"):
                L = float(sel.Left); T = float(sel.Top); W = float(sel.Width); H = float(sel.Height)
                sel_rects.append((L, T, L+W, T+H))
            else:
                try:
                    L = float(sel.Left); T = float(sel.Top); W = float(sel.Width); H = float(sel.Height)
                    sel_rects.append((L, T, L+W, T+H))
                except Exception:
                    pass
        except Exception:
            pass

    if not sel_rects:
        print("選択図形の矩形が取得できません。", file=sys.stderr)
        sys.exit(2)

    selection_bbox = rect_expand(rect_union(sel_rects), SELECTION_MARGIN_PT)

    sheet = excel.ActiveSheet
    all_shapes = []
    walk_flatten(sheet.Shapes, all_shapes)

    shapes = [d for d in all_shapes if rect_intersects(d["rect_ltrb"], selection_bbox)]

    # text は廃止運用。inside_texts の候補は text_orig を持つ図形のみ
    text_shapes = [s for s in shapes if (s.get("text_orig") or "").strip()]
    for s in shapes:
        s["inside_texts"] = []
        r = s["rect_ltrb"]
        for t in text_shapes:
            if t["id"] == s["id"]:
                continue
            tr = t["rect_ltrb"]
            # 完全内包のみ記録（重なりは無視）
            if rect_contains_with_margin(r, tr, CONTAIN_MARGIN_PT):
                s["inside_texts"].append({
                    "id": t["id"],
                    "text_orig": t.get("text_orig",""),
                })
                continue

    data = {
        "workbook": excel.ActiveWorkbook.Name if excel.ActiveWorkbook else "",
        "sheet": sheet.Name if sheet else "",
        "unit": "pt",
        "selection_bbox": selection_bbox,
        "shape_count": len(shapes),
        "shapes": shapes
    }
    with open(args.out, "w", encoding="utf-8") as f:
        dump_with_compact_inside_texts(data, f, indent=2, ensure_ascii=False)
    print(f"Wrote {args.out} (shapes={len(shapes)}, bbox={selection_bbox})")

if __name__ == "__main__":
    try:
        main()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
