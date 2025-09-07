# -*- coding: utf-8 -*-
"""
analyze.py
- ゾーン判定（ルール簡素化）：内側にノード>=1 もしくは 内側にゾーンが含まれる図形をゾーン化（伝播昇格）
- ゾーン名の表示は label_raw（枠の自テキスト）をそのまま利用
- ゾーン外ノードは Internet ゾーン（zone_internet）へ自動割当
- **GW/ゲートウェイ/gateway を含むノードは「境界機器」として“より内側のゾーン”へ自動再割当**
- プロトコル抽出はゾーン/ノード名を一切用いず、判定不能は unknown
- ゾーン階層/隣接/重なり、越境通信、レポート（人間向け）

使い方:
    python analyze.py --diagram diagram.json --out_dir .
"""
import argparse
import json
import math
import os
import re
from typing import List, Dict, Any, Tuple, Set

MSO_TEXTBOX = 17

# ===== 正規化パターン（補助用） =====
ZONE_PATTERNS = {
    "dmz": [
        r"(?i)\bdmz\b",
        r"(?i)d\s*m\s*z",
        r"ＤＭＺ",
        r"dmz\s*ゾーン", r"dmz\s*zone",
        r"公開(?:ゾーン|セグメント|領域)?",
        r"(?i)\binternet\b", r"インターネット",
        r"demilitarized"
    ],
    "internal": [r"(?i)\binternal\b", r"社内", r"業務", r"内部", r"イントラネット"],
    "external": [r"(?i)\bexternal\b", r"社外", r"外部", r"(?i)\binternet\b", r"インターネット"],
    "management": [r"(?i)\bmgmt\b|management", r"運用", r"管理(?:ゾーン|ネットワーク|seg|セグメント)?"],
    "vpc": [r"(?i)\bvpc\b", r"vpcネットワーク", r"vpc\s*network", r"サブネット", r"subnet"],
    "cloud_aws": [r"(?i)\baws\b", r"(?i)aws\s*cloud", r"アマゾン|アマゾンウェブ|(?i)awsクラウド", r"(?i)amazon\s*web\s*services"]
}
ROLE_PATTERNS = {
    "web": [r"(?i)\bweb\b", r"Webサーバ", r"リバースプロキシ", r"proxy", r"nginx", r"httpd", r"alb", r"elb", r"waf"],
    "app": [r"(?i)\bapp\b", r"\bap\b", r"アプリ", r"application", r"tomcat", r"was", r"backend"],
    "db" : [r"(?i)\bdb\b",  r"DBサーバ", r"データベース", r"mysql", r"postgres", r"oracle", r"rds"],
}

# ===== プロトコル検出パターン =====
PROTOCOL_PATTERNS = {
    "ssh": [r"(?i)\bssh\b", r"\b22/tcp\b", r"(?<!\d)22(?!\d)"],
    "telnet": [r"(?i)\btelnet\b", r"\b23/tcp\b", r"(?<!\d)23(?!\d)", r"テルネット"],
    "http": [r"(?i)\bhttp\b", r"\b80/tcp\b", r"(?<!\d)80(?!\d)"],
    "https": [r"(?i)\bhttps\b", r"\b443/tcp\b", r"(?<!\d)443(?!\d)"],
    "mysql": [r"(?i)\bmysql\b", r"(?<!\d)3306(?!\d)"],
    "postgres": [r"(?i)\bpostgres(?:ql)?\b", r"(?<!\d)5432(?!\d)"],
    "tcp": [r"(?i)\btcp\b"],
    "udp": [r"(?i)\budp\b"],
}

FW = "！＂＃＄％＆＇（）＊＋，－．／０１２３４５６７８９：；＜＝＞？" \
     "＠ＡＢＣＤＥＦＧＨＩＪＫＬＭＮＯＰＱＲＳＴＵＶＷＸＹＺ［＼］＾＿" \
     "｀ａｂｃｄｅｆｇｈｉｊｋｌｍｎｏｐｑｒｓｔｕｖｗｘｙｚ｛｜｝～"
HW = "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_" \
     "`abcdefghijklmnopqrstuvwxyz{|}~"
TRANS_FW2HW = str.maketrans({ord(f): h for f, h in zip(FW, HW)})

# ===== 幾何ユーティリティ =====
def rect_area(r): L,T,R,B = r; return max(0.0,(R-L))*max(0.0,(B-T))
def rect_contains(outer, inner):
    L1,T1,R1,B1=outer; L2,T2,R2,B2=inner
    return (L1<=L2) and (T1<=T2) and (R1>=R2) and (B1>=B2)
def rect_intersection(a,b):
    L1,T1,R1,B1=a; L2,T2,R2,B2=b
    L=max(L1,L2); T=max(T1,T2); R=min(R1,R2); B=min(B1,B2)
    if R<=L or B<=T: return (0,0,0,0)
    return (L,T,R,B)
def overlap_ratio(inner, outer):
    inter = rect_intersection(inner, outer); ia = rect_area(inter); a = rect_area(inner)
    return ia/a if a>0 else 0.0
def center(r): L,T,R,B=r; return ((L+R)/2.0,(T+B)/2.0)
def dist_pt_rect(pt, r):
    x,y=pt; L,T,R,B=r
    dx=max(L-x,0,x-R); dy=max(T-y,0,y-B)
    return math.hypot(dx,dy)

# ===== 正規化/役割 =====
def norm_text(s: str) -> str:
    if not s:
        return ""
    s = s.translate(TRANS_FW2HW)
    s = (s.replace("\u3000", " ").replace("\xa0", " ")
           .replace("\r\n", "\n").replace("\r", "\n"))
    s = " ".join(s.split())
    return s.strip()

def normalize_zone(text):
    t = norm_text(text)
    for std, pats in ZONE_PATTERNS.items():
        for p in pats:
            if re.search(p, t):
                return std
    return None

def infer_role(text):
    t = norm_text(text)
    for role, pats in ROLE_PATTERNS.items():
        for p in pats:
            if re.search(p, t):
                return role
    return None

# ==== Gateway（境界機器）判定 ====
GATEWAY_PATTERNS = [
    r"(?i)\bgateway\b",     # 英語
    r"ゲートウェイ",         # 日本語
    r"(?i)\b[a-z]*gw\b",    # IGW/NATGW/VGW/... も含む（gw, igw, natgw 等）
    r"(?i)\nat\b",    # NAT
    r"ナット",    # NAT
]
def is_gateway_text(s: str) -> bool:
    t = norm_text(s or "")
    if not t: return False
    for p in GATEWAY_PATTERNS:
        if re.search(p, t):
            return True
    return False

# ===== inside_texts 再構築（解析側フォールバック） =====
CONTAIN_MARGIN_PT   = 8.0
OVERLAP_MIN_RATIO   = 0.10  # 10%

def ensure_inside_texts(shapes: List[Dict[str,Any]]) -> None:
    need = not any(s.get("inside_texts") for s in shapes)
    if not need:
        return
    text_shapes = [s for s in shapes if (s.get("text") or "").strip()]
    for s in shapes:
        s["inside_texts"] = []
        r = s["rect_ltrb"]
        for t in text_shapes:
            if t is s:
                continue
            tr = t["rect_ltrb"]
            if rect_contains(r, tr) or overlap_ratio(tr, r) >= OVERLAP_MIN_RATIO:
                s["inside_texts"].append({
                    "id": t["id"],
                    "text": t["text"],
                    "text_source": t.get("text_source",""),
                    "rect_ltrb": tr
                })

def effective_text(shape: Dict[str,Any]) -> str:
    if not shape:
        return ""
    base = norm_text(shape.get("text","") or "")
    if base:
        return base
    its = (shape.get("inside_texts") or [])
    if not its:
        return ""
    def _txt(it):
        if isinstance(it, dict): return it.get("text","") or ""
        if isinstance(it, str):  return it
        try: return str(it)
        except Exception: return ""
    its_sorted = sorted(its, key=lambda x: len(_txt(x)), reverse=True)
    picked = [norm_text(_txt(it)) for it in its_sorted[:3] if norm_text(_txt(it))]
    return " / ".join(picked)

# ===== 安全フィルタ =====
def is_valid_rect(rect)->bool:
    if not isinstance(rect,(list,tuple)) or len(rect)!=4: return False
    try:
        L,T,R,B = rect
        return all(isinstance(x,(int,float)) for x in (L,T,R,B))
    except Exception:
        return False

def filter_valid_shapes(shapes_in: List[Dict[str,Any]])->Tuple[List[Dict[str,Any]],List[str]]:
    valid=[]; issues=[]
    for s in shapes_in or []:
        rect=s.get("rect_ltrb")
        if not is_valid_rect(rect):
            issues.append(f"- drop id='{s.get('id','')}' (invalid rect_ltrb={rect})")
            continue
        valid.append(s)
    return valid, issues

# ===== ゾーン検出補助 =====
def is_label_like(shape):
    txt=norm_text(shape.get("text",""))
    if not txt: return False
    if int(shape.get("shape_type",0))==MSO_TEXTBOX:
        if re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", txt):  # IP
            return False
        if re.search(r"[A-Za-z]+[0-9]{1,3}", txt):       # host01 等
            return False
        return True
    if re.search(r"(凡例|注記|概要|説明|レイヤ|層|図中記号)", txt):
        return True
    return False

def is_line_like(shape):
    if shape.get("is_connector"): return True
    if (shape.get("text") or "").strip(): return False
    L,T,R,B=shape["rect_ltrb"]; w=abs(R-L); h=abs(B-T)
    if min(w,h)<1.0: return True
    aspect=max(w,h)/max(1.0,min(w,h))
    return aspect>=8.0

def line_endpoints_rect(shape):
    L,T,R,B=shape["rect_ltrb"]; w=R-L; h=B-T
    if w>=h:
        p1=(L,(T+B)/2.0); p2=(R,(T+B)/2.0)
    else:
        p1=((L+R)/2.0,T); p2=((L+R)/2.0,B)
    dir_hint="unknown"
    arrow=shape.get("arrow",{})
    if arrow:
        if arrow.get("end",0)!=0: dir_hint="p1_to_p2"
        elif arrow.get("begin",0)!=0: dir_hint="p2_to_p1"
    return p1,p2,dir_hint

def snap_point_to_nodes(pt, node_rects, tol=18.0):
    best=None; best_d=1e9
    for n in node_rects:
        x,y=pt; L,T,R,B=n["rect"]
        dx=max(L-x,0,x-R); dy=max(T-y,0,y-B)
        d=math.hypot(dx,dy)
        if d<best_d:
            best_d=d; best=n
    return (best if best_d<=tol else None), best_d

# ===== ゾーン検出（ご要望ルール） =====
def detect_zones(shapes):
    if not shapes:
        return [], []

    by_id = {s["id"]: s for s in shapes}

    def contains(a_rect, b_rect):
        return rect_contains(a_rect, b_rect)

    def is_node_like(s):
        if s.get("is_connector"):
            return False
        if is_label_like(s):
            return False
        return True

    xs = [s["rect_ltrb"][0] for s in shapes] + [s["rect_ltrb"][2] for s in shapes]
    ys = [s["rect_ltrb"][1] for s in shapes] + [s["rect_ltrb"][3] for s in shapes]
    Lg, Tg, Rg, Bg = min(xs), min(ys), max(xs), max(ys)
    scene_area = max(1.0, (Rg - Lg) * (Bg - Tg))

    # 1) 初期ゾーン: 内側にノード>=1
    node_like_ids = {s["id"] for s in shapes if is_node_like(s)}
    zone_ids: Set[str] = set()
    for s in shapes:
        if is_label_like(s) or s.get("is_connector"):
            continue
        sr = s["rect_ltrb"]
        for nid in node_like_ids:
            if nid == s["id"]:
                continue
            if contains(sr, by_id[nid]["rect_ltrb"]):
                zone_ids.add(s["id"])
                break

    # 2) 伝播: 内側に既存ゾーンを含む → ゾーン昇格
    changed = True
    while changed:
        changed = False
        for s in shapes:
            if is_label_like(s) or s.get("is_connector"):
                continue
            sid = s["id"]
            if sid in zone_ids:
                continue
            sr = s["rect_ltrb"]
            for zid in list(zone_ids):
                if zid == sid:
                    continue
                if contains(sr, by_id[zid]["rect_ltrb"]):
                    zone_ids.add(sid); changed = True; break

    # 3) zones_raw 生成
    zones_raw=[]
    for zid in zone_ids:
        s = by_id[zid]; r = s["rect_ltrb"]
        inside_count = sum(1 for t in shapes if t is not s and contains(r, t["rect_ltrb"]))
        zones_raw.append({
            "id": zid,
            "rect": r,
            "area": rect_area(r),
            "inside": inside_count
        })
    if not zones_raw:
        zones_raw=[{
            "id": "_scene_",
            "rect": (Lg, Tg, Rg, Bg),
            "area": scene_area,
            "inside": len(shapes)
        }]

    # 4) ゾーン認識（label_raw/normalized）
    zones_norm=[]
    for z in zones_raw:
        zid = z["id"]; zr = z["rect"]
        sh = by_id.get(zid)
        self_text_raw = norm_text(sh.get("text","") or "") if sh else ""
        label_raw = self_text_raw
        chosen_norm=None; score=0.0
        if self_text_raw:
            n=normalize_zone(self_text_raw)
            if n: chosen_norm=n; score=1.8
        zones_norm.append({
            "zone_id": zid,
            "zone_rect": zr,
            "label_raw": label_raw,
            "normalized": chosen_norm or "unknown",
            "score": round(max(score,0.0),3)
        })

    return zones_raw, zones_norm

# ===== グラフ構築（プロトコル抽出を厳格化） =====
def build_graph(shapes, zone_ids:Set[str]):
    by_id={s["id"]:s for s in shapes}
    def is_zone_rect(s): return s["id"] in zone_ids

    nodes=[s for s in shapes if (not s.get("is_connector")) and (not is_label_like(s)) and (not is_zone_rect(s))]
    node_rects=[{"id":n["id"],"rect":n["rect_ltrb"]} for n in nodes]

    edges=[]
    for s in shapes:
        if not s.get("is_connector"): continue
        src=dst=""
        conn=s.get("conn",{})
        if conn:
            if conn.get("begin_connected"): src=conn.get("begin_shape","")
            if conn.get("end_connected"):   dst=conn.get("end_shape","")
        conf="high" if (src and dst) else ("medium" if (src or dst) else "low")

        L,T,R,B=s["rect_ltrb"]; w=R-L; h=B-T
        if w>=h:
            p_begin=(L,(T+B)/2.0); p_end=(R,(T+B)/2.0)
        else:
            p_begin=((L+R)/2.0,T); p_end=((L+R)/2.0,B)

        if not src:
            n1,_=snap_point_to_nodes(p_begin, node_rects, tol=18.0)
            src=n1["id"] if n1 else ""
        if not dst:
            n2,_=snap_point_to_nodes(p_end, node_rects, tol=18.0)
            dst=n2["id"] if n2 else ""

        def relabel_if_label(node_id, pt):
            if not node_id or node_id not in by_id: return node_id
            sh=by_id[node_id]
            if is_label_like(sh):
                n,_=snap_point_to_nodes(pt, node_rects, tol=22.0)
                return n["id"] if n else node_id
            return node_id

        src=relabel_if_label(src, p_begin)
        dst=relabel_if_label(dst, p_end)
        conf="high" if (src and dst) else ("medium" if (src or dst) else conf)

        edges.append({"id":s["id"],"src":src,"dst":dst,"dir_hint":"src_to_dst","confidence":conf,"kind":"connector"})

    # 疑似エッジ（長細い矩形）
    for s in shapes:
        if s.get("is_connector"): continue
        if not is_line_like(s): continue
        p1,p2,dir_hint=line_endpoints_rect(s)
        n1,_=snap_point_to_nodes(p1, node_rects)
        n2,_=snap_point_to_nodes(p2, node_rects)
        conf="medium" if (n1 and n2) else "low"
        edges.append({"id":s["id"],"src":n1["id"] if n1 else "","dst":n2["id"] if n2 else "","dir_hint":dir_hint,"confidence":conf,"kind":"pseudo"})

    # --- プロトコル抽出（ゾーン名/ノード名は使用禁止。判定不能は unknown） ---
    text_shapes = [s for s in shapes if (s.get("text") or "").strip()]

    def rect_center(r):
        x,y = center(r)
        return x,y

    def dist_pt_segment(pt, a, b):
        px,py = pt; ax,ay = a; bx,by = b
        vx = bx-ax; vy = by-ay
        wx = px-ax; wy = py-ay
        c1 = vx*wx + vy*wy
        if c1 <= 0:
            return math.hypot(px-ax, py-ay)
        c2 = vx*vx + vy*vy
        if c2 <= c1:
            return math.hypot(px-bx, py-by)
        t = c1 / c2
        projx = ax + t*vx; projy = ay + t*vy
        return math.hypot(px-projx, py-projy)

    ZONE_WORD_SKIP = {"aws", "awsクラウド", "クラウド", "cloud", "vpc", "dmz", "internal", "internet",
                      "社内", "ネットワーク", "サブネット", "subnet", "lan", "wan"}

    def looks_like_zone_or_node_label(txt: str) -> bool:
        if not txt:
            return True
        t = norm_text(txt).lower()
        if normalize_zone(t) is not None:
            return True
        if any(w in t for w in ZONE_WORD_SKIP):
            return True
        if infer_role(t) in {"web","app","db"}:
            return True
        if re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", t):  # IP
            return True
        if re.search(r"[a-z][a-z0-9\-]{0,20}\d{1,3}", t, flags=re.I):  # host01
            return True
        if re.search(r"[a-z0-9\-]+\.[a-z]{2,}", t, flags=re.I):       # FQDN
            return True
        return False

    for e in edges:
        try:
            shape_for_edge = by_id.get(e.get("id"))
            if shape_for_edge:
                seg_a, seg_b, _ = line_endpoints_rect(shape_for_edge)
            else:
                seg_a = seg_b = None
                src_rect = by_id.get(e.get("src",""), {}).get("rect_ltrb")
                dst_rect = by_id.get(e.get("dst",""), {}).get("rect_ltrb")
                if src_rect and dst_rect:
                    seg_a = center(src_rect); seg_b = center(dst_rect)

            best_proto = None
            best_proto_raw = None
            best_d = 1e9
            tol = 48.0

            for t in text_shapes:
                if t.get("id") in (e.get("src"), e.get("dst")):
                    continue
                if t.get("id") in zone_ids:
                    continue
                tr = t.get("rect_ltrb")
                if not is_valid_rect(tr):
                    continue
                if not (seg_a and seg_b):
                    continue
                cx, cy = rect_center(tr)
                cand_d = dist_pt_segment((cx,cy), seg_a, seg_b)
                if cand_d > tol:
                    continue

                txt = t.get("text") or ""
                if looks_like_zone_or_node_label(txt):
                    continue

                proto, proto_raw = find_protocol_in_text(txt)
                if proto:
                    if cand_d < best_d:
                        best_d = cand_d
                        best_proto = proto
                        best_proto_raw = proto_raw

            if best_proto:
                e["protocol"] = best_proto
                e["protocol_raw"] = best_proto_raw
            else:
                e["protocol"] = "unknown"
                e["protocol_raw"] = ""
        except Exception:
            e["protocol"] = e.get("protocol","unknown") or "unknown"
            e["protocol_raw"] = e.get("protocol_raw","")

    return nodes, edges

# ===== ゾーン間関係（包含／隣接／重なり） =====
def rect_touching(a, b, tol=1.0):
    L1,T1,R1,B1=a; L2,T2,R2,B2=b
    horizontally_touch = (abs(R1 - L2) <= tol or abs(R2 - L1) <= tol) and not (B1 <= T2 or B2 <= T1)
    vertically_touch   = (abs(B1 - T2) <= tol or abs(B2 - T1) <= tol) and not (R1 <= L2 or R2 <= L1)
    return horizontally_touch or vertically_touch

def build_zone_relations(zones_norm):
    n = len(zones_norm)
    parents = {z["zone_id"]: None for z in zones_norm}

    for i in range(n):
        zi = zones_norm[i]; ri = zi["zone_rect"]
        best_parent = None; best_area = float("inf")
        for j in range(n):
            if i == j: continue
            zj = zones_norm[j]; rj = zj["zone_rect"]
            if rect_contains(rj, ri):
                area_j = rect_area(rj)
                if area_j < best_area:
                    best_area = area_j
                    best_parent = zj["zone_id"]
        parents[zi["zone_id"]] = best_parent

    children = {z["zone_id"]: [] for z in zones_norm}
    for cid, pid in parents.items():
        if pid:
            children[pid].append(cid)

    def depth_of(zid):
        d=0; cur=zid; seen=set()
        while parents.get(cur):
            if cur in seen: break
            seen.add(cur); cur = parents[cur]; d+=1
        return d

    hierarchy = {z["zone_id"]: {"parent": parents[z["zone_id"]], "children": children[z["zone_id"]], "depth": depth_of(z["zone_id"])} for z in zones_norm}

    overlaps = []
    adjacency = []
    for i in range(n):
        zi = zones_norm[i]; ri = zi["zone_rect"]
        for j in range(i+1, n):
            zj = zones_norm[j]; rj = zj["zone_rect"]
            inter = rect_intersection(ri, rj)
            if rect_area(inter) > 0.0:
                overlaps.append((zi["zone_id"], zj["zone_id"]))
            elif rect_touching(ri, rj, tol=1.0):
                adjacency.append((zi["zone_id"], zj["zone_id"]))

    return hierarchy, overlaps, adjacency

# ===== ゾーン割当（最も内側優先＋外部は Internet へ） =====
def assign_nodes_to_most_specific_zone(nodes, zones_norm):
    hierarchy, _, _ = build_zone_relations(zones_norm)
    results=[]
    for n in nodes:
        nr = n["rect_ltrb"]
        containing = [z for z in zones_norm if rect_contains(z["zone_rect"], nr)]
        if containing:
            containing.sort(key=lambda z: (-hierarchy[z["zone_id"]]["depth"], rect_area(z["zone_rect"])))
            z = containing[0]
            results.append({
                "node_id": n["id"],
                "zone_id": z["zone_id"],
                "zone_normalized": z["normalized"],
                "confidence": "high",
                "overlap": 1.0
            })
            continue

        results.append({
            "node_id": n["id"],
            "zone_id": "zone_internet",
            "zone_normalized": "internet",
            "confidence": "high",
            "overlap": 0.0,
            "note": "auto-reassigned-to-internet"
        })
    return results

# ===== 越境通信の要約 =====
def summarize_cross_zone_edges(edges, assigns):
    node2zone = {a["node_id"]: a.get("zone_id") for a in assigns}
    out=[]
    for e in edges:
        s = e.get("src") or ""; d = e.get("dst") or ""
        if not s or not d: continue
        zs = node2zone.get(s); zd = node2zone.get(d)
        if zs is None or zd is None: continue
        if zs != zd:
            out.append({
                "edge_id": e["id"],
                "src_node": s, "dst_node": d,
                "src_zone": zs, "dst_zone": zd,
                "protocol": e.get("protocol"), "protocol_raw": e.get("protocol_raw")
            })
    return out

# ===== 付加：エッジへゾーンタグ反映 =====
def update_edge_zone_tags(edges, assigns):
    node2zone = {a["node_id"]: a.get("zone_id") for a in assigns}
    for e in edges:
        s = e.get("src") or ""; d = e.get("dst") or ""
        e["src_zone"] = node2zone.get(s)
        e["dst_zone"] = node2zone.get(d)

# ===== Gateway（境界機器）の「内側ゾーン」再割当 =====
def adjust_gateway_to_inner_zone(assigns, edges, zones_norm, hierarchy, by_id):
    """
    境界機器（GW/ゲートウェイ/gateway を含むラベル）を、幾何情報に基づいて再割当する。
      1) 自身が包含されているゾーンのうち最も深いゾーンへ（同深度は面積が小さい方）
      2) 無ければ、交差しているゾーンのうち最も深いゾーンへ（同深度は交差面積が大きい方、次点で面積が小さい方）
      3) それも無ければ Internet 扱い（zone_internet）
    """
    # 補助: depth 取得
    def depth(zid: str) -> int:
        if not hierarchy:
            return 0
        info = hierarchy.get(zid) or {}
        return int(info.get("depth", 0))

    # 便利マップ
    zone_info = {z["zone_id"]: z for z in zones_norm}

    for a in assigns:
        nid = a["node_id"]
        txt = a.get("effective_text") or a.get("text_raw") or ""
        if not is_gateway_text(txt):
            continue

        sh = by_id.get(nid)
        if not sh:
            continue
        nr = sh.get("rect_ltrb")
        if not is_valid_rect(nr):
            continue

        # 1) 包含候補（Internet は除外）
        contain_cands = []
        for z in zones_norm:
            zid = z["zone_id"]
            if zid == "zone_internet":
                continue
            zr = z["zone_rect"]
            if rect_contains(zr, nr):
                # (zid, depth, zone_area)
                contain_cands.append((zid, depth(zid), rect_area(zr)))

        if contain_cands:
            # 最も深い → depth 降順、同深度は面積が小さい（より内側）
            contain_cands.sort(key=lambda t: (-t[1], t[2]))
            target = contain_cands[0][0]
            if target != a.get("zone_id"):
                a["zone_id"] = target
                a["zone_normalized"] = zone_info.get(target, {}).get("normalized", a.get("zone_normalized"))
                note = a.get("note")
                tag = "auto-reassigned-[gateway]-by-geom:contain"
                a["note"] = f"{note};{tag}" if note else tag
                if a.get("confidence") in (None, "low", "medium"):
                    a["confidence"] = "high"
            continue  # 包含が最優先

        # 2) 交差候補（Internet は除外）
        intersect_cands = []
        for z in zones_norm:
            zid = z["zone_id"]
            if zid == "zone_internet":
                continue
            zr = z["zone_rect"]
            inter = rect_intersection(zr, nr)
            ia = rect_area(inter)
            if ia > 0.0:
                # (zid, depth, inter_area, zone_area)
                intersect_cands.append((zid, depth(zid), ia, rect_area(zr)))

        if intersect_cands:
            # 最も深い → depth 降順
            # 同深度 → 交差面積が大きい方
            # さらに同率 → ゾーン枠面積が小さい方（より内側）
            intersect_cands.sort(key=lambda t: (-t[1], -t[2], t[3]))
            target = intersect_cands[0][0]
            if target != a.get("zone_id"):
                a["zone_id"] = target
                a["zone_normalized"] = zone_info.get(target, {}).get("normalized", a.get("zone_normalized"))
                note = a.get("note")
                tag = "auto-reassigned-[gateway]-by-geom:intersect"
                a["note"] = f"{note};{tag}" if note else tag
                if a.get("confidence") in (None, "low", "medium"):
                    a["confidence"] = "high"
            continue

        # 3) どのゾーンとも接しない → Internet 扱い
        if a.get("zone_id") != "zone_internet":
            a["zone_id"] = "zone_internet"
            a["zone_normalized"] = "internet"
            note = a.get("note")
            tag = "auto-reassigned-[gateway]-to-internet(no-geom-contact)"
            a["note"] = f"{note};{tag}" if note else tag
            if a.get("confidence") in (None, "low", "medium"):
                a["confidence"] = "high"


# ===== レポート（人向け：label_raw 主体） =====
def render_report(meta, zones_raw, zones_norm, assigns, nodes, edges, by_id, diagnostics: List[str],
                  hierarchy=None, overlaps=None, adjacency=None, cross_zone=None):
    def label_for(zid: str) -> str:
        if zid == "zone_internet": return "Internet"
        for z in zones_norm:
            if z["zone_id"] == zid:
                return z.get("label_raw","") or "(ラベルなし)"
        return "(不明)"

    lines=[]
    lines.append(f"# 構成図解析レポート（{meta.get('workbook','')} / {meta.get('sheet','')}）\n")
    lines.append("## サマリ")
    lines.append(f"- 図形数: {meta.get('shape_count',0)}")
    lines.append(f"- ゾーン候補: {len(zones_norm)}")
    lines.append(f"- ノード数（非コネクタ・ラベル除外）: {len(nodes)}")
    lines.append(f"- エッジ数（コネクタ+疑似）: {len(edges)}\n")

    if diagnostics:
        lines.append("## 診断メモ")
        lines.extend(diagnostics)
        lines.append("")

    lines.append("## ゾーン（人間ラベル）")
    for z in zones_norm:
        zid = z["zone_id"]
        label_raw = z.get("label_raw","") or "(ラベルなし)"
        zr = z["zone_rect"]; L,T,R,B = zr
        lines.append(f"- `{zid}`: **{label_raw}** rect=({int(L)},{int(T)},{int(R)},{int(B)})")

    if hierarchy is not None:
        lines.append("\n## ゾーン階層")
        for zid, info in sorted(hierarchy.items(), key=lambda kv: kv[1]["depth"]):
            parent = info["parent"] or "-"
            lines.append(f"- {zid}: depth={info['depth']} parent={parent} children={len(info['children'])}")

    if overlaps:
        lines.append("\n## ゾーン重なり")
        for a,b in overlaps:
            lines.append(f"- {a} ⟂ {b} (overlap)")

    if adjacency:
        lines.append("\n## ゾーン隣接")
        for a,b in adjacency:
            lines.append(f"- {a} || {b} (adjacent)")

    lines.append("\n## ノードのゾーン割当（人間ラベルで表示）")
    for a in assigns:
        node = by_id.get(a["node_id"])
        from_txt = effective_text(node) if node else ""
        role = infer_role(from_txt) if from_txt else None
        role_s = f", role={role}" if role else ""
        src = node.get("text_source","") if node else ""
        zid = a.get("zone_id")
        label_disp = label_for(zid)
        lines.append(
            f"- node=`{a['node_id']}` → zone=`{label_disp}` "
            f"(conf={a['confidence']}, overlap={a.get('overlap',0)}{role_s}) "
            f"text='{from_txt}' src={src} note={a.get('note','')}"
        )

    lines.append("\n## エッジ推定")
    for e in edges:
        extra = ""
        if e.get("protocol"):
            extra = f", proto={e['protocol']} ({e.get('protocol_raw','')})"
        zhint = ""
        if e.get("src_zone") or e.get("dst_zone"):
            zhint = f", zones={label_for(e.get('src_zone'))}->{label_for(e.get('dst_zone'))}"
        lines.append(
            f"- edge=`{e['id']}` kind={e['kind']} {e['src']} -> {e['dst']} "
            f"(dir_hint={e['dir_hint']}, conf={e['confidence']}{extra}{zhint})"
        )

    if cross_zone:
        lines.append("\n## 越境通信（ゾーン間エッジ）")
        for cz in cross_zone:
            pr = f", proto={cz['protocol']}({cz.get('protocol_raw','')})" if cz.get("protocol") else ""
            lines.append(
                f"- {cz['edge_id']}: "
                f"{cz['src_node']}@{label_for(cz['src_zone'])} "
                f"-> {cz['dst_node']}@{label_for(cz['dst_zone'])}{pr}"
            )

    notes=[]
    if any((not z.get("label_raw")) for z in zones_norm):
        notes.append("- ラベル未記入のゾーンがあります（“(ラベルなし)”）。図面のテキストをご確認ください。")
    if any(a["confidence"]=="low" for a in assigns):
        notes.append("- ゾーン割当 LOW があります。配置や選択範囲の再確認を推奨します。")
    if any((not e["src"]) or (not e["dst"]) for e in edges):
        notes.append("- 片端未接続のエッジがあります。矢印の接続（スナップ）をご確認ください。")
    if notes:
        lines.append("\n## 要確認メモ")
        lines.extend(["- "+n for n in notes])

    return "\n".join(lines)

# ===== プロトコル検出ユーティリティ =====
def find_protocol_in_text(s: str):
    if not s:
        return None, None
    t = norm_text(s)
    for proto, pats in PROTOCOL_PATTERNS.items():
        for p in pats:
            try:
                m = re.search(p, t)
                if m:
                    return proto, m.group(0)
            except Exception:
                continue
    return None, None

# ===== main =====
def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--diagram", required=True, help="export_selected.py の出力 JSON")
    ap.add_argument("--out_dir", required=True, help="出力先ディレクトリ（MD/JSON）")
    args=ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    with open(args.diagram,"r",encoding="utf-8") as f:
        diagram=json.load(f)

    raw_shapes=diagram.get("shapes",[])
    diagnostics: List[str]=[]

    shapes,dropped=filter_valid_shapes(raw_shapes)
    if dropped:
        diagnostics.append("### 除外した図形"); diagnostics.extend(dropped)

    # inside_texts を解析側でも補う（保険）
    ensure_inside_texts(shapes)

    if not shapes:
        meta={"workbook":diagram.get("workbook",""),"sheet":diagram.get("sheet",""),
              "unit":diagram.get("unit","pt"),"shape_count":len(raw_shapes)}
        results={"meta":meta,"zones_raw":[],"zones":[],"zone_relations":{}, "assignments":[],"edges":[],"cross_zone_edges":[]}
        out_json=os.path.join(args.out_dir,"analyze_results.json")
        with open(out_json,"w",encoding="utf-8") as f:
            json.dump(results,f,ensure_ascii=False,indent=2)
        out_md=os.path.join(args.out_dir,"report.md")
        with open(out_md,"w",encoding="utf-8") as f:
            f.write("データが空です。画像文字は OCR が必要な場合があります。")
        print("Wrote (empty dataset):", out_json, out_md, sep="\n - ")
        return

    zones_raw, zones_norm = detect_zones(shapes)
    zone_ids={z["zone_id"] for z in zones_norm}
    node_objs, edges = build_graph(shapes, zone_ids)

    # ゾーン割当（内側優先、外部は Internet）
    assigns = assign_nodes_to_most_specific_zone(node_objs, zones_norm)

    # ゾーン間の関係
    hierarchy, overlaps, adjacency = build_zone_relations(zones_norm)

    # assignments にテキスト情報を追記
    by_id={s["id"]:s for s in shapes}
    for a in assigns:
        sh = by_id.get(a["node_id"])
        if sh:
            def _t(it):
                if isinstance(it, dict): return it.get("text","") or ""
                if isinstance(it, str):  return it
                try: return str(it)
                except Exception: return ""
            a["text_raw"] = norm_text(sh.get("text","") or "")
            a["text_source"] = sh.get("text_source","")
            a["effective_text"] = effective_text(sh)
            its = sh.get("inside_texts") or []
            a["inside_texts"] = [norm_text(_t(it)) for it in its if (_t(it) or "").strip()]
        else:
            a["text_raw"] = ""
            a["text_source"] = ""
            a["effective_text"] = ""
            a["inside_texts"] = []

    # **Gateway（境界機器）の再割当 → エッジへゾーンタグ反映**
    adjust_gateway_to_inner_zone(assigns, edges, zones_norm, hierarchy, by_id)
    update_edge_zone_tags(edges, assigns)

    # 越境通信（再割当後に算出）
    cross_zone = summarize_cross_zone_edges(edges, assigns)

    meta={"workbook":diagram.get("workbook",""),"sheet":diagram.get("sheet",""),
          "unit":diagram.get("unit","pt"),"shape_count":len(shapes)}
    results={
        "meta":meta,
        "zones_raw":zones_raw,
        "zones":zones_norm,
        "zone_relations":{
            "hierarchy": hierarchy,
            "overlaps": overlaps,
            "adjacency": adjacency
        },
        "assignments":assigns,
        "edges":edges,
        "cross_zone_edges": cross_zone
    }
    out_json=os.path.join(args.out_dir,"analyze_results.json")
    with open(out_json,"w",encoding="utf-8") as f:
        json.dump(results,f,ensure_ascii=False,indent=2)

    report_md=render_report(meta, zones_raw, zones_norm, assigns, node_objs, edges, by_id, diagnostics,
                            hierarchy=hierarchy, overlaps=overlaps, adjacency=adjacency, cross_zone=cross_zone)
    out_md=os.path.join(args.out_dir,"report.md")
    with open(out_md,"w",encoding="utf-8") as f:
        f.write(report_md)

    print("Wrote:", out_json, out_md, sep="\n - ")

if __name__ == "__main__":
    if os.environ.get("TEST_PROT"):
        samples = ["ssh通信", "ssh", "22", "telnet", "telnet通信", "23", "HTTP", "https://example", "VPC", "AWSクラウド"]
        for s in samples:
            proto, raw = find_protocol_in_text(s)
            print(f"TEST: '{s}' -> proto={proto}, raw={raw}")
    else:
        main()
