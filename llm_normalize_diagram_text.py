# -*- coding: utf-8 -*-
"""
llm_normalize_diagram_text.py

方針：
- 図形の「表示用 text」は一切いじらない（text は使用しない）
- LLM で分類のみ実施し、各図形に resource_* を付与する
    - resource_label
    - resource_label_conf
    - resource_category
    - resource_label_reason（キーは常に出力、空可）
- 入力テキストは text_orig を使用（無ければ name/title/label を後方互換的に利用）

使い方（PowerShell / Ollama の一例）:
  python .\llm_normalize_diagram_text.py `
    --in .\diagram.json `
    --out .\diagram.labeled.json `
    --labels .\resource_label.yaml `
    --backend ollama `
    --model gemma3:4b `
    --ollama_host http://127.0.0.1:11434 `
    --verbose
    --batch 1

OpenAI 互換:
  python .\llm_normalize_diagram_text.py ^
    --in .\diagram.json ^
    --out .\diagram.labeled.json ^
    --labels .\resource_label.yaml ^
    --backend openai ^
    --model gpt-4o-mini ^
    --base_url https://your-openai-compatible-endpoint ^
    --api_key sk-xxxx ^
    --verbose
"""
from __future__ import annotations
import argparse
import json
import os
import re
import sys
from typing import Any, Dict, List, Tuple, Optional

import requests
import yaml


# ----------------------
# 基本ユーティリティ
# ----------------------
def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path: str, obj: Dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        strip_inside_texts(obj)
        dump_with_compact_lists(obj, f, compact_keys=("inside_texts","overlap_ratio"), indent=2, ensure_ascii=False)


def norm_space(s: str) -> str:
    if not isinstance(s, str):
        return ""
    # 全角空白→半角、連続空白縮約、改行trim
    s = s.replace("\u3000", " ").replace("\xa0", " ")
    s = s.replace("\r\n", "\n").replace("\r", "\n")
    s = " ".join(s.split())
    return s.strip()


def strip_code_fence(s: str) -> str:
    # ```json ... ``` や ``` ... ``` を剥がす
    s = s.strip()
    m = re.match(r"^```(?:json)?\s*(.*?)\s*```$", s, flags=re.S)
    if m:
        return m.group(1).strip()
    return s


def extract_json(raw: str) -> Dict[str, Any]:
    """
    LLM 応答から JSON を抽出して dict 化。
    """
    raw = strip_code_fence(raw)
    first = raw.find("{")
    last = raw.rfind("}")
    if first != -1 and last != -1 and last >= first:
        raw = raw[first:last + 1]
    return json.loads(raw)


# ----------------------
# YAML (label / category / synonyms / description 読み込み)
# ----------------------
def load_allowed_labels(yaml_path: str) -> Tuple[List[str], Dict[str, str]]:
    """
    resource_label.yaml から
      - allowed_labels（label の一覧）
      - label2cat（label -> category のマップ）
    を返す。UNKNOWN を保険で追加。
    期待形式の一例:
    {
      "vocabulary": [
        {"label": "VPC_NETWORK", "category": "NETWORKING"},
        ...
      ]
    }
    """
    with open(yaml_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    vocab = data.get("vocabulary", []) if isinstance(data, dict) else []

    labels: List[str] = []
    label2cat: Dict[str, str] = {}
    for it in vocab:
        if not isinstance(it, dict):
            continue
        lb = it.get("label")
        cat = it.get("category")
        if isinstance(lb, str) and lb.strip():
            lb2 = lb.strip()
            labels.append(lb2)
            label2cat[lb2] = cat.strip().upper() if isinstance(cat, str) and cat.strip() else "UNKNOWN"

    # 最低限 UNKNOWN を含める（仕様上必須）
    if "UNKNOWN" not in labels:
        labels.append("UNKNOWN")
        label2cat["UNKNOWN"] = "UNKNOWN"

    labels = sorted(set(labels))
    return labels, label2cat


def load_label_lexicon(yaml_path: str) -> Dict[str, Dict[str, Any]]:
    """
    resource_label.yaml から label -> {category, synonyms, description, vendors} の辞書を作る
    """
    with open(yaml_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    lex: Dict[str, Dict[str, Any]] = {}
    for it in (data.get("vocabulary") or []):
        if not isinstance(it, dict):
            continue
        lb = (it.get("label") or "").strip()
        if not lb:
            continue
        lex[lb] = {
            "category": (it.get("category") or "").strip(),
            # synonyms/aliases をどちらでも受ける
            "synonyms": [str(x).strip() for x in (it.get("synonyms") or it.get("aliases") or []) if str(x).strip()],
            "description": it.get("description") or "",
            "vendors": it.get("vendors") or {},
        }
    return lex


# ----------------------
# プロンプト（分類のみ）
# ----------------------
SYSTEM_PROMPT_TMPL = r"""You are a careful network/cloud diagram labeler.

Your single task:
  - Assign ONE canonical resource label strictly from allowed_labels for each item (the input is the original text captured from a diagram).

STRICT rules:
 - Each input item contains:
   - "text": original text captured from the shape (text_orig)
   - "inside_texts": an array of short texts found **inside** the shape (e.g., "Public subnet", "Private subnet", "Availability Zone", "NAT gateway", "EC2").
 - Use "inside_texts" as hints for structural judgment. For example, if it contains multiple Public/Private subnet labels and/or Availability Zone and NAT/IGW hints, the shape is likely a VPC (VPC_NETWORK).
 - Use the following label metadata when deciding (category/description/synonyms):
   - labels_info = {labels_info_json}
 - Priority rule:
   * If the shape's own "text" strongly matches a label's synonyms (e.g., "AWS", "AWS Cloud", "AWSクラウド" → AWS_CLOUD_ZONE),
     prefer that label even when inside_texts mention subnets.
   * Choose VPC_NETWORK only when the shape itself indicates a VPC (e.g., a VPC CIDR like 10.10.0.0/16 on that shape, or explicit "VPC" wording).
 - Do **not** change the output schema.
 - allowed_labels = {allowed_labels_json}
 - Even if it doesn't exactly match, refer to the allowed_labels' description/synonyms and choose the closest meaning.
- You MUST choose the label ONLY from allowed_labels. If you cannot judge, use "UNKNOWN".
- The "reason" MUST be in Japanese (簡潔に日本語で説明).
- Return ONLY JSON with the following schema:
{{
  "items":[
    {{
      "shape_id": "string",
      "original": "string",               // from text_orig
      "label": "string",                  // from allowed_labels or "UNKNOWN"
      "label_confidence": 0.0-1.0,
      "reason": "string"                  // 日本語
    }}
  ]
}}
- Do NOT add other fields.
- Confidence should be in [0.0..1.0].
"""


def build_user_prompt(shapes: List[Dict[str, Any]]) -> str:
    """
    LLM へ渡す user メッセージ。
    - 各 item に shape_id / text (=text_orig) / inside_texts を含める
    """
    def _to_texts(inside_list: Any) -> List[str]:
        out: List[str] = []
        if not inside_list:
            return out
        for it in inside_list:
            if isinstance(it, dict):
                t = it.get("text_orig") or it.get("text") or ""
            elif isinstance(it, str):
                t = it
            else:
                t = ""
            t = norm_space(t)
            if t:
                out.append(t)
        # 重複除去（順序保持）
        seen = set()
        uniq: List[str] = []
        for t in out:
            if t not in seen:
                seen.add(t)
                uniq.append(t)
        return uniq

    items: List[Dict[str, Any]] = []
    for s in shapes:
        sid = s.get("id") or s.get("shape_id") or ""
        txt = s.get("text_orig") or ""
        ins = s.get("inside_texts") or []
        items.append({
            "shape_id": str(sid),
            "text": str(txt),
            "inside_texts": _to_texts(ins),
        })
    body = {
        "instruction": "Classify using 'text' (text_orig) and 'inside_texts'; assign ONE label strictly from allowed_labels.",
        "items": items,
    }
    return json.dumps(body, ensure_ascii=False, indent=2)


# ----------------------
# LLM 呼び出し（Ollama / OpenAI 互換）
# ----------------------
def call_ollama_chat(model: str, host: str, system_prompt: str, user_prompt: str,
                     num_ctx: Optional[int] = None, num_predict: Optional[int] = None,
                     verbose: bool = False) -> str:
    """
    Ollama chat: /api/chat, non-stream, response content is JSON text
    """
    url = host.rstrip("/") + "/api/chat"

    # ★必ず先に初期化しておく（UnboundLocalError対策）
    opts: Dict[str, Any] = {"temperature": 0}
    if num_ctx is not None:
        opts["num_ctx"] = int(num_ctx)
    if num_predict is not None:
        opts["num_predict"] = int(num_predict)

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "stream": False,
        "format": "json",
        "options": opts,
    }

    if verbose:
        print(f"[ollama] POST {url} model={model} (num_ctx={opts.get('num_ctx')}, num_predict={opts.get('num_predict')})")
    r = requests.post(url, json=payload, timeout=300)
    if verbose:
        print(f"[ollama] status={r.status_code}")
    r.raise_for_status()
    data = r.json()
    content = (data.get("message") or {}).get("content", "")
    if verbose:
        print("[ollama] RAW (first 400):", content[:400])
    return content


def call_openai_compatible(model: str, base_url: str, api_key: str, system_prompt: str, user_prompt: str,
                           verbose: bool = False) -> str:
    """
    OpenAI 互換 endpoint の /v1/chat/completions
    """
    url = base_url.rstrip("/") + "/v1/chat/completions"
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    body = {
        "model": model,
        "temperature": 0,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "response_format": {"type": "json_object"},
    }
    if verbose:
        print(f"[openai] POST {url} model={model}")
    r = requests.post(url, headers=headers, json=body, timeout=300)
    if verbose:
        print(f"[openai] status={r.status_code}")
    r.raise_for_status()
    data = r.json()
    content = data["choices"][0]["message"]["content"]
    if verbose:
        print("[openai] RAW (first 400):", content[:400])
    return content


# ----------------------
# 後処理（図形の補助変換）
# ----------------------
def resolve_inside_texts_to_dicts(shapes: List[Dict[str, Any]]) -> None:
    """
    互換用フック。必要に応じて後段処理と整合させる。
    現状は何もしない。
    """
    return


def dump_with_compact_lists(data, fp, compact_keys=("inside_texts","overlap_ratio"), indent=2, ensure_ascii=False):
    def _write(o, level):
        if isinstance(o, dict):
            fp.write('{\n')
            items = list(o.items())
            for i, (k, v) in enumerate(items):
                fp.write(' ' * (level * indent) + json.dumps(k, ensure_ascii=ensure_ascii) + ': ')
                if isinstance(v, list) and k in compact_keys:
                    # 配列は複数行、要素は1行のコンパクトJSON
                    fp.write('[\n')
                    for j, elem in enumerate(v):
                        fp.write(' ' * ((level + 1) * indent))
                        fp.write(json.dumps(elem, ensure_ascii=ensure_ascii, separators=(",", ":")))
                        fp.write(',\n' if j != len(v) - 1 else '\n')
                    fp.write(' ' * (level * indent) + ']')
                else:
                    if isinstance(v, (dict, list)):
                        _write(v, level + 1)
                    else:
                        fp.write(json.dumps(v, ensure_ascii=ensure_ascii))
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

def strip_inside_texts(obj: Any) -> None:
    """
    inside_texts を各要素 {id, text_orig} のみに縮約する（他のキーは変更しない）
    """
    if isinstance(obj, dict):
        v = obj.get("inside_texts")
        if isinstance(v, list):
            obj["inside_texts"] = [
                {k: x[k] for k in ("id", "text_orig") if k in x}
                for x in v if isinstance(x, dict)
            ]
        # 再帰的に探索
        for vv in obj.values():
            strip_inside_texts(vv)
    elif isinstance(obj, list):
        for vv in obj:
            strip_inside_texts(vv)


# ----------------------
# メイン
# ----------------------
def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="in_path", required=True, help="入力: diagram.json")
    ap.add_argument("--out", dest="out_path", required=True, help="出力: diagram.labeled.json")
    ap.add_argument("--labels", required=True, help="resource_label.yaml のパス")
    ap.add_argument("--backend", choices=["ollama", "openai"], default="ollama")
    ap.add_argument("--model", default="gemma3:4b", help="モデル名 (ollama or openai)")
    # Ollama
    ap.add_argument("--ollama_host", default=os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434"))
    # OpenAI互換
    ap.add_argument("--base_url", default=os.environ.get("OPENAI_BASE_URL", ""))
    ap.add_argument("--api_key", default=os.environ.get("OPENAI_API_KEY", ""))
    # バッチ/ログ
    ap.add_argument("--batch", type=int, default=24)
    ap.add_argument("--min_conf", type=float, default=0.60, help="互換のため受け付けるが未使用")  # 互換目的で残す（未使用）
    ap.add_argument("--verbose", action="store_true")
    # Ollama のトークン上限（必要に応じてモデルに合わせて増減）
    ap.add_argument("--ollama_num_ctx", type=int, default=8192,
                    help="Ollamaのコンテキスト長（num_ctx）。モデル上限を超える値は切り詰められます。")
    ap.add_argument("--ollama_num_predict", type=int, default=512,
                    help="Ollamaの最大生成トークン数（num_predict）。")
    args = ap.parse_args()

    if not os.path.exists(args.in_path):
        print(f"ERROR: input not found: {os.path.abspath(args.in_path)}", file=sys.stderr)
        sys.exit(2)
    if not os.path.exists(args.labels):
        print(f"ERROR: labels yaml not found: {os.path.abspath(args.labels)}", file=sys.stderr)
        sys.exit(2)

    # 許可ラベル/カテゴリ + 語彙（synonyms/description/vendors）を YAML からロード
    allowed_labels, label2cat = load_allowed_labels(args.labels)
    label_lexicon = load_label_lexicon(args.labels)
    # プロンプトに渡す labels_info（labelごとの category / synonyms / description）を整形
    labels_info: List[Dict[str, Any]] = []
    for lb in allowed_labels:
        meta = label_lexicon.get(lb, {}) if isinstance(label_lexicon, dict) else {}
        labels_info.append({
            "label": lb,
            "category": label2cat.get(lb, "UNKNOWN"),
            #"synonyms": meta.get("synonyms", []),
            "description": meta.get("description", "")
        })
    # SYSTEM_PROMPT_TMPL は {labels_info_json} を参照するため、こちらを渡す
    system_prompt = SYSTEM_PROMPT_TMPL.format(
        allowed_labels_json=json.dumps(allowed_labels, ensure_ascii=False),
        labels_info_json=json.dumps(labels_info, ensure_ascii=False),
    )

    # diagram 読み込み
    d = load_json(args.in_path)
    shapes = d.get("shapes", [])
    if args.verbose:
        print(f"[info] shapes={len(shapes)}")

    # 処理対象: text_orig を持つ図形のみ
    candidates: List[Dict[str, Any]] = []
    for s in shapes:
        sid = s.get("id") or s.get("shape_id")
        txt = s.get("text_orig")
        if not txt:
            txt = s.get("name") or s.get("title") or s.get("label")  # 後方互換
        txt = norm_space(txt or "")
        if not sid or not txt:
            continue
        s["text_orig"] = txt
        candidates.append(s)

    if args.verbose:
        print(f"[info] target candidates={len(candidates)}")

    id2rec: Dict[str, Dict[str, Any]] = {}

    # バッチ処理
    for i in range(0, len(candidates), args.batch):
        chunk = candidates[i:i + args.batch]
        user_prompt = build_user_prompt(chunk)

        print(f"[debug] system_prompt chars={len(system_prompt)} (~tokens≈{len(system_prompt)//4})")
        print(f"[debug] user_prompt chars={len(user_prompt)} (~tokens≈{len(user_prompt)//4})")


        if args.backend == "ollama":
            raw = call_ollama_chat(
                model=args.model,
                host=args.ollama_host,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                num_ctx=args.ollama_num_ctx,
                num_predict=args.ollama_num_predict,
                verbose=args.verbose,
            )
        else:
            if not args.base_url or not args.api_key:
                print("ERROR: --base_url and --api_key are required for backend=openai", file=sys.stderr)
                sys.exit(2)
            raw = call_openai_compatible(
                model=args.model,
                base_url=args.base_url,
                api_key=args.api_key,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                verbose=args.verbose,
            )

        # JSON 抽出
        try:
            obj = extract_json(raw)
        except Exception as e:
            print("LLM JSON parse error:", e, file=sys.stderr)
            if args.verbose:
                print("RAW:", raw[:1200], file=sys.stderr)
            sys.exit(3)

        # items 取り込み
        for it in obj.get("items", []):
            sid = str(it.get("shape_id", "")).strip()
            if not sid:
                continue
            orig = (it.get("original") or it.get("text") or "").strip()
            label = (it.get("label") or "").strip()
            try:
                lconf = float(it.get("label_confidence", 0.0))
            except Exception:
                lconf = 0.0
            reason = (it.get("reason") or "").strip()

            # 許可ラベルに限定（範囲外は UNKNOWN に強制）
            if label not in allowed_labels:
                label = "UNKNOWN"
            id2rec[sid] = {
                "original": orig,
                "label": label,
                "label_confidence": max(0.0, min(1.0, lconf)),
                "reason": reason,
            }

    # 図形へ反映
    for s in shapes:
        sid = str(s.get("id") or s.get("shape_id") or "")
        if not sid or sid not in id2rec:
            continue
        rec = id2rec[sid]

        # ラベルは必須で追記（UNKNOWN 含む）
        s["resource_label"] = rec["label"]
        s["resource_label_conf"] = round(rec["label_confidence"], 3)
        s["resource_category"] = label2cat.get(rec["label"], "UNKNOWN")
        s["resource_label_reason"] = rec.get("reason", "")  # 理由はここだけに統一

    # 互換フック（必要ならここで inside_texts の辞書化などを行う）
    resolve_inside_texts_to_dicts(shapes)

    out = dict(d)
    out["shapes"] = shapes
    save_json(args.out_path, out)
    print("Wrote:", os.path.abspath(args.out_path))


if __name__ == "__main__":
    main()
