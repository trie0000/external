# -*- coding: utf-8 -*-
"""
llm_normalize_diagram_text.py
- diagram.json の各図形 text をローカル生成AIで正規化（例: インターネットGW → IGW）
- Ollama /api/chat + format:"json" を使用して、JSON応答を強制
- 置換は信頼度しきい値以上のみ。元文言は text_orig に退避。
- inside_texts が ID 配列のケースは、正規化後の最新テキストに解決して辞書化（patch2相当）。
- --verbose で進捗/RAW表示を出す

使い方（Ollama の例）:
  python llm_normalize_diagram_text.py --in diagram.json --out diagram.normalized.json \
    --backend ollama --model gemma3:4b

OpenAI互換 API を使う場合:
  python llm_normalize_diagram_text.py --in diagram.json --out diagram.normalized.json \
    --backend openai --model qwen2.5-7b-instruct \
    --base_url http://localhost:8000 --api_key sk-local-xxxx
"""
import argparse, json, os, re, sys, time
from typing import Dict, Any, List
import requests

DEFAULT_MIN_CONF = 0.60

SYSTEM_PROMPT = r"""You are a careful network diagram text normalizer.
Goal: Convert raw Japanese/English labels in diagrams into SHORT, canonical tokens commonly used in infra.
- Examples:
  - "インターネットGW", "Internet Gateway", "IGW" -> "IGW"
  - "NAT ゲートウェイ", "NAT GW", "NATGateway" -> "NATGW"
  - "Application Load Balancer", "ALB" -> "ALB"
  - "Network Load Balancer", "NLB" -> "NLB"
  - "Classic Load Balancer", "ELB" -> "ELB"
  - "Webサーバ1", "web server 01" -> "Webサーバ1" (keep if role+index)
  - "VPC", "仮想プライベートクラウド" -> "VPC"
  - "サブネット", "Subnet-1a" -> "Subnet-1a" (keep structure)
  - "ルートテーブル" -> "RouteTable"
  - "セキュリティグループ" -> "SecurityGroup"
  - "ユーザ", "クライアント", "User" -> "ユーザ" or "User" (keep short)
  - If it is a port/protocol like "443/tcp" or "22", KEEP AS-IS.
- Shorten to common acronyms (IGW, NATGW, ALB, NLB, ELB) when clearly intended.
- Preserve hostnames/IPs/ports as-is.
- If uncertain, keep original unchanged and set low confidence.

Return ONLY JSON with:
{
  "items":[
    {"shape_id":"Rectangle 3","original":"インターネットGW","normalized":"IGW","confidence":0.95,"reason":"internet gateway abbrev"},
    ...
  ]
}
Use confidence 0.0..1.0.
"""

def norm_space(s:str)->str:
    if not s: return ""
    s = s.replace("\u3000"," ").replace("\xa0"," ")
    return re.sub(r"\s+"," ", s.strip())

def load_json(p:str)->Dict[str,Any]:
    with open(p,"r",encoding="utf-8") as f:
        return json.load(f)

def save_json(p:str, obj:Dict[str,Any]):
    with open(p,"w",encoding="utf-8") as f:
        json.dump(obj,f,ensure_ascii=False,indent=2)

def resolve_inside_texts_to_dicts(shapes:List[Dict[str,Any]]):
    """inside_texts が ID配列の場合、{id, text} の辞書配列に解決。既に辞書なら text を最新 shape.text に同期。"""
    by_id = {s.get("id"): s for s in shapes}
    for s in shapes:
        its = s.get("inside_texts")
        if not its:
            continue
        if isinstance(its, list) and its and isinstance(its[0], str):
            new=[]
            for sid in its:
                sh = by_id.get(sid)
                new.append({"id": sid, "text": (sh.get("text","") if sh else sid)})
            s["inside_texts"] = new
        elif isinstance(its, list) and its and isinstance(its[0], dict):
            for item in its:
                sid = item.get("id")
                if sid in by_id:
                    item["text"] = by_id[sid].get("text","") or item.get("text","")

def build_user_prompt(batch:List[Dict[str,Any]])->str:
    items = [{"shape_id": b["id"], "text": b.get("text","")} for b in batch]
    return json.dumps({"task":"normalize diagram labels","candidates": items}, ensure_ascii=False)

# ---- Backends ---------------------------------------------------------------

def call_ollama_chat(model:str, prompt:str, host:str, verbose:bool=False)->str:
    """
    Ollama /api/chat を利用。format:"json" で JSON を強制。
    """
    url = host.rstrip("/") + "/api/chat"
    payload = {
        "model": model,
        "messages": [
            {"role":"system","content": SYSTEM_PROMPT},
            {"role":"user","content": prompt}
        ],
        "stream": False,
        "format": "json",     # ★ JSON応答を強制
        "options": {"temperature": 0},
    }
    if verbose:
        print(f"[ollama] POST {url} model={model}")
    r = requests.post(url, json=payload, timeout=300)
    if verbose:
        print(f"[ollama] status={r.status_code}")
    r.raise_for_status()
    data = r.json()
    # /api/chat の応答形式
    content = data.get("message",{}).get("content","")
    if verbose:
        print("[ollama] RAW (first 400):", content[:400])
    return content

def call_openai_compatible(model:str, prompt:str, base_url:str, api_key:str, verbose:bool=False)->str:
    url = base_url.rstrip("/") + "/v1/chat/completions"
    headers={"Authorization":f"Bearer {api_key}","Content-Type":"application/json"}
    body={
        "model": model,
        "temperature": 0,
        "messages":[
            {"role":"system","content": SYSTEM_PROMPT},
            {"role":"user","content": prompt}
        ],
        "response_format":{"type":"json_object"}
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

# JSON抽出: フェンスや前後ノイズが混じっても救う
def extract_json(s:str)->Dict[str,Any]:
    s = s.strip()
    # 1) コードフェンス除去
    s = re.sub(r"^```(?:json)?\s*|\s*```$", "", s, flags=re.I|re.M)
    # 2) 文字列全体がJSONならそのまま
    try:
        return json.loads(s)
    except Exception:
        pass
    # 3) 文中の最初の { … } を抜き出す
    m = re.search(r"\{[\s\S]*\}", s)
    if not m:
        raise ValueError("No JSON object found in model output")
    return json.loads(m.group(0))

# ---- main ------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="in_path", required=True, help="diagram.json")
    ap.add_argument("--out", dest="out_path", required=True, help="出力先 (diagram.normalized.json)")
    ap.add_argument("--backend", choices=["ollama","openai"], default="ollama")
    ap.add_argument("--model", default="gemma3:4b")
    ap.add_argument("--ollama_host", default=os.environ.get("OLLAMA_HOST","http://localhost:11434"))
    ap.add_argument("--base_url", default=os.environ.get("OPENAI_BASE_URL",""))
    ap.add_argument("--api_key",  default=os.environ.get("OPENAI_API_KEY",""))
    ap.add_argument("--batch", type=int, default=24)
    ap.add_argument("--min_conf", type=float, default=DEFAULT_MIN_CONF)
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    if not os.path.exists(args.in_path):
        print(f"ERROR: input not found: {os.path.abspath(args.in_path)}", file=sys.stderr)
        sys.exit(2)

    d = load_json(args.in_path)
    shapes = d.get("shapes", [])
    if args.verbose:
        print(f"[info] shapes={len(shapes)}")

    # text を持つ図形のみ対象
    candidates=[]
    for s in shapes:
        t = norm_space(s.get("text",""))
        if not t:
            continue
        s["text"] = t
        candidates.append(s)

    id2norm: Dict[str, Dict[str,Any]] = {}
    for i in range(0, len(candidates), args.batch):
        chunk = candidates[i:i+args.batch]
        prompt = build_user_prompt(chunk)
        if args.backend=="ollama":
            raw = call_ollama_chat(args.model, prompt, host=args.ollama_host, verbose=args.verbose)
        else:
            if not args.base_url or not args.api_key:
                print("ERROR: --base_url and --api_key required for backend=openai", file=sys.stderr)
                sys.exit(2)
            raw = call_openai_compatible(args.model, prompt, args.base_url, args.api_key, verbose=args.verbose)

        try:
            obj = extract_json(raw)
        except Exception as e:
            print("LLM JSON parse error:", e, file=sys.stderr)
            if args.verbose:
                print("RAW:", raw[:800], file=sys.stderr)
            sys.exit(3)

        for it in obj.get("items", []):
            sid  = it.get("shape_id","")
            orig = it.get("original") or it.get("text") or ""
            norm = it.get("normalized") or orig
            conf = float(it.get("confidence", 0.0))
            reason = it.get("reason","")
            if sid:
                id2norm[sid] = {"original": orig, "normalized": norm, "confidence": conf, "reason": reason}

    # 置換（text_orig 退避、しきい値未満は置換しない）
    for s in shapes:
        sid = s.get("id")
        if not sid or sid not in id2norm:
            continue
        rec = id2norm[sid]
        if rec["confidence"] >= args.min_conf and rec["normalized"]:
            txt = rec["normalized"].strip()
            # Port/IP のような完全数値やポート記法は変更しない
            numeric_like = bool(re.match(r"^\d+(?:/\w+)?$", txt))
            if not numeric_like and txt != s.get("text",""):
                s["text_orig"] = s.get("text","")
                s["text"] = txt
                s["text_ai_norm_conf"] = round(rec["confidence"],3)
                if rec.get("reason"):
                    s["text_ai_norm_reason"] = rec["reason"]

    # inside_texts を最新テキストへ同期（ID配列→辞書化も実施）
    resolve_inside_texts_to_dicts(shapes)

    # 出力
    out = dict(d)
    out["shapes"] = shapes
    save_json(args.out_path, out)
    print("Wrote:", os.path.abspath(args.out_path))

if __name__ == "__main__":
    main()
