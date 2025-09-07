# -*- coding: utf-8 -*-
"""
ai_review.py
- `analyze_results.json` を読み込み、指定プロンプトと併せてローカル ollama サーバへ送信し
  AI にネットワーク構成の妥当性レビューを行わせる簡易ラッパー。

使い方例:
  python ai_review.py --input analyze_results.json --out ai_review.txt
  python ai_review.py --input analyze_results.json --out ai_review.txt --model gemma3:12b

環境:
  - デフォルトで Ollama のエンドポイントは http://localhost:11434/v1
  - requests ライブラリを使用

注意:
  - ローカルの Ollama サーバの API 仕様/エンドポイントが異なる場合は --ollama オプションでフル URL を指定してください。
"""

import argparse
import json
import os
import sys
import time
from typing import Any

try:
    import requests
except Exception as e:
    print("Missing dependency: requests. Install with 'pip install -r requirements.txt'", file=sys.stderr)
    raise

PROMPT_HEADER = (
    "あなたはネットワーク構成のレビューアです。 以下のJSONはExcelの構成図をPythonで解析した結果です。\n"
    "- \"zones\": ゾーン枠とそのラベル\n"
    "- \"assignments\": 各ノードがどのゾーンに属するか（confidence付き）\n"
    "- \"edges\": ノード間の接続（コネクタまたは推定）\n\n"
    "あなたの役割は、この機械的な結果を根拠にして：\n"
    "1. ゾーン割当や接続の妥当性をレビューする\n"
    "2. confidence=low や normalized=\"unknown\" の部分について確認質問を挙げる\n"
    "3. ポリシー違反（例：DBサーバがDMZ内にある 等）があれば指摘する\n"
    "4. レポートを人が読みやすい文章に整形する\n\n"
    "以下が入力データです：\n"
)

DEFAULT_OLLAMA_URL = "http://localhost:11434"


def build_prompt(diagram: Any) -> str:
    return PROMPT_HEADER + json.dumps(diagram, ensure_ascii=False, indent=2)


def call_ollama(ollama_url: str, prompt: str, model: str | None = None, timeout: int = 30, verbose: bool = False, auth_token: str | None = None) -> requests.Response:
    """Try to send prompt to an Ollama-like server.

    This function is robust: if the provided URL does not accept the default payload,
    it will try several common endpoint suffixes and two payload shapes until one
    returns HTTP 200. It returns the successful requests.Response or raises the
    last exception.
    """
    headers = {"Content-Type": "application/json; charset=utf-8"}
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"

    # Candidate endpoint suffixes to try if base URL alone fails
    suffixes = ["", "/v1/chat/completions", "/generate", "/api/generate", "/v1/generate", "/v1/completions", "/complete", "/api/completions", "/chat/completions"]

    # Candidate payload shapes
    payloads = []
    # simple prompt payload
    p1 = {"prompt": prompt}
    if model:
        p1["model"] = model
    payloads.append(p1)
    # chat-like payload
    if model:
        payloads.append({"model": model, "messages": [{"role": "user", "content": prompt}]})
    # fallback minimal
    payloads.append({"text": prompt})

    last_exc = None
    # Normalize base (remove trailing slash)
    base = ollama_url.rstrip("/")
    for suf in suffixes:
        url = base + suf
        for payload in payloads:
            try:
                if verbose:
                    print(f"Trying POST {url} payload_keys={list(payload.keys())}")
                resp = requests.post(url, json=payload, headers=headers, timeout=timeout)
                if resp.status_code == 200:
                    if verbose:
                        print(f"Success: {url}")
                    return resp
                else:
                    if verbose:
                        print(f"Got status {resp.status_code} from {url}")
            except Exception as e:
                last_exc = e
                if verbose:
                    print(f"Error contacting {url}: {e}")
                # continue trying other combos
                continue

    # If we reach here, nothing succeeded
    if last_exc:
        raise last_exc
    raise RuntimeError("No endpoint responded with HTTP 200 for provided Ollama base URL")


def detect_remote_model(base_url: str, timeout: int = 3):
    """Try to query the server for available models. Return first model id or None."""
    base = base_url.rstrip('/')
    candidates = [base + '/v1/models', base + '/models']
    for u in candidates:
        try:
            r = requests.get(u, timeout=timeout)
            if r.status_code == 200:
                try:
                    j = r.json()
                    # common shape: {"object":"list","data":[{"id":"gpt-oss:20b"},...]}
                    if isinstance(j, dict) and 'data' in j and isinstance(j['data'], list) and j['data']:
                        first = j['data'][0]
                        if isinstance(first, dict) and 'id' in first:
                            return first['id']
                except Exception:
                    continue
        except Exception:
            continue
    return None


def extract_text_from_response(resp: requests.Response) -> str:
    # Best-effort extraction: prefer obvious fields, else return raw text
    content_type = resp.headers.get("Content-Type", "")
    text = resp.text
    try:
        j = resp.json()
    except Exception:
        j = None
    # Common possible shapes: {"output": "..."}, {"text":"..."}, {"choices":[{"text":...}]}
    if isinstance(j, dict):
        if "output" in j and isinstance(j["output"], str):
            return j["output"]
        if "text" in j and isinstance(j["text"], str):
            return j["text"]
        if "result" in j and isinstance(j["result"], str):
            return j["result"]
        if "choices" in j and isinstance(j["choices"], list) and j["choices"]:
            first = j["choices"][0]
            # OpenAI /v1/chat/completions 形式を想定: choices[].message.content を優先
            if isinstance(first, dict):
                msg = first.get("message") or first.get("message", {})
                if isinstance(msg, dict) and isinstance(msg.get("content"), str):
                    return msg.get("content")
                # Fallback: completions 互換の text フィールド
                if "text" in first and isinstance(first["text"], str):
                    return first["text"]
            # 念のため、素の文字列が来たらそれを返す
            if isinstance(first, str):
                return first
        # fallback: pretty-print json
        try:
            return json.dumps(j, ensure_ascii=False, indent=2)
        except Exception:
            return text
    # If j is None, try to parse newline-delimited JSON (streaming responses)
    if j is None and text:
        lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
        objs = []
        for ln in lines:
            try:
                objs.append(json.loads(ln))
            except Exception:
                # not a json line, skip
                continue
        if objs:
            # Prefer explicit 'response' fields (take last non-empty)
            responses = [o.get('response','') for o in objs if isinstance(o, dict)]
            nonempty = [r for r in responses if r]
            if nonempty:
                return nonempty[-1]
            # Fallback: stitch together 'thinking' fields streamed incrementally
            think_parts = [o.get('thinking','') for o in objs if isinstance(o, dict) and o.get('thinking')]
            if think_parts:
                # join without extra separator to reconstruct streaming tokens
                joined = ''.join(think_parts)
                if joined.strip():
                    return joined
    # final fallback: return raw text
    return text


def call_ollama_stream(ollama_url: str, prompt: str, model: str | None = None, timeout: int = 60, verbose: bool = False, auth_token: str | None = None) -> str:
    """Post with streaming=True and parse newline-delimited JSON as it arrives.

    Returns the best-effort assembled text (prefer explicit 'response', else stitched 'thinking').
    Raises the last exception if no endpoint succeeded.
    """
    headers = {"Content-Type": "application/json; charset=utf-8"}
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"
    suffixes = ["", "/v1/chat/completions", "/generate", "/api/generate", "/v1/generate", "/v1/completions", "/complete", "/api/completions", "/chat/completions"]

    payloads = []
    p1 = {"prompt": prompt}
    if model:
        p1["model"] = model
    payloads.append(p1)
    if model:
        payloads.append({"model": model, "messages": [{"role": "user", "content": prompt}]})
    payloads.append({"text": prompt})

    last_exc = None
    base = ollama_url.rstrip("/")
    for suf in suffixes:
        url = base + suf
        for payload in payloads:
            try:
                if verbose:
                    print(f"Trying STREAM POST {url} payload_keys={list(payload.keys())}")
                # stream=True so we can parse NDJSON as it arrives; use generous read timeout
                resp = requests.post(url, json=payload, headers=headers, stream=True, timeout=(10, timeout))
                if resp.status_code != 200:
                    if verbose:
                        print(f"Got status {resp.status_code} from {url}")
                    continue

                # iterate lines as they arrive
                responses = []
                think_parts = []
                start = time.time()
                for raw in resp.iter_lines(decode_unicode=True):
                    if raw is None:
                        continue
                    line = raw.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except Exception:
                        # not JSON, skip
                        continue
                    if not isinstance(obj, dict):
                        continue
                    # collect explicit 'response' fields
                    if obj.get('response'):
                        responses.append(obj.get('response'))
                    if obj.get('thinking'):
                        think_parts.append(obj.get('thinking'))
                    # if server signals done, stop
                    if obj.get('done'):
                        if verbose:
                            print("Stream signalled done, stopping read")
                        break
                    # safety: respect overall timeout
                    if time.time() - start > timeout:
                        if verbose:
                            print("Streaming read timed out")
                        break

                # prefer last non-empty explicit response
                nonempty = [r for r in responses if r]
                if nonempty:
                    return nonempty[-1]
                # else stitch thinking parts
                joined = ''.join(think_parts)
                if joined.strip():
                    return joined
                # if nothing useful, fallback to full buffered text
                try:
                    raw_text = resp.text
                except Exception:
                    raw_text = ''
                if raw_text.strip():
                    return raw_text
                # else continue trying other endpoints
            except Exception as e:
                last_exc = e
                if verbose:
                    print(f"STREAM Error contacting {url}: {e}")
                continue

    if last_exc:
        raise last_exc
    raise RuntimeError("No endpoint returned usable streaming result")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", "-i", default="analyze_results.json", help="analyze_results.json path")
    ap.add_argument("--out", "-o", default="ai_review.txt", help="output report file")
    ap.add_argument("--ollama", default=DEFAULT_OLLAMA_URL, help="Ollama server URL (full endpoint), default=%(default)s")
    ap.add_argument("--model", default=None, help="Model name to ask Ollama (optional)")
    ap.add_argument("--timeout", type=int, default=30, help="HTTP request timeout seconds")
    ap.add_argument("--auth-token", default=None, help="Authorization token to send as Bearer <token>")
    ap.add_argument("--verbose", action="store_true", help="Enable verbose endpoint probing")
    ap.add_argument("--dry-run", action="store_true", help="Print prompt summary without calling server")
    args = ap.parse_args()

    if not os.path.exists(args.input):
        print(f"Input file not found: {args.input}", file=sys.stderr)
        sys.exit(2)

    with open(args.input, "r", encoding="utf-8") as f:
        diagram = json.load(f)

    prompt = build_prompt(diagram)

    if args.dry_run:
        print("DRY RUN: prompt length:", len(prompt))
        print(prompt[:2000])
        return

    print("Sending prompt to ollama server:", args.ollama)
    # auto-detect model if not provided
    if not args.model:
        m = detect_remote_model(args.ollama, timeout=3)
        if m:
            args.model = m
            if args.verbose:
                print(f"Auto-detected model: {m}")
    try:
        resp = call_ollama(args.ollama, prompt, model=args.model, timeout=args.timeout, verbose=args.verbose, auth_token=args.auth_token)
    except Exception as e:
        print("Request failed:", e, file=sys.stderr)
        sys.exit(3)

    if resp.status_code != 200:
        print(f"Server returned status {resp.status_code} - response:\n{resp.text}", file=sys.stderr)
        sys.exit(4)

    out_text = extract_text_from_response(resp)
    # If extracted text is empty or indicates model is still loading, try a streaming read
    need_stream = False
    if not out_text or (isinstance(out_text, str) and '"done_reason"' in out_text and 'load' in out_text):
        need_stream = True
    if need_stream:
        if args.verbose:
            print("Initial response empty or indicates load; attempting streaming read...")
        try:
            stream_text = call_ollama_stream(args.ollama, prompt, model=args.model, timeout=max(60, args.timeout), verbose=args.verbose, auth_token=args.auth_token)
            if stream_text and stream_text.strip():
                out_text = stream_text
        except Exception as e:
            if args.verbose:
                print("Streaming attempt failed:", e)

    with open(args.out, "w", encoding="utf-8") as f:
        f.write(out_text)

    print("Wrote review to:", args.out)


if __name__ == "__main__":
    main()
