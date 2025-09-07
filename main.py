# -*- coding: utf-8 -*-
"""
main.py
Wrapper to run export_selected.py then analyze.py in one command.
Usage examples:
  # export from Excel and analyze into current dir
  python main.py --out_dir . --debug

  # analyze an existing diagram.json
  python main.py --diagram .\diagram.json --out_dir .

This script runs the other scripts as subprocesses to avoid modifying their internals.
"""
import argparse
import os
import subprocess
import sys

def run_cmd(cmd, capture=False):
    print("Running:", " ".join(cmd))
    try:
        if capture:
            res = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            print(res.stdout)
            if res.stderr:
                print(res.stderr, file=sys.stderr)
            return res.returncode
        else:
            res = subprocess.run(cmd, check=True)
            return res.returncode
    except subprocess.CalledProcessError as e:
        if e.stdout:
            print(e.stdout)
        if e.stderr:
            print(e.stderr, file=sys.stderr)
        print(f"Command failed: {e}", file=sys.stderr)
        return e.returncode or 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--diagram", help="既存 diagram.json を指定（指定したら export はスキップ）")
    ap.add_argument("--out_dir", required=True, help="解析出力先ディレクトリ（analyze.py の out_dir）")
    ap.add_argument("--out", help="export_selected.py の出力ファイルパス（指定がなければ out_dir/diagram.json）")
    ap.add_argument("--debug", action="store_true", help="--debug を両方のスクリプトに渡す")
    args = ap.parse_args()

    out_dir = os.path.abspath(args.out_dir)
    os.makedirs(out_dir, exist_ok=True)

    python = sys.executable

    if args.diagram:
        diagram_path = os.path.abspath(args.diagram)
        if not os.path.exists(diagram_path):
            print(f"diagram file not found: {diagram_path}", file=sys.stderr)
            sys.exit(2)
    else:
        # run export_selected.py
        diagram_path = os.path.abspath(args.out or os.path.join(out_dir, "diagram.json"))
        cmd = [python, os.path.join(os.path.dirname(__file__), "export_selected.py"), "--out", diagram_path]
        if args.debug:
            cmd.append("--debug")
        rc = run_cmd(cmd)
        if rc != 0:
            print("export_selected failed", file=sys.stderr)
            sys.exit(rc)

    # run analyze.py
    cmd2 = [python, os.path.join(os.path.dirname(__file__), "analyze.py"), "--diagram", diagram_path, "--out_dir", out_dir]
    rc2 = run_cmd(cmd2)
    if rc2 != 0:
        print("analyze failed", file=sys.stderr)
        sys.exit(rc2)

    print("Done. Outputs written to:")
    print(" - ", os.path.join(out_dir, "analyze_results.json"))
    print(" - ", os.path.join(out_dir, "report.md"))

if __name__ == '__main__':
    main()
