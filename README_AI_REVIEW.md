AI レビュー使い方

このワークスペースに追加した `ai_review.py` は、`analyze_results.json` を読み込み、ローカルの Ollama API に送信してネットワーク構成の妥当性レビューを行います。

前提
- ローカルに Ollama が動作しており、HTTP API が `http://localhost:11434/v1` に存在すること
- Python 3.8+ と pip が利用可能であり、`requests` がインストールされていること

セットアップ
1. 依存パッケージをインストール:

```powershell
pip install -r requirements.txt
```

実行例
- 通常実行:

```powershell
python .\ai_review.py --input analyze_results.json --out review.txt
```

- サーバのエンドポイントやモデルを指定する場合:

```powershell
python .\ai_review.py --input analyze_results.json --out review.txt --ollama http://localhost:11434/v1 --model ollama-model
```

- 呼び出し前にプロンプトを確認したい（dry-run）:

```powershell
python .\ai_review.py --input analyze_results.json --dry-run
```

出力
- 成果: 指定した `--out` ファイルに AI のレビュー文章を出力します。

問題が起きたら
- HTTP エラーやタイムアウトが起きる場合、`--ollama` でエンドポイントを確認してください。
- Ollama の API 仕様が異なる場合、`ai_review.py` の `call_ollama` を適宜編集して POST ボディやヘッダを調整してください。
