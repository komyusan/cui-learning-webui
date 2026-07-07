# CUI Learning WebUI

CUIの学習コストを下げるWebベース支援ツール（研究プロトタイプ MVP v0.1）

## 構成

```
cui-learning-webui/
├── frontend/
│   └── index.html       # Tailwind CSS / JS 単一ページ
├── backend/
│   ├── main.py          # FastAPI アプリ
│   ├── executor.py      # Docker SDK サンドボックス実行
│   ├── requirements.txt
│   └── Dockerfile
└── docker-compose.yml
```

## 起動方法

### フロントエンドのみ（バックエンドなし・デモモード）

```bash
# cui-learning-webui/ で実行
open frontend/index.html
```
バックエンド未接続でも「デモモード」で動作確認できます。

### バックエンド + フロントエンド（フル動作）

> **すべて `cui-learning-webui/`（プロジェクトルート）で実行してください。**

#### コピペ用（Docker Compose 推奨）

```bash
# 初回 or コード変更後
docker compose up --build -d backend

# ブラウザで開く（← file:// ではなく http:// で開くこと）
open http://localhost:8000
```

#### ローカル実行（Docker Compose を使わない場合）

```bash
# backend/ に移動してから実行
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export OPENAI_API_KEY="sk-..."   # APIキーを設定
docker pull instrumentisto/nmap:latest
uvicorn main:app --reload --port 8000
```

```bash
# 別ターミナルで（プロジェクトルートから）
open http://localhost:8000
```

> **注意**: `open frontend/index.html` で直接ファイルを開くと「デモモード」になります。
> バックエンドと繋げるには必ず `http://localhost:8000` でアクセスしてください。

#### ログ監視

```bash
# cui-learning-webui/ で実行
docker compose logs backend -f
```

API ドキュメント: http://localhost:8000/docs

## 機能（MVP）

- [x] nmapオプション選択UI（ドロップダウン・チェックボックス）
- [x] リアルタイムコマンドプレビュー
- [x] FastAPI `/api/execute` エンドポイント
- [x] Dockerサンドボックスでの実行（`instrumentisto/nmap`）
- [x] ターミナル風出力表示
- [x] OpenAI API連携による AI チューター解説（gpt-4o-mini）
- [ ] 複数ツール対応（gobuster, nikto等）