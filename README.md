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
open frontend/index.html
```
バックエンド未接続でも「デモモード」で動作確認できます。

### バックエンド + フロントエンド（フル動作）

#### 1. 仮想環境の準備

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

#### 2. サンドボックスイメージの取得

```bash
docker pull instrumentisto/nmap:latest
```

#### 3. バックエンド起動

```bash
uvicorn main:app --reload --port 8000
```

#### 4. ブラウザで開く

```
open frontend/index.html
```

API ドキュメント: http://localhost:8000/docs

## 機能（MVP）

- [x] nmapオプション選択UI（ドロップダウン・チェックボックス）
- [x] リアルタイムコマンドプレビュー
- [x] FastAPI `/api/execute` エンドポイント
- [x] Dockerサンドボックスでの実行（`instrumentisto/nmap`）
- [x] ターミナル風出力表示
- [x] AI解説エリア（ダミー実装）
- [ ] OpenAI API連携による本物の解説（次フェーズ）
- [ ] 複数ツール対応（gobuster, nikto等）