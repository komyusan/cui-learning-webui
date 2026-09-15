# CUI Learning WebUI

CUIの学習コストを下げるWebベース支援ツール（研究プロトタイプ MVP v0.1）

## 構成

```text
cui-learning-webui/
├── frontend/
│   └── index.html       # Tailwind CSS / JS 単一ページ
├── backend/
│   ├── main.py          # FastAPI アプリ
│   ├── executor.py      # Docker SDK サンドボックス実行
│   ├── requirements.txt # FastAPI, Docker, OpenAI, SQLAlchemy, httpx 等
│   └── Dockerfile
├── .env                 # APIキー等の環境変数（Git管理外）
└── docker-compose.yml   # バックエンドおよびスキャン対象（やられ環境）の定義
```

## VM環境での起動・動作確認方法

本システムは、バックエンドと複数のスキャン対象コンテナ（Metasploitable2、DVWA、dummy-web等）を連携して動作します。

### 1. VM側での準備と起動

対象のVM（例: `cui-vm`）にSSHログインし、プロジェクトのルートディレクトリ（`cui-learning-webui/`）で以下の操作を行います。

```bash
# 最新のソースコードを反映
git pull origin komi-test

# .env ファイルの作成とAPIキーの設定（初回のみ）
cp .env.example .env
nano .env  # OPENAI_API_KEY 等を記述して保存

# 全コンテナのビルドおよびバックグラウンド起動
docker compose up -d --build

# 起動状態の確認（全コンテナが Up になっていることを確認）
docker compose ps
```

### 2. ローカルPCからのアクセス（SSHトンネリング）

VMが学内ネットワーク等のプライベート環境にあり、直接HTTPアクセスできない場合は、ローカルPCからSSHポートフォワーディングを利用して接続します。

**ローカルPCのターミナル**で以下のコマンドを実行してください。

```bash
# VMの8000番ポートをローカルの8000番ポートへ転送する
# ※ `cui-vm` の部分は、各自のSSH接続先（IPアドレスやエイリアス）に置き換えてください
ssh -L 8000:localhost:8000 cui-vm
```

上記のトンネル接続を開いたまま、ブラウザで以下のURLにアクセスします。

- **http://localhost:8000**

> **注意**: ファイルを直接開く（`open frontend/index.html`）とバックエンドと通信できないデモモードになります。必ず上記のローカルホストURL経由でアクセスしてください。

### 3. 作業の終了（トンネルの切断とコンテナの停止）

作業を終了する際は、以下の操作を行います。

1. **SSHトンネルの切断**
トンネリングを実行しているローカルPCのターミナルで `Ctrl + C` を押すか、`exit` を入力して接続を閉じます。
2. **コンテナの停止（任意）**
コンテナはバックグラウンドで稼働し続けるため、そのままでも次回トンネルを開通するだけで利用可能です。もしVMのリソースを解放するためにシステムを明示的に停止したい場合は、VMのターミナル（プロジェクトルート）で以下を実行します。
```bash
docker compose stop
```


## ローカル環境での起動方法（VM不使用の場合）

バックエンドをローカルPCで直接起動する場合の手順です。

### Docker Compose を使う場合（推奨）

```bash
# プロジェクトルート（cui-learning-webui/）で実行
# 初回 or コード変更後
docker compose up -d --build

# ブラウザで開く（file:// ではなく http:// でアクセスすること）
open http://localhost:8000
```

## 運用・メンテナンス用コマンド

VM上のプロジェクトルートで実行します。

```bash
# バックエンドのログをリアルタイム監視（エラー時のデバッグ用）
docker compose logs -f backend

# システムの一時停止（コンテナのデータは維持）
docker compose stop

# システムの再開
docker compose start

# 環境の完全リセット（コンテナとネットワークの削除）
docker compose down
```

API ドキュメント: http://localhost:8000/docs

## 機能（MVP）

- [x] オプション選択式UI（ドロップダウン・チェックボックス）
- [x] リアルタイムコマンドプレビュー
- [x] FastAPI `/api/execute` エンドポイント
- [x] Dockerサンドボックスでのセキュアなコマンド実行
- [x] ターミナル風出力表示
- [x] OpenAI API連携による AI チューター解説（gpt-4o-mini）
- [x] ターミナル上の重要キーワード動的ハイライト機能（Structured Outputs連携）
- [x] 停滞状態（Stuck State）検知とプロンプトの自動分岐
- [x] SQLiteを用いたコマンド実行ログの記録
- [x] やられ環境群（dummy-web, DVWA, Metasploitable2, MySQL等）の統合
- [ ] 複数ツールのフロントエンド対応（Nmap以外への拡張）