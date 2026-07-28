"""
database.py
CUI Learning WebUI — SQLAlchemy データベース接続設定

このモジュールの役割:
  1. SQLite データベースへの接続文字列 (URL) を定義する
  2. SQLAlchemy の Engine（DB との接続プール）を作成する
  3. セッションファクトリ SessionLocal を提供する
  4. すべての ORM モデルが継承するベースクラス Base を定義する
  5. FastAPI の依存注入 (Depends) で使う get_db() ジェネレータを提供する
"""

import os                               # 環境変数・ファイルパス操作用標準ライブラリ
import logging                          # ログ出力用標準ライブラリ

from sqlalchemy import create_engine    # DB への接続エンジンを生成する関数
from sqlalchemy.orm import (            # ORM セッション関連クラスのインポート
    declarative_base,                   #   モデル定義の基底クラスを生成するファクトリ
    sessionmaker,                       #   セッションファクトリを生成するクラス
    Session,                            #   型ヒント用 Session 型
)

logger = logging.getLogger(__name__)    # モジュール名でロガーを取得

# ──────────────────────────────────────────────
# データベース URL の設定
# ──────────────────────────────────────────────
# Docker コンテナ内では /app/data/ にマウントされたボリュームを使用する。
# ローカル開発時はカレントディレクトリに cui_learning.db を作る。
# 環境変数 DATABASE_URL で上書き可能にしておく（将来の PostgreSQL 移行を考慮）。

_DB_DIR = "/app/data"                   # コンテナ内のデータ永続化ディレクトリ

# ローカル実行時（/app/data が存在しない場合）は backend/ 直下に作る
if not os.path.exists(_DB_DIR):
    _DB_DIR = os.path.dirname(os.path.abspath(__file__))

# /app/data ディレクトリが存在しない場合は自動で作成する（コンテナ起動時を想定）
os.makedirs(_DB_DIR, exist_ok=True)     # exist_ok=True: すでに存在する場合はエラーにしない

# SQLite の接続 URL を構築する
# 形式: sqlite:///絶対パス  （/// の後は OS のパス区切りに合わせる）
DATABASE_URL: str = os.environ.get(
    "DATABASE_URL",                     # 環境変数が設定されていればそちらを優先する
    f"sqlite:///{os.path.join(_DB_DIR, 'cui_learning.db')}"  # デフォルトは SQLite ファイル
)

logger.info("[database] DATABASE_URL = %s", DATABASE_URL)  # 起動ログに URL を出力（デバッグ用）

# ──────────────────────────────────────────────
# SQLAlchemy Engine の作成
# ──────────────────────────────────────────────
# connect_args={"check_same_thread": False}
#   SQLite はデフォルトで「同一スレッドからの接続しか許可しない」設定になっている。
#   FastAPI は非同期フレームワークで複数スレッドからDBを操作するため、この制限を解除する。
engine = create_engine(
    DATABASE_URL,                               # 接続先データベースの URL
    connect_args={"check_same_thread": False},  # SQLite のスレッド制限を解除
    echo=False,                                 # True にするとすべての SQL が標準出力に表示される（デバッグ時に便利）
)

# ──────────────────────────────────────────────
# セッションファクトリの作成
# ──────────────────────────────────────────────
# sessionmaker でセッション生成クラスを作る。
# autocommit=False: 明示的に db.commit() を呼ぶまで変更が確定しない（安全）
# autoflush=False : commit 前に自動的に flush（DB への書き込みバッファを空にする）しない
SessionLocal = sessionmaker(
    autocommit=False,   # 自動コミット無効（明示的 commit が必要）
    autoflush=False,    # 自動フラッシュ無効（commit 前の不用意な DB 書き込みを防ぐ）
    bind=engine,        # 上で作成した Engine を紐付ける
)

# ──────────────────────────────────────────────
# ORM モデル基底クラスの作成
# ──────────────────────────────────────────────
# declarative_base() が返す Base クラスを全モデルに継承させることで、
# SQLAlchemy がそれらのクラスをテーブル定義として認識する。
Base = declarative_base()               # 全 ORM モデルが継承する基底クラス


# ──────────────────────────────────────────────
# FastAPI 依存注入用ジェネレータ
# ──────────────────────────────────────────────
def get_db():
    """
    FastAPI の Depends() で使用する DB セッションのジェネレータ。

    使用例（main.py のエンドポイントで）:
        from database import get_db
        from sqlalchemy.orm import Session
        from fastapi import Depends

        @app.post("/api/execute")
        async def execute(db: Session = Depends(get_db)):
            ...

    - yield 前: セッションを生成してエンドポイントに渡す
    - yield 後: リクエスト終了後に必ず close() される（finally で保証）
    """
    db: Session = SessionLocal()        # 新しいセッションを生成
    try:
        yield db                        # エンドポイント関数にセッションを渡す
    finally:
        db.close()                      # リクエスト終了後（例外発生時も）必ず接続を閉じる


# ──────────────────────────────────────────────
# テーブル初期化関数
# ──────────────────────────────────────────────
def init_db():
    """
    アプリ起動時に呼び出し、Base に登録されたすべてのテーブルを作成する。
    テーブルがすでに存在する場合は何もしない（CREATE TABLE IF NOT EXISTS 相当）。
    main.py の lifespan イベントからこの関数を呼ぶ。
    """
    import db_models  # noqa: F401  ← テーブル定義をインポートして Base に登録させる
    Base.metadata.create_all(bind=engine)  # Base に登録されたモデルのテーブルをすべて作成
    logger.info("[database] テーブルの初期化が完了しました")
