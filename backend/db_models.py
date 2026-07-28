"""
db_models.py
CUI Learning WebUI — SQLAlchemy ORM モデル定義

【重要】このファイルには SQLAlchemy の ORM モデル（テーブル定義）のみを記述する。
        Pydantic モデル（リクエスト/レスポンスのバリデーション用）は models.py に残す。
        両者を混在させないことで、責務の境界を明確にする。

テーブル構成:
  - sessions    : セッション（学習セッションの状態保持）
  - command_logs: コマンド実行ログ（学習記録）
"""

import uuid                                         # UUID 生成用標準ライブラリ
from datetime import datetime                       # 日時型用標準ライブラリ

from sqlalchemy import (                            # SQLAlchemy の列型・制約のインポート
    Column,                                         #   列定義クラス
    String,                                         #   文字列型
    Integer,                                        #   整数型
    Float,                                          #   浮動小数点数型
    Boolean,                                        #   真偽値型
    Text,                                           #   長文テキスト型
    DateTime,                                       #   日時型
    ForeignKey,                                     #   外部キー制約
)
from sqlalchemy.orm import relationship             # テーブル間のリレーションシップ定義

from database import Base                           # 全モデルが継承する基底クラス（database.py で定義）


# ──────────────────────────────────────────────
# sessions テーブル
# ──────────────────────────────────────────────
class Session(Base):
    """
    学習セッションを管理するテーブル。

    各セッションは UUID で識別され、現在の PTES フェーズ（学習ステップ）を保持する。
    command_logs テーブルと 1:N の関係（1セッション : 複数ログ）。
    """

    __tablename__ = "sessions"          # DB 上のテーブル名

    # PrimaryKey: セッションID（UUID文字列）
    # default=lambda: str(uuid.uuid4()) により、INSERT 時に自動で UUID が生成される
    session_id = Column(
        String(36),                     # UUID は "xxxxxxxx-xxxx-..." の 36 文字
        primary_key=True,               # 主キーとして設定
        default=lambda: str(uuid.uuid4()),  # 未指定の場合は自動的に UUID を生成
        nullable=False,                 # NULL を許可しない
    )

    # 現在の学習フェーズ（例: "Step 1: Reconnaissance", "Step 2: Scanning" 等）
    current_step = Column(
        String(100),                    # フェーズ名の最大文字数を 100 に制限
        nullable=False,                 # NULL を許可しない
        default="Step 1",              # 初期フェーズのデフォルト値
    )

    # レコード作成日時（セッション開始時刻）
    created_at = Column(
        DateTime,                       # 日時型
        nullable=False,                 # NULL を許可しない
        default=datetime.utcnow,        # INSERT 時の現在 UTC 時刻を自動設定
    )

    # レコード最終更新日時（フェーズが変わるたびに更新）
    updated_at = Column(
        DateTime,                       # 日時型
        nullable=False,                 # NULL を許可しない
        default=datetime.utcnow,        # INSERT 時の現在 UTC 時刻を自動設定
        onupdate=datetime.utcnow,       # UPDATE 時も自動で現在時刻に更新
    )

    # リレーションシップ: このセッションに紐づく command_logs の一覧を取得できる
    # cascade="all, delete-orphan": セッション削除時に紐づくログも自動削除する
    logs = relationship(
        "CommandLog",                   # リレーション先の ORM クラス名（文字列で指定）
        back_populates="session",       # CommandLog 側の session プロパティと双方向リンク
        cascade="all, delete-orphan",   # 親（Session）削除時に子（CommandLog）も削除
    )

    def __repr__(self) -> str:
        """デバッグ用の文字列表現"""
        return (
            f"<Session id={self.session_id!r} "
            f"step={self.current_step!r} "
            f"created={self.created_at}>"
        )


# ──────────────────────────────────────────────
# command_logs テーブル
# ──────────────────────────────────────────────
class CommandLog(Base):
    """
    コマンド実行ログを記録するテーブル。

    各レコードは 1 回のコマンド実行を表し、
    実行内容・結果・AI レスポンス・時間情報を保存する。
    sessions テーブルと N:1 の関係（複数ログ : 1セッション）。
    """

    __tablename__ = "command_logs"      # DB 上のテーブル名

    # PrimaryKey: ログID（自動採番整数）
    log_id = Column(
        Integer,                        # 整数型
        primary_key=True,               # 主キーとして設定
        autoincrement=True,             # INSERT のたびに 1 ずつ自動増加
    )

    # 外部キー: どのセッションのログかを示す
    session_id = Column(
        String(36),                                         # sessions.session_id と同じ型
        ForeignKey("sessions.session_id", ondelete="CASCADE"),  # 親セッション削除時に連鎖削除
        nullable=False,                                     # NULL を許可しない
        index=True,                                         # クエリ高速化のためインデックスを付与
    )

    # 使用したセキュリティツール名（例: "nmap", "gobuster", "curl" 等）
    tool_name = Column(
        String(50),                     # ツール名の最大文字数を 50 に制限
        nullable=False,                 # NULL を許可しない
    )

    # 実行されたコマンドのオプション文字列（例: "-sV -T3 -p 80"）
    command_options = Column(
        String(500),                    # オプション文字列の最大長を 500 文字に制限
        nullable=True,                  # オプションなしのコマンドもあるため NULL を許可
    )

    # コマンドの終了コード（0 = 成功, 非0 = エラー）
    exit_code = Column(
        Integer,                        # 整数型
        nullable=True,                  # コマンド実行失敗時は NULL になる可能性があるため
    )

    # AI チューターの解説テキスト（長文になる可能性があるため Text 型）
    ai_response = Column(
        Text,                           # 長文テキスト型（長さ制限なし）
        nullable=True,                  # AI 接続エラー時は NULL になる可能性があるため
    )

    # コマンドの実行時間（秒）
    # コマンド送信直前〜結果受信直後の経過時間を記録する
    execution_duration = Column(
        Float,                          # 浮動小数点数型（例: 2.345 秒）
        nullable=True,                  # 計測不可の場合は NULL
    )

    # 前回のコマンド実行からの経過時間（秒）
    # 同一セッション内での前のログの created_at と今回の created_at の差分
    # 初回コマンドは前回がないため 0.0 を格納する
    time_since_last_cmd = Column(
        Float,                          # 浮動小数点数型（例: 45.2 秒）
        nullable=True,                  # 初回は None または 0.0
    )

    # ヘルプフラグ有無フラグ
    # コマンドオプションに --help, -h, man などが含まれるかどうかを記録する
    # 学習者が試行錯誤しているかの指標になる
    is_help_request = Column(
        Boolean,                        # 真偽値型
        nullable=False,                 # NULL を許可しない
        default=False,                  # デフォルトは False（ヘルプなし）
    )

    # ログの作成日時（= コマンド実行の記録日時）
    created_at = Column(
        DateTime,                       # 日時型
        nullable=False,                 # NULL を許可しない
        default=datetime.utcnow,        # INSERT 時に現在の UTC 時刻を自動設定
    )

    # リレーションシップ: 紐づく Session オブジェクトを取得できる
    session = relationship(
        "Session",                      # リレーション先の ORM クラス名
        back_populates="logs",          # Session 側の logs プロパティと双方向リンク
    )

    def __repr__(self) -> str:
        """デバッグ用の文字列表現"""
        return (
            f"<CommandLog id={self.log_id} "
            f"session={self.session_id!r} "
            f"tool={self.tool_name!r} "
            f"exit={self.exit_code}>"
        )
