"""
main.py
CUI Learning WebUI — FastAPI バックエンド

エンドポイント:
  POST /api/execute  : オプションを受け取り、コマンドを生成・実行して結果を返す
  GET  /api/health   : ヘルスチェック
"""

import logging
import ipaddress
import re
import uuid                                         # ▼▼▼変更箇所▼▼▼ UUID生成用（session_id の自動発行に使用）
import time                                         # ▼▼▼変更箇所▼▼▼ コマンド実行時間計測用
from contextlib import asynccontextmanager          # ▼▼▼変更箇所▼▼▼ lifespan イベント定義用
from datetime import datetime, timezone             # ▼▼▼変更箇所▼▼▼ DB の created_at 算出用
from urllib.parse import urlparse
from fastapi import FastAPI, HTTPException, Depends # ▼▼▼変更箇所▼▼▼ Depends を追加（依存注入でDBセッションを受け取る）
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session                  # ▼▼▼変更箇所▼▼▼ DB セッションの型ヒント用
import os

from executor import run_command_in_sandbox
from models import (
    NmapOptions, GobusterOptions, CurlOptions, HydraOptions,
    AircrackOptions, Iperf3Options, MetasploitOptions,
    ExecuteRequest, ExecuteResponse
)
from commands import (
    ALLOWED_TOOLS, build_nmap_command, build_gobuster_command,
    build_curl_command, build_hydra_command, build_aircrack_command,
    build_iperf_command, build_metasploit_command
)
from ai_service import build_llm_context, generate_ai_response
from database import get_db, init_db               # ▼▼▼変更箇所▼▼▼ DB初期化関数と依存注入関数をインポート
from db_models import Session as DBSession, CommandLog  # ▼▼▼変更箇所▼▼▼ ORM モデルをインポート（Session は名前衝突を避けるため DBSession と alias）

# ──────────────────────────────────────────────
# ロギング設定
# ──────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────
# ▼▼▼変更箇所▼▼▼ lifespan イベント（アプリ起動時にDBテーブルを自動作成）
# ──────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    FastAPI の lifespan イベントハンドラ。
    アプリ起動時（yield 前）に init_db() を呼び、
    sessions / command_logs テーブルが存在しない場合は自動作成する。
    """
    # ── 起動処理 ──
    logger.info("[lifespan] アプリケーション起動: DB テーブルを初期化します")
    init_db()                           # sessions / command_logs テーブルを CREATE TABLE IF NOT EXISTS で作成
    logger.info("[lifespan] DB テーブルの初期化が完了しました")
    yield                               # アプリの実行中はここで待機
    # ── 終了処理（必要であればここに書く）──
    logger.info("[lifespan] アプリケーションを終了します")

# ──────────────────────────────────────────────
# FastAPI アプリ初期化
# ──────────────────────────────────────────────
app = FastAPI(
    title="CUI Learning WebUI API",
    description="セキュリティツール演習のためのCUI学習支援システム",
    version="0.1.0",
    lifespan=lifespan,                  # ▼▼▼変更箇所▼▼▼ lifespan を登録（起動時の DB 初期化に必要）
)

# CORS設定（開発時はすべてのオリジンを許可）
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ──────────────────────────────────────────────
# セキュリティ検証（ガードレール）
# ──────────────────────────────────────────────
def is_safe_target(target_input: str) -> bool:
    """ターゲットがホワイトリストに登録されている安全な対象か検証する"""
    if not target_input:
        return False

    # 複数ターゲット指定 (カンマやスペース区切り) に対応
    if "://" in target_input:
        targets = [target_input.strip()]
    else:
        targets = [t.strip() for t in re.split(r'[\s,]+', target_input) if t.strip()]

    if not targets:
        return False

    allowed_hostnames = {
        "127.0.0.1",
        "localhost",
        "iperf3-server",
        "target-web",
        "example.com",
        "dummy-web",    # 学習用ダミーサーバ（nginx）
        # ▼▼▼変更箇所▼▼▼ やられ環境コンテナを攻撃ターゲットとして許可
        "dvwa",         # Damn Vulnerable Web Application（Webアプリ脆弱性演習用）
        "metasploitable",  # Metasploitable2（旧式サービス群が稼働する侵入テスト演習OS）
        "mysql",        # MySQL 5.7（脆弱なパスワード設定のDBサーバ、パスワードクラック演習用）
        # ▲▲▲変更箇所ここまで▲▲▲
    }

    for target in targets:
        if "://" in target:
            try:
                parsed = urlparse(target)
                hostname = parsed.hostname
            except Exception:
                return False
        else:
            try:
                parsed = urlparse("//" + target)
                hostname = parsed.hostname
            except Exception:
                hostname = target.split("/")[0].split(":")[0]

        if not hostname:
            return False

        hostname = hostname.lower()

        is_allowed = False
        if hostname in allowed_hostnames:
            is_allowed = True
        else:
            try:
                ip = ipaddress.ip_address(hostname)
                if ip.version == 4 and ip.is_private:
                    is_allowed = True
            except ValueError:
                pass
        
        if not is_allowed:
            return False

    return True


# ──────────────────────────────────────────────
# ▼▼▼変更箇所▼▼▼ ヘルプリクエスト判定ヘルパー関数
# ──────────────────────────────────────────────
def _is_help_request(command_list: list[str]) -> bool:
    """
    コマンドリストに --help / -h / man 等のヘルプ系フラグが含まれているか判定する。

    Parameters
    ----------
    command_list : 実行するコマンドのトークンリスト（例: ["nmap", "-sV", "--help"]）

    Returns
    -------
    True  : ヘルプ系フラグを含む
    False : 含まない
    """
    HELP_FLAGS = {"--help", "-h", "man", "--version", "-v"}     # ヘルプ系とみなすフラグの集合
    return any(token in HELP_FLAGS for token in command_list)   # いずれかのフラグが存在すれば True


# ──────────────────────────────────────────────
# ▼▼▼変更箇所▼▼▼ セッション取得または新規作成ヘルパー関数
# ──────────────────────────────────────────────
def _get_or_create_session(
    db: Session,
    session_id: str | None,
    current_step: str,
) -> DBSession:
    """
    session_id が指定されていれば既存セッションを取得し、current_step を更新する。
    session_id が None または存在しない場合は新しいセッションを作成する。

    Parameters
    ----------
    db           : SQLAlchemy DB セッション（FastAPI Depends から注入）
    session_id   : フロントエンドから受け取った session_id（なければ None）
    current_step : 現在の PTES 学習フェーズ名

    Returns
    -------
    DBSession : 既存または新規の Session ORM オブジェクト
    """
    db_session = None                                   # 取得/作成したセッションを格納する変数

    if session_id:                                      # session_id が指定されている場合
        db_session = (
            db.query(DBSession)                         # sessions テーブルを検索
            .filter(DBSession.session_id == session_id) # 一致する session_id を絞り込む
            .first()                                    # 最初の1件を取得（存在しなければ None）
        )

    if db_session is None:                              # DB にセッションが存在しない場合（初回 or session_id 未指定）
        new_id = session_id or str(uuid.uuid4())        # 指定された ID か新規 UUID を使う
        db_session = DBSession(                         # 新しい Session オRM オブジェクトを生成
            session_id=new_id,                          # セッション ID を設定
            current_step=current_step,                  # 現在の学習フェーズを設定
            created_at=datetime.now(timezone.utc),      # 作成日時（UTC）を設定
            updated_at=datetime.now(timezone.utc),      # 更新日時（UTC）を設定
        )
        db.add(db_session)                              # DB セッションに追加（まだ INSERT はされない）
        db.flush()                                      # session_id を確定させる（commit 前に ID を使えるよう）
        logger.info("[session] 新規セッション作成: %s", db_session.session_id)
    else:                                               # 既存セッションが見つかった場合
        db_session.current_step = current_step          # 現在の学習フェーズを最新に更新
        db_session.updated_at = datetime.now(timezone.utc)  # 更新日時を現在時刻に更新
        logger.info("[session] 既存セッション取得: %s", db_session.session_id)

    return db_session                                   # Session ORM オブジェクトを返す


# ──────────────────────────────────────────────
# ▼▼▼変更箇所▼▼▼ 前回コマンドからの経過時間を算出するヘルパー関数
# ──────────────────────────────────────────────
def _calc_time_since_last_cmd(db: Session, session_id: str) -> float:
    """
    同一セッションの直近の command_log レコードの created_at と
    現在時刻の差分（秒）を算出する。

    Parameters
    ----------
    db         : SQLAlchemy DB セッション
    session_id : 対象のセッション ID

    Returns
    -------
    float : 前回コマンドからの経過秒数。初回（ログなし）は 0.0 を返す。
    """
    last_log = (
        db.query(CommandLog)                            # command_logs テーブルを検索
        .filter(CommandLog.session_id == session_id)   # 同じセッションのログのみ
        .order_by(CommandLog.created_at.desc())        # created_at の降順（最新が先頭）
        .first()                                        # 最新の1件を取得
    )

    if last_log is None:                                # 同一セッションに過去のログがない（初回）
        return 0.0                                      # 初回は経過時間 0.0 を返す

    # 前回ログの created_at は UTC naive datetime として保存されているため
    # 現在の UTC 時刻も naive datetime で計算する
    now_utc = datetime.now(timezone.utc).replace(tzinfo=None)   # タイムゾーン情報を除去して比較
    last_time = last_log.created_at                              # 直近ログの作成日時

    elapsed = (now_utc - last_time).total_seconds()    # 経過秒数を計算（timedelta → float）
    return max(0.0, elapsed)                            # 負の値にならないよう 0.0 以上を保証


# ──────────────────────────────────────────────
# エンドポイント
# ──────────────────────────────────────────────
@app.get("/api/health")
async def health_check():
    return {"status": "ok", "message": "CUI Learning WebUI is running"}


@app.post("/api/execute", response_model=ExecuteResponse)
async def execute_command(
    req: ExecuteRequest,
    db: Session = Depends(get_db),      # ▼▼▼変更箇所▼▼▼ FastAPI の依存注入で DB セッションを受け取る
):
    """
    フロントエンドからオプションを受け取り、
    コマンドを生成してDockerサンドボックスで実行する。
    """
    if req.tool not in ALLOWED_TOOLS:
        raise HTTPException(
            status_code=400,
            detail=f"ツール '{req.tool}' はサポートされていません。対応ツール: {ALLOWED_TOOLS}",
        )

    # ターゲットの検証
    target_str = None
    if req.tool in ("nmap", "gobuster", "curl", "hydra", "iperf3"):
        target_str = req.options.get("target")
    elif req.tool == "metasploit":
        target_str = req.options.get("rhosts")

    if target_str is not None:
        if not isinstance(target_str, str) or not is_safe_target(target_str):
            raise HTTPException(
                status_code=400,
                # ▼▼▼変更箇所▼▼▼ エラーメッセージを現在のホワイトリストに合わせて更新
                detail="安全上の理由から、指定されたターゲットへの実行は制限されています。"
                        "指定可能なターゲット: localhost, 127.0.0.1, dummy-web, example.com, "
                        "dvwa, metasploitable, mysql, iperf3-server、またはプライベートIPアドレス（192.168.x.x 等）"
            )

    # コマンドの構築
    # ツールごとに適用するネットワークモードの初期値を設定する
    # composeのデフォルトネットワークを動的に取得、または "cui-learning-network" を使用
    compose_network = os.environ.get("DOCKER_NETWORK", "cui-learning-network")
    network_mode = "none" # デフォルトは外部通信を完全に遮断するnoneとする

    if req.tool == "nmap":
        opts = NmapOptions(**req.options)
        command = build_nmap_command(opts)
        image = "instrumentisto/nmap:latest"
        network_mode = compose_network # nmapもターゲットサーバに通信するためネットワークを許可
    elif req.tool == "gobuster":
        opts = GobusterOptions(**req.options)
        command = build_gobuster_command(opts)
        image = "secsi/gobuster:latest"
        network_mode = compose_network # gobusterも通信必須
    elif req.tool == "curl":
        opts = CurlOptions(**req.options)
        command = build_curl_command(opts)
        image = "curlimages/curl:latest"
        network_mode = compose_network
    elif req.tool == "hydra":
        opts = HydraOptions(**req.options)
        # cui-learning-sandbox の ENTRYPOINT は /entrypoint.sh (exec "$@") なので
        # ツール名を先頭に付けてフルコマンドとして渡す必要がある
        command = ["hydra"] + build_hydra_command(opts)
        image = "cui-learning-sandbox:latest"
        network_mode = compose_network # hydra は自身の SSH に接続するためネットワーク許可
    elif req.tool == "aircrack-ng":
        opts = AircrackOptions(**req.options)
        # 同様にツール名を先頭に付ける
        command = ["aircrack-ng"] + build_aircrack_command(opts)
        image = "cui-learning-sandbox:latest"
    elif req.tool == "iperf3":
        opts = Iperf3Options(**req.options)
        command = build_iperf_command(opts)
        image = "networkstatic/iperf3:latest"
        network_mode = compose_network
    elif req.tool == "metasploit":
        opts = MetasploitOptions(**req.options)
        command = build_metasploit_command(opts)
        image = "metasploitframework/metasploit-framework:latest"
        network_mode = compose_network

    # command リストにすでにツール名が含まれている場合（hydra, aircrack-ng）は
    # そのまま join する。含まれていない場合（nmap 等）はツール名を先頭に付ける。
    if command and command[0] == req.tool:
        command_str = " ".join(command)
    else:
        command_str = f"{req.tool} " + " ".join(command)
    logger.info(f"Built command: {command_str}")

    # ▼▼▼変更箇所▼▼▼ ── セッション管理 ──────────────────────────────────────
    # リクエストから session_id を取得（なければ None → 新規セッションを自動生成）
    session_id_from_req = req.session_id                       # Pydantic モデルから直接取得

    # DB からセッションを取得または新規作成
    db_session = _get_or_create_session(
        db=db,
        session_id=session_id_from_req,     # フロントエンドから受け取った session_id（なければ None）
        current_step=req.current_step,      # 現在の PTES 学習フェーズ
    )
    active_session_id = db_session.session_id   # 確定した session_id（新規 or 既存）

    # ▼▼▼変更箇所▼▼▼ ── 前回コマンドからの経過時間を計算 ──────────────────────
    time_since_last = _calc_time_since_last_cmd(db, active_session_id)  # 前回コマンドからの経過秒数
    # ▼▼▼変更箇所▼▼▼ ── ヘルプフラグ判定 ──────────────────────────────────────
    is_help = _is_help_request(command)         # --help / -h 等のフラグが含まれるか判定

    # ▼▼▼変更箇所▼▼▼ ── コマンド実行時間の計測開始 ────────────────────────────
    exec_start = time.monotonic()               # 計測開始時刻（time.monotonic は sleep や NTP の影響を受けない）

    # サンドボックスで実行
    result = run_command_in_sandbox(command, image=image, network_mode=network_mode)

    # ▼▼▼変更箇所▼▼▼ ── コマンド実行時間の計測終了 ────────────────────────────
    execution_duration = time.monotonic() - exec_start  # コマンド実行にかかった秒数（float）

    exit_code = result["exit_code"]                 # コマンドの終了コードを取得
    # ▼▼▼変更箇所▼▼▼ stdout / stderr を result から取り出して変数に格納する
    cmd_stdout = result.get("stdout", "")           # 標準出力テキストを取得（キーが存在しない場合は空文字）
    cmd_stderr = result.get("stderr", "")           # 標準エラー出力テキストを取得（キーが存在しない場合は空文字）
    # ▲▲▲変更箇所ここまで▲▲▲

    # AIコンテキスト生成とAI解説の取得
    # ▼▼▼変更箇所▼▼▼ build_llm_context に stdout/stderr と Stuck State 情報を渡す
    llm_context_json = build_llm_context(
        req,            # フロントエンドからのリクエストオブジェクト
        command,        # 実行したコマンドのトークンリスト
        exit_code,      # コマンドの終了コード
        stdout=cmd_stdout,                  # 標準出力テキスト
        stderr=cmd_stderr,                  # 標準エラー出力テキスト
        time_since_last_cmd=time_since_last, # ▼▼▼変更箇所▼▼▼ 前回コマンドからの経過秒数を追加
        is_help_request=is_help,             # ▼▼▼変更箇所▼▼▼ ヘルプフラグ判定結果を追加
    )
    # ▲▲▲変更箇所ここまで▲▲▲
    logger.info(f"LLM Context: {llm_context_json}")
    
    # ▼▼▼変更箇所▼▼▼ generate_ai_response に Stuck State情報を渡し、戻り値(dict)を受け取る
    ai_result = generate_ai_response(
        llm_context_json=llm_context_json, 
        tool=req.tool,
        time_since_last_cmd=time_since_last, # ▼▼▼変更箇所▼▼▼ 経過時間を追加
        is_help_request=is_help              # ▼▼▼変更箇所▼▼▼ ヘルプフラグを追加
    )
    ai_explanation = ai_result.get("message", "")      # AI フィードバックテキストを取り出す
    ai_highlights  = ai_result.get("highlights", [])   # ハイライト用キーワードリストを取り出す（なければ空リスト）
    # ▲▲▲変更箇所ここまで▲▲▲

    # ▼▼▼変更箇所▼▼▼ ── コマンドログを DB に保存 ──────────────────────────────
    # コマンドオプション部分のみを文字列として保存（ツール名除く）
    options_str = " ".join(opt for opt in command if opt != req.tool)   # ツール名を除いたオプション部分

    log_entry = CommandLog(                                     # CommandLog ORM オブジェクトを生成
        session_id=active_session_id,                           # 紐づくセッション ID
        tool_name=req.tool,                                     # 使用したツール名
        command_options=options_str if options_str else None,   # 実行オプション文字列（空なら None）
        exit_code=exit_code,                                    # コマンドの終了コード
        ai_response=ai_explanation,                             # AI チューターの解説テキスト
        execution_duration=execution_duration,                  # コマンド実行にかかった秒数
        time_since_last_cmd=time_since_last,                    # 前回コマンドからの経過秒数
        is_help_request=is_help,                                # ヘルプフラグの有無
        created_at=datetime.now(timezone.utc).replace(tzinfo=None),  # 記録日時（UTC naive）
    )
    db.add(log_entry)       # DB セッションにログを追加（まだ INSERT はされない）
    db.commit()             # ここで session の UPDATE と log の INSERT を一括コミット
    db.refresh(log_entry)   # commit 後に DB から最新の状態（log_id 等）を取得

    logger.info(
        "[db] CommandLog 保存完了: log_id=%d, session=%s, tool=%s, exit=%d, duration=%.3fs",
        log_entry.log_id, active_session_id, req.tool, exit_code, execution_duration,
    )
    # ▲▲▲変更箇所ここまで▲▲▲

    return ExecuteResponse(
        command=command_str,                # 実行されたコマンド文字列
        stdout=result["stdout"],            # コマンドの標準出力
        stderr=result["stderr"],            # コマンドの標準エラー出力
        exit_code=exit_code,               # 終了コード
        ai_explanation=ai_explanation,      # AI チューターの解説テキスト（message フィールドから取得）
        # ▼▼▼変更箇所▼▼▼ DB コミット後に確定した session_id をレスポンスに含める
        # フロントエンドはこの値を localStorage に保存し、次回リクエストに session_id フィールドとして送る
        session_id=active_session_id,       # 新規生成 or 既存継続のどちらでも確定済み ID
        # ▼▼▼変更箇所▼▼▼ AI がフォーカスしたキーワードリストをレスポンスに含める
        # フロントエンドはこのリストを使い、ターミナル出力内の該当テキストを <span> でハイライトする
        ai_highlights=ai_highlights,        # ハイライト用キーワードリスト（空リストの場合はハイライトなし）
    )

# ──────────────────────────────────────────────
# フロントエンドの静的ファイル配信（本番時）
# ──────────────────────────────────────────────
frontend_path = os.path.join(os.path.dirname(__file__), "..", "frontend")
if os.path.exists(frontend_path):
    app.mount("/", StaticFiles(directory=frontend_path, html=True), name="frontend")
