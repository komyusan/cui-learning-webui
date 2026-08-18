"""
main.py
CUI Learning WebUI — FastAPI バックエンド

エンドポイント:
  POST /api/execute  : オプションを受け取り、コマンドを生成・実行して結果を返す
  GET  /api/health   : ヘルスチェック
"""

import logging
import ipaddress
import os
import re
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session

from executor import run_command_in_sandbox
from models import (
    NmapOptions, GobusterOptions, CurlOptions, HydraOptions,
    AircrackOptions, Iperf3Options, MetasploitOptions,
    ExecuteRequest, ExecuteResponse,
)
from commands import (
    ALLOWED_TOOLS, build_nmap_command, build_gobuster_command,
    build_curl_command, build_hydra_command, build_aircrack_command,
    build_iperf_command, build_metasploit_command,
)
from ai_service import build_llm_context, generate_ai_response
from database import get_db, init_db
from db_models import Session as DBSession, CommandLog


# ──────────────────────────────────────────────
# ロギング設定
# ──────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────
# アプリ起動 / 終了ライフサイクル
# ──────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """起動時に DB テーブルを自動作成する。"""
    logger.info("[lifespan] アプリケーション起動: DB テーブルを初期化します")
    init_db()
    logger.info("[lifespan] DB テーブルの初期化が完了しました")
    yield
    logger.info("[lifespan] アプリケーションを終了します")


# ──────────────────────────────────────────────
# FastAPI アプリ初期化
# ──────────────────────────────────────────────
app = FastAPI(
    title="CUI Learning WebUI API",
    description="セキュリティツール演習のためのCUI学習支援システム",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ──────────────────────────────────────────────
# セキュリティ検証（ターゲットホワイトリスト）
# ──────────────────────────────────────────────
_ALLOWED_HOSTNAMES = {
    "127.0.0.1",
    "localhost",
    "iperf3-server",
    "target-web",
    "example.com",
    "dummy-web",        # 学習用ダミーサーバ（nginx）
    "dvwa",             # Damn Vulnerable Web Application
    "metasploitable",   # Metasploitable2（侵入テスト演習OS）
    "mysql",            # MySQL 5.7（パスワードクラック演習用）
}


def is_safe_target(target_input: str) -> bool:
    """ターゲットがホワイトリストに登録された安全な対象かを検証する。"""
    if not target_input:
        return False

    # URL スキームがある場合はそのまま、それ以外はカンマ・スペース区切りで分割
    if "://" in target_input:
        targets = [target_input.strip()]
    else:
        targets = [t.strip() for t in re.split(r"[\s,]+", target_input) if t.strip()]

    if not targets:
        return False

    for target in targets:
        try:
            parsed = urlparse(target if "://" in target else "//" + target)
            hostname = parsed.hostname
        except Exception:
            return False

        if not hostname:
            return False

        hostname = hostname.lower()

        if hostname in _ALLOWED_HOSTNAMES:
            continue

        # プライベート IP アドレス（192.168.x.x 等）も許可
        try:
            ip = ipaddress.ip_address(hostname)
            if ip.version == 4 and ip.is_private:
                continue
        except ValueError:
            pass

        return False  # ホワイトリストにも private IP にも該当しない

    return True


# ──────────────────────────────────────────────
# ヘルパー関数
# ──────────────────────────────────────────────

def _is_help_request(command_list: list[str]) -> bool:
    """コマンドリストにヘルプ系フラグが含まれているか判定する。"""
    HELP_FLAGS = {"--help", "-h", "man", "--version", "-v"}
    return any(token in HELP_FLAGS for token in command_list)


def _get_or_create_session(
    db: Session,
    session_id: str | None,
    current_step: str,
) -> DBSession:
    """
    session_id が指定されていれば既存セッションを取得し、current_step を更新する。
    存在しない場合は新しいセッションを作成する。
    """
    db_session: DBSession | None = None

    if session_id:
        db_session = (
            db.query(DBSession)
            .filter(DBSession.session_id == session_id)
            .first()
        )

    if db_session is None:
        new_id = session_id or str(uuid.uuid4())
        db_session = DBSession(
            session_id=new_id,
            current_step=current_step,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        db.add(db_session)
        db.flush()
        logger.info("[session] 新規セッション作成: %s", db_session.session_id)
    else:
        db_session.current_step = current_step
        db_session.updated_at = datetime.now(timezone.utc)
        logger.info("[session] 既存セッション取得: %s", db_session.session_id)

    return db_session


def _calc_time_since_last_cmd(db: Session, session_id: str) -> float:
    """
    同一セッションの直近コマンドログからの経過時間（秒）を返す。
    ログが存在しない場合（初回）は 0.0 を返す。
    """
    last_log = (
        db.query(CommandLog)
        .filter(CommandLog.session_id == session_id)
        .order_by(CommandLog.created_at.desc())
        .first()
    )

    if last_log is None:
        return 0.0

    # created_at は UTC naive datetime として保存されているため naive 同士で比較する
    now_utc = datetime.now(timezone.utc).replace(tzinfo=None)
    elapsed = (now_utc - last_log.created_at).total_seconds()
    return max(0.0, elapsed)


# ──────────────────────────────────────────────
# エンドポイント
# ──────────────────────────────────────────────

@app.get("/api/health")
async def health_check():
    return {"status": "ok", "message": "CUI Learning WebUI is running"}


@app.post("/api/execute", response_model=ExecuteResponse)
async def execute_command(
    req: ExecuteRequest,
    db: Session = Depends(get_db),
):
    """
    フロントエンドからオプションを受け取り、
    コマンドを生成して Docker サンドボックスで実行する。
    """
    # ── ツール検証 ──
    if req.tool not in ALLOWED_TOOLS:
        raise HTTPException(
            status_code=400,
            detail=f"ツール '{req.tool}' はサポートされていません。対応ツール: {ALLOWED_TOOLS}",
        )

    # ── ターゲット検証 ──
    if req.tool in ("nmap", "gobuster", "curl", "hydra", "iperf3"):
        target_str = req.options.get("target")
    elif req.tool == "metasploit":
        target_str = req.options.get("rhosts")
    else:
        target_str = None

    if target_str is not None and (
        not isinstance(target_str, str) or not is_safe_target(target_str)
    ):
        raise HTTPException(
            status_code=400,
            detail=(
                "安全上の理由から、指定されたターゲットへの実行は制限されています。"
                "指定可能なターゲット: localhost, 127.0.0.1, dummy-web, example.com, "
                "dvwa, metasploitable, mysql, iperf3-server、またはプライベートIPアドレス（192.168.x.x 等）"
            ),
        )

    # ── コマンド構築 ──
    compose_network = os.environ.get("DOCKER_NETWORK", "cui-learning-network")
    network_mode = "none"  # デフォルト: 外部通信を遮断

    if req.tool == "nmap":
        command = build_nmap_command(NmapOptions(**req.options))
        image = "instrumentisto/nmap:latest"
        network_mode = compose_network
    elif req.tool == "gobuster":
        command = build_gobuster_command(GobusterOptions(**req.options))
        image = "secsi/gobuster:latest"
        network_mode = compose_network
    elif req.tool == "curl":
        command = build_curl_command(CurlOptions(**req.options))
        image = "curlimages/curl:latest"
        network_mode = compose_network
    elif req.tool == "hydra":
        command = ["hydra"] + build_hydra_command(HydraOptions(**req.options))
        image = "cui-learning-sandbox:latest"
        network_mode = compose_network
    elif req.tool == "aircrack-ng":
        command = ["aircrack-ng"] + build_aircrack_command(AircrackOptions(**req.options))
        image = "cui-learning-sandbox:latest"
    elif req.tool == "iperf3":
        command = build_iperf_command(Iperf3Options(**req.options))
        image = "networkstatic/iperf3:latest"
        network_mode = compose_network
    elif req.tool == "metasploit":
        command = build_metasploit_command(MetasploitOptions(**req.options))
        image = "metasploitframework/metasploit-framework:latest"
        network_mode = compose_network

    # hydra / aircrack-ng はツール名がすでに先頭にある
    command_str = (
        " ".join(command) if command[0] == req.tool
        else f"{req.tool} " + " ".join(command)
    )
    logger.info("Built command: %s", command_str)

    # ── セッション管理 ──
    db_session = _get_or_create_session(
        db=db,
        session_id=req.session_id,
        current_step=req.current_step,
    )
    active_session_id = db_session.session_id

    time_since_last = _calc_time_since_last_cmd(db, active_session_id)
    is_help = _is_help_request(command)

    # ── コマンド実行 ──
    exec_start = time.monotonic()
    result = run_command_in_sandbox(command, image=image, network_mode=network_mode)
    execution_duration = time.monotonic() - exec_start

    exit_code = result["exit_code"]
    cmd_stdout = result.get("stdout", "")
    cmd_stderr = result.get("stderr", "")

    # ── AI フィードバック生成 ──
    llm_context_json = build_llm_context(
        req,
        command,
        exit_code,
        stdout=cmd_stdout,
        stderr=cmd_stderr,
        time_since_last_cmd=time_since_last,
        is_help_request=is_help,
    )
    logger.info("LLM Context: %s", llm_context_json)

    ai_result = generate_ai_response(
        llm_context_json=llm_context_json,
        tool=req.tool,
        time_since_last_cmd=time_since_last,
        is_help_request=is_help,
    )
    ai_explanation = ai_result.get("message", "")
    ai_highlights = ai_result.get("highlights", [])

    # ── ログを DB に保存 ──
    options_str = " ".join(opt for opt in command if opt != req.tool) or None
    log_entry = CommandLog(
        session_id=active_session_id,
        tool_name=req.tool,
        command_options=options_str,
        exit_code=exit_code,
        ai_response=ai_explanation,
        execution_duration=execution_duration,
        time_since_last_cmd=time_since_last,
        is_help_request=is_help,
        created_at=datetime.now(timezone.utc).replace(tzinfo=None),
    )
    db.add(log_entry)
    db.commit()
    db.refresh(log_entry)

    logger.info(
        "[db] CommandLog 保存完了: log_id=%d, session=%s, tool=%s, exit=%d, duration=%.3fs",
        log_entry.log_id, active_session_id, req.tool, exit_code, execution_duration,
    )

    return ExecuteResponse(
        command=command_str,
        stdout=result["stdout"],
        stderr=result["stderr"],
        exit_code=exit_code,
        ai_explanation=ai_explanation,
        session_id=active_session_id,
        ai_highlights=ai_highlights,
    )


# ──────────────────────────────────────────────
# フロントエンドの静的ファイル配信
# ──────────────────────────────────────────────
frontend_path = os.path.join(os.path.dirname(__file__), "..", "frontend")
if os.path.exists(frontend_path):
    app.mount("/", StaticFiles(directory=frontend_path, html=True), name="frontend")
