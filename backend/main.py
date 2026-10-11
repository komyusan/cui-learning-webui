"""
main.py
CUI Learning WebUI — FastAPI バックエンド

エンドポイント:
  POST /api/execute  : オプションを受け取り、コマンドを生成・実行して結果を返す
  GET  /api/health   : ヘルスチェック（認証不要）
  POST /api/login    : LDAP 認証してセッションクッキーを発行
  POST /api/logout   : セッションクッキーを削除
  GET  /api/me       : ログイン中ユーザの確認
"""

import logging
import ipaddress
import os
import re
import time
import uuid
from pathlib import Path
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from urllib.parse import quote
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, Depends, File, UploadFile, Response
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session

from executor import run_command_in_sandbox
from models import (
    NmapOptions, GobusterOptions, CurlOptions, HydraOptions,
    AircrackOptions, Iperf3Options, MetasploitOptions,
    WhoisOptions, DigOptions,
    ExecuteRequest, ExecuteResponse, SessionStateResponse,
    MaterialFileInfo, MaterialListResponse, MaterialUploadResponse,
)
from commands import (
    ALLOWED_TOOLS, build_nmap_command, build_gobuster_command,
    build_curl_command, build_hydra_command, build_aircrack_command,
    build_iperf_command, build_metasploit_command,
    build_whois_command, build_dig_command,
)
from ai_service import build_llm_context, generate_ai_response
from database import get_db, init_db
from db_models import Session as DBSession, CommandLog, User
from auth import (
    authenticate_ldap, create_session_cookie, get_current_user,
    is_skip_auth, DEV_USER_UID,
    SESSION_COOKIE_NAME, SESSION_MAX_AGE,
)


# ──────────────────────────────────────────────
# ロギング設定
# ──────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

APP_DIR = Path(__file__).resolve().parent
PERSISTENT_DATA_DIR = Path("/app/data")
if not PERSISTENT_DATA_DIR.exists():
    PERSISTENT_DATA_DIR = APP_DIR

MATERIALS_DIR = PERSISTENT_DATA_DIR / "materials"
MATERIALS_DIR.mkdir(parents=True, exist_ok=True)


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


class LoginRequest(BaseModel):
    uid: str
    password: str


@app.post("/api/login")
async def login(
    req: LoginRequest,
    response: Response,
    db: Session = Depends(get_db),
):
    """LDAP で認証し、成功したら署名付きセッションクッキーをセットする。"""
    # 開発モード（SKIP_AUTH=true）: 認証せず dev_user で即成功とする
    if is_skip_auth():
        logger.warning("[auth] SKIP_AUTH=true: 認証をスキップします")
        return {"status": "ok", "uid": DEV_USER_UID}

    user_info = authenticate_ldap(req.uid.strip(), req.password)
    if user_info is None:
        raise HTTPException(
            status_code=401,
            detail="学籍番号またはパスワードが正しくありません。",
        )

    # ユーザ情報を DB に記録（初回は作成、以降は最終ログイン時刻を更新）
    now_utc = datetime.now(timezone.utc).replace(tzinfo=None)
    user = db.query(User).filter(User.ldap_uid == user_info["uid"]).first()
    if user is None:
        user = User(
            ldap_uid=user_info["uid"],
            cn=user_info["cn"],
            mail=user_info["mail"],
            first_login_at=now_utc,
            last_login_at=now_utc,
        )
        db.add(user)
    else:
        user.cn = user_info["cn"]
        user.mail = user_info["mail"]
        user.last_login_at = now_utc
    db.commit()

    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=create_session_cookie(user_info["uid"]),
        max_age=SESSION_MAX_AGE,
        httponly=True,
        samesite="lax",
        secure=os.environ.get("SESSION_COOKIE_SECURE", "false").lower() == "true",
    )
    return {"status": "ok", "uid": user_info["uid"]}


@app.post("/api/logout")
async def logout(response: Response):
    """セッションクッキーを削除する。"""
    response.delete_cookie(key=SESSION_COOKIE_NAME)
    return {"status": "ok"}


@app.get("/api/me")
async def me(uid: str = Depends(get_current_user)):
    """現在ログイン中のユーザの uid を返す（フロントのログイン状態確認用）。"""
    return {"uid": uid}


@app.get("/api/sessions/{session_id}", response_model=SessionStateResponse)
async def get_session_state(
    session_id: str,
    db: Session = Depends(get_db),
):
    db_session = (
        db.query(DBSession)
        .filter(DBSession.session_id == session_id)
        .first()
    )

    if db_session is None:
        raise HTTPException(status_code=404, detail="セッションが見つかりません。")

    return SessionStateResponse(
        session_id=db_session.session_id,
        current_step=db_session.current_step,
        created_at=db_session.created_at,
        updated_at=db_session.updated_at,
    )


def _build_material_info(file_path: Path) -> MaterialFileInfo:
    stat = file_path.stat()
    quoted_name = quote(file_path.name)
    return MaterialFileInfo(
        filename=file_path.name,
        url=f"/materials/{quoted_name}",
        size=stat.st_size,
        uploaded_at=datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc),
    )


@app.get("/api/materials", response_model=MaterialListResponse)
async def list_materials():
    pdf_files = sorted(
        MATERIALS_DIR.glob("*.pdf"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    return MaterialListResponse(
        materials=[_build_material_info(path) for path in pdf_files]
    )


@app.post("/api/materials/upload", response_model=MaterialUploadResponse)
async def upload_material(file: UploadFile = File(...)):
    if not file.filename:
        raise HTTPException(status_code=400, detail="アップロードするPDFを選択してください。")

    original_name = Path(file.filename).name
    if Path(original_name).suffix.lower() != ".pdf":
        raise HTTPException(status_code=400, detail="PDFファイルのみアップロードできます。")

    # 日本語ファイル名は基本的に保持する（講義資料の識別性を優先）。
    # パストラバーサルや制御文字だけ除去して保存する。
    safe_name = original_name.replace("/", "_").replace("\\", "_")
    safe_name = safe_name.replace("\x00", "_").strip()
    if not safe_name:
        safe_name = "material.pdf"

    destination = MATERIALS_DIR / safe_name
    stem = destination.stem
    suffix = destination.suffix
    counter = 1
    while destination.exists():
        destination = MATERIALS_DIR / f"{stem}_{counter}{suffix}"
        counter += 1

    max_size_bytes = 25 * 1024 * 1024
    total_size = 0

    try:
        with destination.open("wb") as buffer:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                total_size += len(chunk)
                if total_size > max_size_bytes:
                    raise HTTPException(
                        status_code=400,
                        detail="PDFのサイズは25MB以下にしてください。",
                    )
                buffer.write(chunk)
    except HTTPException:
        destination.unlink(missing_ok=True)
        raise
    finally:
        await file.close()

    return MaterialUploadResponse(material=_build_material_info(destination))


@app.post("/api/execute", response_model=ExecuteResponse)
async def execute_command(
    req: ExecuteRequest,
    db: Session = Depends(get_db),
    uid: str = Depends(get_current_user),
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
    if req.tool in ("whois", "dig"):
        # 任意のドメイン/IPを許可するため is_safe_target は適用しない。
        # ただしオプション注入を防ぐため、最低限の形式のみ検証する。
        raw_target = req.options.get("target")
        if (
            not isinstance(raw_target, str)
            or not raw_target.strip()
            or raw_target.startswith("-")
            or re.search(r"\s", raw_target)
        ):
            raise HTTPException(
                status_code=400,
                detail="ターゲットには空白を含まない、'-' で始まらないドメイン/IPを指定してください。",
            )
        target_str = None
    elif req.tool in ("nmap", "gobuster", "curl", "hydra", "iperf3"):
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
    elif req.tool == "whois":
        command = build_whois_command(WhoisOptions(**req.options))
        image = "cui-learning-sandbox:latest"
        network_mode = compose_network
    elif req.tool == "dig":
        command = build_dig_command(DigOptions(**req.options))
        image = "cui-learning-sandbox:latest"
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
        session_id=uid,  # ユーザごとに session_id を固定（ログをユーザに紐付ける）
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
app.mount("/materials", StaticFiles(directory=MATERIALS_DIR), name="materials")

frontend_path = os.path.join(os.path.dirname(__file__), "..", "frontend")
if os.path.exists(frontend_path):
    app.mount("/", StaticFiles(directory=frontend_path, html=True), name="frontend")
