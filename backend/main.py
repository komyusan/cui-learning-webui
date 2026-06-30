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
from urllib.parse import urlparse
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
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
from ai_service import build_llm_context, generate_dummy_ai_response

# ──────────────────────────────────────────────
# ロギング設定
# ──────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────
# FastAPI アプリ初期化
# ──────────────────────────────────────────────
app = FastAPI(
    title="CUI Learning WebUI API",
    description="セキュリティツール演習のためのCUI学習支援システム",
    version="0.1.0",
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
        "dummy-web"  # 学習用ダミーサーバを追加
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
# エンドポイント
# ──────────────────────────────────────────────
@app.get("/api/health")
async def health_check():
    return {"status": "ok", "message": "CUI Learning WebUI is running"}


@app.post("/api/execute", response_model=ExecuteResponse)
async def execute_command(req: ExecuteRequest):
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
                detail="安全上の理由から、指定されたターゲットへの実行は制限されています。ローカル環境または dummy-web, example.com のみ指定可能です。"
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
        command = build_hydra_command(opts)
        image = "cui-learning-sandbox:latest"
        network_mode = compose_network # hydraもダミーサーバへ通信するかもしれないので許可
    elif req.tool == "aircrack-ng":
        opts = AircrackOptions(**req.options)
        command = build_aircrack_command(opts)
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

    command_str = f"{req.tool} " + " ".join(command)
    logger.info(f"Built command: {command_str}")

    # サンドボックスで実行
    result = run_command_in_sandbox(command, image=image, network_mode=network_mode)
    exit_code = result["exit_code"]

    # AIコンテキスト生成とダミー解説の取得
    llm_context_json = build_llm_context(req, command, exit_code)
    logger.info(f"LLM Context: {llm_context_json}")
    ai_explanation = generate_dummy_ai_response(llm_context_json, req.tool)

    return ExecuteResponse(
        command=command_str,
        stdout=result["stdout"],
        stderr=result["stderr"],
        exit_code=exit_code,
        ai_explanation=ai_explanation
    )

# ──────────────────────────────────────────────
# フロントエンドの静的ファイル配信（本番時）
# ──────────────────────────────────────────────
frontend_path = os.path.join(os.path.dirname(__file__), "..", "frontend")
if os.path.exists(frontend_path):
    app.mount("/", StaticFiles(directory=frontend_path, html=True), name="frontend")
