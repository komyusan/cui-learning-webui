"""
main.py
CUI Learning WebUI — FastAPI バックエンド

エンドポイント:
  POST /api/execute  : オプションを受け取り、コマンドを生成・実行して結果を返す
  GET  /api/health   : ヘルスチェック
"""

import logging
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional
import os

from executor import run_command_in_sandbox

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
# スキーマ定義
# ──────────────────────────────────────────────
class NmapOptions(BaseModel):
    """nmapコマンドのオプション"""
    target: str                          # スキャン対象ホスト/IP
    scan_type: Optional[str] = "-sV"     # スキャン種別
    os_detection: bool = False           # -O: OS検出
    timing: Optional[str] = "-T3"       # タイミングテンプレート
    port_range: Optional[str] = None    # -p: ポート範囲
    output_format: Optional[str] = None # -oN / -oX 等
    extra_flags: Optional[str] = None   # その他フリーテキスト（将来拡張用）


class ExecuteRequest(BaseModel):
    tool: str           # "nmap" など
    options: NmapOptions


class ExecuteResponse(BaseModel):
    command: str        # 生成されたコマンド文字列（表示用）
    stdout: str
    stderr: str
    exit_code: int


# ──────────────────────────────────────────────
# コマンド生成ロジック
# ──────────────────────────────────────────────
ALLOWED_TOOLS = {"nmap"}

def build_nmap_command(opts: NmapOptions) -> list[str]:
    """NmapOptions から nmap コマンドリストを構築する。"""
    cmd = []

    if opts.scan_type:
        cmd.extend(opts.scan_type.split())

    if opts.os_detection:
        cmd.append("-O")

    if opts.timing:
        cmd.extend(opts.timing.split())

    if opts.port_range:
        cmd.extend(["-p", opts.port_range])

    if opts.output_format:
        cmd.extend(opts.output_format.split())

    # ターゲットは最後に追加
    cmd.append(opts.target)
    return cmd


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

    # コマンドの構築
    command = build_nmap_command(req.options)
    command_str = " ".join(command)
    logger.info(f"Built command: {command_str}")

    # サンドボックスで実行
    result = run_command_in_sandbox(command)

    return ExecuteResponse(
        command=command_str,
        stdout=result["stdout"],
        stderr=result["stderr"],
        exit_code=result["exit_code"],
    )


# ──────────────────────────────────────────────
# フロントエンドの静的ファイル配信（本番時）
# ──────────────────────────────────────────────
frontend_path = os.path.join(os.path.dirname(__file__), "..", "frontend")
if os.path.exists(frontend_path):
    app.mount("/", StaticFiles(directory=frontend_path, html=True), name="frontend")
