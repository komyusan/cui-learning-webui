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


class GobusterOptions(BaseModel):
    """gobusterコマンドのオプション"""
    target: str                         # 探索対象URL
    mode: str = "dir"                   # 探索モード(dir, dns, vhostなど)
    wordlist: str = "/usr/share/wordlists/dirb/common.txt" # 辞書ファイル
    quiet: bool = False                 # -q: バナーやエラー非表示
    extra_flags: Optional[str] = None


class CurlOptions(BaseModel):
    """curlコマンドのオプション"""
    target: str                         # 対象URL
    method: str = "GET"                 # -X: HTTPメソッド
    header: Optional[str] = None        # -H: ヘッダー
    verbose: bool = False               # -v: 詳細出力
    extra_flags: Optional[str] = None


class HydraOptions(BaseModel):
    """hydraコマンドのオプション"""
    target: str                          # ターゲット (IP, URL)
    service: str = "ssh"                 # 対象サービスモジュール
    user: str                            # ユーザー名
    user_list: bool = False              # ユーザー名リストかどうか(-L または -l)
    wordlist: str = "/usr/share/wordlists/passwords.txt" # パスワード辞書(-P)
    extra_flags: Optional[str] = None


class AircrackOptions(BaseModel):
    """aircrack-ngコマンドのオプション"""
    target_file: str                     # .ivs または .cap ファイル
    wordlist: str = "/usr/share/wordlists/passwords.txt" # -w
    bssid: Optional[str] = None          # -b
    extra_flags: Optional[str] = None


class Iperf3Options(BaseModel):
    """iperf3コマンドのオプション"""
    target: str                          # サーバー (例: iperf3-server)
    protocol: str = "tcp"                # プロトコル (tcp / udp)
    time: int = 10                       # -t: 実行時間
    bandwidth: Optional[str] = None      # -b: 帯域幅


class MetasploitOptions(BaseModel):
    """metasploitコマンドのオプション"""
    module: str                          # 例: auxiliary/scanner/portscan/tcp
    rhosts: str                          # RHOSTS
    rport: Optional[str] = None          # RPORT


class ExecuteRequest(BaseModel):
    tool: str           # "nmap" または "gobuster"
    current_step: str = "Step 1" # フロントエンドからの現在のステップ
    options: dict       # ツールに応じたオプション辞書


class ExecuteResponse(BaseModel):
    command: str        # 生成されたコマンド文字列（表示用）
    stdout: str
    stderr: str
    exit_code: int
    ai_explanation: Optional[str] = None

# ──────────────────────────────────────────────
# AI コンテキスト生成＆ダミー応答ロジック
# ──────────────────────────────────────────────
import json

def build_llm_context(req: ExecuteRequest, command_list: list[str], exit_code: int) -> str:
    """将来のLLMAPIへ渡すコンテキストJSONを生成する"""
    # ユーザーが指定したオプションフラグの抽出（簡易的）
    # コマンドのリストから、ツール名やターゲット以外のハイフンから始まるオプションを抽出
    user_options = [opt for opt in command_list if opt.startswith("-")]
    
    context = {
        "current_step": req.current_step,
        "user_selected_options": user_options,
        "execution_result": "success" if exit_code == 0 else "failed"
    }
    return json.dumps(context, ensure_ascii=False)

def generate_dummy_ai_response(llm_context_json: str, tool: str) -> str:
    """ダミーのAIチューター応答を生成する"""
    context = json.loads(llm_context_json)
    step = context.get("current_step", "Step 1")
    success = (context.get("execution_result") == "success")

    if step.startswith("Step 1"):
        if tool == "nmap":
            if success:
                return "💡 Nmapの実行が成功したね！開いているポートが見つかったかな？🤔 次はどのサービスが動いているか特定してみると良いかも！"
            else:
                return "🤔 うーん、スキャンに失敗したみたい。ターゲットのIPアドレスやオプションを見直してみよう。pingが通らないなら `-sn` などを試すのもアリだよ💡"
        else:
            return "💡 情報収集フェーズでは、まずは Nmap を使ってネットワークの全体像を把握するのが王道だよ。他のツールも試してみてね🤔"
    elif step.startswith("Step 2"):
        if tool == "gobuster":
            if success:
                return "💡 Gobusterでディレクトリ探索が成功したね！隠されたWebページは見つかったかな？🤔 脆弱性がありそうなページを探してみよう！"
            else:
                return "🤔 探索が失敗しちゃったみたい。URLの指定や辞書ファイル（Wordlist）のパスが正しいか確認してみて💡"
        else:
            return "💡 脆弱性スキャンフェーズだね！Webサーバーが見つかったなら、Gobusterなどでディレクトリ探索をするのがおすすめだよ🤔"
    elif step.startswith("Step 3"):
        if tool in ["hydra", "metasploit"]:
            if success:
                return "💡 エクスプロイト成功の兆し！🤔 システムに侵入する足がかりは見つかったかな？"
            else:
                return "🤔 攻撃が弾かれたみたい。パスワードリストが合っているか、対象のポートが開いているか確認してみよう💡"
        else:
            return "💡 エクスプロイト（攻撃）フェーズだよ。特定した脆弱性に対して、HydraやMetasploitを使ってアプローチしてみよう🤔"
    elif step.startswith("Step 4"):
        return "💡 ポストエクスプロイトフェーズだね。侵入後にどんな情報が取れるか、さらに権限昇格できるか試してみよう🤔 ログの消去も忘れずに！"
    else:
        return "🤔 新しいステップかな？まずは基本のコマンドから試してみよう💡"

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
        "example.com"
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
# コマンド生成ロジック
# ──────────────────────────────────────────────
ALLOWED_TOOLS = {"nmap", "gobuster", "curl", "hydra", "aircrack-ng", "iperf3", "metasploit"}

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


def build_gobuster_command(opts: GobusterOptions) -> list[str]:
    """GobusterOptions から gobuster コマンドリストを構築する。"""
    cmd = [opts.mode]
    cmd.extend(["-u", opts.target])
    cmd.extend(["-w", opts.wordlist])
    if opts.quiet:
        cmd.append("-q")
    return cmd


def build_curl_command(opts: CurlOptions) -> list[str]:
    """CurlOptions から curl コマンドリストを構築する。"""
    cmd = []
    if opts.method and opts.method.upper() != "GET":
        cmd.extend(["-X", opts.method.upper()])
    if opts.header:
        cmd.extend(["-H", opts.header])
    if opts.verbose:
        cmd.append("-v")
    cmd.append(opts.target)
    return cmd


def build_hydra_command(opts: HydraOptions) -> list[str]:
    """HydraOptions から hydra コマンドリストを構築する。"""
    cmd = []
    if opts.user_list:
        cmd.extend(["-L", opts.user])
    else:
        cmd.extend(["-l", opts.user])
    
    cmd.extend(["-P", opts.wordlist])
    # URLベースのサービスの時は -s ポートなどを追加する機能も考えられるが、ここではシンプルに実装
    cmd.extend([opts.target, opts.service])
    return cmd


def build_aircrack_command(opts: AircrackOptions) -> list[str]:
    """AircrackOptions から aircrack-ng コマンドリストを構築する。"""
    cmd = []
    cmd.extend(["-w", opts.wordlist])
    if opts.bssid:
        cmd.extend(["-b", opts.bssid])
    cmd.append(opts.target_file)
    return cmd


def build_iperf_command(opts: Iperf3Options) -> list[str]:
    """Iperf3Options から iperf3 コマンドリストを構築する。"""
    cmd = ["-c", opts.target]
    if opts.protocol.lower() == "udp":
        cmd.append("-u")
    cmd.extend(["-t", str(opts.time)])
    if opts.bandwidth:
        cmd.extend(["-b", opts.bandwidth])
    return cmd


def build_metasploit_command(opts: MetasploitOptions) -> list[str]:
    """MetasploitOptions から msfconsole コマンドリストを構築する。"""
    # -q: quiet, -x: execute script
    script = f"use {opts.module}; set RHOSTS {opts.rhosts}; "
    if opts.rport:
        script += f"set RPORT {opts.rport}; "
    script += "run; exit"
    return ["-q", "-x", script]


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
                detail="安全上の理由から、指定されたターゲットへの実行は制限されています。ローカル環境または example.com のみ指定可能です。"
            )

    # コマンドの構築
    if req.tool == "nmap":
        opts = NmapOptions(**req.options)
        command = build_nmap_command(opts)
        image = "instrumentisto/nmap:latest"
    elif req.tool == "gobuster":
        opts = GobusterOptions(**req.options)
        command = build_gobuster_command(opts)
        image = "secsi/gobuster:latest"
    elif req.tool == "curl":
        opts = CurlOptions(**req.options)
        command = build_curl_command(opts)
        image = "curlimages/curl:latest"
    elif req.tool == "hydra":
        opts = HydraOptions(**req.options)
        command = build_hydra_command(opts)
        image = "cui-learning-sandbox:latest"
    elif req.tool == "aircrack-ng":
        opts = AircrackOptions(**req.options)
        command = build_aircrack_command(opts)
        image = "cui-learning-sandbox:latest"
    elif req.tool == "iperf3":
        opts = Iperf3Options(**req.options)
        command = build_iperf_command(opts)
        image = "networkstatic/iperf3:latest"
    elif req.tool == "metasploit":
        opts = MetasploitOptions(**req.options)
        command = build_metasploit_command(opts)
        image = "metasploitframework/metasploit-framework:latest"

    command_str = f"{req.tool} " + " ".join(command)
    logger.info(f"Built command: {command_str}")

    # サンドボックスで実行
    result = run_command_in_sandbox(command, image=image)
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
