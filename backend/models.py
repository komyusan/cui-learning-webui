"""
models.py
CUI Learning WebUI — Pydantic リクエスト / レスポンスモデル定義
"""

from typing import Optional
from pydantic import BaseModel


# ──────────────────────────────────────────────
# ツールオプションモデル
# ──────────────────────────────────────────────

class NmapOptions(BaseModel):
    target: str
    scan_type: Optional[str] = "-sV"
    os_detection: bool = False
    timing: Optional[str] = "-T3"
    port_range: Optional[str] = None
    output_format: Optional[str] = None
    extra_flags: Optional[str] = None


class GobusterOptions(BaseModel):
    target: str
    mode: str = "dir"
    wordlist: str = "/usr/share/wordlists/dirb/common.txt"
    quiet: bool = False
    extra_flags: Optional[str] = None


class CurlOptions(BaseModel):
    target: str                             # リクエスト先の URL
    method: str = "GET"                     # HTTP メソッド（デフォルト: GET）
    header: Optional[str] = None           # 追加 HTTP ヘッダー（例: "Content-Type: application/json"）
    verbose: bool = False                  # -v: 詳細な HTTP 通信ログを出力するか
    follow_location: bool = False          # -L: リダイレクトを自動追跡するか（デフォルト: False）


class HydraOptions(BaseModel):
    target: str
    service: str = "ssh"
    user: str
    user_list: bool = False
    wordlist: str = "/usr/share/wordlists/passwords.txt"
    extra_flags: Optional[str] = None


class AircrackOptions(BaseModel):
    target_file: str
    wordlist: str = "/usr/share/wordlists/passwords.txt"
    bssid: Optional[str] = None
    extra_flags: Optional[str] = None


class Iperf3Options(BaseModel):
    target: str
    protocol: str = "tcp"
    time: int = 10
    bandwidth: Optional[str] = None


class MetasploitOptions(BaseModel):
    module: str
    rhosts: str
    rport: Optional[str] = None


# ──────────────────────────────────────────────
# API リクエスト / レスポンスモデル
# ──────────────────────────────────────────────

class ExecuteRequest(BaseModel):
    tool: str
    current_step: str = "Step 1"
    options: dict
    session_id: Optional[str] = None       # 省略時は None → 新規セッションを自動生成


class ExecuteResponse(BaseModel):
    command: str                            # 実行されたコマンド文字列
    stdout: str                             # コマンドの標準出力
    stderr: str                             # コマンドの標準エラー出力
    exit_code: int                          # コマンドの終了コード
    ai_explanation: Optional[str] = None   # AI チューターの解説テキスト
    session_id: Optional[str] = None       # 確定したセッション ID（新規生成 or 既存継続）
    ai_highlights: list[str] = []          # ターミナルハイライト用キーワードリスト
