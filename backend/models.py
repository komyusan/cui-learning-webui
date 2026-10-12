"""
models.py
CUI Learning WebUI — Pydantic リクエスト / レスポンスモデル定義
"""

from datetime import datetime
from typing import Literal, Optional
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


class WhoisOptions(BaseModel):
    target: str                             # 照会対象のドメイン / IP


class DigOptions(BaseModel):
    target: str                             # 照会対象のドメイン
    record_type: Literal["A", "MX", "TXT", "ANY"] = "A"  # レコード指定（許可リスト）
    short: bool = False                     # +short: 回答のみを短く出力するか


# ──────────────────────────────────────────────
# API リクエスト / レスポンスモデル
# ──────────────────────────────────────────────

class ExecuteRequest(BaseModel):
    tool: str
    current_step: str = "Step 1"
    options: dict
    session_id: Optional[str] = None       # 省略時は None → 新規セッションを自動生成
    condition: str = "with_ai"             # 実験条件: "with_ai"（GUI+AI解説）/ "without_ai"（ターミナルのみ）


class RawExecuteRequest(BaseModel):
    raw_command: str                        # ターミナル入力の生コマンド（例: "nmap -sV dummy-web"）
    current_step: str = "Step 1"


class ExecuteResponse(BaseModel):
    command: str                            # 実行されたコマンド文字列
    stdout: str                             # コマンドの標準出力
    stderr: str                             # コマンドの標準エラー出力
    exit_code: int                          # コマンドの終了コード
    ai_explanation: Optional[str] = None   # AI チューターの解説テキスト
    session_id: Optional[str] = None       # 確定したセッション ID（新規生成 or 既存継続）
    ai_highlights: list[str] = []          # ターミナルハイライト用キーワードリスト


class SessionStateResponse(BaseModel):
    session_id: str
    current_step: str
    created_at: datetime
    updated_at: datetime


class MaterialFileInfo(BaseModel):
    filename: str
    url: str
    size: int
    uploaded_at: datetime


class MaterialListResponse(BaseModel):
    materials: list[MaterialFileInfo]


class MaterialUploadResponse(BaseModel):
    material: MaterialFileInfo
