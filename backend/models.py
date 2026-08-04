from pydantic import BaseModel
from typing import Optional

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
    header: Optional[str] = None           # 追加する HTTP ヘッダー（例: "Content-Type: application/json"）
    verbose: bool = False                  # -v フラグ: 詳細なHTTP通信ログを出力するか
    # ▼▼▼変更箇所▼▼▼ -L (--location) オプションを追加
    # curl はデフォルトでリダイレクト（301/302 等）を自動追跡しない。
    # このフラグを True にすると -L オプションが付加され、リダイレクト先を自動的に追跡する。
    # DVWA のようにルート(/)→ログインページへリダイレクトするサイトの HTML 取得に必要。
    follow_location: bool = False          # -L フラグ: リダイレクトを自動追跡するか（デフォルト: False）
    # ▲▲▲変更箇所ここまで▲▲▲

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

class ExecuteRequest(BaseModel):
    tool: str
    current_step: str = "Step 1"
    options: dict
    # ▼▼▼変更箇所▼▼▼ フロントエンドから既存セッションを引き継ぐための session_id（省略時は None → 新規セッションを自動生成）
    session_id: Optional[str] = None

class ExecuteResponse(BaseModel):
    command: str        # 実行されたコマンド文字列
    stdout: str         # コマンドの標準出力
    stderr: str         # コマンドの標準エラー出力
    exit_code: int      # コマンドの終了コード
    ai_explanation: Optional[str] = None  # AI チューターの解説テキスト
    # ▼▼▼変更箇所▼▼▼ レスポンスに session_id を追加（フロントエンドが localStorage に保存して次回リクエストに使う）
    session_id: Optional[str] = None    # 確定したセッション ID（新規生成 or 既存継続）
    # ▼▼▼変更箇所▼▼▼ ハイライト用キーワードリストを追加
    # AI がターミナル出力の中で特に注目させたいキーワード（例: "vsftpd 2.3.4", "21/tcp"）を格納する。
    # フロントエンドはこのリストを使い、ターミナル出力内の該当文字列を <span> でハイライトする。
    # デフォルトは空リスト（ハイライトなし）。
    ai_highlights: list[str] = []      # ターミナルハイライト用キーワードリスト
