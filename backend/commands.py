from models import (
    NmapOptions, GobusterOptions, CurlOptions,
    HydraOptions, AircrackOptions, Iperf3Options, MetasploitOptions
)

ALLOWED_TOOLS = {"nmap", "gobuster", "curl", "hydra", "aircrack-ng", "iperf3", "metasploit"}

def build_nmap_command(opts: NmapOptions) -> list[str]:
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
    cmd.append(opts.target)
    return cmd

def build_gobuster_command(opts: GobusterOptions) -> list[str]:
    cmd = [opts.mode]
    cmd.extend(["-u", opts.target])
    cmd.extend(["-w", opts.wordlist])
    if opts.quiet:
        cmd.append("-q")
    return cmd

def build_curl_command(opts: CurlOptions) -> list[str]:
    cmd = []                                        # コマンド引数を格納するリスト
    if opts.method and opts.method.upper() != "GET":
        cmd.extend(["-X", opts.method.upper()])     # GET 以外のメソッドは -X で明示指定
    if opts.header:
        cmd.extend(["-H", opts.header])             # 追加ヘッダーがあれば -H オプションで付加
    if opts.verbose:
        cmd.append("-v")                            # verbose フラグが True なら -v を追加
    # ▼▼▼変更箇所▼▼▼ -L (--location) フラグの追加
    # curl はデフォルトでリダイレクトレスポンス（301/302/307 等）を追跡しない。
    # follow_location=True のとき "-L" を追加することで、
    # Location ヘッダーで示されたリダイレクト先を自動的に再リクエストする。
    if opts.follow_location:
        cmd.append("-L")                            # リダイレクトを自動追跡する -L フラグを追加
    # ▲▲▲変更箇所ここまで▲▲▲
    cmd.append(opts.target)                         # ターゲット URL はコマンドの末尾に配置（curl の引数仕様）
    return cmd                                      # 完成したコマンド引数リストを返す

def build_hydra_command(opts: HydraOptions) -> list[str]:
    cmd = []
    if opts.user_list:
        cmd.extend(["-L", opts.user])
    else:
        cmd.extend(["-l", opts.user])
    cmd.extend(["-P", opts.wordlist])
    cmd.extend([opts.target, opts.service])
    return cmd

def build_aircrack_command(opts: AircrackOptions) -> list[str]:
    cmd = []
    cmd.extend(["-w", opts.wordlist])
    if opts.bssid:
        cmd.extend(["-b", opts.bssid])
    cmd.append(opts.target_file)
    return cmd

def build_iperf_command(opts: Iperf3Options) -> list[str]:
    cmd = ["-c", opts.target]
    if opts.protocol.lower() == "udp":
        cmd.append("-u")
    cmd.extend(["-t", str(opts.time)])
    if opts.bandwidth:
        cmd.extend(["-b", opts.bandwidth])
    return cmd

def build_metasploit_command(opts: MetasploitOptions) -> list[str]:
    script = f"use {opts.module}; set RHOSTS {opts.rhosts}; "
    if opts.rport:
        script += f"set RPORT {opts.rport}; "
    script += "run; exit"
    return ["-q", "-x", script]
