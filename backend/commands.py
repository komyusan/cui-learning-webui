"""
commands.py
CUI Learning WebUI — ツール別コマンド構築関数

各 build_* 関数はオプションモデルを受け取り、
Docker サンドボックスへ渡すコマンド引数リストを返す。
"""

import re

from models import (
    NmapOptions, GobusterOptions, CurlOptions,
    HydraOptions, AircrackOptions, Iperf3Options, MetasploitOptions,
    WhoisOptions, DigOptions,
)

ALLOWED_TOOLS = {"nmap", "gobuster", "curl", "hydra", "aircrack-ng", "iperf3", "metasploit", "whois", "dig"}


class OptionNotAllowedError(ValueError):
    """許可されていないオプションが指定されたときに送出する。"""


# ── オプション・ホワイトリスト ──
# raw_parser._TOOL_SPECS の deny_flags / value_flags と整合する範囲で、
# GUI（補助ありモード）から渡される値だけを許可する。
_NMAP_SCAN_FLAGS = {"-sV", "-sS", "-sT", "-sU", "-sn", "-sC", "-sA", "-sF", "-sN", "-sX", "-A", "-Pn", "-v"}
_NMAP_TIMING_FLAGS = {f"-T{n}" for n in range(6)}
_NMAP_OUTPUT_FLAGS = {"-oN", "-oX", "-oG"}
_NMAP_OUTPUT_VALUE_RE = re.compile(r"^[A-Za-z0-9_./-]+$")
_PORT_RANGE_RE = re.compile(r"^[0-9,\-]{1,64}$")
_GOBUSTER_MODES = {"dir", "dns", "vhost"}
_CURL_METHODS = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"}
_WORDLIST_RE = re.compile(r"^/usr/share/wordlists/[A-Za-z0-9_./-]+$")
_HEADER_RE = re.compile(r"^[A-Za-z0-9-]+:[^\r\n]*$")
_HYDRA_SERVICES = {"ssh", "ftp", "http-get", "http-post-form", "telnet", "mysql", "smtp"}
_IPERF_PROTOCOLS = {"tcp", "udp"}
_BANDWIDTH_RE = re.compile(r"^\d{1,6}[KMG]?$")
_BSSID_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


def _check_flags(flags: list[str], allowed: set[str], label: str) -> None:
    """flags の全要素が allowed に含まれることを検証する。"""
    for f in flags:
        if f not in allowed:
            raise OptionNotAllowedError(f"{label} '{f}' は許可されていません。")


def _check_match(value: str, pattern: re.Pattern, label: str) -> None:
    if not pattern.match(value):
        raise OptionNotAllowedError(f"{label} '{value}' の形式が許可されていません。")


def build_nmap_command(opts: NmapOptions) -> list[str]:
    cmd: list[str] = []
    if opts.scan_type:
        flags = opts.scan_type.split()
        _check_flags(flags, _NMAP_SCAN_FLAGS, "nmap スキャンタイプ")
        cmd.extend(flags)
    if opts.os_detection:
        cmd.append("-O")
    if opts.timing:
        flags = opts.timing.split()
        _check_flags(flags, _NMAP_TIMING_FLAGS, "nmap タイミング")
        cmd.extend(flags)
    if opts.port_range:
        _check_match(opts.port_range, _PORT_RANGE_RE, "ポート範囲")
        cmd.extend(["-p", opts.port_range])
    if opts.output_format:
        parts = opts.output_format.split()
        if len(parts) != 2:
            raise OptionNotAllowedError("nmap 出力形式は '<フラグ> <ファイル>' の形式で指定してください。")
        _check_flags(parts[:1], _NMAP_OUTPUT_FLAGS, "nmap 出力形式")
        _check_match(parts[1], _NMAP_OUTPUT_VALUE_RE, "出力先")
        cmd.extend(parts)
    cmd.append(opts.target)
    return cmd


def build_gobuster_command(opts: GobusterOptions) -> list[str]:
    _check_flags([opts.mode], _GOBUSTER_MODES, "gobuster モード")
    _check_match(opts.wordlist, _WORDLIST_RE, "ワードリスト")
    cmd = [opts.mode, "-u", opts.target, "-w", opts.wordlist]
    if opts.quiet:
        cmd.append("-q")
    return cmd


def build_curl_command(opts: CurlOptions) -> list[str]:
    cmd: list[str] = []
    if opts.method:
        _check_flags([opts.method.upper()], _CURL_METHODS, "HTTP メソッド")
    if opts.method and opts.method.upper() != "GET":
        cmd.extend(["-X", opts.method.upper()])
    if opts.header:
        _check_match(opts.header, _HEADER_RE, "HTTP ヘッダー")
        cmd.extend(["-H", opts.header])
    if opts.verbose:
        cmd.append("-v")
    if opts.follow_location:
        cmd.append("-L")
    cmd.append(opts.target)
    return cmd


def build_hydra_command(opts: HydraOptions) -> list[str]:
    _check_flags([opts.service], _HYDRA_SERVICES, "hydra サービス")
    _check_match(opts.wordlist, _WORDLIST_RE, "ワードリスト")
    user_flag = "-L" if opts.user_list else "-l"
    return [user_flag, opts.user, "-P", opts.wordlist, opts.target, opts.service]


def build_aircrack_command(opts: AircrackOptions) -> list[str]:
    _check_match(opts.wordlist, _WORDLIST_RE, "ワードリスト")
    cmd = ["-w", opts.wordlist]
    if opts.bssid:
        _check_match(opts.bssid, _BSSID_RE, "BSSID")
        cmd.extend(["-b", opts.bssid])
    cmd.append(opts.target_file)
    return cmd


def build_iperf_command(opts: Iperf3Options) -> list[str]:
    _check_flags([opts.protocol.lower()], _IPERF_PROTOCOLS, "iperf3 プロトコル")
    cmd = ["-c", opts.target]
    if opts.protocol.lower() == "udp":
        cmd.append("-u")
    cmd.extend(["-t", str(opts.time)])
    if opts.bandwidth:
        _check_match(opts.bandwidth, _BANDWIDTH_RE, "帯域幅")
        cmd.extend(["-b", opts.bandwidth])
    return cmd


def build_metasploit_command(opts: MetasploitOptions) -> list[str]:
    script = f"use {opts.module}; set RHOSTS {opts.rhosts}; "
    if opts.rport:
        script += f"set RPORT {opts.rport}; "
    script += "run; exit"
    return ["-q", "-x", script]


def build_whois_command(opts: WhoisOptions) -> list[str]:
    # whois <target>（追加オプションなし）
    return ["whois", opts.target]


def build_dig_command(opts: DigOptions) -> list[str]:
    # dig <target> <record_type> [+short]（クエリ → 型 → +オプションの順）
    cmd = ["dig", opts.target, opts.record_type]
    if opts.short:
        cmd.append("+short")
    return cmd
