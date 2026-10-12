"""
raw_parser.py
ターミナル入力（補助なしモード）の生コマンド文字列を、安全に検証・分解するモジュール。

【方針】
  - 文字列をシェルに渡さない。shlex で分割した argv リストだけを Docker に渡す。
  - ツール名は ALLOWED_TOOLS で検証する。
  - ターゲット（ホスト/URL）を抽出して呼び出し側のホワイトリストで検証できるようにする。
  - 解釈できない値付きフラグは「位置引数」として扱われ、ホワイトリスト検証で弾かれる（fail-closed）。
"""

import re
import shlex
from dataclasses import dataclass, field

from commands import ALLOWED_TOOLS


class RawCommandError(ValueError):
    """生コマンドが不正・未対応のときに送出する。"""


@dataclass
class ParsedRawCommand:
    tool: str
    args: list[str]
    targets: list[str] = field(default_factory=list)     # is_safe_target で検証すべき対象
    needs_target: bool = True                            # ターゲットが 1 つ以上必須か
    metasploit: dict | None = None                       # metasploit 用 {"module", "rhosts", "rport"}


# ツールごとの解析設定
#   value_flags : 次のトークンが「値」（ターゲットではない）のフラグ
#   target_flags: 次のトークンが「ターゲット」のフラグ
#   deny_flags  : 使用を禁止するフラグ（ホワイトリスト回避や外部通信に使われうるもの）
_TOOL_SPECS: dict[str, dict] = {
    "nmap": {
        "value_flags": {"-p", "-oN", "-oX", "-oG", "-oA", "--script", "--top-ports",
                        "--max-rate", "--min-rate", "--host-timeout"},
        "target_flags": set(),
        "deny_flags": {"-iL", "-D", "-S", "-e", "-sI", "--proxies", "--resume"},
    },
    "gobuster": {
        "value_flags": {"-w", "-t", "-x", "-s", "-a", "-c", "-o", "-H", "--wordlist",
                        "--threads", "--output"},
        "target_flags": {"-u", "--url"},
        "deny_flags": {"--proxy"},
    },
    "curl": {
        "value_flags": {"-X", "-H", "-d", "-o", "-A", "-u", "-m", "-b", "-c", "-w",
                        "--request", "--header", "--data", "--output", "--max-time",
                        "--user-agent", "--user"},
        "target_flags": {"--url"},
        "deny_flags": {"-x", "--proxy", "--resolve", "--connect-to", "-K", "--config",
                       "-T", "--upload-file", "--socks5", "--socks4"},
    },
    "hydra": {
        "value_flags": {"-l", "-L", "-p", "-P", "-s", "-t", "-T", "-m", "-o", "-C",
                        "-w", "-W", "-e", "-M"},
        "target_flags": set(),
        "deny_flags": {"-M"},
    },
    "iperf3": {
        "value_flags": {"-t", "-b", "-p", "-P", "-l", "-i", "-O", "-n", "-k", "-w",
                        "-M", "-S", "--bitrate", "--time"},
        "target_flags": {"-c", "--client"},
        "deny_flags": set(),
    },
    "aircrack-ng": {
        "value_flags": {"-w", "-b", "-e"},
        "target_flags": set(),
        "deny_flags": set(),
    },
    "whois": {"value_flags": set(), "target_flags": set(), "deny_flags": set()},
    "dig": {"value_flags": set(), "target_flags": set(), "deny_flags": set()},
}

_GOBUSTER_MODES = {"dir", "dns", "vhost", "fuzz", "s3", "gcs", "tftp"}
_SERVICE_RE = re.compile(r"^[a-z0-9-]+$")
_MODULE_RE = re.compile(r"^[A-Za-z0-9_/.-]+$")
_PORT_RE = re.compile(r"^\d{1,5}$")


def parse_raw_command(raw_command: str) -> ParsedRawCommand:
    """生コマンド文字列を検証・分解する。不正なら RawCommandError を送出する。"""
    if not isinstance(raw_command, str) or not raw_command.strip():
        raise RawCommandError("コマンドを入力してください。")
    if len(raw_command) > 1000:
        raise RawCommandError("コマンドが長すぎます。")

    try:
        tokens = shlex.split(raw_command)
    except ValueError:
        raise RawCommandError("引用符が閉じられていません。")

    if not tokens:
        raise RawCommandError("コマンドを入力してください。")

    tool, args = tokens[0], tokens[1:]
    if tool not in ALLOWED_TOOLS:
        raise RawCommandError(
            f"ツール '{tool}' はサポートされていません。対応ツール: {sorted(ALLOWED_TOOLS)}"
        )

    if tool == "metasploit":
        return _parse_metasploit(args)

    spec = _TOOL_SPECS[tool]
    targets: list[str] = []
    positionals: list[str] = []

    i = 0
    while i < len(args):
        tok = args[i]
        if tok.startswith("-") and len(tok) > 1:
            flag = tok.split("=", 1)[0]
            if flag in spec["deny_flags"]:
                raise RawCommandError(f"フラグ '{flag}' は使用できません。")
            if "://" in tok:
                # --url=http://... のように値が埋め込まれた形はここで検証対象にする
                targets.append(tok.split("=", 1)[1] if "=" in tok else tok)
            elif flag in spec["target_flags"] and "=" not in tok:
                if i + 1 >= len(args):
                    raise RawCommandError(f"フラグ '{flag}' に値がありません。")
                targets.append(args[i + 1])
                i += 1
            elif flag in spec["value_flags"] and "=" not in tok:
                i += 1  # 次のトークン（値）を読み飛ばす
        else:
            positionals.append(tok)
        i += 1

    if tool == "gobuster":
        # 先頭の位置引数はモード（dir 等）
        if not positionals or positionals[0] not in _GOBUSTER_MODES:
            raise RawCommandError(f"gobuster のモードを指定してください: {sorted(_GOBUSTER_MODES)}")
        positionals = positionals[1:]
        targets.extend(positionals)
    elif tool == "hydra":
        # 位置引数は <host> <service>、または <service>://<host>
        if len(positionals) == 1 and "://" in positionals[0]:
            targets.append(positionals[0])
        elif len(positionals) == 2 and _SERVICE_RE.match(positionals[1]):
            targets.append(positionals[0])
        else:
            raise RawCommandError("hydra は '<ホスト> <サービス>' の形式で指定してください。")
    elif tool in ("whois", "dig"):
        # 任意のドメイン/IP を許可（既存 API と同様）。ホワイトリスト検証は行わない。
        if not positionals and not any(not a.startswith("-") for a in args):
            raise RawCommandError("照会対象のドメイン/IP を指定してください。")
        return ParsedRawCommand(tool=tool, args=args, targets=[], needs_target=False)
    elif tool == "aircrack-ng":
        return ParsedRawCommand(tool=tool, args=args, targets=[], needs_target=False)
    else:
        # nmap / curl / iperf3 の位置引数は全てターゲットとして検証する
        targets.extend(positionals)

    if not targets:
        raise RawCommandError("ターゲットを指定してください。")

    return ParsedRawCommand(tool=tool, args=args, targets=targets)


def _parse_metasploit(args: list[str]) -> ParsedRawCommand:
    """metasploit <module> <rhosts> [rport] の形式のみ受け付ける。"""
    if len(args) not in (2, 3):
        raise RawCommandError("metasploit は '<モジュール> <RHOSTS> [RPORT]' の形式で指定してください。")
    module, rhosts = args[0], args[1]
    rport = args[2] if len(args) == 3 else None

    if not _MODULE_RE.match(module):
        raise RawCommandError("モジュール名の形式が正しくありません。")
    if rport is not None and not _PORT_RE.match(rport):
        raise RawCommandError("RPORT は数値で指定してください。")
    if re.search(r"[;\s]", rhosts):
        raise RawCommandError("RHOSTS の形式が正しくありません。")

    return ParsedRawCommand(
        tool="metasploit",
        args=args,
        targets=[rhosts],
        metasploit={"module": module, "rhosts": rhosts, "rport": rport},
    )
