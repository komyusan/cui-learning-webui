"""
ai_service.py
CUI Learning WebUI — AI チューターサービス

OpenAI API (gpt-4o-mini) を使用して、PTES に沿ったレッスン主導型の
AI 解説を生成します。
環境変数 OPENAI_API_KEY は docker-compose 側で注入されるため、
このモジュール内での dotenv 読み込みは不要です。

【IPv6 ブラックホール対策】
Docker for Mac の仮想ネットワーク層では getaddrinfo が IPv6 アドレスを先頭に返すため、
TCP タイムアウト（75 秒）が発生する。以下の 2 つの対策を組み合わせて回避する。

  主対策 (entrypoint.sh):
    /etc/resolv.conf に "options no-aaaa" を追記し、
    glibc レベルで AAAA クエリを遮断する。

  副対策 (このモジュール):
    socket.getaddrinfo を AF_INET 強制にパッチし、
    Python レベルで IPv4 アドレスのみを返すようにする。
"""

import json
import logging
import socket
import ssl as _ssl
import threading as _threading
import time as _time

import httpx
from openai import OpenAI, APITimeoutError, AuthenticationError, APIConnectionError

from models import ExecuteRequest

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────
# 副対策: socket.getaddrinfo を AF_INET 強制にパッチ
# ──────────────────────────────────────────────

_orig_getaddrinfo = socket.getaddrinfo


def _ipv4_only_getaddrinfo(host, port=0, family=0, type=0, proto=0, flags=0):
    """
    AF_INET アドレスのみを返す getaddrinfo ラッパー。

    AF_INET6 が明示された場合はそのまま通し、
    AF_UNSPEC (0) および AF_INET の場合は AF_INET を強制する。
    これにより IPv4-mapped-IPv6 (::ffff:x.x.x.x) の生成と AAAA クエリを防ぐ。
    """
    if family == socket.AF_INET6:
        return _orig_getaddrinfo(host, port, family, type, proto, flags)

    try:
        results = _orig_getaddrinfo(host, port, socket.AF_INET, type, proto, 0)
        if results:
            logger.info(
                "[getaddrinfo] %s:%s → %s (AF_INET 強制)",
                host, port, [r[4][0] for r in results],
            )
            return results
    except socket.gaierror:
        pass

    logger.warning("[getaddrinfo] %s:%s: AF_INET 解決失敗 → オリジナルでフォールバック", host, port)
    return _orig_getaddrinfo(host, port, family, type, proto, flags)


socket.getaddrinfo = _ipv4_only_getaddrinfo


# ──────────────────────────────────────────────
# Keep-warm スレッド: ネットワークコールドスタート対策
# ──────────────────────────────────────────────
# Docker Desktop の仮想ネットワーク層は一定時間通信がないとコールド状態になり、
# 最初の TCP 接続に最大 15 秒かかる。
# 12 秒間隔で api.openai.com へ TCP 接続することでウォーム状態を維持する。

_WARMUP_HOST = "api.openai.com"
_WARMUP_PORT = 443
_WARMUP_INTERVAL = 12  # NAT タイムアウト (15 秒) より短い間隔


def _keep_network_warm() -> None:
    """api.openai.com:443 への TCP 接続を定期的に行い、ネットワークをウォームに保つ。"""
    _time.sleep(3)  # uvicorn の起動を待つ

    while True:
        start = _time.time()
        try:
            sock = socket.create_connection((_WARMUP_HOST, _WARMUP_PORT), timeout=20)
            elapsed = _time.time() - start
            sock.close()
            logger.info("[keep-warm] %s:%d TCP 接続成功 (%.2fs)", _WARMUP_HOST, _WARMUP_PORT, elapsed)
        except Exception as exc:
            elapsed = _time.time() - start
            logger.warning("[keep-warm] %s:%d TCP 接続失敗 (%.2fs): %s", _WARMUP_HOST, _WARMUP_PORT, elapsed, exc)

        _time.sleep(_WARMUP_INTERVAL)


_threading.Thread(target=_keep_network_warm, daemon=True, name="openai-keep-warm").start()


# ──────────────────────────────────────────────
# OpenAI クライアント (シングルトン)
# ──────────────────────────────────────────────
# モジュールレベルのシングルトンを再利用することで
# httpx のコネクションプールが維持され、リクエストが高速化される。

_openai_client_instance: OpenAI | None = None
_openai_client_lock = _threading.Lock()


def _get_openai_client() -> OpenAI:
    """OpenAI クライアントのシングルトンインスタンスを返す（スレッドセーフ）。"""
    global _openai_client_instance
    if _openai_client_instance is None:
        with _openai_client_lock:
            if _openai_client_instance is None:
                _openai_client_instance = _build_openai_client()
                logger.info("[OpenAI] シングルトンクライアントを初期化しました")
    return _openai_client_instance


def _build_openai_client() -> OpenAI:
    """httpx タイムアウト・コネクション上限を設定した OpenAI クライアントを生成する。"""
    http_client = httpx.Client(
        timeout=httpx.Timeout(
            connect=60.0,   # keep-warm 失敗後のコールドスタートをもカバー
            read=60.0,      # GPT-4o-mini のレスポンス生成待ち
            write=15.0,     # リクエスト送信
            pool=10.0,      # コネクションプール取得待ち
        ),
        limits=httpx.Limits(
            max_connections=5,
            max_keepalive_connections=3,
            keepalive_expiry=60,  # keep-warm の間隔内で接続を維持
        ),
    )
    return OpenAI(http_client=http_client, max_retries=0)


# ──────────────────────────────────────────────
# コンテキスト生成
# ──────────────────────────────────────────────

_MAX_OUTPUT_LENGTH = 1000  # stdout / stderr のトークン超過防止用の最大文字数


def _truncate_output(text: str, max_length: int = _MAX_OUTPUT_LENGTH) -> str:
    """出力テキストが max_length 文字を超える場合、末尾を切り詰めて省略文言を付加する。"""
    if len(text) <= max_length:
        return text
    return text[:max_length] + "\n...(出力が長いため以下省略)..."


def build_llm_context(
    req: ExecuteRequest,
    command_list: list[str],
    exit_code: int,
    stdout: str = "",
    stderr: str = "",
    time_since_last_cmd: float = 0.0,
    is_help_request: bool = False,
) -> str:
    """
    実行結果から LLM へ渡すコンテキスト JSON 文字列を生成する。

    Parameters
    ----------
    req                 : フロントエンドからのリクエスト
    command_list        : 実行されたコマンドのトークンリスト
    exit_code           : コマンドの終了コード
    stdout              : コマンドの標準出力テキスト
    stderr              : コマンドの標準エラー出力テキスト
    time_since_last_cmd : 前回コマンドからの経過秒数
    is_help_request     : ヘルプフラグを含むか

    Returns
    -------
    JSON 文字列
    """
    user_options = [opt for opt in command_list if opt.startswith("-")]

    context = {
        "current_step": req.current_step,
        "user_selected_options": user_options,
        "execution_result": "success" if exit_code == 0 else "failed",
        "exit_code": exit_code,
        "stdout": _truncate_output(stdout),
        "stderr": _truncate_output(stderr),
        "time_since_last_cmd": time_since_last_cmd,
        "is_help_request": is_help_request,
    }
    return json.dumps(context, ensure_ascii=False)


# ──────────────────────────────────────────────
# システムプロンプト生成
# ──────────────────────────────────────────────

_STUCK_THRESHOLD_SEC = 60.0  # Stuck State 判定の閾値（秒）

# 通常モード・緊急サポートモード共通の JSON 出力フォーマット指示
_JSON_FORMAT_INSTRUCTION = """
【出力フォーマット（厳守）】
必ず以下の JSON 形式のみで応答してください。それ以外の形式は禁止です。
JSON以外のテキスト（前置きや後書き）は一切含めないでください。

{
  "message": "学生へのフィードバックテキスト（絵文字を含む、最大4行）",
  "highlights": ["ターミナル出力内でハイライトすべきキーワード1", "キーワード2"]
}

- "message": 上記の指示に従ったフィードバックを日本語で記述してください。
- "highlights": 学生に最も注目させたい語句を、stdout または stderr からそのまま抜き出した\
文字列で1〜2個だけリストしてください。注目させる情報がない場合は空リスト [] にしてください。"""


def _build_context_block(
    current_step: str,
    options_str: str,
    execution_result: str,
    exit_code: int,
    stdout: str,
    stderr: str,
) -> str:
    """学習コンテキスト情報のブロック文字列を生成する（通常・緊急共通部分）。"""
    return (
        f"現在の学習ステップ: {current_step}\n"
        f"ユーザーが選択したオプション: {options_str}\n"
        f"実行結果: {execution_result}（終了コード: {exit_code}）\n"
        f"\n--- 実行された標準出力（stdout）---\n"
        f"{stdout if stdout else '（出力なし）'}\n"
        f"\n--- 実行された標準エラー出力（stderr）---\n"
        f"{stderr if stderr else '（エラーなし）'}"
    )


def build_system_prompt(
    current_step: str,
    user_selected_options: list[str],
    execution_result: str,
    exit_code: int = 0,
    stdout: str = "",
    stderr: str = "",
    time_since_last_cmd: float = 0.0,
    is_help_request: bool = False,
    extra_materials: str | None = None,
) -> str:
    """
    AI チューター用のシステムプロンプトを組み立てる。

    Stuck State（前回から 60 秒以上経過 or ヘルプ要求）の場合は
    「正解を教えるな」という禁止命令を含まない緊急サポートモード用プロンプトを生成する。
    通常時は足場かけ（Scaffolding）に基づくプロンプトを生成する。

    2 種類のプロンプトを完全に分岐させることで、同一プロンプト内に矛盾した命令が
    共存する状態（Instruction Conflict）を排除している。
    """
    options_str = ", ".join(user_selected_options) if user_selected_options else "（なし）"
    is_stuck = time_since_last_cmd >= _STUCK_THRESHOLD_SEC or is_help_request

    logger.info(
        "Stuck State: %s (Time: %.1f s, Help: %s)",
        is_stuck, time_since_last_cmd, is_help_request,
    )

    context_block = _build_context_block(
        current_step, options_str, execution_result, exit_code, stdout, stderr,
    )

    if is_stuck:
        stuck_reason = (
            f"前回の操作から {time_since_last_cmd:.0f} 秒以上経過"
            if time_since_last_cmd >= _STUCK_THRESHOLD_SEC
            else "ヘルプコマンドを実行"
        )
        prompt = f"""あなたは、セキュリティとコマンドを教える AI チューターです。
現在、学生は「{stuck_reason}」したため行き詰まっています。

{context_block}

【🚨 緊急サポートモード — 以下の指示のみに従ってください】

学生は今、詰まっています。通常の「ヒントだけ出す」制約はありません。
次のことを行ってください：

1. stdout/stderr の内容から、今の状況（どのサービスが動いているか等）を1〜2文で簡単に説明する。
2. 次に学生が実行すべき**完全なコマンドを1つ**、コードブロックなしで提示する。
   例: `nmap -sV -p 3306 metasploitable` のように具体的に書く。
3. そのコマンドが「なぜ必要か」を1文で添える。
4. 励ますひと言と絵文字で締める。

回答は4行以内に収めること。"""

    else:
        prompt = f"""あなたは、セキュリティとそれに関するコマンドを教える「レッスン主導型」の優秀なAIチューターです。
学生の自由な質問に直接答えるのではなく、あらかじめ定められたレッスンプラン（PTES）に従って、セキュリティ初学者を順序よく導いてください。

{context_block}

【認知的負荷を下げるための教育ルール（必ず厳守してください）】

ルール1【情報の絞り込み】:
  実行結果（stdoutまたはstderr）に複数のポート、バージョン、サービス情報が含まれている場合、
  それらをすべて解説してはいけません。
  最も重要または脆弱性が疑われる「1つの要素（特定のポート番号やバージョン番号など）」だけを
  選び、そこにのみ言及してください。その他の情報には触れないでください。

ルール2【足場かけ（Scaffolding）】:
  次に打つべき具体的なコマンドや正解を直接教えてはいけません。
  必ず「このバージョンについて調べてみませんか？」や
  「このポートは何のサービスに使われているか知っていますか？」といった、
  学生自身が考えるきっかけとなる問いかけやヒントでフィードバックを終えてください。

ルール3【結果の分析】:
  終了コードが0（成功）であっても、出力内容から有益な情報が得られなかったと判断できる場合
  （例: スキャン対象のポートがすべて閉じている、応答がない等）は、
  単に「うまくいきました」と褒めるのではなく、
  ターゲットの変更やオプションの追加・変更を具体的に示唆してください。

【その他のルール】
4. 情報を小出しにする: 今実行したオプションだけにフォーカスして簡潔に解説してください。
5. 出力の冗長性を防ぐ: 回答には必ず1〜2個の絵文字を使用し、最大4行以内に収めてください。"""

    if extra_materials:
        prompt += f"\n\n【参考資料】\n{extra_materials}"

    prompt += _JSON_FORMAT_INSTRUCTION
    return prompt


# ──────────────────────────────────────────────
# AI レスポンス生成（メインエントリ）
# ──────────────────────────────────────────────

def generate_ai_response(
    llm_context_json: str,
    tool: str,
    time_since_last_cmd: float = 0.0,
    is_help_request: bool = False,
    extra_materials: str | None = None,
) -> dict:
    """
    OpenAI API を呼び出してレッスン主導型の AI 解説を生成する。

    Parameters
    ----------
    llm_context_json    : build_llm_context() が返す JSON 文字列
    tool                : 使用されたツール名
    time_since_last_cmd : 前回コマンドからの経過秒数
    is_help_request     : ヘルプフラグを含むか
    extra_materials     : 外部講義資料テキスト（任意）

    Returns
    -------
    dict : {"message": str, "highlights": list[str]}
    """
    try:
        context = json.loads(llm_context_json)
        current_step       = context.get("current_step", "不明なステップ")
        user_selected_opts = context.get("user_selected_options", [])
        execution_result   = context.get("execution_result", "不明")
        exit_code          = context.get("exit_code", 0)
        stdout             = context.get("stdout", "")
        stderr             = context.get("stderr", "")

        system_prompt = build_system_prompt(
            current_step=current_step,
            user_selected_options=user_selected_opts,
            execution_result=execution_result,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            time_since_last_cmd=time_since_last_cmd,
            is_help_request=is_help_request,
            extra_materials=extra_materials,
        )

        user_message = (
            f"ツール「{tool}」を使って上記のコマンドを実行しました。\n"
            f"実行結果は「{execution_result}」です。\n"
            f"標準出力: {'(出力あり)' if stdout else '(なし)'}\n"
            f"標準エラー: {'(出力あり)' if stderr else '(なし)'}\n"
            f"学習の指針に従い、簡潔にフィードバックをしてください。"
        )

        logger.info(
            "Calling OpenAI API: step=%s, tool=%s, result=%s",
            current_step, tool, execution_result,
        )

        client = _get_openai_client()
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": user_message},
            ],
            response_format={"type": "json_object"},
            max_tokens=200,
            temperature=0.7,
        )

        ai_text = response.choices[0].message.content.strip()
        logger.info("OpenAI response received: %s...", ai_text[:80])

        try:
            return json.loads(ai_text)
        except json.JSONDecodeError:
            return {"message": ai_text, "highlights": []}

    except APITimeoutError as e:
        logger.error("[OpenAI] タイムアウト: %s", e)
        return {"message": "⏱️ AI チューターへの接続がタイムアウトしました。ネットワーク設定を確認してください。", "highlights": []}
    except AuthenticationError as e:
        logger.error("[OpenAI] 認証エラー: %s", e)
        return {"message": "🔑 APIキーが無効です。環境変数 OPENAI_API_KEY を確認してください。", "highlights": []}
    except APIConnectionError as e:
        logger.error("[OpenAI] 接続エラー: %s", e)
        return {"message": "🌐 AI チューターへの接続に失敗しました。コンテナのネットワーク設定を確認してください。", "highlights": []}
    except Exception as e:
        logger.error("[OpenAI] 予期せぬエラー: %s", e)
        return {"message": "❌ AI チューターの処理中にエラーが発生しました。", "highlights": []}
