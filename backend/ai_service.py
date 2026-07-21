"""
ai_service.py
CUI Learning WebUI — AI チューターサービス

OpenAI API (gpt-4o-mini) を使用して、PTES に沿ったレッスン主導型の
AI 解説を生成します。
環境変数 OPENAI_API_KEY は docker-compose 側で注入されるため、
このモジュール内での dotenv 読み込みは不要です。

【IPv6 ブラックホール対策 — 根本原因と解決策】

■ 根本原因:
  socket.create_connection(host, port) は内部で getaddrinfo(host, AF_UNSPEC) を呼ぶ。
  AF_UNSPEC の場合:
  - hostname → AAAA + A 両方を返す (IPv6 が先頭になりやすい)
  - IP 文字列 → ::ffff:x.x.x.x (IPv4-mapped-IPv6) + IPv4 を返すことがある
  → どちらも IPv6 アドレスが先頭に来て AF_INET6 ソケットで接続試行される
  → Docker for Mac の IPv6 ブラックホールにハマり OS TCP タイムアウト (75 秒) を待つ

■ 主対策 (entrypoint.sh):
  /etc/resolv.conf の options 行に "no-aaaa" を追記する。
  → C ライブラリ (glibc) レベルで AAAA クエリを遮断。
  → OpenSSL が内部で行う証明書関連の接続も IPv4 になる。

■ 副対策 (このモジュール):
  socket.getaddrinfo を AF_INET 強制にパッチする (Python レベル)。
  - hostname → A クエリのみ → IPv4 のみ
  - IP 文字列 → IPv4 のみ (IPv4-mapped-IPv6 は生成されない)
  ※ create_connection でホスト名を IP に差し替える方式は逆効果だったため廃止。
    (IP を渡すと AF_UNSPEC で再度 IPv4-mapped-IPv6 が生成されてしまう)
"""

import json
import logging
import socket
import httpx
from openai import OpenAI, APITimeoutError, AuthenticationError, APIConnectionError
from models import ExecuteRequest

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────
# 副対策: socket.getaddrinfo を AF_INET 強制にパッチ
# ──────────────────────────────────────────────
# 問題: getaddrinfo(host, port, AF_UNSPEC) は以下を返す:
#   - hostname → [AAAA アドレス, A アドレス, ...] → IPv6 が先頭 → ブラックホール
#   - IP 文字列 → [::ffff:x.x.x.x (AF_INET6), x.x.x.x (AF_INET)] → IPv4-mapped-IPv6 が先頭
# どちらも IPv6 ソケットで接続試行 → Docker for Mac の TCP タイムアウト (75 秒)
#
# 解決: AF_INET を明示的に指定することで:
#   - ホスト名 → A クエリのみ、IPv4 アドレスのみ返す
#   - IP 文字列 → ::ffff:x.x.x.x は生成されない、IPv4 のみ返す
_orig_getaddrinfo = socket.getaddrinfo

def _ipv4_only_getaddrinfo(host, port=0, family=0, type=0, proto=0, flags=0):
    """
    socket.getaddrinfo のラッパー。AF_INET アドレスのみを返す。

    AF_UNSPEC (0) または AF_INET で呼ばれた場合、AF_INET を強制することで
    IPv4-mapped-IPv6 (::ffff:x.x.x.x) の生成と AAAA クエリを防ぐ。
    AF_INET6 が明示された場合はそのまま通す（他サービスへの影響を最小化）。
    """
    if family == socket.AF_INET6:
        # AF_INET6 が明示的に指定された場合はそのまま通す
        return _orig_getaddrinfo(host, port, family, type, proto, flags)

    # AF_INET または AF_UNSPEC: AF_INET を強制し、flags=0 で AI_V4MAPPED 等を無効化
    try:
        results = _orig_getaddrinfo(host, port, socket.AF_INET, type, proto, 0)
        if results:
            logger.info(
                "[getaddrinfo] %s:%s → %s (AF_INET 強制)",
                host, port, [r[4][0] for r in results]
            )
            return results
    except socket.gaierror:
        pass  # AF_INET で解決できない場合はフォールバック

    logger.warning("[getaddrinfo] %s:%s: AF_INET 解決失敗 → オリジナルでフォールバック", host, port)
    return _orig_getaddrinfo(host, port, family, type, proto, flags)

socket.getaddrinfo = _ipv4_only_getaddrinfo
logger.info("[getaddrinfo] socket.getaddrinfo パッチ適用完了 (AF_INET 強制)")


# ──────────────────────────────────────────────
# Keep-warm スレッド： Docker Desktop ネットワークのコールドスタート対策
# ──────────────────────────────────────────────
# 問題: Docker Desktop for Mac の仮想ネットワーク層 (vpnkit/slirp) は、
#   一定時間通信がないと「コールド」状態になる。
#   コールド状態からの最初の TCP 接続は OS レベルで最大 15 秒かかる。
#   2 つの IP を試みると合計 30 秒のタイムアウトになる。
#
# 解決: 15 秒ごとに api.openai.com への TCP 接続を行うことで
#   ネットワーク層を常に「ウォーム」状態に保つ。
import ssl as _ssl
import threading as _threading
import time as _time

_WARMUP_HOST = "api.openai.com"
_WARMUP_PORT = 443
_WARMUP_INTERVAL = 12  # 秒： Docker の NAT タイムアウト (15秒) より長い間隔で接続を維持

def _keep_network_warm():
    """
    Docker Desktop for Mac のネットワークコールドスタート対策。
    api.openai.com:443 への TCP 接続を 12 秒ごとに行い、仮想ネットワーク層を
    常に「ウォーム」に保つ。起動 3 秒後に最初の接続を行い、以後はループする。
    """
    _time.sleep(3)  # uvicorn の起動を待つ

    while True:
        start = _time.time()
        try:
            sock = socket.create_connection((_WARMUP_HOST, _WARMUP_PORT), timeout=20)
            elapsed = _time.time() - start
            sock.close()
            logger.info(
                "[keep-warm] %s:%d TCP 接続成功 (%.2fs)",
                _WARMUP_HOST, _WARMUP_PORT, elapsed
            )
        except Exception as exc:
            elapsed = _time.time() - start
            logger.warning(
                "[keep-warm] %s:%d TCP 接続失敗 (%.2fs): %s",
                _WARMUP_HOST, _WARMUP_PORT, elapsed, exc
            )

        _time.sleep(_WARMUP_INTERVAL)

_threading.Thread(target=_keep_network_warm, daemon=True, name="openai-keep-warm").start()


# ──────────────────────────────────────────────
# OpenAI クライアント (シングルトン)
# ──────────────────────────────────────────────
# リクエストごとに新しい OpenAI インスタンスを作るのではなく、
# モジュールレベルのシングルトンインスタンスを再利用する。
# httpx のコネクションプールが再利用され、次回ここからの接続が高速化される。
_openai_client_instance: OpenAI | None = None
_openai_client_lock = _threading.Lock()

def _get_openai_client() -> OpenAI:
    """OpenAI クライアントのシングルトンインスタンスを返す。"""
    global _openai_client_instance
    if _openai_client_instance is None:
        with _openai_client_lock:
            if _openai_client_instance is None:
                _openai_client_instance = _build_openai_client()
                logger.info("[OpenAI] シングルトンクライアントを初期化しました")
    return _openai_client_instance


def _build_openai_client() -> OpenAI:
    """
    getaddrinfo パッチ済み環境で動作する OpenAI クライアントを生成する。

    keep-warm スレッドがネットワークを常にウォームに保つため、
    接続可能な場合は connect=5.0 で十分。失敗時は 60.0 でカバー。
    """
    http_client = httpx.Client(
        timeout=httpx.Timeout(
            connect=60.0,  # keep-warm 失敗後のコールドスタートをもカバー (15s × 2IP + 余裕)
            read=60.0,     # GPT-4o-mini のレスポンス生成待ち
            write=15.0,    # リクエスト送信
            pool=10.0,     # コネクションプール取得待ち
        ),
        limits=httpx.Limits(
            max_connections=5,
            max_keepalive_connections=3,
            keepalive_expiry=60,  # 60秒間接続を維持（keep-warmの間隔内）
        ),
    )

    return OpenAI(
        http_client=http_client,
        max_retries=0,  # タイムアウト時にすぐエラーを返す（リトライしない）
    )




# ──────────────────────────────────────────────
# コンテキスト生成
# ──────────────────────────────────────────────
def build_llm_context(req: ExecuteRequest, command_list: list[str], exit_code: int) -> str:
    """
    実行結果から LLM へ渡すコンテキスト JSON を生成する。

    Parameters
    ----------
    req          : フロントエンドからのリクエスト
    command_list : 実行されたコマンドのリスト
    exit_code    : コマンドの終了コード

    Returns
    -------
    JSON 文字列
    """
    user_options = [opt for opt in command_list if opt.startswith("-")]
    context = {
        "current_step": req.current_step,
        "user_selected_options": user_options,
        "execution_result": "success" if exit_code == 0 else "failed"
    }
    return json.dumps(context, ensure_ascii=False)


# ──────────────────────────────────────────────
# システムプロンプト生成
# ──────────────────────────────────────────────
def build_system_prompt(
    current_step: str,
    user_selected_options: list[str],
    execution_result: str,
    extra_materials: str | None = None,
) -> str:
    """
    AI チューター用のシステムプロンプトを組み立てる。

    Parameters
    ----------
    current_step           : 現在の学習ステップ名
    user_selected_options  : ユーザーが選択したオプション一覧
    execution_result       : 実行結果 ("success" / "failed")
    extra_materials        : 将来的に挿入する外部講義資料テキスト（任意）

    Returns
    -------
    システムプロンプト文字列
    """
    options_str = ", ".join(user_selected_options) if user_selected_options else "（なし）"

    base_prompt = f"""あなたは、セキュリティとそれに関するコマンドを教える「レッスン主導型」の優秀なAIチューターです。
学生の自由な質問に直接答えるのではなく、あらかじめ定められたレッスンプラン（PTES）に従って、セキュリティ初学者を順序よく導いてください。

現在の学習ステップ: {current_step}
ユーザーが選択したオプション: {options_str}
実行結果: {execution_result}

【教える際の振る舞いとルール】
1. 情報を小出しにする: 一度にすべてのコマンドの意味や仕組みを長文で解説せず、今実行しようとしているオプションだけにフォーカスして簡潔に解説してください。
2. 心地よいフラストレーションを与える: 学生が答えを求めても、すぐに完全なコマンドの正解を教えないでください。意図的にヒントを最小限に留め、WebUI上のオプションを自分で選んで試行錯誤するように促してください。
3. エラー発生時の建設的なフィードバック: エラーログが返ってきた場合、単に「失敗しました」と返すのではなく、ログの内容から「なぜ失敗したのか」のヒントを与え、再試行を促すようにナビゲートしてください。現在のステップをクリアするまで次のステップの答えは教えないでください。
4. 出力の冗長性を防ぐ工夫: 解説が長くなりすぎるのを防ぎ、親しみやすさを出すために、回答には必ず1〜2個の絵文字を使用してください（最大3行以内）。"""

    # 将来的な拡張: 外部講義資料をプロンプトに動的挿入
    if extra_materials:
        base_prompt += f"\n\n【参考資料】\n{extra_materials}"

    return base_prompt


# ──────────────────────────────────────────────
# AI レスポンス生成（メインエントリ）
# ──────────────────────────────────────────────
def generate_ai_response(
    llm_context_json: str,
    tool: str,
    extra_materials: str | None = None,
) -> str:
    """
    OpenAI API を呼び出してレッスン主導型の AI 解説を生成する。

    Parameters
    ----------
    llm_context_json : build_llm_context() が返す JSON 文字列
    tool             : 使用されたツール名
    extra_materials  : 将来的に挿入する外部講義資料テキスト（任意）

    Returns
    -------
    AI チューターからの解説文字列
    """
    try:
        context = json.loads(llm_context_json)
        current_step = context.get("current_step", "不明なステップ")
        user_selected_options = context.get("user_selected_options", [])
        execution_result = context.get("execution_result", "不明")

        system_prompt = build_system_prompt(
            current_step=current_step,
            user_selected_options=user_selected_options,
            execution_result=execution_result,
            extra_materials=extra_materials,
        )

        user_message = (
            f"ツール「{tool}」を使って上記のコマンドを実行しました。"
            f"実行結果は「{execution_result}」です。"
            f"学習の指針に従い、簡潔にフィードバックをしてください。"
        )

        logger.info(f"Calling OpenAI API: step={current_step}, tool={tool}, result={execution_result}")

        # シングルトンクライアントを再利用する。
        # keep-warm スレッドがネットワークをウォームに保っているため、
        # httpx のコネクションプールが再利用できる状態になっているはず。
        client = _get_openai_client()

        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
            max_tokens=200,
            temperature=0.7,
        )

        ai_text = response.choices[0].message.content.strip()
        logger.info(f"OpenAI response received: {ai_text[:80]}...")
        return ai_text

    except APITimeoutError as e:
        logger.error(f"[OpenAI] タイムアウト: コンテナから api.openai.com への疎通を確認してください: {e}")
        return "⏱️ AI チューターへの接続がタイムアウトしました。ネットワーク設定を確認してください。"
    except AuthenticationError as e:
        logger.error(f"[OpenAI] 認証エラー: OPENAI_API_KEY が正しく設定されているか確認してください: {e}")
        return "🔑 APIキーが無効です。環境変数 OPENAI_API_KEY を確認してください。"
    except APIConnectionError as e:
        logger.error(f"[OpenAI] 接続エラー: コンテナからインターネットへの疎通がない可能性があります: {e}")
        return "🌐 AI チューターへの接続に失敗しました。コンテナのネットワーク設定を確認してください。"
