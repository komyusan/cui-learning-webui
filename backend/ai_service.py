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

# ▼▼▼変更箇所▼▼▼ トークン超過防止用の最大文字数定数
_MAX_OUTPUT_LENGTH = 1000  # stdout / stderr の最大保持文字数（これを超えた場合は末尾を切り詰める）

def _truncate_output(text: str, max_length: int = _MAX_OUTPUT_LENGTH) -> str:
    """
    出力テキストを max_length 文字以内に切り詰める。

    トークン数超過を防ぐため、1000文字を超える場合は末尾を切り捨て、
    「...（以下省略）」という省略文言を付加する。

    Parameters
    ----------
    text       : 切り詰め対象の文字列（stdout または stderr）
    max_length : 最大文字数（デフォルト: 1000）

    Returns
    -------
    切り詰め後の文字列。元の文字数が max_length 以下なら変更なし。
    """
    if len(text) <= max_length:          # 文字数が上限以下なら何もしない
        return text
    # 上限を超えている場合: 先頭 max_length 文字を残し、省略文言を付加する
    return text[:max_length] + "\n...(出力が長いため以下省略)..."


# ▼▼▼変更箇所▼▼▼ stdout / stderr 引数に加え、time_since_last_cmd / is_help_request を追加
def build_llm_context(
    req: ExecuteRequest,
    command_list: list[str],
    exit_code: int,
    stdout: str = "",                   # コマンドの標準出力（省略可、デフォルトは空文字）
    stderr: str = "",                   # コマンドの標準エラー出力（省略可、デフォルトは空文字）
    time_since_last_cmd: float = 0.0,  # 前回コマンドからの経過秒数
    is_help_request: bool = False,      # ヘルプフラグ包含判定結果
) -> str:
    """
    実行結果から LLM へ渡すコンテキスト JSON を生成する。

    Parameters
    ----------
    req                 : フロントエンドからのリクエスト
    command_list        : 実行されたコマンドのリスト
    exit_code           : コマンドの終了コード
    stdout              : コマンドの標準出力テキスト
    stderr              : コマンドの標準エラー出力テキスト
    time_since_last_cmd : 前回コマンドからの経過秒数
    is_help_request     : ヘルプフラグ包含判定結果

    Returns
    -------
    JSON 文字列
    """
    user_options = [opt for opt in command_list if opt.startswith("-")]  # "-" で始まるトークンをオプションとして抽出

    context = {
        "current_step": req.current_step,               # 現在の学習ステップ名
        "user_selected_options": user_options,           # ユーザーが選択したオプション一覧
        "execution_result": "success" if exit_code == 0 else "failed",  # 終了コードを success/failed に変換
        "exit_code": exit_code,                          # 数値の終了コードも直接渡す
        "stdout": _truncate_output(stdout),              # 標準出力（切り詰め済み）
        "stderr": _truncate_output(stderr),              # 標準エラー出力（切り詰め済み）
        "time_since_last_cmd": time_since_last_cmd,      # 前回コマンドからの経過秒数
        "is_help_request": is_help_request,              # ヘルプフラグが含まれていたか
    }
    return json.dumps(context, ensure_ascii=False)  # JSON文字列として返す（日本語をエスケープしない）


# ──────────────────────────────────────────────
# システムプロンプト生成
# ──────────────────────────────────────────────

# ▼▼▼変更箇所▼▼▼ 引数を追加し、認知的負荷理論に基づくルールとStuck Stateの対応を組み込む
def build_system_prompt(
    current_step: str,                  # 現在の学習ステップ名
    user_selected_options: list[str],   # ユーザーが使用したオプション一覧
    execution_result: str,              # 実行結果文字列 ("success" / "failed")
    exit_code: int = 0,                 # 数値の終了コード（結果分析ルールに使用）
    stdout: str = "",                   # 標準出力テキスト（情報絞り込みルールに使用）
    stderr: str = "",                   # 標準エラー出力テキスト（エラー分析に使用）
    time_since_last_cmd: float = 0.0,  # 前回コマンドからの経過秒数
    is_help_request: bool = False,      # ヘルプフラグ包含判定結果
    extra_materials: str | None = None, # 将来的な外部講義資料の動的挿入用（任意）
) -> str:
    """
    AI チューター用のシステムプロンプトを組み立てる。

    認知的負荷理論（足場かけ: Scaffolding）に基づき、3つの教育ルールを
    システムプロンプトに組み込む。さらにStuck Stateを検知してサポートを強化する。

    Parameters
    ----------
    current_step           : 現在の学習ステップ名
    user_selected_options  : ユーザーが選択したオプション一覧
    execution_result       : 実行結果 ("success" / "failed")
    exit_code              : コマンドの終了コード
    stdout                 : 標準出力テキスト
    stderr                 : 標準エラー出力テキスト
    time_since_last_cmd    : 前回コマンドからの経過秒数
    is_help_request        : ヘルプフラグ包含判定結果
    extra_materials        : 将来的に挿入する外部講義資料テキスト（任意）

    Returns
    -------
    システムプロンプト文字列
    """
    options_str = ", ".join(user_selected_options) if user_selected_options else "（なし）"  # オプション一覧を文字列化

    # ▼▼▼変更箇所▼▼▼ Stuck State（詰まり状態）の判定
    _STUCK_THRESHOLD_SEC = 60.0                          # Stuck 判定の閾値秒数
    is_stuck = (                                          # いずれか一方が真なら Stuck
        time_since_last_cmd >= _STUCK_THRESHOLD_SEC      # 60秒以上の間隔がある
        or is_help_request                               # またはヘルプフラグが含まれている
    )

    # ▼▼▼変更箇所▼▼▼ Stuck State判定結果のロギング
    logger.info(f"Stuck State: {is_stuck} (Time: {time_since_last_cmd}, Help: {is_help_request})")

    # ▼▼▼変更箇所▼▼▼ Stuck State に応じて完全に別プロンプトを生成（混在を排除）
    if is_stuck:
        # ────────────────────────────────────────────────────────
        # 🚨 緊急サポートモード用プロンプト
        # 「正解を教えるな」という禁止命令を一切含まない別プロンプトを生成。
        # 通常プロンプトの後に「解除」を追記する方式だと LLM が先の禁止命令を
        # 優先してしまうため、この方式に変更した。
        # ────────────────────────────────────────────────────────
        stuck_reason = (                                            # 詰まり理由を文字列で表現
            f"前回の操作から {time_since_last_cmd:.0f} 秒以上経過"
            if time_since_last_cmd >= _STUCK_THRESHOLD_SEC
            else "ヘルプコマンドを実行"
        )

        prompt = f"""あなたは、セキュリティとコマンドを教える AI チューターです。
現在、学生は「{stuck_reason}」したため行き詰まっています。

現在の学習ステップ: {current_step}
ユーザーが選択したオプション: {options_str}
実行結果: {execution_result}（終了コード: {exit_code}）

--- 実行された標準出力（stdout）---
{stdout if stdout else "（出力なし）"}

--- 実行された標準エラー出力（stderr）---
{stderr if stderr else "（エラーなし）"}

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
        # ────────────────────────────────────────────────────────
        # 通常モード用プロンプト（足場かけ: 正解を教えない）
        # ────────────────────────────────────────────────────────
        prompt = f"""あなたは、セキュリティとそれに関するコマンドを教える「レッスン主導型」の優秀なAIチューターです。
学生の自由な質問に直接答えるのではなく、あらかじめ定められたレッスンプラン（PTES）に従って、セキュリティ初学者を順序よく導いてください。

現在の学習ステップ: {current_step}
ユーザーが選択したオプション: {options_str}
実行結果: {execution_result}（終了コード: {exit_code}）

--- 実行された標準出力（stdout）---
{stdout if stdout else "（出力なし）"}

--- 実行された標準エラー出力（stderr）---
{stderr if stderr else "（エラーなし）"}

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

    # 外部講義資料をプロンプトに動的挿入（任意）
    if extra_materials:                                             # 外部資料が指定されている場合のみ追加
        prompt += f"\n\n【参考資料】\n{extra_materials}"

    # ▼▼▼変更箇所▼▼▼ JSON 出力フォーマット指示（通常・緊急 共通で末尾に追加）
    prompt += """

【出力フォーマット（厳守）】
必ず以下の JSON 形式のみで応答してください。それ以外の形式は禁止です。
JSON以外のテキスト（前置きや後書き）は一切含めないでください。

{
  "message": "学生へのフィードバックテキスト（絵文字を含む、最大4行）",
  "highlights": ["ターミナル出力内でハイライトすべきキーワード1", "キーワード2"]
}

- "message": 上記の指示に従ったフィードバックを日本語で記述してください。
- "highlights": 学生に最も注目させたい語句を、stdout または stderr からそのまま抜き出した文字列で1〜2個だけリストしてください。注目させる情報がない場合は空リスト [] にしてください。"""

    return prompt



# ──────────────────────────────────────────────
# AI レスポンス生成（メインエントリ）
# ──────────────────────────────────────────────

# ▼▼▼変更箇所▼▼▼ 戻り値の型を dict に変更し、Stuck Stateの引数を追加
def generate_ai_response(
    llm_context_json: str,              # build_llm_context() が返す JSON 文字列
    tool: str,                          # 使用されたツール名
    time_since_last_cmd: float = 0.0,  # 前回コマンドからの経過秒数
    is_help_request: bool = False,      # ヘルプフラグ包含判定結果
    extra_materials: str | None = None, # 将来的な外部講義資料テキスト（任意）
) -> dict:
    """
    OpenAI API を呼び出してレッスン主導型の AI 解説を生成する。

    Parameters
    ----------
    llm_context_json    : build_llm_context() が返す JSON 文字列
    tool                : 使用されたツール名
    time_since_last_cmd : 前回コマンドからの経過秒数
    is_help_request     : ヘルプフラグ包含判定結果
    extra_materials     : 将来的に挿入する外部講義資料テキスト（任意）

    Returns
    -------
    dict : {"message": str, "highlights": list[str]}
    """
    try:
        context = json.loads(llm_context_json)                          # JSON文字列をdictに変換
        current_step = context.get("current_step", "不明なステップ")    # 学習ステップ名を取得
        user_selected_options = context.get("user_selected_options", [])  # オプション一覧を取得
        execution_result = context.get("execution_result", "不明")     # 実行結果文字列を取得
        exit_code = context.get("exit_code", 0)                        # 数値の終了コードを取得
        stdout = context.get("stdout", "")                             # 標準出力テキストを取得
        stderr = context.get("stderr", "")                             # 標準エラー出力テキストを取得

        # ▼▼▼変更箇所▼▼▼ build_system_prompt に Stuck State情報 と stdout/stderr を渡す
        system_prompt = build_system_prompt(
            current_step=current_step,
            user_selected_options=user_selected_options,
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
            response_format={"type": "json_object"},  # ▼▼▼変更箇所▼▼▼ JSON出力を強制
            max_tokens=200,
            temperature=0.7,
        )

        ai_text = response.choices[0].message.content.strip()
        logger.info(f"OpenAI response received: {ai_text[:80]}...")
        
        # ▼▼▼変更箇所▼▼▼ JSON文字列をパースして dict として返す
        try:
            return json.loads(ai_text)
        except json.JSONDecodeError:
            return {"message": ai_text, "highlights": []}

    except APITimeoutError as e:
        logger.error(f"[OpenAI] タイムアウト: {e}")
        return {"message": "⏱️ AI チューターへの接続がタイムアウトしました。ネットワーク設定を確認してください。", "highlights": []}
    except AuthenticationError as e:
        logger.error(f"[OpenAI] 認証エラー: {e}")
        return {"message": "🔑 APIキーが無効です。環境変数 OPENAI_API_KEY を確認してください。", "highlights": []}
    except APIConnectionError as e:
        logger.error(f"[OpenAI] 接続エラー: {e}")
        return {"message": "🌐 AI チューターへの接続に失敗しました。コンテナのネットワーク設定を確認してください。", "highlights": []}
    except Exception as e:
        logger.error(f"[OpenAI] 予期せぬエラー: {e}")
        return {"message": "❌ AI チューターの処理中にエラーが発生しました。", "highlights": []}
