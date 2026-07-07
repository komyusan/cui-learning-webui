"""
ai_service.py
CUI Learning WebUI — AI チューターサービス

OpenAI API (gpt-4o-mini) を使用して、PTES に沿ったレッスン主導型の
AI 解説を生成します。
環境変数 OPENAI_API_KEY は docker-compose 側で注入されるため、
このモジュール内での dotenv 読み込みは不要です。
"""

import json
import logging
import socket
from openai import OpenAI, APITimeoutError, AuthenticationError, APIConnectionError
from models import ExecuteRequest

logger = logging.getLogger(__name__)


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

        import httpx
        client = OpenAI(
            # Docker の NAT テーブルが ~60s でアイドル接続を切断するため
            # connect/read を分離して設定し、keepalive で接続を維持する
            timeout=httpx.Timeout(
                connect=10.0,   # 接続確立タイムアウト（秒）
                read=45.0,      # レスポンス読み取りタイムアウト（秒）
                write=10.0,     # リクエスト送信タイムアウト（秒）
                pool=5.0,       # コネクションプール取得タイムアウト（秒）
            ),
            http_client=httpx.Client(
                transport=httpx.HTTPTransport(
                    retries=1,
                    socket_options=[
                        # TCP keepalive を有効化 → NAT が接続を切断しにくくなる
                        (socket.SOL_SOCKET,  socket.SO_KEEPALIVE, 1),
                        (socket.IPPROTO_TCP, socket.TCP_KEEPIDLE,  10),  # 10秒後に keepalive 開始
                        (socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 5),   # 5秒ごとにプローブ
                        (socket.IPPROTO_TCP, socket.TCP_KEEPCNT,   3),   # 3回失敗で切断
                    ],
                ),
            ),
            max_retries=1,
        )

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
