import json
from models import ExecuteRequest

def build_llm_context(req: ExecuteRequest, command_list: list[str], exit_code: int) -> str:
    user_options = [opt for opt in command_list if opt.startswith("-")]
    context = {
        "current_step": req.current_step,
        "user_selected_options": user_options,
        "execution_result": "success" if exit_code == 0 else "failed"
    }
    return json.dumps(context, ensure_ascii=False)

def generate_dummy_ai_response(llm_context_json: str, tool: str) -> str:
    context = json.loads(llm_context_json)
    step = context.get("current_step", "Step 1")
    success = (context.get("execution_result") == "success")

    if step.startswith("Step 1"):
        if tool == "nmap":
            if success:
                return "💡 Nmapの実行が成功したね！開いているポートが見つかったかな？🤔 次はどのサービスが動いているか特定してみると良いかも！"
            else:
                return "🤔 うーん、スキャンに失敗したみたい。ターゲットのIPアドレスやオプションを見直してみよう。pingが通らないなら `-sn` などを試すのもアリだよ💡"
        else:
            return "💡 情報収集フェーズでは、まずは Nmap を使ってネットワークの全体像を把握するのが王道だよ。他のツールも試してみてね🤔"
    elif step.startswith("Step 2"):
        if tool == "gobuster":
            if success:
                return "💡 Gobusterでディレクトリ探索が成功したね！隠されたWebページは見つかったかな？🤔 脆弱性がありそうなページを探してみよう！"
            else:
                return "🤔 探索が失敗しちゃったみたい。URLの指定や辞書ファイル（Wordlist）のパスが正しいか確認してみて💡"
        else:
            return "💡 脆弱性スキャンフェーズだね！Webサーバーが見つかったなら、Gobusterなどでディレクトリ探索をするのがおすすめだよ🤔"
    elif step.startswith("Step 3"):
        if tool in ["hydra", "metasploit"]:
            if success:
                return "💡 エクスプロイト成功の兆し！🤔 システムに侵入する足がかりは見つかったかな？"
            else:
                return "🤔 攻撃が弾かれたみたい。パスワードリストが合っているか、対象のポートが開いているか確認してみよう💡"
        else:
            return "💡 エクスプロイト（攻撃）フェーズだよ。特定した脆弱性に対して、HydraやMetasploitを使ってアプローチしてみよう🤔"
    elif step.startswith("Step 4"):
        return "💡 ポストエクスプロイトフェーズだね。侵入後にどんな情報が取れるか、さらに権限昇格できるか試してみよう🤔 ログの消去も忘れずに！"
    else:
        return "🤔 新しいステップかな？まずは基本のコマンドから試してみよう💡"
