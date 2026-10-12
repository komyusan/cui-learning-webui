"""
container_manager.py
ユーザごとの専用Dockerネットワーク・演習対象コンテナ群を起動／停止するモジュール。

  ログイン時  : start_user_containers(uid)
  ログアウト時: stop_user_containers(uid)
  /api/execute: get_user_container_names(uid) でホワイトリストを動的生成

これらは同期関数（Docker SDK はブロッキング）。
FastAPI 側では asyncio.to_thread() 経由で呼び出すこと。
"""

import docker
import logging
import os
import re
import threading

logger = logging.getLogger(__name__)

# 共有ネットワーク（docker-compose 側で作成済み）
SHARED_NETWORK = os.environ.get("DOCKER_NETWORK", "cui-learning-network")

# ユーザ専用ネットワーク名のプレフィックス
USER_NETWORK_PREFIX = "cui-network-"

# 起動するコンテナ定義（キー: 論理名 / ネットワークエイリアス）
_CONTAINER_SPECS: dict[str, dict] = {
    "dvwa": {
        "image": "vulnerables/web-dvwa",
        "platform": "linux/amd64",
    },
    "metasploitable": {
        "image": "tleemcjr/metasploitable2",
        "platform": "linux/amd64",
        "tty": True,
    },
    "mysql": {
        "image": "mysql:5.7",
        "platform": "linux/amd64",
        "environment": {
            "MYSQL_ROOT_PASSWORD": "password",
            "MYSQL_DATABASE": "dvwa",
            "MYSQL_USER": "dvwa",
            "MYSQL_PASSWORD": "p@ssw0rd",
        },
    },
    "dummy-web": {
        "image": "nginx:latest",
    },
    "iperf3-server": {
        "image": "networkstatic/iperf3",
        "command": "-s",
    },
}

# 起動／停止の競合（同時ログイン・ログアウト）を避けるための排他ロック
_lock = threading.Lock()


def _safe_uid(uid: str) -> str:
    """uid を Docker のコンテナ名・ネットワーク名で使える文字だけに正規化する。"""
    safe = re.sub(r"[^a-z0-9_.-]", "-", uid.strip().lower())
    if not safe:
        raise ValueError("uid が空です。")
    return safe


def get_user_network_name(uid: str) -> str:
    """ユーザ専用ネットワーク名 cui-network-<uid> を返す。"""
    return f"{USER_NETWORK_PREFIX}{_safe_uid(uid)}"


def get_user_container_names(uid: str) -> dict:
    """
    ユーザ専用コンテナのホスト名マッピングを返す。
    例: {"dvwa": "dvwa-<uid>", "metasploitable": "metasploitable-<uid>", ...}
    """
    safe = _safe_uid(uid)
    return {key: f"{key}-{safe}" for key in _CONTAINER_SPECS}


def _remove_all(client, uid: str) -> None:
    """ユーザのコンテナとネットワークを削除する（存在しなくてもエラーにしない）。"""
    for name in get_user_container_names(uid).values():
        try:
            # v=False: ボリュームは削除しない（db_data 等には一切触れない）
            client.containers.get(name).remove(v=False, force=True)
            logger.info("[container] 削除: %s", name)
        except docker.errors.NotFound:
            pass
        except Exception as e:
            logger.warning("[container] %s の削除に失敗: %s", name, e)

    network_name = get_user_network_name(uid)
    try:
        client.networks.get(network_name).remove()
        logger.info("[container] ネットワーク削除: %s", network_name)
    except docker.errors.NotFound:
        pass
    except Exception as e:
        logger.warning("[container] ネットワーク %s の削除に失敗: %s", network_name, e)


def _is_already_running(client, uid: str) -> bool:
    """ネットワークと全コンテナが揃って running なら True。"""
    try:
        client.networks.get(get_user_network_name(uid))
        for name in get_user_container_names(uid).values():
            if client.containers.get(name).status != "running":
                return False
        return True
    except docker.errors.NotFound:
        return False


def start_user_containers(uid: str) -> dict:
    """
    ユーザ専用のDockerネットワークとコンテナ群を起動する。
    既に起動済みの場合は再起動せずそのまま返す。
    起動中にエラーが発生した場合は、作成済みのものを全てクリーンアップして例外を送出する。

    Returns:
        {"network": ネットワーク名, "containers": [コンテナ名のリスト]}
    """
    client = docker.from_env()
    network_name = get_user_network_name(uid)
    names = get_user_container_names(uid)

    with _lock:
        if _is_already_running(client, uid):
            logger.info("[container] 起動済みのため再利用: %s", network_name)
            return {"network": network_name, "containers": list(names.values())}

        # 中途半端な残骸（一部だけ存在する等）があれば先に片付ける
        _remove_all(client, uid)

        try:
            user_network = client.networks.create(network_name, driver="bridge")
            logger.info("[container] ネットワーク作成: %s", network_name)

            for key, spec in _CONTAINER_SPECS.items():
                run_kwargs = {k: v for k, v in spec.items() if k != "image"}
                container = client.containers.run(
                    spec["image"],
                    name=names[key],
                    detach=True,
                    network=SHARED_NETWORK,
                    **run_kwargs,
                )
                # ユーザ専用ネットワークにも接続（論理名をエイリアスとして解決可能にする）
                user_network.connect(container, aliases=[key])
                logger.info("[container] 起動: %s", names[key])

        except Exception as e:
            logger.error("[container] 起動失敗のためクリーンアップします: %s", e)
            _remove_all(client, uid)
            raise RuntimeError(f"ユーザ用コンテナの起動に失敗しました: {e}") from e

    return {"network": network_name, "containers": list(names.values())}


def stop_user_containers(uid: str) -> None:
    """
    ユーザ専用のコンテナ群とネットワークを全て停止・削除する。
    存在しない場合はエラーにしない。

    【重要】削除対象は Docker コンテナとユーザ専用ネットワークのみ。
            ボリューム（db_data 等）、SQLite の DB ファイル、DB 内のログ・セッションデータには
            一切触れない。
    """
    client = docker.from_env()
    with _lock:
        _remove_all(client, uid)
