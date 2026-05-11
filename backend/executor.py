"""
executor.py
Dockerコンテナ内でコマンドを安全に実行するモジュール。
Alpine Linuxの使い捨てコンテナを起動し、標準出力を取得して返す。
"""

import docker
import logging

logger = logging.getLogger(__name__)

# サンドボックス設定
SANDBOX_IMAGE = "instrumentisto/nmap:latest"
CONTAINER_TIMEOUT = 30  # 秒

# リソース制限（ホスト環境を保護）
RESOURCE_LIMITS = {
    "mem_limit": "128m",
    "cpu_period": 100000,
    "cpu_quota": 50000,   # CPUを50%に制限
    "network_mode": "none",  # ネットワーク無効（ローカル演習用はbridge/hostに変更可）
}


def run_command_in_sandbox(command: list[str]) -> dict:
    """
    Dockerコンテナ内でコマンドを実行し、結果を返す。

    Args:
        command: 実行するコマンドのリスト（例: ["nmap", "-sV", "target"]）

    Returns:
        {
            "stdout": str,   # 標準出力
            "stderr": str,   # 標準エラー出力
            "exit_code": int # 終了コード（0=成功）
        }
    """
    client = docker.from_env()

    try:
        logger.info(f"Executing in sandbox: {' '.join(command)}")

        # コンテナを起動してコマンドを実行（--rm 相当の使い捨て）
        result = client.containers.run(
            image=SANDBOX_IMAGE,
            command=command,
            remove=True,           # 実行後にコンテナを自動削除
            stdout=True,
            stderr=True,
            mem_limit=RESOURCE_LIMITS["mem_limit"],
            cpu_period=RESOURCE_LIMITS["cpu_period"],
            cpu_quota=RESOURCE_LIMITS["cpu_quota"],
            # network_mode=RESOURCE_LIMITS["network_mode"],  # nmapテスト時はコメントアウト
        )

        stdout = result.decode("utf-8", errors="replace") if result else ""
        return {
            "stdout": stdout,
            "stderr": "",
            "exit_code": 0,
        }

    except docker.errors.ContainerError as e:
        # コンテナが非ゼロ終了コードで終了した場合
        stderr = e.stderr.decode("utf-8", errors="replace") if e.stderr else str(e)
        return {
            "stdout": "",
            "stderr": stderr,
            "exit_code": e.exit_status,
        }

    except docker.errors.ImageNotFound:
        return {
            "stdout": "",
            "stderr": f"[ERROR] Docker image '{SANDBOX_IMAGE}' not found. Run: docker pull {SANDBOX_IMAGE}",
            "exit_code": 127,
        }

    except Exception as e:
        logger.error(f"Unexpected error during sandbox execution: {e}")
        return {
            "stdout": "",
            "stderr": f"[ERROR] サンドボックス実行に失敗しました: {str(e)}",
            "exit_code": -1,
        }
