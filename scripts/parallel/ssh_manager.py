"""
SSH + tmux 管理モジュール

リモートサーバーでのvLLM起動・停止をtmux経由で管理する
"""

import subprocess
import time
from dataclasses import dataclass
from typing import Optional, Tuple
import shlex


@dataclass
class SSHConnection:
    """SSH接続情報"""
    host: str
    user: str
    port: int = 22

    @property
    def target(self) -> str:
        return f"{self.user}@{self.host}"


class SSHManager:
    """SSH経由のリモート操作を管理"""

    def __init__(self, connection: SSHConnection):
        self.conn = connection
        self._port_forward_pid: Optional[int] = None

    def test_connection(self, timeout: int = 10) -> Tuple[bool, str]:
        """
        SSH接続をテスト

        Returns:
            (成功したか, メッセージ)
        """
        try:
            result = subprocess.run(
                ['ssh', '-o', 'ConnectTimeout=5', '-o', 'BatchMode=yes',
                 self.conn.target, 'echo', 'ok'],
                capture_output=True,
                text=True,
                timeout=timeout
            )

            if result.returncode == 0 and 'ok' in result.stdout:
                return True, f"SSH connection to {self.conn.host} successful"
            else:
                return False, f"SSH connection failed: {result.stderr}"

        except subprocess.TimeoutExpired:
            return False, f"SSH connection to {self.conn.host} timed out"
        except Exception as e:
            return False, f"SSH connection error: {e}"

    def run_command(self, command: str, timeout: int = 30) -> Tuple[int, str, str]:
        """
        リモートでコマンド実行

        Args:
            command: 実行するコマンド
            timeout: タイムアウト(秒)

        Returns:
            (return_code, stdout, stderr)
        """
        try:
            result = subprocess.run(
                ['ssh', self.conn.target, command],
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "Command timed out"
        except Exception as e:
            return -1, "", str(e)

    def start_port_forward(self, local_port: int, remote_port: int) -> Tuple[bool, str]:
        """
        SSHポートフォワードを開始

        Args:
            local_port: ローカルポート
            remote_port: リモートポート

        Returns:
            (成功したか, メッセージ)
        """
        try:
            # 既存のポートフォワードを確認
            check = subprocess.run(
                ['ss', '-tlnp'],
                capture_output=True,
                text=True
            )
            if f":{local_port}" in check.stdout:
                return True, f"Port {local_port} already forwarded"

            # バックグラウンドでポートフォワード開始
            proc = subprocess.Popen(
                ['ssh', '-fN', '-L', f'{local_port}:localhost:{remote_port}',
                 self.conn.target],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )

            # 少し待ってからポートを確認
            time.sleep(1)

            check = subprocess.run(
                ['ss', '-tlnp'],
                capture_output=True,
                text=True
            )
            if f":{local_port}" in check.stdout:
                return True, f"Port forward established: localhost:{local_port} -> {self.conn.host}:{remote_port}"
            else:
                return False, "Port forward may have failed"

        except Exception as e:
            return False, f"Failed to start port forward: {e}"

    def stop_port_forward(self, local_port: int) -> Tuple[bool, str]:
        """
        SSHポートフォワードを停止

        Args:
            local_port: ローカルポート

        Returns:
            (成功したか, メッセージ)
        """
        try:
            # ポートをリッスンしているSSHプロセスを探して終了
            result = subprocess.run(
                ['pkill', '-f', f'ssh.*-L.*{local_port}'],
                capture_output=True
            )
            return True, f"Port forward on {local_port} stopped"
        except Exception as e:
            return False, f"Failed to stop port forward: {e}"


class TmuxManager:
    """tmuxセッションの管理"""

    def __init__(self, ssh_manager: SSHManager, session_name: str):
        self.ssh = ssh_manager
        self.session_name = session_name

    def session_exists(self) -> bool:
        """セッションが存在するか確認"""
        code, stdout, _ = self.ssh.run_command(
            f'tmux has-session -t {self.session_name} 2>/dev/null && echo exists'
        )
        return 'exists' in stdout

    def create_session(self) -> Tuple[bool, str]:
        """新しいtmuxセッションを作成"""
        if self.session_exists():
            return True, f"Session {self.session_name} already exists"

        code, stdout, stderr = self.ssh.run_command(
            f'tmux new-session -d -s {self.session_name}'
        )

        if code == 0:
            return True, f"Created tmux session: {self.session_name}"
        else:
            return False, f"Failed to create session: {stderr}"

    def send_command(self, command: str) -> Tuple[bool, str]:
        """セッションにコマンドを送信"""
        escaped_cmd = shlex.quote(command)
        code, stdout, stderr = self.ssh.run_command(
            f"tmux send-keys -t {self.session_name} {escaped_cmd} Enter"
        )

        if code == 0:
            return True, f"Sent command to {self.session_name}"
        else:
            return False, f"Failed to send command: {stderr}"

    def send_ctrl_c(self) -> Tuple[bool, str]:
        """Ctrl+Cを送信"""
        code, _, stderr = self.ssh.run_command(
            f'tmux send-keys -t {self.session_name} C-c'
        )
        if code == 0:
            return True, "Sent Ctrl+C"
        else:
            return False, f"Failed to send Ctrl+C: {stderr}"

    def kill_session(self) -> Tuple[bool, str]:
        """セッションを終了"""
        if not self.session_exists():
            return True, f"Session {self.session_name} does not exist"

        code, _, stderr = self.ssh.run_command(
            f'tmux kill-session -t {self.session_name}'
        )

        if code == 0:
            return True, f"Killed tmux session: {self.session_name}"
        else:
            return False, f"Failed to kill session: {stderr}"

    def capture_output(self, lines: int = 50) -> str:
        """セッションの出力をキャプチャ"""
        code, stdout, _ = self.ssh.run_command(
            f'tmux capture-pane -t {self.session_name} -p -S -{lines}'
        )
        return stdout if code == 0 else ""


class RemoteVLLMManager:
    """リモートvLLMの管理"""

    def __init__(
        self,
        host: str,
        user: str,
        session_name: str,
        local_port: int,
        remote_port: int = 8000,
        gpu: int = 0
    ):
        self.host = host
        self.user = user
        self.session_name = session_name
        self.local_port = local_port
        self.remote_port = remote_port
        self.gpu = gpu

        self.ssh = SSHManager(SSHConnection(host=host, user=user))
        self.tmux = TmuxManager(self.ssh, session_name)

    def check_orphan_session(self) -> Tuple[bool, str]:
        """孤立したセッションがあるか確認"""
        if self.tmux.session_exists():
            output = self.tmux.capture_output(10)
            return True, output
        return False, ""

    def start(
        self,
        model: str = "Qwen/Qwen3-4B",
        max_model_len: int = 8192,
        gpu_memory_utilization: float = 0.85
    ) -> Tuple[bool, str]:
        """
        リモートでvLLMを起動

        Args:
            model: モデル名
            max_model_len: 最大コンテキスト長
            gpu_memory_utilization: GPUメモリ使用率

        Returns:
            (成功したか, メッセージ)
        """
        # SSH接続テスト
        ok, msg = self.ssh.test_connection()
        if not ok:
            return False, msg

        # tmuxセッション作成
        ok, msg = self.tmux.create_session()
        if not ok:
            return False, msg

        # vLLM起動コマンド
        vllm_cmd = (
            f"CUDA_VISIBLE_DEVICES={self.gpu} vllm serve {model} "
            f"--port {self.remote_port} "
            f"--max-model-len {max_model_len} "
            f"--gpu-memory-utilization {gpu_memory_utilization} "
            f"--dtype auto"
        )

        ok, msg = self.tmux.send_command(vllm_cmd)
        if not ok:
            return False, msg

        # ポートフォワード開始
        ok, msg = self.ssh.start_port_forward(self.local_port, self.remote_port)
        if not ok:
            # vLLM起動したがポートフォワード失敗
            self.stop()
            return False, msg

        return True, f"Started vLLM on {self.host} (localhost:{self.local_port})"

    def wait_ready(self, timeout: int = 120) -> Tuple[bool, str]:
        """vLLMが準備完了するまで待機"""
        import requests

        start = time.time()
        while time.time() - start < timeout:
            try:
                resp = requests.get(
                    f"http://localhost:{self.local_port}/v1/models",
                    timeout=5
                )
                if resp.status_code == 200:
                    return True, "vLLM is ready"
            except:
                pass

            time.sleep(2)

        return False, f"vLLM did not become ready within {timeout}s"

    def stop(self) -> Tuple[bool, str]:
        """vLLMを停止"""
        messages = []

        # Ctrl+Cを送信
        ok, msg = self.tmux.send_ctrl_c()
        messages.append(msg)

        time.sleep(2)

        # セッション終了
        ok, msg = self.tmux.kill_session()
        messages.append(msg)

        # ポートフォワード停止
        ok, msg = self.ssh.stop_port_forward(self.local_port)
        messages.append(msg)

        return True, "; ".join(messages)

    def health_check(self) -> bool:
        """ヘルスチェック"""
        try:
            import requests
            resp = requests.get(
                f"http://localhost:{self.local_port}/v1/models",
                timeout=5
            )
            return resp.status_code == 200
        except:
            return False


if __name__ == "__main__":
    # テスト
    print("SSH Manager test")

    # 接続テスト（実際のホスト名に変更してテスト）
    # ssh = SSHManager(SSHConnection(host="gpu-server-b", user="asomura"))
    # ok, msg = ssh.test_connection()
    # print(f"Connection test: {ok}, {msg}")
