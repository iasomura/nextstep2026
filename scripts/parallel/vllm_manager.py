"""
vLLM管理モジュール

ローカルとリモートのvLLMを統一的に管理する
"""

import os
import subprocess
import signal
import time
import requests
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional, Tuple, List
from pathlib import Path

from .config import WorkerConfig, VLLMConfig
from .ssh_manager import RemoteVLLMManager


@dataclass
class VLLMStatus:
    """vLLMの状態"""
    is_running: bool
    is_ready: bool
    port: int
    pid: Optional[int] = None
    error: Optional[str] = None


class BaseVLLMManager(ABC):
    """vLLM管理の基底クラス"""

    def __init__(self, port: int, vllm_config: VLLMConfig):
        self.port = port
        self.vllm_config = vllm_config

    @abstractmethod
    def start(self) -> Tuple[bool, str]:
        """vLLMを起動"""
        pass

    @abstractmethod
    def stop(self) -> Tuple[bool, str]:
        """vLLMを停止"""
        pass

    @abstractmethod
    def get_status(self) -> VLLMStatus:
        """状態を取得"""
        pass

    def health_check(self) -> bool:
        """ヘルスチェック"""
        try:
            resp = requests.get(
                f"http://localhost:{self.port}/v1/models",
                timeout=5
            )
            return resp.status_code == 200
        except:
            return False

    def wait_ready(self, timeout: int = 120) -> Tuple[bool, str]:
        """準備完了まで待機"""
        start = time.time()
        while time.time() - start < timeout:
            if self.health_check():
                return True, "vLLM is ready"
            time.sleep(2)
            elapsed = int(time.time() - start)
            print(f"\r   Waiting for vLLM... {elapsed}s", end="", flush=True)

        print()
        return False, f"vLLM did not become ready within {timeout}s"


class LocalVLLMManager(BaseVLLMManager):
    """ローカルvLLMの管理"""

    def __init__(
        self,
        port: int,
        gpu: int,
        vllm_config: VLLMConfig,
        log_dir: Optional[Path] = None
    ):
        super().__init__(port, vllm_config)
        self.gpu = gpu
        self.log_dir = log_dir or Path(".")
        self._process: Optional[subprocess.Popen] = None
        self._pid_file = self.log_dir / f".vllm_{port}.pid"
        self._log_file = self.log_dir / f"vllm_{port}.log"

    def _find_pid_by_port(self) -> Optional[int]:
        """ポート番号からvLLMメインプロセスのPIDを取得"""
        try:
            # "vllm serve" かつ "--port {port}" を含むプロセスを検索
            result = subprocess.run(
                ['pgrep', '-f', f'vllm serve.*--port {self.port}'],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0 and result.stdout.strip():
                return int(result.stdout.strip().split('\n')[0])
        except (subprocess.TimeoutExpired, ValueError):
            pass
        return None

    def start(self) -> Tuple[bool, str]:
        """vLLMを起動"""
        if self.health_check():
            # 既存プロセスのPIDを記録（stop時に使用）
            pid = self._find_pid_by_port()
            if pid:
                self._pid_file.parent.mkdir(parents=True, exist_ok=True)
                self._pid_file.write_text(str(pid))
            return True, f"vLLM already running on port {self.port} (PID: {pid})"

        # 既存プロセスの確認
        if self._pid_file.exists():
            try:
                pid = int(self._pid_file.read_text().strip())
                os.kill(pid, 0)  # プロセス存在確認
                return True, f"vLLM already running (PID: {pid})"
            except (ProcessLookupError, ValueError):
                self._pid_file.unlink(missing_ok=True)

        # ログディレクトリ作成
        self.log_dir.mkdir(parents=True, exist_ok=True)

        # 環境変数設定
        env = os.environ.copy()
        env['CUDA_VISIBLE_DEVICES'] = str(self.gpu)

        # vLLMコマンド構築
        cmd = [
            'vllm', 'serve', self.vllm_config.model,
            '--port', str(self.port),
            '--max-model-len', str(self.vllm_config.max_model_len),
            '--max-num-seqs', str(self.vllm_config.max_num_seqs),
            '--gpu-memory-utilization', str(self.vllm_config.gpu_memory_utilization),
            '--dtype', self.vllm_config.dtype,
            '--host', '127.0.0.1'
        ]

        try:
            with open(self._log_file, 'w') as log_f:
                self._process = subprocess.Popen(
                    cmd,
                    env=env,
                    stdout=log_f,
                    stderr=subprocess.STDOUT,
                    start_new_session=True  # デーモン化
                )

            # PID保存
            self._pid_file.write_text(str(self._process.pid))

            return True, f"Started vLLM on port {self.port} (PID: {self._process.pid})"

        except Exception as e:
            return False, f"Failed to start vLLM: {e}"

    def stop(self) -> Tuple[bool, str]:
        """vLLMを停止"""
        pid = None

        # PIDファイルから取得
        if self._pid_file.exists():
            try:
                pid = int(self._pid_file.read_text().strip())
            except ValueError:
                pass

        # プロセスオブジェクトから取得
        if pid is None and self._process:
            pid = self._process.pid

        # ポートから検索
        if pid is None:
            pid = self._find_pid_by_port()

        if pid is None:
            return True, "No vLLM process to stop"

        try:
            # SIGTERM送信
            os.kill(pid, signal.SIGTERM)

            # 終了待ち
            for _ in range(10):
                try:
                    os.kill(pid, 0)
                    time.sleep(1)
                except ProcessLookupError:
                    break
            else:
                # 強制終了
                os.kill(pid, signal.SIGKILL)

            self._pid_file.unlink(missing_ok=True)
            self._process = None

            return True, f"Stopped vLLM (PID: {pid})"

        except ProcessLookupError:
            self._pid_file.unlink(missing_ok=True)
            return True, "vLLM process already stopped"
        except Exception as e:
            return False, f"Failed to stop vLLM: {e}"

    def get_status(self) -> VLLMStatus:
        """状態を取得"""
        pid = None
        is_running = False

        if self._pid_file.exists():
            try:
                pid = int(self._pid_file.read_text().strip())
                os.kill(pid, 0)
                is_running = True
            except (ProcessLookupError, ValueError):
                pass

        is_ready = self.health_check() if is_running else False

        return VLLMStatus(
            is_running=is_running,
            is_ready=is_ready,
            port=self.port,
            pid=pid
        )

    def restart(self) -> Tuple[bool, str]:
        """vLLMを再起動"""
        self.stop()
        time.sleep(5)  # GPUメモリ解放待ち
        return self.start()


class ExternalVLLMManager(BaseVLLMManager):
    """外部管理vLLMへの接続（ポートフォワード等）

    start_cmd/stop_cmd が指定されている場合はSSH等で起動/停止を行う。
    指定されていない場合はヘルスチェックのみ。
    """

    def __init__(
        self,
        port: int,
        vllm_config: VLLMConfig,
        start_cmd: Optional[str] = None,
        stop_cmd: Optional[str] = None
    ):
        super().__init__(port, vllm_config)
        self.start_cmd = start_cmd
        self.stop_cmd = stop_cmd

    def start(self) -> Tuple[bool, str]:
        """vLLMを起動（start_cmdがあれば実行）

        変更履歴:
          - 2026-01-25: SSH tunnel不安定対策としてリトライロジック追加 (3回, 2秒間隔)
        """
        # リトライ付きヘルスチェック（SSH tunnel不安定対策）
        for attempt in range(3):
            if self.health_check():
                return True, f"External vLLM on port {self.port} is reachable"
            if attempt < 2:
                time.sleep(2)

        if self.start_cmd:
            try:
                print(f"   Executing start_cmd for port {self.port}...")
                result = subprocess.run(
                    self.start_cmd, shell=True,
                    capture_output=True, text=True, timeout=30
                )
                if result.returncode != 0:
                    return False, f"start_cmd failed (exit {result.returncode}): {result.stderr.strip()}"
                return True, f"External vLLM on port {self.port} start_cmd executed"
            except subprocess.TimeoutExpired:
                return False, f"start_cmd timed out for port {self.port}"
            except Exception as e:
                return False, f"start_cmd error: {e}"

        return False, f"External vLLM on port {self.port} is not reachable"

    def stop(self) -> Tuple[bool, str]:
        """vLLMを停止（stop_cmdがあれば実行）"""
        if self.stop_cmd:
            try:
                result = subprocess.run(
                    self.stop_cmd, shell=True,
                    capture_output=True, text=True, timeout=30
                )
                if result.returncode != 0:
                    return False, f"stop_cmd failed (exit {result.returncode}): {result.stderr.strip()}"
                return True, f"External vLLM on port {self.port} stopped via stop_cmd"
            except subprocess.TimeoutExpired:
                return False, f"stop_cmd timed out for port {self.port}"
            except Exception as e:
                return False, f"stop_cmd error: {e}"

        return True, f"External vLLM on port {self.port} (no-op, externally managed)"

    def get_status(self) -> VLLMStatus:
        """状態を取得"""
        is_ready = self.health_check()
        return VLLMStatus(
            is_running=is_ready,
            is_ready=is_ready,
            port=self.port
        )


class RemoteVLLMManagerWrapper(BaseVLLMManager):
    """リモートvLLMのラッパー"""

    def __init__(
        self,
        port: int,
        vllm_config: VLLMConfig,
        host: str,
        user: str,
        session_name: str,
        remote_port: int = 8000,
        gpu: int = 0
    ):
        super().__init__(port, vllm_config)
        self.remote = RemoteVLLMManager(
            host=host,
            user=user,
            session_name=session_name,
            local_port=port,
            remote_port=remote_port,
            gpu=gpu
        )

    def start(self) -> Tuple[bool, str]:
        """vLLMを起動"""
        return self.remote.start(
            model=self.vllm_config.model,
            max_model_len=self.vllm_config.max_model_len,
            gpu_memory_utilization=self.vllm_config.gpu_memory_utilization
        )

    def stop(self) -> Tuple[bool, str]:
        """vLLMを停止"""
        return self.remote.stop()

    def get_status(self) -> VLLMStatus:
        """状態を取得"""
        is_ready = self.health_check()
        return VLLMStatus(
            is_running=is_ready,  # リモートではrunning≈ready
            is_ready=is_ready,
            port=self.port
        )

    def check_orphan(self) -> Tuple[bool, str]:
        """孤立セッションの確認"""
        return self.remote.check_orphan_session()


def create_vllm_manager(
    worker_config: WorkerConfig,
    vllm_config: VLLMConfig,
    log_dir: Optional[Path] = None
) -> BaseVLLMManager:
    """
    WorkerConfigからvLLMManagerを生成

    Args:
        worker_config: Worker設定
        vllm_config: vLLM設定
        log_dir: ログディレクトリ

    Returns:
        BaseVLLMManager のサブクラスインスタンス
    """
    if worker_config.type == "local":
        return LocalVLLMManager(
            port=worker_config.port,
            gpu=worker_config.gpu,
            vllm_config=vllm_config,
            log_dir=log_dir
        )
    elif worker_config.type == "external":
        return ExternalVLLMManager(
            port=worker_config.port,
            vllm_config=vllm_config,
            start_cmd=worker_config.start_cmd,
            stop_cmd=worker_config.stop_cmd
        )
    elif worker_config.type == "remote":
        if not worker_config.ssh or not worker_config.tmux:
            raise ValueError(f"Worker {worker_config.id}: remote type requires ssh and tmux config")

        return RemoteVLLMManagerWrapper(
            port=worker_config.port,
            vllm_config=vllm_config,
            host=worker_config.ssh.host,
            user=worker_config.ssh.user,
            session_name=worker_config.tmux.session_name,
            remote_port=worker_config.ssh.remote_port,
            gpu=worker_config.ssh.gpu
        )
    else:
        raise ValueError(f"Unknown worker type: {worker_config.type}")


class VLLMCluster:
    """複数vLLMの管理"""

    def __init__(self):
        self.managers: List[BaseVLLMManager] = []
        self._started = False

    def add(self, manager: BaseVLLMManager):
        """マネージャーを追加"""
        self.managers.append(manager)

    def start_all(self, wait_ready: bool = True, timeout: int = 120) -> Tuple[bool, List[str]]:
        """全vLLMを起動"""
        messages = []
        all_ok = True

        for mgr in self.managers:
            ok, msg = mgr.start()
            messages.append(f"Port {mgr.port}: {msg}")
            if not ok:
                all_ok = False

        if all_ok and wait_ready:
            for mgr in self.managers:
                ok, msg = mgr.wait_ready(timeout=timeout)
                if not ok:
                    all_ok = False
                    messages.append(f"Port {mgr.port}: {msg}")

        self._started = all_ok
        return all_ok, messages

    # 変更履歴:
    #   - 2026-01-24: stop_by_port追加（Worker完了時に個別vLLM停止）
    def stop_by_port(self, port: int) -> str:
        """指定ポートのvLLMを停止"""
        for mgr in self.managers:
            if mgr.port == port:
                ok, msg = mgr.stop()
                return f"Port {port}: {msg}"
        return f"Port {port}: manager not found"

    def stop_all(self) -> List[str]:
        """全vLLMを停止"""
        messages = []
        for mgr in self.managers:
            ok, msg = mgr.stop()
            messages.append(f"Port {mgr.port}: {msg}")
        self._started = False
        return messages

    def health_check_all(self) -> dict:
        """全vLLMのヘルスチェック"""
        return {mgr.port: mgr.health_check() for mgr in self.managers}

    def get_healthy_ports(self) -> List[int]:
        """正常なポートのリストを取得"""
        return [mgr.port for mgr in self.managers if mgr.health_check()]

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._started:
            self.stop_all()
