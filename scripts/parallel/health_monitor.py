"""
ヘルスチェックモジュール

vLLMサーバーの状態を監視し、障害を検出する
"""

import threading
import time
import queue
from dataclasses import dataclass
from typing import Dict, List, Callable, Optional
from enum import Enum


class HealthStatus(Enum):
    """ヘルス状態"""
    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


@dataclass
class HealthEvent:
    """ヘルスイベント"""
    port: int
    status: HealthStatus
    previous_status: HealthStatus
    failure_count: int
    timestamp: float
    message: str


class HealthMonitor:
    """
    vLLMのヘルス監視

    バックグラウンドスレッドで定期的にヘルスチェックを実行し、
    障害検出時にコールバックを呼び出す
    """

    def __init__(
        self,
        check_interval: int = 5,
        timeout: int = 10,
        max_failures: int = 3
    ):
        """
        Args:
            check_interval: チェック間隔（秒）
            timeout: タイムアウト（秒）
            max_failures: 障害判定の連続失敗回数
        """
        self.check_interval = check_interval
        self.timeout = timeout
        self.max_failures = max_failures

        self._ports: List[int] = []
        self._status: Dict[int, HealthStatus] = {}
        self._failure_counts: Dict[int, int] = {}
        self._callbacks: List[Callable[[HealthEvent], None]] = []

        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._event_queue: queue.Queue = queue.Queue()
        self._lock = threading.Lock()

    def add_port(self, port: int):
        """監視対象ポートを追加"""
        with self._lock:
            if port not in self._ports:
                self._ports.append(port)
                self._status[port] = HealthStatus.UNKNOWN
                self._failure_counts[port] = 0

    def remove_port(self, port: int):
        """監視対象ポートを削除"""
        with self._lock:
            if port in self._ports:
                self._ports.remove(port)
                del self._status[port]
                del self._failure_counts[port]

    def add_callback(self, callback: Callable[[HealthEvent], None]):
        """障害検出時のコールバックを追加"""
        self._callbacks.append(callback)

    def start(self):
        """監視開始"""
        if self._running:
            return

        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()

    def stop(self):
        """監視停止"""
        self._running = False
        if self._thread:
            self._thread.join(timeout=self.check_interval + 1)

    def get_status(self, port: int) -> HealthStatus:
        """指定ポートの状態を取得"""
        with self._lock:
            return self._status.get(port, HealthStatus.UNKNOWN)

    def get_all_status(self) -> Dict[int, HealthStatus]:
        """全ポートの状態を取得"""
        with self._lock:
            return dict(self._status)

    def get_healthy_ports(self) -> List[int]:
        """正常なポートのリストを取得"""
        with self._lock:
            return [p for p, s in self._status.items() if s == HealthStatus.HEALTHY]

    def get_unhealthy_ports(self) -> List[int]:
        """異常なポートのリストを取得"""
        with self._lock:
            return [p for p, s in self._status.items() if s == HealthStatus.UNHEALTHY]

    def wait_for_failure(self, timeout: Optional[float] = None) -> Optional[HealthEvent]:
        """障害イベントを待機"""
        try:
            return self._event_queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def _monitor_loop(self):
        """監視ループ"""
        while self._running:
            with self._lock:
                ports = list(self._ports)

            for port in ports:
                self._check_port(port)

            time.sleep(self.check_interval)

    def _check_port(self, port: int):
        """単一ポートのヘルスチェック"""
        import requests

        try:
            resp = requests.get(
                f"http://localhost:{port}/v1/models",
                timeout=self.timeout
            )
            is_healthy = resp.status_code == 200
        except:
            is_healthy = False

        with self._lock:
            previous_status = self._status.get(port, HealthStatus.UNKNOWN)

            if is_healthy:
                self._failure_counts[port] = 0
                new_status = HealthStatus.HEALTHY
            else:
                self._failure_counts[port] += 1
                if self._failure_counts[port] >= self.max_failures:
                    new_status = HealthStatus.UNHEALTHY
                else:
                    new_status = previous_status  # 即座に異常判定しない

            self._status[port] = new_status

            # 状態変化時にイベント発行
            if new_status != previous_status:
                event = HealthEvent(
                    port=port,
                    status=new_status,
                    previous_status=previous_status,
                    failure_count=self._failure_counts[port],
                    timestamp=time.time(),
                    message=self._get_status_message(port, new_status)
                )

                # コールバック呼び出し
                for callback in self._callbacks:
                    try:
                        callback(event)
                    except Exception as e:
                        print(f"Health callback error: {e}")

                # イベントキューに追加
                self._event_queue.put(event)

    def _get_status_message(self, port: int, status: HealthStatus) -> str:
        """状態メッセージを生成"""
        if status == HealthStatus.HEALTHY:
            return f"vLLM on port {port} is healthy"
        elif status == HealthStatus.UNHEALTHY:
            return f"vLLM on port {port} is unhealthy (failed {self._failure_counts[port]} times)"
        else:
            return f"vLLM on port {port} status unknown"


class RecoveryManager:
    """
    障害復旧の管理

    ヘルスモニターと連携して、障害検出時に自動復旧を試みる
    """

    def __init__(
        self,
        health_monitor: HealthMonitor,
        vllm_managers: Dict[int, 'BaseVLLMManager'],  # port -> manager
        max_restarts: int = 3,
        restart_delay: int = 30
    ):
        self.health_monitor = health_monitor
        self.vllm_managers = vllm_managers
        self.max_restarts = max_restarts
        self.restart_delay = restart_delay

        self._restart_counts: Dict[int, int] = {p: 0 for p in vllm_managers}
        self._recovery_callbacks: List[Callable[[int, bool], None]] = []
        self._lock = threading.Lock()

        # ヘルスモニターにコールバック登録
        health_monitor.add_callback(self._on_health_event)

    def add_recovery_callback(self, callback: Callable[[int, bool], None]):
        """復旧結果コールバックを追加 (port, success)"""
        self._recovery_callbacks.append(callback)

    def _on_health_event(self, event: HealthEvent):
        """ヘルスイベント処理"""
        if event.status == HealthStatus.UNHEALTHY:
            self._attempt_recovery(event.port)

    def _attempt_recovery(self, port: int):
        """復旧を試みる"""
        with self._lock:
            if port not in self.vllm_managers:
                return

            self._restart_counts[port] += 1
            restart_count = self._restart_counts[port]

            if restart_count > self.max_restarts:
                print(f"[Recovery] Port {port}: Max restarts exceeded ({self.max_restarts})")
                self._notify_recovery(port, False)
                return

        print(f"[Recovery] Port {port}: Attempting restart ({restart_count}/{self.max_restarts})")

        manager = self.vllm_managers[port]

        # 停止
        manager.stop()
        time.sleep(self.restart_delay)

        # 再起動
        ok, msg = manager.start()
        if ok:
            ok, msg = manager.wait_ready(timeout=120)

        if ok:
            print(f"[Recovery] Port {port}: Restart successful")
            with self._lock:
                self._restart_counts[port] = 0  # リセット
            self._notify_recovery(port, True)
        else:
            print(f"[Recovery] Port {port}: Restart failed - {msg}")
            # 次の障害検出で再試行される

    def _notify_recovery(self, port: int, success: bool):
        """復旧結果を通知"""
        for callback in self._recovery_callbacks:
            try:
                callback(port, success)
            except Exception as e:
                print(f"Recovery callback error: {e}")

    def reset_restart_count(self, port: int):
        """再起動カウントをリセット"""
        with self._lock:
            self._restart_counts[port] = 0

    def get_restart_counts(self) -> Dict[int, int]:
        """再起動カウントを取得"""
        with self._lock:
            return dict(self._restart_counts)
