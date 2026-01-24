#!/usr/bin/env python3
"""
vLLM Server Manager

Provides automatic start/stop of vLLM server for 02_main.py pipeline.

Usage:
    from scripts.vllm_manager import VLLMManager

    with VLLMManager(cfg) as manager:
        # vLLM is now running
        result = extract_brands_via_llm(cfg)
    # vLLM is automatically stopped
"""

import os
import subprocess
import time
import signal
import socket
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse
import requests


class VLLMManager:
    """
    Context manager for vLLM server lifecycle.

    Automatically starts vLLM server when entering context,
    and stops it when exiting.
    """

    def __init__(
        self,
        cfg: dict,
        model: str = None,
        host: str = None,
        port: int = None,
        auto_start: bool = True,
        startup_timeout: int = 120,
        gpu_memory_utilization: float = 0.85,
        max_model_len: int = 8192,
    ):
        """
        Initialize vLLM manager.

        Args:
            cfg: Configuration dict with llm_base_url, llm_model
            model: Override model name (default: from cfg or Qwen/Qwen3-4B)
            host: Override host (default: from cfg or 127.0.0.1)
            port: Override port (default: from cfg or 8000)
            auto_start: Whether to auto-start server (default: True)
            startup_timeout: Max seconds to wait for server startup
            gpu_memory_utilization: GPU memory fraction to use
            max_model_len: Maximum sequence length
        """
        self.cfg = cfg
        self.auto_start = auto_start
        self.startup_timeout = startup_timeout
        self.gpu_memory_utilization = gpu_memory_utilization
        self.max_model_len = max_model_len

        # Parse base URL from config
        base_url = cfg.get('llm_base_url', 'http://127.0.0.1:8000/v1')
        parsed = urlparse(base_url)

        self.host = host or parsed.hostname or '127.0.0.1'
        self.port = port or parsed.port or 8000
        self.model = model or cfg.get('llm_model', 'Qwen/Qwen3-4B')

        # PID and log file paths
        self.script_dir = Path(__file__).parent
        self.pid_file = self.script_dir / '.vllm.pid'
        self.log_file = self.script_dir / 'vllm.log'

        # Process handle
        self._process: Optional[subprocess.Popen] = None
        self._started_by_us = False

    def is_server_running(self) -> bool:
        """Check if vLLM server is already running."""
        # Check PID file
        if self.pid_file.exists():
            try:
                pid = int(self.pid_file.read_text().strip())
                # Check if process exists
                os.kill(pid, 0)
                return True
            except (ValueError, ProcessLookupError, PermissionError):
                pass

        # Check if port is in use
        return self._is_port_in_use()

    def _is_port_in_use(self) -> bool:
        """Check if the configured port is in use."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            return s.connect_ex((self.host, self.port)) == 0

    def _wait_for_server(self, timeout: int = None) -> bool:
        """Wait for server to become ready."""
        timeout = timeout or self.startup_timeout
        health_url = f"http://{self.host}:{self.port}/health"
        models_url = f"http://{self.host}:{self.port}/v1/models"

        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                # First check basic connectivity
                if self._is_port_in_use():
                    # Then check health endpoint
                    try:
                        resp = requests.get(health_url, timeout=5)
                        if resp.status_code == 200:
                            # Finally verify models are loaded
                            resp = requests.get(models_url, timeout=5)
                            if resp.status_code == 200:
                                return True
                    except requests.exceptions.RequestException:
                        pass
            except Exception:
                pass
            time.sleep(2)
        return False

    def start(self) -> bool:
        """Start vLLM server if not already running."""
        if self.is_server_running():
            print(f"   vLLM server already running on {self.host}:{self.port}")
            return True

        print(f"   Starting vLLM server...")
        print(f"     Model: {self.model}")
        print(f"     Endpoint: http://{self.host}:{self.port}/v1")

        # Build command
        cmd = [
            'vllm', 'serve', self.model,
            '--dtype', 'auto',
            '--max-model-len', str(self.max_model_len),
            '--max-num-seqs', '8',
            '--gpu-memory-utilization', str(self.gpu_memory_utilization),
            '--host', self.host,
            '--port', str(self.port),
        ]

        # Start server
        with open(self.log_file, 'w') as log:
            self._process = subprocess.Popen(
                cmd,
                stdout=log,
                stderr=subprocess.STDOUT,
                preexec_fn=os.setsid,  # Create new process group
            )

        # Save PID
        self.pid_file.write_text(str(self._process.pid))
        self._started_by_us = True

        print(f"     PID: {self._process.pid}")
        print(f"     Log: {self.log_file}")
        print(f"     Waiting for server to be ready (max {self.startup_timeout}s)...")

        if self._wait_for_server():
            print(f"   vLLM server is ready!")
            return True
        else:
            print(f"   ERROR: vLLM server failed to start within {self.startup_timeout}s")
            print(f"   Check log: {self.log_file}")
            self.stop()
            return False

    def stop(self) -> None:
        """Stop vLLM server if we started it."""
        if not self._started_by_us:
            return

        print("   Stopping vLLM server...")

        # Get PID
        pid = None
        if self._process:
            pid = self._process.pid
        elif self.pid_file.exists():
            try:
                pid = int(self.pid_file.read_text().strip())
            except (ValueError, FileNotFoundError):
                pass

        if pid:
            try:
                # Send SIGTERM to process group
                os.killpg(os.getpgid(pid), signal.SIGTERM)

                # Wait for graceful shutdown
                for _ in range(10):
                    try:
                        os.kill(pid, 0)
                        time.sleep(1)
                    except ProcessLookupError:
                        break
                else:
                    # Force kill if still running
                    try:
                        os.killpg(os.getpgid(pid), signal.SIGKILL)
                    except ProcessLookupError:
                        pass

                print("   vLLM server stopped.")
            except ProcessLookupError:
                print("   vLLM server already stopped.")
            except Exception as e:
                print(f"   Warning: Error stopping vLLM: {e}")

        # Cleanup PID file
        if self.pid_file.exists():
            self.pid_file.unlink()

        self._process = None
        self._started_by_us = False

    def __enter__(self):
        """Context manager entry."""
        if self.auto_start:
            if not self.start():
                raise RuntimeError("Failed to start vLLM server")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.stop()
        return False


def check_vllm_status(cfg: dict) -> dict:
    """
    Check vLLM server status.

    Returns:
        dict with 'running', 'url', 'model' keys
    """
    base_url = cfg.get('llm_base_url', 'http://127.0.0.1:8000/v1')
    parsed = urlparse(base_url)
    host = parsed.hostname or '127.0.0.1'
    port = parsed.port or 8000

    status = {
        'running': False,
        'url': f"http://{host}:{port}/v1",
        'model': None,
    }

    try:
        resp = requests.get(f"http://{host}:{port}/v1/models", timeout=5)
        if resp.status_code == 200:
            status['running'] = True
            data = resp.json()
            if data.get('data'):
                status['model'] = data['data'][0].get('id')
    except Exception:
        pass

    return status


if __name__ == '__main__':
    # Test usage
    import sys

    if len(sys.argv) < 2:
        print("Usage: python vllm_manager.py {start|stop|status}")
        sys.exit(1)

    cfg = {
        'llm_base_url': 'http://127.0.0.1:8000/v1',
        'llm_model': 'Qwen/Qwen3-4B',
    }

    cmd = sys.argv[1]

    if cmd == 'status':
        status = check_vllm_status(cfg)
        print(f"vLLM Status: {'Running' if status['running'] else 'Stopped'}")
        if status['running']:
            print(f"  URL: {status['url']}")
            print(f"  Model: {status['model']}")
    elif cmd == 'start':
        manager = VLLMManager(cfg, auto_start=False)
        manager.start()
    elif cmd == 'stop':
        manager = VLLMManager(cfg, auto_start=False)
        manager._started_by_us = True  # Force stop
        manager.stop()
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)
