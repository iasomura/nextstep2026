"""
GPU空き確認モジュール

ローカルおよびリモートのGPU状態を確認する
"""

import subprocess
import re
from dataclasses import dataclass
from typing import List, Optional, Dict
import xml.etree.ElementTree as ET


@dataclass
class GPUInfo:
    """GPU情報"""
    id: int
    name: str
    memory_used_mb: int
    memory_total_mb: int
    utilization_percent: int
    processes: List[Dict[str, str]]

    @property
    def memory_free_mb(self) -> int:
        return self.memory_total_mb - self.memory_used_mb

    @property
    def is_available(self) -> bool:
        """GPUが利用可能か（メモリ使用が少ない）"""
        return self.memory_used_mb < 1000

    @property
    def has_other_users(self) -> bool:
        """他ユーザーのプロセスがあるか"""
        import os
        current_user = os.environ.get('USER', '')
        for proc in self.processes:
            if proc.get('user', '') != current_user:
                return True
        return False


def get_local_gpu_info() -> List[GPUInfo]:
    """
    ローカルのGPU情報を取得

    Returns:
        GPUInfo のリスト
    """
    try:
        # nvidia-smi をXML形式で実行
        result = subprocess.run(
            ['nvidia-smi', '-q', '-x'],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode != 0:
            print(f"nvidia-smi failed: {result.stderr}")
            return []

        return _parse_nvidia_smi_xml(result.stdout)

    except FileNotFoundError:
        print("nvidia-smi not found. Is NVIDIA driver installed?")
        return []
    except subprocess.TimeoutExpired:
        print("nvidia-smi timed out")
        return []
    except Exception as e:
        print(f"Error getting GPU info: {e}")
        return []


def get_remote_gpu_info(host: str, user: str) -> List[GPUInfo]:
    """
    リモートのGPU情報を取得

    Args:
        host: リモートホスト
        user: SSHユーザー

    Returns:
        GPUInfo のリスト
    """
    try:
        result = subprocess.run(
            ['ssh', f'{user}@{host}', 'nvidia-smi', '-q', '-x'],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode != 0:
            print(f"Remote nvidia-smi failed on {host}: {result.stderr}")
            return []

        return _parse_nvidia_smi_xml(result.stdout)

    except subprocess.TimeoutExpired:
        print(f"SSH to {host} timed out")
        return []
    except Exception as e:
        print(f"Error getting remote GPU info from {host}: {e}")
        return []


def _parse_nvidia_smi_xml(xml_str: str) -> List[GPUInfo]:
    """nvidia-smi XML出力をパース"""
    gpus = []

    try:
        root = ET.fromstring(xml_str)

        for i, gpu in enumerate(root.findall('gpu')):
            name = gpu.find('product_name').text or f"GPU {i}"

            # メモリ情報
            fb_memory = gpu.find('fb_memory_usage')
            memory_used = _parse_memory(fb_memory.find('used').text)
            memory_total = _parse_memory(fb_memory.find('total').text)

            # 使用率
            utilization = gpu.find('utilization')
            gpu_util = utilization.find('gpu_util').text
            util_percent = int(re.search(r'(\d+)', gpu_util).group(1)) if gpu_util else 0

            # プロセス情報
            processes = []
            procs_elem = gpu.find('processes')
            if procs_elem is not None:
                for proc in procs_elem.findall('process_info'):
                    pid = proc.find('pid').text
                    proc_name = proc.find('process_name').text
                    used_mem = proc.find('used_memory').text

                    # ユーザー名を取得
                    user = _get_process_user(pid)

                    processes.append({
                        'pid': pid,
                        'name': proc_name,
                        'memory': used_mem,
                        'user': user
                    })

            gpus.append(GPUInfo(
                id=i,
                name=name,
                memory_used_mb=memory_used,
                memory_total_mb=memory_total,
                utilization_percent=util_percent,
                processes=processes
            ))

    except ET.ParseError as e:
        print(f"Failed to parse nvidia-smi XML: {e}")
    except Exception as e:
        print(f"Error parsing GPU info: {e}")

    return gpus


def _parse_memory(mem_str: str) -> int:
    """メモリ文字列をMBに変換"""
    if not mem_str:
        return 0
    match = re.search(r'(\d+)', mem_str)
    return int(match.group(1)) if match else 0


def _get_process_user(pid: str) -> str:
    """PIDからユーザー名を取得"""
    try:
        result = subprocess.run(
            ['ps', '-o', 'user=', '-p', pid],
            capture_output=True,
            text=True,
            timeout=5
        )
        return result.stdout.strip()
    except:
        return ""


def check_gpu_availability(
    gpu_id: int,
    threshold_mb: int = 1000,
    local: bool = True,
    host: Optional[str] = None,
    user: Optional[str] = None
) -> tuple[bool, Optional[GPUInfo], str]:
    """
    指定GPUの利用可能性をチェック

    Args:
        gpu_id: GPU ID
        threshold_mb: 空き判定の閾値(MB)
        local: ローカルGPUか
        host: リモートホスト
        user: SSHユーザー

    Returns:
        (利用可能か, GPUInfo, メッセージ)
    """
    if local:
        gpus = get_local_gpu_info()
    else:
        if not host or not user:
            return False, None, "Remote host/user not specified"
        gpus = get_remote_gpu_info(host, user)

    if not gpus:
        return False, None, "Failed to get GPU info"

    if gpu_id >= len(gpus):
        return False, None, f"GPU {gpu_id} not found (only {len(gpus)} GPUs available)"

    gpu = gpus[gpu_id]

    if gpu.memory_used_mb >= threshold_mb:
        msg = f"GPU {gpu_id} is in use ({gpu.memory_used_mb}MB used)"
        if gpu.processes:
            users = set(p.get('user', 'unknown') for p in gpu.processes)
            msg += f" by {', '.join(users)}"
        return False, gpu, msg

    if gpu.has_other_users:
        return True, gpu, f"GPU {gpu_id} available but has other user processes"

    return True, gpu, f"GPU {gpu_id} is available ({gpu.memory_free_mb}MB free)"


def print_gpu_status(gpus: List[GPUInfo], title: str = "GPU Status"):
    """GPU状態をテーブル形式で表示"""
    print("=" * 80)
    print(title)
    print("=" * 80)
    print(f"{'GPU':^4} | {'Memory Used':^12} | {'Memory Total':^12} | {'Util':^6} | {'User Processes':^20} | {'Available':^10}")
    print("-" * 80)

    for gpu in gpus:
        users = set(p.get('user', 'unknown') for p in gpu.processes) if gpu.processes else {'(none)'}
        users_str = ', '.join(users)[:20]
        available = "Yes" if gpu.is_available else "No"

        print(f" {gpu.id:^3} | {gpu.memory_used_mb:>8} MB | {gpu.memory_total_mb:>8} MB | {gpu.utilization_percent:>4}% | {users_str:<20} | {'✓ ' + available if gpu.is_available else '✗ ' + available:^10}")

    print("=" * 80)


if __name__ == "__main__":
    # テスト実行
    print("Checking local GPUs...")
    gpus = get_local_gpu_info()
    if gpus:
        print_gpu_status(gpus, "Local GPU Status")
    else:
        print("No GPUs found or nvidia-smi failed")
