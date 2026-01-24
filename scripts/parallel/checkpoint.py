"""
チェックポイント管理モジュール

評価の進捗を保存・復元する
"""

import os
import json
import csv
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Any
import threading
import fcntl


@dataclass
class WorkerProgress:
    """Worker単位の進捗"""
    worker_id: int
    status: str = "pending"  # pending, running, completed, failed
    total: int = 0
    completed: int = 0
    failed: int = 0
    last_completed_domain: str = ""
    last_completed_index: int = -1
    current_processing: Optional[str] = None
    current_index: int = -1
    started_at: Optional[str] = None
    updated_at: Optional[str] = None
    vllm_restarts: int = 0
    errors: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class GlobalState:
    """全体の状態"""
    run_id: str
    total_domains: int
    num_workers: int
    active_workers: List[int] = field(default_factory=list)
    failed_workers: List[int] = field(default_factory=list)
    started_at: Optional[str] = None
    updated_at: Optional[str] = None
    completed: bool = False


@dataclass
class CheckpointData:
    """チェックポイントデータ"""
    global_state: GlobalState
    workers: Dict[int, WorkerProgress] = field(default_factory=dict)
    redistribution: Optional[Dict[str, Any]] = None


class CheckpointManager:
    """チェックポイントの管理"""

    def __init__(self, checkpoint_dir: Path, run_id: str):
        self.checkpoint_dir = Path(checkpoint_dir)
        self.run_id = run_id
        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)

        self._lock = threading.Lock()
        self._global_state_file = self.checkpoint_dir / "parallel_state.json"
        self._worker_state_files: Dict[int, Path] = {}

    def init_global_state(self, total_domains: int, num_workers: int) -> GlobalState:
        """グローバル状態を初期化"""
        state = GlobalState(
            run_id=self.run_id,
            total_domains=total_domains,
            num_workers=num_workers,
            active_workers=list(range(num_workers)),
            started_at=datetime.now().isoformat()
        )
        self._save_global_state(state)
        return state

    def init_worker_state(self, worker_id: int, total: int, domains: List[str]) -> WorkerProgress:
        """Worker状態を初期化"""
        self._worker_state_files[worker_id] = self.checkpoint_dir / f"worker_{worker_id}_checkpoint.json"

        progress = WorkerProgress(
            worker_id=worker_id,
            status="pending",
            total=total,
            started_at=datetime.now().isoformat()
        )
        self._save_worker_state(progress)

        # ドメインリストも保存
        domains_file = self.checkpoint_dir / f"worker_{worker_id}_domains.json"
        with open(domains_file, 'w') as f:
            json.dump(domains, f)

        return progress

    def load_checkpoint(self) -> Optional[CheckpointData]:
        """チェックポイントを読み込み"""
        if not self._global_state_file.exists():
            return None

        try:
            # グローバル状態
            with open(self._global_state_file) as f:
                global_data = json.load(f)
            global_state = GlobalState(**global_data)

            # Worker状態
            workers = {}
            for worker_id in range(global_state.num_workers):
                worker_file = self.checkpoint_dir / f"worker_{worker_id}_checkpoint.json"
                if worker_file.exists():
                    with open(worker_file) as f:
                        worker_data = json.load(f)
                    # errorsフィールドのデフォルト処理
                    if 'errors' not in worker_data:
                        worker_data['errors'] = []
                    workers[worker_id] = WorkerProgress(**worker_data)

            return CheckpointData(
                global_state=global_state,
                workers=workers
            )

        except Exception as e:
            print(f"Error loading checkpoint: {e}")
            return None

    def update_worker_progress(
        self,
        worker_id: int,
        domain: str,
        index: int,
        success: bool,
        error: Optional[str] = None
    ):
        """Worker進捗を更新"""
        with self._lock:
            worker_file = self.checkpoint_dir / f"worker_{worker_id}_checkpoint.json"

            # 現在の状態を読み込み
            if worker_file.exists():
                with open(worker_file) as f:
                    data = json.load(f)
                if 'errors' not in data:
                    data['errors'] = []
                progress = WorkerProgress(**data)
            else:
                progress = WorkerProgress(worker_id=worker_id)

            # 更新
            progress.status = "running"
            progress.updated_at = datetime.now().isoformat()

            if success:
                progress.completed += 1
                progress.last_completed_domain = domain
                progress.last_completed_index = index
            else:
                progress.failed += 1
                progress.errors.append({
                    "domain": domain,
                    "index": index,
                    "error": error,
                    "timestamp": datetime.now().isoformat()
                })

            progress.current_processing = None
            progress.current_index = -1

            self._save_worker_state(progress)

    def mark_worker_processing(self, worker_id: int, domain: str, index: int):
        """処理中のドメインをマーク"""
        with self._lock:
            worker_file = self.checkpoint_dir / f"worker_{worker_id}_checkpoint.json"

            if worker_file.exists():
                with open(worker_file) as f:
                    data = json.load(f)
                if 'errors' not in data:
                    data['errors'] = []
                progress = WorkerProgress(**data)
            else:
                progress = WorkerProgress(worker_id=worker_id)

            progress.current_processing = domain
            progress.current_index = index
            progress.updated_at = datetime.now().isoformat()

            self._save_worker_state(progress)

    def mark_worker_completed(self, worker_id: int):
        """Worker完了をマーク"""
        with self._lock:
            worker_file = self.checkpoint_dir / f"worker_{worker_id}_checkpoint.json"

            if worker_file.exists():
                with open(worker_file) as f:
                    data = json.load(f)
                if 'errors' not in data:
                    data['errors'] = []
                progress = WorkerProgress(**data)
                progress.status = "completed"
                progress.updated_at = datetime.now().isoformat()
                self._save_worker_state(progress)

    def mark_worker_failed(self, worker_id: int, error: str):
        """Worker失敗をマーク"""
        with self._lock:
            worker_file = self.checkpoint_dir / f"worker_{worker_id}_checkpoint.json"

            if worker_file.exists():
                with open(worker_file) as f:
                    data = json.load(f)
                if 'errors' not in data:
                    data['errors'] = []
                progress = WorkerProgress(**data)
                progress.status = "failed"
                progress.errors.append({
                    "error": error,
                    "timestamp": datetime.now().isoformat()
                })
                progress.updated_at = datetime.now().isoformat()
                self._save_worker_state(progress)

    def record_vllm_restart(self, worker_id: int):
        """vLLM再起動を記録"""
        with self._lock:
            worker_file = self.checkpoint_dir / f"worker_{worker_id}_checkpoint.json"

            if worker_file.exists():
                with open(worker_file) as f:
                    data = json.load(f)
                if 'errors' not in data:
                    data['errors'] = []
                progress = WorkerProgress(**data)
                progress.vllm_restarts += 1
                progress.updated_at = datetime.now().isoformat()
                self._save_worker_state(progress)

    def get_resume_index(self, worker_id: int) -> int:
        """再開位置を取得"""
        worker_file = self.checkpoint_dir / f"worker_{worker_id}_checkpoint.json"

        if not worker_file.exists():
            return 0

        with open(worker_file) as f:
            data = json.load(f)

        # 処理中だったドメインがあればそこから、なければ次から
        if data.get('current_index', -1) >= 0:
            return data['current_index']
        elif data.get('last_completed_index', -1) >= 0:
            return data['last_completed_index'] + 1
        else:
            return 0

    def _save_global_state(self, state: GlobalState):
        """グローバル状態を保存"""
        state.updated_at = datetime.now().isoformat()
        self._atomic_write(self._global_state_file, asdict(state))

    def _save_worker_state(self, progress: WorkerProgress):
        """Worker状態を保存"""
        worker_file = self.checkpoint_dir / f"worker_{progress.worker_id}_checkpoint.json"
        self._atomic_write(worker_file, asdict(progress))

    def _atomic_write(self, path: Path, data: dict):
        """アトミック書き込み（クラッシュセーフ）"""
        temp_path = path.with_suffix('.tmp')

        with open(temp_path, 'w') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())

        temp_path.rename(path)


class ResultWriter:
    """結果のWAL書き込み"""

    def __init__(self, result_file: Path, fieldnames: List[str]):
        self.result_file = Path(result_file)
        self.fieldnames = fieldnames
        self._lock = threading.Lock()
        self._init_file()

    def _init_file(self):
        """ファイル初期化"""
        if not self.result_file.exists():
            self.result_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.result_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=self.fieldnames)
                writer.writeheader()

    def append(self, row: dict):
        """1行追記"""
        with self._lock:
            with open(self.result_file, 'a', newline='') as f:
                # ファイルロック
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                try:
                    writer = csv.DictWriter(f, fieldnames=self.fieldnames)
                    writer.writerow({k: row.get(k, '') for k in self.fieldnames})
                    f.flush()
                    os.fsync(f.fileno())
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)

    def count_rows(self) -> int:
        """行数をカウント"""
        if not self.result_file.exists():
            return 0
        with open(self.result_file) as f:
            return sum(1 for _ in f) - 1  # ヘッダー除く
