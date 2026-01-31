"""
オーケストレーターモジュール

並列評価の全体制御を行う

変更履歴:
    - 2026-01-26: 証明書データ統合 - cert_features_fileをworkerに渡すように変更
"""

import os
import sys
import json
import time
import signal
import multiprocessing
from pathlib import Path
from dataclasses import dataclass
from typing import List, Dict, Any, Optional
from datetime import datetime

import pandas as pd

from .config import ParallelConfig, WorkerConfig, load_config
from .vllm_manager import VLLMCluster, create_vllm_manager, BaseVLLMManager
from .checkpoint import CheckpointManager, ResultWriter, CheckpointData
from .health_monitor import HealthMonitor, RecoveryManager, HealthStatus
from .gpu_checker import get_local_gpu_info, get_remote_gpu_info, print_gpu_status, check_gpu_availability


@dataclass
class EvaluationResult:
    """評価結果サマリー"""
    run_id: str
    total_domains: int
    completed: int
    failed: int
    elapsed_seconds: float
    workers_used: int
    result_file: Path


class ParallelOrchestrator:
    """
    並列評価のオーケストレーター

    vLLMクラスター、Worker、ヘルスモニターを統合管理する
    """

    def __init__(
        self,
        config: ParallelConfig,
        run_id: str,
        artifacts_dir: Path,
        base_dir: Path,
        additional_gpus: Optional[List[int]] = None,
        skip_confirmation: bool = False,
        cert_features_file: Optional[Path] = None
    ):
        """
        Args:
            config: 並列評価設定
            run_id: 実行ID
            artifacts_dir: 成果物ディレクトリ
            base_dir: プロジェクトベースディレクトリ
            additional_gpus: 追加で使用するGPU/Worker ID
            skip_confirmation: 確認プロンプトをスキップ
            cert_features_file: 証明書特徴量CSVファイル
        """
        self.config = config
        self.skip_confirmation = skip_confirmation
        self.run_id = run_id
        self.artifacts_dir = Path(artifacts_dir)
        self.base_dir = Path(base_dir)
        self.cert_features_file = Path(cert_features_file) if cert_features_file else None

        # 使用するWorker設定
        self.active_workers = config.get_active_workers(additional_gpus)
        print(f"[Orchestrator] Active workers: {[w.id for w in self.active_workers]}")

        # ディレクトリ設定
        self.results_dir = self.artifacts_dir / "results" / "stage2_validation"
        self.logs_dir = self.artifacts_dir / "logs" / "parallel"
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.logs_dir.mkdir(parents=True, exist_ok=True)

        # コンポーネント
        self.vllm_cluster: Optional[VLLMCluster] = None
        self.checkpoint_manager: Optional[CheckpointManager] = None
        self.health_monitor: Optional[HealthMonitor] = None
        self.recovery_manager: Optional[RecoveryManager] = None

        # 状態
        self._worker_processes: Dict[int, multiprocessing.Process] = {}
        self._shutdown_requested = False

        # 証明書データ確認
        if self.cert_features_file and self.cert_features_file.exists():
            print(f"[Orchestrator] Certificate features: {self.cert_features_file}")
        elif self.cert_features_file:
            print(f"[Orchestrator] Warning: Certificate file not found: {self.cert_features_file}")

    def check_gpus(self) -> Dict[int, Dict[str, Any]]:
        """GPU状態を確認"""
        import requests

        results = {}

        for worker in self.active_workers:
            if worker.type == "local":
                available, gpu_info, msg = check_gpu_availability(
                    worker.gpu,
                    threshold_mb=self.config.shared_server.gpu_memory_threshold_mb,
                    local=True
                )
                results[worker.id] = {
                    "type": "local",
                    "gpu": worker.gpu,
                    "available": available,
                    "message": msg,
                    "info": gpu_info
                }
            elif worker.type == "external":
                # 外部管理: エンドポイントの到達性のみ確認
                try:
                    resp = requests.get(
                        f"http://localhost:{worker.port}/v1/models",
                        timeout=5
                    )
                    available = resp.status_code == 200
                    msg = f"External vLLM on port {worker.port} is reachable" if available else f"External vLLM on port {worker.port} not responding"
                except Exception as e:
                    available = False
                    msg = f"External vLLM on port {worker.port} unreachable: {e}"

                results[worker.id] = {
                    "type": "external",
                    "port": worker.port,
                    "available": available,
                    "message": msg,
                    "info": None
                }
            else:
                # リモート
                if worker.ssh:
                    available, gpu_info, msg = check_gpu_availability(
                        worker.ssh.gpu,
                        threshold_mb=self.config.shared_server.gpu_memory_threshold_mb,
                        local=False,
                        host=worker.ssh.host,
                        user=worker.ssh.user
                    )
                    results[worker.id] = {
                        "type": "remote",
                        "host": worker.ssh.host,
                        "gpu": worker.ssh.gpu,
                        "available": available,
                        "message": msg,
                        "info": gpu_info
                    }

        return results

    def setup(self) -> bool:
        """
        セットアップ

        Returns:
            成功したか
        """
        print("\n" + "=" * 70)
        print("Setting up Parallel Evaluation")
        print("=" * 70)

        # 1. GPU確認
        if self.config.shared_server.check_gpu_usage_before_start:
            print("\n[Step 1] Checking GPU availability...")
            gpu_status = self.check_gpus()

            unavailable = [wid for wid, status in gpu_status.items() if not status["available"]]
            if unavailable:
                print(f"\n⚠️  Some GPUs are not available: {unavailable}")
                for wid in unavailable:
                    print(f"   Worker {wid}: {gpu_status[wid]['message']}")

                if self.config.shared_server.require_confirmation and not self.skip_confirmation:
                    response = input("\nContinue anyway? [y/N]: ").strip().lower()
                    if response != 'y':
                        print("Aborted.")
                        return False
                else:
                    print("   (--yes specified, continuing...)")

        # 2. vLLMクラスター初期化
        print("\n[Step 2] Initializing vLLM cluster...")
        self.vllm_cluster = VLLMCluster()

        vllm_managers: Dict[int, BaseVLLMManager] = {}
        for worker in self.active_workers:
            manager = create_vllm_manager(
                worker,
                self.config.vllm,
                log_dir=self.logs_dir
            )
            self.vllm_cluster.add(manager)
            vllm_managers[worker.port] = manager

        # vLLM起動
        ok, messages = self.vllm_cluster.start_all(wait_ready=True, timeout=120)
        for msg in messages:
            print(f"   {msg}")

        if not ok:
            print("\n❌ Failed to start vLLM cluster")
            return False

        print("   ✓ vLLM cluster ready")

        # 3. ヘルスモニター初期化
        print("\n[Step 3] Starting health monitor...")
        self.health_monitor = HealthMonitor(
            check_interval=self.config.health_check.interval,
            timeout=self.config.health_check.timeout,
            max_failures=self.config.health_check.max_failures
        )

        for worker in self.active_workers:
            self.health_monitor.add_port(worker.port)

        self.health_monitor.start()
        print("   ✓ Health monitor started")

        # 4. リカバリーマネージャー初期化
        if self.config.failover.enabled:
            print("\n[Step 4] Initializing recovery manager...")
            self.recovery_manager = RecoveryManager(
                self.health_monitor,
                vllm_managers,
                max_restarts=self.config.retry.vllm_restarts,
                restart_delay=self.config.retry.vllm_restart_delay
            )
            print("   ✓ Recovery manager ready")

        # 5. チェックポイント初期化
        print("\n[Step 5] Initializing checkpoint manager...")
        self.checkpoint_manager = CheckpointManager(self.results_dir, self.run_id)
        print("   ✓ Checkpoint manager ready")

        print("\n" + "=" * 70)
        print("Setup complete!")
        print("=" * 70 + "\n")

        return True

    def run(
        self,
        target_df: pd.DataFrame,
        resume: bool = False
    ) -> Optional[EvaluationResult]:
        """
        並列評価を実行

        Args:
            target_df: 評価対象データフレーム
            resume: 前回から再開するか

        Returns:
            評価結果サマリー
        """
        start_time = time.time()
        total_domains = len(target_df)

        # シグナルハンドラ設定
        def signal_handler(signum, frame):
            print(f"\n\nReceived signal {signum}, initiating shutdown...")
            self._shutdown_requested = True
            self._stop_workers()

        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)

        # チェックポイント確認
        checkpoint_data = None
        if resume:
            checkpoint_data = self.checkpoint_manager.load_checkpoint()
            if checkpoint_data:
                print(f"[Orchestrator] Resuming from checkpoint")

        # データ分割（speed_weightに基づく比率分割）
        num_workers = len(self.active_workers)
        domains_per_worker = self._split_domains(target_df, self.active_workers)

        # グローバル状態初期化
        if not checkpoint_data:
            self.checkpoint_manager.init_global_state(total_domains, num_workers)

        # Worker起動
        print(f"\n[Orchestrator] Starting {num_workers} workers...")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        for i, worker_config in enumerate(self.active_workers):
            worker_id = worker_config.id
            domains = domains_per_worker[i]

            # 入力ファイル作成
            domains_file = self.results_dir / f"worker_{worker_id}_input.json"
            with open(domains_file, 'w') as f:
                json.dump(domains, f)

            # 結果ファイル
            result_file = self.results_dir / f"worker_{worker_id}_results.csv"

            # 再開インデックス
            start_index = 0
            if checkpoint_data and worker_id in checkpoint_data.workers:
                start_index = self.checkpoint_manager.get_resume_index(worker_id)
                print(f"   Worker {worker_id}: Resuming from index {start_index}")

            # Worker状態初期化
            if not checkpoint_data or worker_id not in checkpoint_data.workers:
                domain_names = [d["domain"] for d in domains]
                self.checkpoint_manager.init_worker_state(worker_id, len(domains), domain_names)

            # プロセス起動
            process = multiprocessing.Process(
                target=self._run_worker,
                args=(
                    worker_id,
                    worker_config.port,
                    domains_file,
                    result_file,
                    self.results_dir,
                    self.base_dir,
                    start_index,
                    self.config.evaluation.timeout_per_domain,
                    self.cert_features_file
                )
            )
            process.start()
            self._worker_processes[worker_id] = process
            print(f"   Worker {worker_id}: Started (PID: {process.pid})")

        # 完了待ち
        print(f"\n[Orchestrator] Waiting for workers to complete...")
        self._wait_for_workers()

        # 結果集約
        if not self._shutdown_requested:
            result = self._merge_results(timestamp, total_domains, start_time)
            return result
        else:
            print("\n[Orchestrator] Shutdown requested, partial results saved")
            return None

    # 変更履歴:
    #   - 2026-01-25: speed_weightに基づく比率分割に変更（均等分割から）
    def _split_domains(
        self,
        df: pd.DataFrame,
        workers: List[WorkerConfig]
    ) -> List[List[Dict[str, Any]]]:
        """データをWorkerにspeed_weight比率で分割"""
        # NaN → None 変換（JSON互換のため）
        domains = df.where(df.notna(), None).to_dict('records')
        total = len(domains)

        # 重みに基づく分割数の計算
        weights = [w.speed_weight for w in workers]
        total_weight = sum(weights)

        splits = []
        start = 0
        allocated = 0

        for i, weight in enumerate(weights):
            if i == len(weights) - 1:
                # 最後のWorkerに残り全部を割り当て（端数処理）
                size = total - allocated
            else:
                size = round(total * weight / total_weight)
                allocated += size
            splits.append(domains[start:start + size])
            start += size

        # 分割結果をログ出力
        for i, (w, split) in enumerate(zip(workers, splits)):
            pct = len(split) / total * 100
            print(f"   Worker {w.id}: {len(split)} domains ({pct:.1f}%, weight={w.speed_weight})")

        return splits

    def _run_worker(
        self,
        worker_id: int,
        vllm_port: int,
        domains_file: Path,
        result_file: Path,
        checkpoint_dir: Path,
        base_dir: Path,
        start_index: int,
        timeout_per_domain: int,
        cert_features_file: Optional[Path] = None
    ):
        """Workerプロセスのエントリポイント"""
        from .worker import run_worker_process

        run_worker_process(
            worker_id=worker_id,
            vllm_port=vllm_port,
            domains_file=domains_file,
            result_file=result_file,
            checkpoint_dir=checkpoint_dir,
            base_dir=base_dir,
            start_index=start_index,
            timeout_per_domain=timeout_per_domain,
            cert_features_file=cert_features_file
        )

    # 変更履歴:
    #   - 2026-01-25: stop_on_complete後にhealth_monitor.remove_portを呼び、Recoveryによる誤再起動を防止
    #   - 2026-01-24: Worker完了時にstop_on_complete=TrueのWorkerのvLLMを即停止（共用GPU配慮）
    def _wait_for_workers(self):
        """Worker完了を待機"""
        # worker_id → WorkerConfig のマッピング
        worker_config_map = {w.id: w for w in self.active_workers}

        while self._worker_processes and not self._shutdown_requested:
            for worker_id, process in list(self._worker_processes.items()):
                if not process.is_alive():
                    process.join()
                    del self._worker_processes[worker_id]
                    print(f"   Worker {worker_id}: Completed (exit code: {process.exitcode})")

                    # 共用GPUのWorkerはvLLMを即停止
                    wc = worker_config_map.get(worker_id)
                    if wc and wc.stop_on_complete and self.vllm_cluster:
                        # ヘルスモニターから除外（Recoveryによる誤再起動を防止）
                        if self.health_monitor:
                            self.health_monitor.remove_port(wc.port)
                        msg = self.vllm_cluster.stop_by_port(wc.port)
                        print(f"   {msg}")

            # ヘルス状態確認
            if self.health_monitor:
                unhealthy = self.health_monitor.get_unhealthy_ports()
                if unhealthy:
                    # stop_on_complete済みのポートは無視
                    stopped_ports = {
                        wc.port for wid, wc in worker_config_map.items()
                        if wc.stop_on_complete and wid not in self._worker_processes
                    }
                    active_unhealthy = [p for p in unhealthy if p not in stopped_ports]
                    if active_unhealthy:
                        print(f"\n⚠️  Unhealthy vLLM ports detected: {active_unhealthy}")

            time.sleep(1)

    def _stop_workers(self):
        """Worker停止"""
        for worker_id, process in self._worker_processes.items():
            if process.is_alive():
                print(f"   Stopping Worker {worker_id}...")
                process.terminate()
                process.join(timeout=10)
                if process.is_alive():
                    process.kill()

    def _merge_results(
        self,
        timestamp: str,
        total_domains: int,
        start_time: float
    ) -> EvaluationResult:
        """結果を集約"""
        print("\n[Orchestrator] Merging results...")

        all_results = []
        for worker in self.active_workers:
            result_file = self.results_dir / f"worker_{worker.id}_results.csv"
            if result_file.exists():
                df = pd.read_csv(result_file)
                all_results.append(df)
                print(f"   Worker {worker.id}: {len(df)} results")

        if all_results:
            merged_df = pd.concat(all_results, ignore_index=True)

            # 重複除去（ドメインで）
            merged_df = merged_df.drop_duplicates(subset=["domain"], keep="last")

            # 保存
            output_file = self.results_dir / f"eval_df__nALL__ts_{timestamp}.csv"
            merged_df.to_csv(output_file, index=False)
            print(f"\n   Merged results: {len(merged_df)} domains")
            print(f"   Output: {output_file}")

            completed = len(merged_df[merged_df["error"].isna()])
            failed = len(merged_df[merged_df["error"].notna()])
        else:
            output_file = None
            completed = 0
            failed = 0

        elapsed = time.time() - start_time

        return EvaluationResult(
            run_id=self.run_id,
            total_domains=total_domains,
            completed=completed,
            failed=failed,
            elapsed_seconds=elapsed,
            workers_used=len(self.active_workers),
            result_file=output_file
        )

    def retry_failed_domains(
        self,
        failed_domains: list,
        timeout: int = 120
    ) -> dict:
        """
        失敗ドメインをリトライ

        Args:
            failed_domains: 失敗ドメインリスト（domain, ml_probability, worker_idを含む）
            timeout: タイムアウト秒数（デフォルト120秒）

        Returns:
            dict: リトライ結果サマリー

        変更履歴:
            - 2026-01-31: リトライ機能追加
        """
        if not failed_domains:
            return {"total": 0, "success": 0, "failed": 0, "results": []}

        print(f"\n[Orchestrator] Retrying {len(failed_domains)} failed domains...")

        # Worker 0を使用
        if not self.active_workers:
            print("[ERROR] No active workers available for retry")
            return {"total": len(failed_domains), "success": 0, "failed": len(failed_domains), "results": []}

        worker_config = self.active_workers[0]

        # ResultWriterの準備
        from .checkpoint import ResultWriter
        from .worker import EvaluationWorker

        result_file = self.results_dir / f"retry_results_{self.run_id}.csv"
        fieldnames = [
            "domain", "ml_probability", "ai_is_phishing", "ai_confidence",
            "ai_risk_level", "processing_time", "worker_id", "error",
            "ai_reasoning", "ai_risk_factors", "ai_detected_brands",
            "trace_precheck_ml_category", "trace_precheck_tld_category",
            "trace_precheck_brand_detected", "trace_precheck_high_risk_hits",
            "trace_precheck_quick_risk", "trace_selected_tools",
            "trace_brand_risk_score", "trace_cert_risk_score",
            "trace_domain_risk_score", "trace_ctx_risk_score",
            "trace_ctx_issues", "trace_phase6_rules_fired",
            "graph_state_slim_json", "tool_brand_output", "tool_cert_output",
            "tool_domain_output", "tool_ctx_output"
        ]
        result_writer = ResultWriter(result_file, fieldnames)

        # 証明書データ読み込み
        cert_features_map = None
        if self.cert_features_file and self.cert_features_file.exists():
            import joblib
            cert_features_map = joblib.load(self.cert_features_file)

        # Worker作成
        worker = EvaluationWorker(
            worker_id=0,
            vllm_port=worker_config.port,
            base_dir=self.base_dir,
            checkpoint_manager=self.checkpoint_manager,
            result_writer=result_writer,
            cert_features_map=cert_features_map
        )

        try:
            # 変更履歴:
            #   - 2026-01-31: initialize() 呼び出しを追加（_agent初期化漏れ修正）
            # Worker初期化（_agentを作成）
            if not worker.initialize():
                print("[ERROR] Worker initialization failed")
                return {"total": len(failed_domains), "success": 0, "failed": len(failed_domains), "results": []}

            # リトライ実行
            retry_result = worker.retry_failed(failed_domains, timeout_per_domain=timeout)
            return retry_result

        finally:
            worker.cleanup()

    def cleanup(self):
        """クリーンアップ"""
        print("\n[Orchestrator] Cleaning up...")

        # ヘルスモニター停止
        if self.health_monitor:
            self.health_monitor.stop()
            print("   ✓ Health monitor stopped")

        # vLLMクラスター停止
        if self.vllm_cluster:
            messages = self.vllm_cluster.stop_all()
            for msg in messages:
                print(f"   {msg}")
            print("   ✓ vLLM cluster stopped")

        print("\n[Orchestrator] Cleanup complete")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()


def print_status_dashboard(orchestrator: ParallelOrchestrator):
    """ステータスダッシュボードを表示"""
    print("\n" + "=" * 80)
    print("Parallel Evaluation Status")
    print("=" * 80)

    if orchestrator.checkpoint_manager:
        checkpoint = orchestrator.checkpoint_manager.load_checkpoint()
        if checkpoint:
            print(f"Run ID: {checkpoint.global_state.run_id}")
            print(f"Total domains: {checkpoint.global_state.total_domains}")
            print(f"Workers: {checkpoint.global_state.num_workers}")
            print()

            header = f"{'Worker':^8} | {'Status':^10} | {'Progress':^15} | {'Completed':^10} | {'Failed':^8}"
            print(header)
            print("-" * len(header))

            for wid, wp in checkpoint.workers.items():
                pct = wp.completed / wp.total * 100 if wp.total > 0 else 0
                progress = f"{wp.completed}/{wp.total} ({pct:.1f}%)"
                print(f"{wid:^8} | {wp.status:^10} | {progress:^15} | {wp.completed:^10} | {wp.failed:^8}")

    if orchestrator.health_monitor:
        print("\nvLLM Health:")
        status = orchestrator.health_monitor.get_all_status()
        for port, health in status.items():
            symbol = "✓" if health == HealthStatus.HEALTHY else "✗"
            print(f"  Port {port}: {symbol} {health.value}")

    print("=" * 80)
