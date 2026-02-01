#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
evaluate_e2e_parallel.py — 並列End-to-End評価スクリプト

複数GPUを使用してStage3(AI Agent)評価を並列実行する。

使用方法:
    # デフォルト（1 GPU）
    python scripts/evaluate_e2e_parallel.py

    # GPU追加
    python scripts/evaluate_e2e_parallel.py --add-gpu 1
    python scripts/evaluate_e2e_parallel.py --add-gpu 1,2

    # GPU状態確認
    python scripts/evaluate_e2e_parallel.py --check-gpus

    # 再開
    python scripts/evaluate_e2e_parallel.py --resume
    python scripts/evaluate_e2e_parallel.py --resume --add-gpu 1

    # ドライラン
    python scripts/evaluate_e2e_parallel.py --dry-run

特徴:
    - デフォルト1 GPU、追加GPUはオプション指定
    - vLLM障害時の自動復旧
    - チェックポイントによる再開機能
    - SSH+tmuxによるリモートGPU対応

作成日: 2026-01-22
"""

import argparse
import importlib
import os
import sys
import time
from pathlib import Path
from datetime import datetime
from typing import List, Optional

import pandas as pd


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="並列End-to-End評価スクリプト",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # GPU設定
    parser.add_argument("--add-gpu", type=str, default=None,
                        help="追加で使用するGPU/Worker ID (例: 1 or 1,2)")
    parser.add_argument("--check-gpus", action="store_true",
                        help="GPU状態を確認して終了")

    # 実行オプション
    parser.add_argument("--resume", "-r", action="store_true",
                        help="前回のチェックポイントから再開")
    parser.add_argument("--retry-failed", action="store_true",
                        help="失敗ドメインのみリトライ（タイムアウト2倍）")
    parser.add_argument("--dry-run", action="store_true",
                        help="ドライラン（データ分割確認のみ）")
    parser.add_argument("--yes", "-y", action="store_true",
                        help="確認プロンプトをスキップ")

    # 設定
    parser.add_argument("--config", type=str, default=None,
                        help="設定ファイルパス (default: scripts/parallel_config.yaml)")

    # 評価設定
    parser.add_argument("--n-sample", type=str, default="ALL",
                        help="評価サンプル数 (default: ALL)")
    parser.add_argument("--random-state", type=int, default=42,
                        help="乱数シード (default: 42)")
    parser.add_argument("--shuffle", action="store_true",
                        help="データをシャッフルする (default: False)")

    return parser.parse_args()


def parse_additional_gpus(gpu_str: Optional[str]) -> Optional[List[int]]:
    """追加GPU文字列をパース"""
    if not gpu_str:
        return None

    try:
        return [int(x.strip()) for x in gpu_str.split(",") if x.strip()]
    except ValueError:
        print(f"Error: Invalid GPU specification: {gpu_str}")
        sys.exit(1)


def setup_environment() -> dict:
    """環境セットアップ"""
    # プロジェクトルート
    base_dir = Path(__file__).parent.parent.resolve()
    if str(base_dir) not in sys.path:
        sys.path.insert(0, str(base_dir))

    # RUN_ID決定
    import run_id_registry as runreg
    rid = runreg.bootstrap()
    os.environ["RUN_ID"] = rid

    # paths
    try:
        import _compat.paths as paths
    except ImportError:
        import paths as paths
    importlib.reload(paths)

    print(f"[INFO] RUN_ID = {rid}")
    print(f"[INFO] Base dir = {base_dir}")

    # 変更履歴:
    #   - 2026-01-24: 相対パスをresolveして絶対パスに変換（ワーカープロセスでのFileNotFoundError修正）
    artifacts_dir = (base_dir / paths.ARTIFACTS).resolve() if hasattr(paths, "ARTIFACTS") else (base_dir / "artifacts" / rid)

    return {
        "run_id": rid,
        "base_dir": base_dir,
        "artifacts_dir": artifacts_dir,
        "handoff_dir": Path(paths.compat_base_dirs["handoff"]),
        "results_dir": Path(paths.compat_base_dirs["results"]),
    }


def load_handoff_data(handoff_dir: Path) -> pd.DataFrame:
    """Stage2 handoffデータを読み込み"""
    csv_path = handoff_dir / "handoff_candidates_latest.csv"
    if not csv_path.exists():
        print(f"Error: {csv_path} not found")
        sys.exit(1)

    handoff_df = pd.read_csv(csv_path)

    # y_true → label 変換（必要に応じて）
    if "y_true" in handoff_df.columns and "label" not in handoff_df.columns:
        handoff_df["label"] = handoff_df["y_true"].astype(int)

    print(f"[INFO] Loaded {len(handoff_df)} handoff domains from {csv_path.name}")

    return handoff_df


def main():
    args = parse_args()

    print("=" * 70)
    print("Parallel End-to-End Evaluation")
    print("=" * 70)

    # 設定読み込み
    from parallel.config import load_config

    config_path = args.config
    if config_path is None:
        config_path = Path(__file__).parent / "parallel_config.yaml"

    config = load_config(config_path)
    print(f"[INFO] Config loaded from {config_path}")

    # 追加GPUパース
    additional_gpus = parse_additional_gpus(args.add_gpu)
    if additional_gpus:
        print(f"[INFO] Additional GPUs requested: {additional_gpus}")

    # GPU確認モード
    if args.check_gpus:
        import requests
        from parallel.gpu_checker import get_local_gpu_info, print_gpu_status

        print("\n[Checking local GPUs...]")
        gpus = get_local_gpu_info()
        if gpus:
            print_gpu_status(gpus, "Local GPU Status")
        else:
            print("No local GPUs found or nvidia-smi failed")

        # 各Workerの状態確認
        for worker in config.workers:
            if worker.type == "external":
                print(f"\n[Checking external vLLM on port {worker.port}...]")
                try:
                    resp = requests.get(f"http://localhost:{worker.port}/v1/models", timeout=5)
                    if resp.status_code == 200:
                        print(f"  Worker {worker.id}: OK (port {worker.port} reachable)")
                    else:
                        print(f"  Worker {worker.id}: NG (status {resp.status_code})")
                except Exception as e:
                    print(f"  Worker {worker.id}: NG (unreachable: {e})")

            elif worker.type == "remote" and worker.ssh:
                print(f"\n[Checking remote GPUs on {worker.ssh.host}...]")
                from parallel.gpu_checker import get_remote_gpu_info
                remote_gpus = get_remote_gpu_info(worker.ssh.host, worker.ssh.user)
                if remote_gpus:
                    print_gpu_status(remote_gpus, f"Remote GPU Status ({worker.ssh.host})")
                else:
                    print(f"  Failed to get GPU info from {worker.ssh.host}")

        return

    # 環境セットアップ
    env = setup_environment()

    # リトライモード
    if args.retry_failed:
        from parallel.checkpoint import CheckpointManager
        from parallel.orchestrator import ParallelOrchestrator

        # 変更履歴:
        #   - 2026-01-31: パス修正 - orchestrator と同じ stage2_validation サブディレクトリを使用
        results_dir = env["results_dir"] / "stage2_validation"
        checkpoint_manager = CheckpointManager(results_dir, env["run_id"])

        # 失敗ドメインを取得
        failed_domains = checkpoint_manager.get_all_failed_domains()

        if not failed_domains:
            print("[INFO] No failed domains to retry.")
            return

        print(f"\n[RETRY MODE] Found {len(failed_domains)} failed domains")
        for fd in failed_domains[:10]:
            print(f"  - {fd['domain']} (Worker {fd.get('worker_id', '?')}): {fd.get('error', 'unknown')}")
        if len(failed_domains) > 10:
            print(f"  ... and {len(failed_domains) - 10} more")

        if not args.yes:
            response = input("\nRetry these domains? [y/N]: ").strip().lower()
            if response != 'y':
                print("Aborted.")
                return

        # handoffからml_probabilityを取得
        handoff_df = load_handoff_data(env["handoff_dir"])
        ml_prob_map = dict(zip(handoff_df["domain"], handoff_df["ml_probability"]))

        for fd in failed_domains:
            fd["ml_probability"] = ml_prob_map.get(fd["domain"], 0.5)

        # 証明書特徴量ファイル
        cert_features_file = env["artifacts_dir"] / "processed" / "cert_full_info_map.pkl"
        if not cert_features_file.exists():
            cert_features_file = None

        # オーケストレーターでリトライ実行
        with ParallelOrchestrator(
            config=config,
            run_id=env["run_id"],
            artifacts_dir=env["artifacts_dir"],
            base_dir=env["base_dir"],
            additional_gpus=additional_gpus,
            skip_confirmation=True,
            cert_features_file=cert_features_file
        ) as orchestrator:

            if not orchestrator.setup():
                print("\nSetup failed. Exiting.")
                sys.exit(1)

            # Worker 0でリトライ（1GPUで十分）
            retry_result = orchestrator.retry_failed_domains(failed_domains, timeout=120)

            print("\n" + "=" * 70)
            print("Retry Complete!")
            print("=" * 70)
            print(f"  Total: {retry_result['total']}")
            print(f"  Success: {retry_result['success']}")
            print(f"  Failed: {retry_result['failed']}")

        return

    # handoffデータ読み込み
    handoff_df = load_handoff_data(env["handoff_dir"])

    # サンプリング
    # シャッフル（--shuffle オプション）
    if args.shuffle:
        handoff_df = handoff_df.sample(frac=1, random_state=args.random_state).reset_index(drop=True)
        print(f"[INFO] Shuffled {len(handoff_df)} domains (random_state={args.random_state})")

    n_sample = args.n_sample.strip().upper()
    if n_sample != "ALL":
        try:
            n = int(n_sample)
            if n > 0 and n < len(handoff_df):
                handoff_df = handoff_df.sample(n=n, random_state=args.random_state)
                print(f"[INFO] Sampled {len(handoff_df)} domains")
        except ValueError:
            pass

    # 証明書特徴量ファイルを検索（PKLを優先）
    cert_features_file = None

    # 1. PKLファイルを優先（完全な証明書データを含む）
    cert_pkl_path = env["artifacts_dir"] / "processed" / "cert_full_info_map.pkl"
    if cert_pkl_path.exists():
        cert_features_file = cert_pkl_path
        print(f"[INFO] Certificate features (PKL): {cert_features_file}")
    else:
        # 2. CSVファイルにフォールバック
        cert_csv_path = env["artifacts_dir"] / "results" / "stage3_analysis" / "handoff_cert_features.csv"
        if cert_csv_path.exists():
            cert_features_file = cert_csv_path
            print(f"[INFO] Certificate features (CSV): {cert_features_file}")
        else:
            print("[INFO] No certificate features file found (optional)")

    # ドライラン
    if args.dry_run:
        from parallel.orchestrator import ParallelOrchestrator

        orchestrator = ParallelOrchestrator(
            config=config,
            run_id=env["run_id"],
            artifacts_dir=env["artifacts_dir"],
            base_dir=env["base_dir"],
            additional_gpus=additional_gpus,
            cert_features_file=cert_features_file
        )

        print("\n[DRY RUN] Data split:")
        splits = orchestrator._split_domains(handoff_df, orchestrator.active_workers)
        for i, split in enumerate(splits):
            print(f"  Worker {orchestrator.active_workers[i].id}: {len(split)} domains")

        print("\n[DRY RUN] Would use the following workers:")
        for worker in orchestrator.active_workers:
            if worker.type == "local":
                print(f"  Worker {worker.id}: Local GPU {worker.gpu}, port {worker.port}")
            elif worker.type == "external":
                print(f"  Worker {worker.id}: External (port-forwarded), port {worker.port}")
            else:
                print(f"  Worker {worker.id}: Remote {worker.ssh.host}, port {worker.port}")

        return

    # 確認プロンプト
    if not args.yes and not args.resume:
        print(f"\n[CONFIRMATION]")
        print(f"  Domains to evaluate: {len(handoff_df)}")
        print(f"  Workers: {len(config.get_active_workers(additional_gpus))}")

        if additional_gpus:
            print(f"  Additional GPUs: {additional_gpus}")

        estimated_time = len(handoff_df) * 8 / len(config.get_active_workers(additional_gpus)) / 3600
        print(f"  Estimated time: {estimated_time:.1f} hours")

        response = input("\nProceed? [y/N]: ").strip().lower()
        if response != 'y':
            print("Aborted.")
            return

    # オーケストレーター作成・実行
    from parallel.orchestrator import ParallelOrchestrator

    with ParallelOrchestrator(
        config=config,
        run_id=env["run_id"],
        artifacts_dir=env["artifacts_dir"],
        base_dir=env["base_dir"],
        additional_gpus=additional_gpus,
        skip_confirmation=args.yes,
        cert_features_file=cert_features_file
    ) as orchestrator:

        # セットアップ（resume対応）
        if not orchestrator.setup(resume=args.resume):
            print("\nSetup failed. Exiting.")
            sys.exit(1)

        # 実行
        result = orchestrator.run(handoff_df, resume=args.resume)

        if result:
            print("\n" + "=" * 70)
            print("Evaluation Complete!")
            print("=" * 70)
            print(f"  Run ID: {result.run_id}")
            print(f"  Total domains: {result.total_domains}")
            print(f"  Completed: {result.completed}")
            print(f"  Failed: {result.failed}")
            print(f"  Workers used: {result.workers_used}")
            print(f"  Elapsed: {result.elapsed_seconds / 3600:.2f} hours")
            if result.result_file:
                print(f"  Results: {result.result_file}")
        else:
            print("\nEvaluation interrupted. Use --resume to continue.")
            sys.exit(1)


if __name__ == "__main__":
    main()
