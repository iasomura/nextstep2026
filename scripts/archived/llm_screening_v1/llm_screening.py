#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
llm_screening.py — LLMスクリーニング実行スクリプト

Stage1 FN候補（ML < threshold & phishing）をLLMでスクリーニングし、
高リスクドメインをStage3送信対象として抽出する。

使用方法:
    # 現在のRUN_IDを使用（artifacts/_current/run_id.txt）
    python scripts/llm_screening.py

    # オプション指定
    python scripts/llm_screening.py --ml-threshold 0.10 --risk-threshold 0.70

    # 再開
    python scripts/llm_screening.py --resume

特徴:
    - Stage3と同じ並列インフラを使用（安定性）
    - with_structured_output でPydanticスキーマ使用
    - チェックポイントによる再開機能

変更履歴:
    - 2026-02-03: 初版作成
"""
import argparse
import importlib
import os
import sys
from pathlib import Path
from datetime import datetime
from typing import Optional

import pandas as pd


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="LLMスクリーニング - FN候補の高リスクドメイン抽出",
    )

    # 基本設定
    parser.add_argument("--run-id", type=str, default=None,
                        help="RUN_ID (省略時は artifacts/_current/run_id.txt)")
    parser.add_argument("--ml-threshold", type=float, default=0.10,
                        help="FN候補抽出のML閾値 (default: 0.10)")
    parser.add_argument("--risk-threshold", type=float, default=0.70,
                        help="Stage3送信のリスク閾値 (default: 0.70)")
    parser.add_argument("--typo-threshold", type=float, default=0.80,
                        help="ブランド類似度閾値 (default: 0.80)")

    # 実行オプション
    parser.add_argument("--resume", "-r", action="store_true",
                        help="前回のチェックポイントから再開")
    parser.add_argument("--dry-run", action="store_true",
                        help="ドライラン（データ確認のみ）")

    # vLLM設定
    parser.add_argument("--port", type=int, default=8000,
                        help="vLLMポート (default: 8000)")
    parser.add_argument("--model", type=str,
                        default="JunHowie/Qwen3-4B-Thinking-2507-GPTQ-Int8",
                        help="モデル名")

    return parser.parse_args()


def setup_environment() -> dict:
    """環境セットアップ"""
    # プロジェクトルート
    base_dir = Path(__file__).parent.parent.resolve()
    if str(base_dir) not in sys.path:
        sys.path.insert(0, str(base_dir))

    return {"base_dir": base_dir}


def get_run_id(args_run_id: Optional[str], base_dir: Path) -> str:
    """RUN_IDを取得"""
    if args_run_id:
        return args_run_id

    # run_id_registryから取得
    try:
        import run_id_registry as runreg
        return runreg.bootstrap()
    except Exception:
        pass

    # フォールバック: _current/run_id.txt
    run_id_file = base_dir / "artifacts" / "_current" / "run_id.txt"
    if run_id_file.exists():
        return run_id_file.read_text().strip()

    raise RuntimeError("RUN_ID not found. Run pipeline first or specify --run-id")


def extract_fn_candidates(
    stage2_csv: Path,
    ml_threshold: float
) -> pd.DataFrame:
    """Stage2結果からFN候補を抽出"""
    df = pd.read_csv(stage2_csv)

    # FN候補: ML < threshold & 実際はphishing
    fn_candidates = df[
        (df['ml_probability'] < ml_threshold) &
        (df['y_true'] == 1)
    ].copy()

    print(f"Stage2 total: {len(df)}")
    print(f"FN candidates (ML < {ml_threshold} & phishing): {len(fn_candidates)}")

    return fn_candidates


def run_screening(
    fn_candidates: pd.DataFrame,
    output_dir: Path,
    args: argparse.Namespace,
    base_dir: Path,
) -> dict:
    """スクリーニング実行"""
    from scripts.parallel.checkpoint import CheckpointManager, ResultWriter
    from scripts.parallel.screening_worker import ScreeningWorker

    # 出力ディレクトリ
    output_dir.mkdir(parents=True, exist_ok=True)

    # RUN_IDを抽出（output_dirのparent.nameから）
    run_id = output_dir.parent.name

    # 結果CSVのフィールド名
    fieldnames = [
        "domain", "ml_probability", "risk_score",
        "is_typosquatting", "target_brand", "similarity_score",
        "legitimacy_score", "red_flags", "is_dga", "dga_score",
        "impersonation_target", "should_send_to_stage3",
        "processing_time", "worker_id", "error", "source"
    ]

    # チェックポイント・結果ライター初期化
    checkpoint_manager = CheckpointManager(
        checkpoint_dir=output_dir,
        run_id=run_id,
    )
    result_writer = ResultWriter(output_dir / "screening_results.csv", fieldnames=fieldnames)

    # 再開処理
    start_index = 0
    if args.resume:
        results_file = output_dir / "screening_results.csv"
        if results_file.exists():
            # 既存結果から完了済みドメインを取得
            existing_df = pd.read_csv(results_file)
            completed_domains = set(existing_df['domain'].tolist())
            fn_candidates = fn_candidates[~fn_candidates['domain'].isin(completed_domains)]
            print(f"Resuming: {len(completed_domains)} already completed, {len(fn_candidates)} remaining")

    # Worker初期化
    worker = ScreeningWorker(
        worker_id=0,
        vllm_port=args.port,
        base_dir=base_dir,
        checkpoint_manager=checkpoint_manager,
        result_writer=result_writer,
        model_name=args.model,
        risk_threshold=args.risk_threshold,
        typo_threshold=args.typo_threshold,
    )

    if not worker.initialize():
        raise RuntimeError("Worker initialization failed")

    # ドメインリスト作成
    domains = fn_candidates[['domain', 'ml_probability']].to_dict('records')
    if 'source' in fn_candidates.columns:
        for i, row in enumerate(fn_candidates.itertuples()):
            domains[i]['source'] = row.source

    # 実行
    result = worker.run(domains, start_index=start_index)

    # 結果ファイル確定（ResultWriterはfinalize不要）
    # result_writer.finalize()  # Not needed - writes are immediate

    return result


def generate_stage3_list(output_dir: Path) -> int:
    """Stage3送信リストを生成"""
    results_file = output_dir / "screening_results.csv"
    if not results_file.exists():
        print(f"Error: {results_file} not found")
        return 0

    df = pd.read_csv(results_file)

    # Stage3送信対象を抽出
    stage3_domains = df[df['should_send_to_stage3'] == True]['domain'].tolist()

    # リスト保存
    stage3_list_file = output_dir / "stage3_rescue_list.txt"
    with open(stage3_list_file, 'w') as f:
        f.write('\n'.join(stage3_domains))

    print(f"Stage3 rescue list: {len(stage3_domains)} domains")
    print(f"Saved to: {stage3_list_file}")

    return len(stage3_domains)


def print_summary(output_dir: Path):
    """サマリー表示"""
    results_file = output_dir / "screening_results.csv"
    if not results_file.exists():
        return

    df = pd.read_csv(results_file)
    success_df = df[df['error'].isna()]

    print(f"\n{'='*60}")
    print("LLM Screening Summary")
    print(f"{'='*60}")
    print(f"Total processed: {len(df)}")
    print(f"Success: {len(success_df)} ({100*len(success_df)/len(df):.1f}%)")
    print(f"Failed: {len(df) - len(success_df)}")

    if len(success_df) > 0:
        print(f"\n--- Risk Analysis ---")
        print(f"Typosquatting detected: {success_df['is_typosquatting'].sum()} "
              f"({100*success_df['is_typosquatting'].mean():.1f}%)")
        print(f"DGA detected: {success_df['is_dga'].sum()} "
              f"({100*success_df['is_dga'].mean():.1f}%)")
        print(f"Risk >= 0.7: {(success_df['risk_score'] >= 0.7).sum()} "
              f"({100*(success_df['risk_score'] >= 0.7).mean():.1f}%)")
        print(f"Risk mean: {success_df['risk_score'].mean():.3f}")

        # Stage3送信対象
        stage3_count = success_df['should_send_to_stage3'].sum()
        print(f"\n--- Stage3 Candidates ---")
        print(f"Stage3 rescue: {stage3_count} ({100*stage3_count/len(success_df):.1f}%)")

        # ブランド別集計
        brands = success_df[success_df['target_brand'].notna()]['target_brand'].value_counts()
        if len(brands) > 0:
            print(f"\n--- Detected Brands (Top 10) ---")
            for brand, count in brands.head(10).items():
                print(f"  {brand}: {count}")

    print(f"{'='*60}\n")


def main():
    args = parse_args()

    # 環境セットアップ
    env = setup_environment()
    base_dir = env["base_dir"]

    # RUN_ID取得
    run_id = get_run_id(args.run_id, base_dir)
    print(f"RUN_ID: {run_id}")

    # パス設定
    artifacts_dir = base_dir / "artifacts" / run_id
    stage2_results = artifacts_dir / "results" / "stage2_decisions_latest.csv"
    output_dir = artifacts_dir / "llm_screening"

    # Stage2結果確認
    if not stage2_results.exists():
        print(f"Error: {stage2_results} not found")
        print("Run the pipeline first (01-04 notebooks)")
        sys.exit(1)

    # FN候補抽出
    fn_candidates = extract_fn_candidates(stage2_results, args.ml_threshold)

    if len(fn_candidates) == 0:
        print("No FN candidates found. Nothing to screen.")
        sys.exit(0)

    # ドライラン
    if args.dry_run:
        print(f"\n[DRY RUN] Would screen {len(fn_candidates)} domains")
        print(f"  ML threshold: {args.ml_threshold}")
        print(f"  Risk threshold: {args.risk_threshold}")
        print(f"  Output: {output_dir}")
        print("\nSample domains:")
        for _, row in fn_candidates.head(10).iterrows():
            print(f"  {row['domain']} (ML={row['ml_probability']:.3f})")
        sys.exit(0)

    # スクリーニング実行
    print(f"\nStarting LLM screening...")
    print(f"  vLLM port: {args.port}")
    print(f"  Model: {args.model}")
    print(f"  Risk threshold: {args.risk_threshold}")
    print()

    result = run_screening(fn_candidates, output_dir, args, base_dir)

    # Stage3リスト生成
    generate_stage3_list(output_dir)

    # サマリー表示
    print_summary(output_dir)

    print(f"Results saved to: {output_dir}")


if __name__ == "__main__":
    main()
