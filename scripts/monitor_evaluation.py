#!/usr/bin/env python3
"""
Stage3 AI Agent 評価モニタリングスクリプト

1000件ごとにFN/FP分析を行い、進捗を監視する。

使用方法:
    python scripts/monitor_evaluation.py                    # 最新のRUN_IDを使用
    python scripts/monitor_evaluation.py --run-id 2026-01-25_123456
    python scripts/monitor_evaluation.py --interval 500     # 500件ごとに分析
    python scripts/monitor_evaluation.py --watch            # リアルタイム監視モード

作成日: 2026-01-25
"""

import argparse
import os
import sys
import time
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any, List
import pandas as pd


def get_latest_run_id(artifacts_dir: Path) -> Optional[str]:
    """最新のRUN_IDを取得"""
    current_file = artifacts_dir / "_current" / "run_id.txt"
    if current_file.exists():
        return current_file.read_text().strip()

    # ディレクトリから最新を探す
    run_dirs = [d for d in artifacts_dir.iterdir()
                if d.is_dir() and d.name.startswith("202") and not d.name.startswith("_")]
    if run_dirs:
        return sorted(run_dirs)[-1].name
    return None


def load_results(results_dir: Path) -> pd.DataFrame:
    """全Workerの結果を読み込んでマージ"""
    dfs = []
    for f in results_dir.glob("worker_*_results.csv"):
        if f.stat().st_size > 0:
            try:
                df = pd.read_csv(f)
                dfs.append(df)
            except Exception as e:
                print(f"Warning: Failed to read {f}: {e}")

    if not dfs:
        return pd.DataFrame()

    return pd.concat(dfs, ignore_index=True)


def analyze_performance(df: pd.DataFrame) -> Dict[str, Any]:
    """性能分析を行う"""
    if df.empty:
        return {"error": "No data"}

    # エラー行を除外
    valid = df[df['error'].isna() | (df['error'] == '')]

    if valid.empty:
        return {"error": "No valid data"}

    # y_true と ai_is_phishing を使用
    y_true = valid['y_true'].astype(int)
    y_pred = valid['ai_is_phishing'].astype(int)

    # 基本統計
    total = len(valid)
    phishing_count = (y_true == 1).sum()
    benign_count = (y_true == 0).sum()

    # TP, FP, TN, FN
    tp = ((y_pred == 1) & (y_true == 1)).sum()
    fp = ((y_pred == 1) & (y_true == 0)).sum()
    tn = ((y_pred == 0) & (y_true == 0)).sum()
    fn = ((y_pred == 0) & (y_true == 1)).sum()

    # メトリクス
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / total if total > 0 else 0.0

    # ML Baseline との比較用
    ml_pred = (valid['ml_probability'] > 0.5).astype(int)
    ml_tp = ((ml_pred == 1) & (y_true == 1)).sum()
    ml_fp = ((ml_pred == 1) & (y_true == 0)).sum()
    ml_fn = ((ml_pred == 0) & (y_true == 1)).sum()
    ml_precision = ml_tp / (ml_tp + ml_fp) if (ml_tp + ml_fp) > 0 else 0.0
    ml_recall = ml_tp / (ml_tp + ml_fn) if (ml_tp + ml_fn) > 0 else 0.0
    ml_f1 = 2 * ml_precision * ml_recall / (ml_precision + ml_recall) if (ml_precision + ml_recall) > 0 else 0.0

    return {
        "total": total,
        "phishing": phishing_count,
        "benign": benign_count,
        "TP": tp,
        "FP": fp,
        "TN": tn,
        "FN": fn,
        "Precision": round(precision, 4),
        "Recall": round(recall, 4),
        "F1": round(f1, 4),
        "Accuracy": round(accuracy, 4),
        # ML Baseline
        "ML_TP": ml_tp,
        "ML_FP": ml_fp,
        "ML_FN": ml_fn,
        "ML_Precision": round(ml_precision, 4),
        "ML_Recall": round(ml_recall, 4),
        "ML_F1": round(ml_f1, 4),
        # 差分
        "FP_diff": fp - ml_fp,
        "FN_diff": fn - ml_fn,
        "F1_diff": round(f1 - ml_f1, 4),
    }


def analyze_fn_categories(df: pd.DataFrame) -> Dict[str, int]:
    """FNの内訳を分析"""
    if df.empty:
        return {}

    valid = df[df['error'].isna() | (df['error'] == '')]
    y_true = valid['y_true'].astype(int)
    y_pred = valid['ai_is_phishing'].astype(int)

    # FNドメインを抽出
    fn_mask = (y_pred == 0) & (y_true == 1)
    fn_domains = valid[fn_mask]['domain'].tolist()
    fn_tlds = valid[fn_mask]['tld'].tolist() if 'tld' in valid.columns else []

    # TLDによる内訳
    dangerous_tlds = {'top', 'xyz', 'icu', 'buzz', 'cfd', 'cyou', 'rest', 'sbs',
                      'tk', 'ml', 'ga', 'cf', 'gq', 'pw', 'cn', 'cc', 'asia',
                      'vip', 'shop', 'club', 'one', 'click', 'link', 'online',
                      'site', 'website', 'lat', 'info'}

    fn_dangerous_tld = sum(1 for tld in fn_tlds if tld in dangerous_tlds)

    # 短いドメイン
    fn_short = sum(1 for d in fn_domains if len(d.split('.')[0]) <= 6)

    return {
        "FN_dangerous_tld": fn_dangerous_tld,
        "FN_short_domain": fn_short,
        "FN_total": len(fn_domains),
    }


def print_report(stats: Dict[str, Any], fn_cats: Dict[str, int], timestamp: str):
    """レポートを表示"""
    print()
    print("=" * 70)
    print(f"Stage3 AI Agent 評価レポート ({timestamp})")
    print("=" * 70)

    if "error" in stats:
        print(f"Error: {stats['error']}")
        return

    print(f"\n【処理件数】")
    print(f"  完了: {stats['total']:,} 件 (phishing: {stats['phishing']:,}, benign: {stats['benign']:,})")

    print(f"\n【AI Agent 性能】")
    print(f"  TP: {stats['TP']:,}  FP: {stats['FP']:,}  TN: {stats['TN']:,}  FN: {stats['FN']:,}")
    print(f"  Precision: {stats['Precision']:.4f}  Recall: {stats['Recall']:.4f}  F1: {stats['F1']:.4f}")

    print(f"\n【ML Baseline (>0.5) 性能】")
    print(f"  TP: {stats['ML_TP']:,}  FP: {stats['ML_FP']:,}  FN: {stats['ML_FN']:,}")
    print(f"  Precision: {stats['ML_Precision']:.4f}  Recall: {stats['ML_Recall']:.4f}  F1: {stats['ML_F1']:.4f}")

    print(f"\n【AI Agent vs ML Baseline】")
    fp_diff = stats['FP_diff']
    fn_diff = stats['FN_diff']
    f1_diff = stats['F1_diff']

    fp_status = "改善" if fp_diff < 0 else "悪化" if fp_diff > 0 else "同等"
    fn_status = "改善" if fn_diff < 0 else "悪化" if fn_diff > 0 else "同等"
    f1_status = "改善" if f1_diff > 0 else "悪化" if f1_diff < 0 else "同等"

    print(f"  FP差分: {fp_diff:+d} ({fp_status})")
    print(f"  FN差分: {fn_diff:+d} ({fn_status})")
    print(f"  F1差分: {f1_diff:+.4f} ({f1_status})")

    if fn_cats:
        print(f"\n【FN内訳】")
        print(f"  危険TLD: {fn_cats.get('FN_dangerous_tld', 0):,}")
        print(f"  短ドメイン(≤6文字): {fn_cats.get('FN_short_domain', 0):,}")

    print("=" * 70)


def main():
    parser = argparse.ArgumentParser(description="Stage3 AI Agent 評価モニタリング")
    parser.add_argument("--run-id", help="RUN_ID (省略時は最新)")
    parser.add_argument("--interval", type=int, default=1000, help="分析間隔 (件数)")
    parser.add_argument("--watch", action="store_true", help="リアルタイム監視モード")
    parser.add_argument("--watch-interval", type=int, default=30, help="監視間隔 (秒)")
    args = parser.parse_args()

    # パス設定
    script_dir = Path(__file__).parent
    project_dir = script_dir.parent
    artifacts_dir = project_dir / "artifacts"

    # RUN_ID取得
    run_id = args.run_id or get_latest_run_id(artifacts_dir)
    if not run_id:
        print("Error: No RUN_ID found. Run evaluation first.")
        sys.exit(1)

    results_dir = artifacts_dir / run_id / "results" / "stage2_validation"
    if not results_dir.exists():
        print(f"Error: Results directory not found: {results_dir}")
        sys.exit(1)

    print(f"Monitoring RUN_ID: {run_id}")
    print(f"Results dir: {results_dir}")
    print(f"Analysis interval: {args.interval} domains")

    last_count = 0
    last_report_count = 0

    while True:
        df = load_results(results_dir)
        current_count = len(df)

        if current_count == 0:
            print("Waiting for results...")
            if not args.watch:
                break
            time.sleep(args.watch_interval)
            continue

        # 新しい結果がinterval件以上増えたら分析
        if current_count - last_report_count >= args.interval:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            stats = analyze_performance(df)
            fn_cats = analyze_fn_categories(df)
            print_report(stats, fn_cats, timestamp)
            last_report_count = current_count

        if not args.watch:
            # 単発実行: 現在の結果を表示して終了
            if last_report_count == 0:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                stats = analyze_performance(df)
                fn_cats = analyze_fn_categories(df)
                print_report(stats, fn_cats, timestamp)
            break

        # 監視モード
        if current_count != last_count:
            print(f"\r[{datetime.now().strftime('%H:%M:%S')}] "
                  f"Processed: {current_count:,} domains "
                  f"(+{current_count - last_count} since last check)", end="", flush=True)
            last_count = current_count

        time.sleep(args.watch_interval)


if __name__ == "__main__":
    main()
