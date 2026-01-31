#!/usr/bin/env python3
"""
Real-time FN/FP monitoring script for Stage3 AI Agent evaluation.

Usage:
    python scripts/monitor_fnfp.py [--watch] [--interval SECONDS]

Options:
    --watch         Continuous monitoring mode
    --interval N    Refresh interval in seconds (default: 30)
"""
import os
import sys
import time
import argparse
import pandas as pd
from pathlib import Path
from datetime import datetime

# Default paths
DEFAULT_BASE_DIR = Path("/data/hdd/asomura/nextstep/artifacts/2026-01-24_213326/results/stage2_validation")


def load_results(base_dir: Path):
    """Load all worker results from CSV files."""
    dfs = []
    for i in range(3):
        csv_path = base_dir / f"worker_{i}_results.csv"
        if csv_path.exists():
            try:
                df = pd.read_csv(csv_path)
                df['worker_id'] = i
                dfs.append(df)
            except Exception as e:
                print(f"[WARNING] Error loading worker_{i}: {e}", file=sys.stderr)
    if dfs:
        return pd.concat(dfs, ignore_index=True)
    return pd.DataFrame()


def analyze_fnfp(df):
    """Analyze FN and FP cases from evaluation results."""
    if df.empty:
        return None, None, None

    # Check for required columns
    if 'ai_is_phishing' not in df.columns or 'y_true' not in df.columns:
        return None, None, None

    # Calculate confusion matrix components
    fn = df[(df['y_true'] == 1) & (df['ai_is_phishing'] == False)]
    fp = df[(df['y_true'] == 0) & (df['ai_is_phishing'] == True)]
    tp = df[(df['y_true'] == 1) & (df['ai_is_phishing'] == True)]
    tn = df[(df['y_true'] == 0) & (df['ai_is_phishing'] == False)]

    return fn, fp, {'tp': len(tp), 'tn': len(tn), 'fn': len(fn), 'fp': len(fp)}


def print_report(df, fn, fp, stats, show_all_fn=False, show_all_fp=False):
    """Print FN/FP analysis report."""
    print(f"\n{'='*60}")
    print(f"Stage3 AI Agent - FN/FP Monitor")
    print(f"{'='*60}")
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    if stats is None:
        print("\n[INFO] Waiting for results...")
        return

    total = stats['tp'] + stats['tn'] + stats['fn'] + stats['fp']

    print(f"\n--- Summary ---")
    print(f"Total evaluated: {total}")
    print(f"TP: {stats['tp']}, TN: {stats['tn']}, FN: {stats['fn']}, FP: {stats['fp']}")

    if stats['tp'] + stats['fn'] > 0:
        recall = stats['tp'] / (stats['tp'] + stats['fn'])
        print(f"Recall: {recall:.4f}")
    else:
        recall = 0

    if stats['tp'] + stats['fp'] > 0:
        precision = stats['tp'] / (stats['tp'] + stats['fp'])
        print(f"Precision: {precision:.4f}")
    else:
        precision = 0

    if precision + recall > 0:
        f1 = 2 * precision * recall / (precision + recall)
        print(f"F1: {f1:.4f}")

    # FN analysis
    print(f"\n--- FN Cases ({len(fn)} total) ---")
    if fn is not None and len(fn) > 0:
        display_fn = fn if show_all_fn else fn.tail(20)
        for _, row in display_fn.iterrows():
            domain = row.get('domain', 'N/A')
            ml = row.get('ml_probability', 0)
            conf = row.get('ai_confidence', 0)
            tld = row.get('tld', '')
            source = row.get('source', '')
            print(f"  {domain} (ml={ml:.3f}, conf={conf:.2f}, tld={tld}, src={source})")
        if not show_all_fn and len(fn) > 20:
            print(f"  ... and {len(fn) - 20} more")
    else:
        print("  (none)")

    # FP analysis
    print(f"\n--- FP Cases ({len(fp)} total) ---")
    if fp is not None and len(fp) > 0:
        display_fp = fp if show_all_fp else fp.tail(20)
        for _, row in display_fp.iterrows():
            domain = row.get('domain', 'N/A')
            ml = row.get('ml_probability', 0)
            conf = row.get('ai_confidence', 0)
            tld = row.get('tld', '')
            source = row.get('source', '')
            print(f"  {domain} (ml={ml:.3f}, conf={conf:.2f}, tld={tld}, src={source})")
        if not show_all_fp and len(fp) > 20:
            print(f"  ... and {len(fp) - 20} more")
    else:
        print("  (none)")


def main():
    parser = argparse.ArgumentParser(description="Real-time FN/FP monitoring for Stage3 AI Agent")
    parser.add_argument('--watch', '-w', action='store_true', help='Continuous monitoring mode')
    parser.add_argument('--interval', '-i', type=int, default=30, help='Refresh interval in seconds')
    parser.add_argument('--base-dir', type=str, default=str(DEFAULT_BASE_DIR), help='Results directory')
    parser.add_argument('--all-fn', action='store_true', help='Show all FN cases')
    parser.add_argument('--all-fp', action='store_true', help='Show all FP cases')
    args = parser.parse_args()

    base_dir = Path(args.base_dir)

    if args.watch:
        print(f"[INFO] Watching {base_dir} (interval: {args.interval}s)")
        print("[INFO] Press Ctrl+C to stop")
        try:
            while True:
                os.system('clear')
                df = load_results(base_dir)
                fn, fp, stats = analyze_fnfp(df)
                print_report(df, fn, fp, stats, args.all_fn, args.all_fp)
                time.sleep(args.interval)
        except KeyboardInterrupt:
            print("\n[INFO] Monitoring stopped")
    else:
        df = load_results(base_dir)
        fn, fp, stats = analyze_fnfp(df)
        print_report(df, fn, fp, stats, args.all_fn, args.all_fp)


if __name__ == "__main__":
    main()
