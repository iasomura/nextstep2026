#!/usr/bin/env python3
"""
VT結果からVT未検出ドメインを抽出するスクリプト

Usage:
    python scripts/update_vt_not_detected.py
    python scripts/update_vt_not_detected.py --threshold 2  # malicious<=2を未検出扱い
"""

import argparse
import pandas as pd
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description='Extract VT non-detected domains')
    parser.add_argument('--input', '-i', default='artifacts/stage2_fn_vt_results.csv',
                        help='VT results CSV file')
    parser.add_argument('--output', '-o', default='artifacts/stage2_fn_vt_not_detected.csv',
                        help='Output CSV for non-detected domains')
    parser.add_argument('--threshold', '-t', type=int, default=0,
                        help='Threshold for malicious count (<=threshold is "not detected")')
    parser.add_argument('--show-domains', '-s', action='store_true',
                        help='Show domain list')
    args = parser.parse_args()

    # 結果読み込み
    df = pd.read_csv(args.input)
    total = len(df)

    print(f"=== VT検出状況サマリ (閾値: malicious<={args.threshold}) ===")
    print(f"チェック済み: {total}件\n")

    # 分類
    not_detected = df[df['malicious'] <= args.threshold].copy()
    detected = df[df['malicious'] > args.threshold]

    print(f"VT未検出 (malicious<={args.threshold}): {len(not_detected)}件 ({len(not_detected)/total*100:.1f}%)")
    print(f"VT検出あり (malicious>{args.threshold}): {len(detected)}件 ({len(detected)/total*100:.1f}%)")

    # malicious分布
    print("\n=== malicious検出数分布 ===")
    for count in sorted(df['malicious'].unique()):
        n = len(df[df['malicious'] == count])
        marker = " ← 未検出扱い" if count <= args.threshold else ""
        print(f"  malicious={count:2d}: {n:3d}件{marker}")

    # 保存
    not_detected.to_csv(args.output, index=False)
    print(f"\n→ {args.output} に保存しました ({len(not_detected)}件)")

    # ドメイン一覧表示
    if args.show_domains and len(not_detected) > 0:
        print(f"\n=== VT未検出ドメイン一覧 ===")
        for _, row in not_detected.iterrows():
            print(f"  {row['domain']} (ML: {row.get('ml_probability', 'N/A'):.3f}, source: {row.get('source', 'N/A')})")

    # 検出ドメインも別ファイルに保存
    detected_output = args.output.replace('not_detected', 'detected')
    detected.to_csv(detected_output, index=False)
    print(f"→ {detected_output} に保存しました ({len(detected)}件)")


if __name__ == '__main__':
    main()
