#!/usr/bin/env python3
"""
HANDOFF内のPhishingサイトの特徴分析

3,389件のPhishingと25,295件のBenignを比較し、
識別に有用な特徴を発見する。
"""

import pandas as pd
import numpy as np
from pathlib import Path
from scipy import stats

def analyze_phishing_characteristics(artifact_dir: Path):
    """Phishing vs Benign の特徴比較分析"""

    results_dir = artifact_dir / "results"

    # Stage2候補データを読み込み
    df = pd.read_csv(results_dir / "stage2_decisions_candidates_latest.csv")

    # 現在のHANDOFF
    handoff = df[df['selected'] == 1].copy()

    phish = handoff[handoff['y_true'] == 1]
    benign = handoff[handoff['y_true'] == 0]

    print("=" * 70)
    print("HANDOFF内 Phishing特徴分析")
    print("=" * 70)
    print(f"\n  Phishing: {len(phish):,}件")
    print(f"  Benign:   {len(benign):,}件")

    # ================================================================
    # 1. 数値特徴の比較
    # ================================================================
    print("\n" + "=" * 70)
    print("【1. 数値特徴の比較】")
    print("=" * 70)

    numeric_cols = ['ml_probability', 'defer_score', 'p_error', 'uncertainty']

    print(f"\n{'特徴':<20} {'Phish平均':>12} {'Benign平均':>12} {'差':>10} {'p値':>12}")
    print("-" * 70)

    significant_features = []
    for col in numeric_cols:
        if col in handoff.columns:
            p_mean = phish[col].mean()
            b_mean = benign[col].mean()
            diff = p_mean - b_mean

            # t検定
            t_stat, p_val = stats.ttest_ind(phish[col].dropna(), benign[col].dropna())

            sig = "***" if p_val < 0.001 else "**" if p_val < 0.01 else "*" if p_val < 0.05 else ""
            print(f"{col:<20} {p_mean:>12.4f} {b_mean:>12.4f} {diff:>+10.4f} {p_val:>10.2e} {sig}")

            if p_val < 0.01:
                significant_features.append((col, diff, p_val))

    # ================================================================
    # 2. TLD分析
    # ================================================================
    print("\n" + "=" * 70)
    print("【2. TLD分析（Phish率が高い/低いTLD）】")
    print("=" * 70)

    tld_stats = []
    for tld in handoff['tld'].unique():
        tld_data = handoff[handoff['tld'] == tld]
        n_total = len(tld_data)
        n_phish = len(tld_data[tld_data['y_true'] == 1])
        if n_total >= 10:  # 10件以上のTLDのみ
            tld_stats.append({
                'tld': tld,
                'total': n_total,
                'phish': n_phish,
                'phish_rate': n_phish / n_total
            })

    tld_df = pd.DataFrame(tld_stats).sort_values('phish_rate', ascending=False)

    print("\n■ 高Phish率TLD (上位15):")
    print(f"  {'TLD':<10} {'件数':>8} {'Phish':>8} {'Phish率':>10}")
    print("  " + "-" * 40)
    for _, row in tld_df.head(15).iterrows():
        print(f"  {row['tld']:<10} {row['total']:>8} {row['phish']:>8} {row['phish_rate']*100:>9.1f}%")

    print("\n■ 低Phish率TLD (下位10):")
    for _, row in tld_df.tail(10).iterrows():
        print(f"  {row['tld']:<10} {row['total']:>8} {row['phish']:>8} {row['phish_rate']*100:>9.1f}%")

    # ================================================================
    # 3. ドメイン文字列の特徴
    # ================================================================
    print("\n" + "=" * 70)
    print("【3. ドメイン文字列の特徴】")
    print("=" * 70)

    # ドメイン長
    phish['domain_len'] = phish['domain'].str.len()
    benign['domain_len'] = benign['domain'].str.len()

    print(f"\n■ ドメイン長:")
    print(f"  Phishing: 平均 {phish['domain_len'].mean():.1f}, 中央値 {phish['domain_len'].median():.0f}")
    print(f"  Benign:   平均 {benign['domain_len'].mean():.1f}, 中央値 {benign['domain_len'].median():.0f}")

    # 数字を含む割合
    phish['has_digit'] = phish['domain'].str.contains(r'\d', regex=True)
    benign['has_digit'] = benign['domain'].str.contains(r'\d', regex=True)

    print(f"\n■ 数字を含むドメイン:")
    print(f"  Phishing: {phish['has_digit'].mean()*100:.1f}%")
    print(f"  Benign:   {benign['has_digit'].mean()*100:.1f}%")

    # ハイフンを含む割合
    phish['has_hyphen'] = phish['domain'].str.contains('-')
    benign['has_hyphen'] = benign['domain'].str.contains('-')

    print(f"\n■ ハイフンを含むドメイン:")
    print(f"  Phishing: {phish['has_hyphen'].mean()*100:.1f}%")
    print(f"  Benign:   {benign['has_hyphen'].mean()*100:.1f}%")

    # サブドメイン数（ドット数）
    phish['dot_count'] = phish['domain'].str.count(r'\.')
    benign['dot_count'] = benign['domain'].str.count(r'\.')

    print(f"\n■ ドット数（サブドメイン深さ）:")
    print(f"  Phishing: 平均 {phish['dot_count'].mean():.2f}")
    print(f"  Benign:   平均 {benign['dot_count'].mean():.2f}")

    # ================================================================
    # 4. ブランド・危険TLD
    # ================================================================
    print("\n" + "=" * 70)
    print("【4. ブランド・危険TLD・IDN】")
    print("=" * 70)

    for col in ['brand_hit', 'is_dangerous_tld', 'is_idn']:
        if col in handoff.columns:
            p_rate = phish[col].mean() * 100
            b_rate = benign[col].mean() * 100
            print(f"\n■ {col}:")
            print(f"  Phishing: {p_rate:.1f}%")
            print(f"  Benign:   {b_rate:.1f}%")

    # ================================================================
    # 5. 確率帯別の分析
    # ================================================================
    print("\n" + "=" * 70)
    print("【5. Stage1確率帯別のPhish分布】")
    print("=" * 70)

    bins = [0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]
    handoff['p_bin'] = pd.cut(handoff['ml_probability'], bins=bins)

    print(f"\n{'確率帯':<15} {'総数':>8} {'Phish':>8} {'Phish率':>10} {'累積Phish':>10}")
    print("-" * 55)

    cumsum = 0
    for bin_range in sorted(handoff['p_bin'].unique(), key=lambda x: x.left if pd.notna(x) else -1):
        if pd.isna(bin_range):
            continue
        bin_data = handoff[handoff['p_bin'] == bin_range]
        n_total = len(bin_data)
        n_phish = len(bin_data[bin_data['y_true'] == 1])
        cumsum += n_phish
        phish_rate = n_phish / n_total if n_total > 0 else 0

        print(f"{str(bin_range):<15} {n_total:>8} {n_phish:>8} {phish_rate*100:>9.1f}% {cumsum:>10}")

    # ================================================================
    # 6. 特徴的なパターンの発見
    # ================================================================
    print("\n" + "=" * 70)
    print("【6. Phishing特有のパターン】")
    print("=" * 70)

    # 高Phish率の条件を探索
    patterns = [
        ("p1 >= 0.5", handoff['ml_probability'] >= 0.5),
        ("p1 >= 0.3", handoff['ml_probability'] >= 0.3),
        ("defer >= 0.8", handoff['defer_score'] >= 0.8),
        ("defer >= 0.9", handoff['defer_score'] >= 0.9),
        ("dangerous_tld", handoff['is_dangerous_tld'] == 1),
        ("brand_hit", handoff['brand_hit'] == 1),
        ("is_idn", handoff['is_idn'] == 1),
        ("p1>=0.3 & defer>=0.8", (handoff['ml_probability'] >= 0.3) & (handoff['defer_score'] >= 0.8)),
        ("p1>=0.3 & dangerous", (handoff['ml_probability'] >= 0.3) & (handoff['is_dangerous_tld'] == 1)),
    ]

    print(f"\n{'条件':<25} {'該当数':>8} {'Phish':>8} {'Phish率':>10} {'カバー率':>10}")
    print("-" * 65)

    total_phish = len(phish)
    for name, condition in patterns:
        subset = handoff[condition]
        n_total = len(subset)
        n_phish = len(subset[subset['y_true'] == 1])
        phish_rate = n_phish / n_total if n_total > 0 else 0
        coverage = n_phish / total_phish if total_phish > 0 else 0

        print(f"{name:<25} {n_total:>8} {n_phish:>8} {phish_rate*100:>9.1f}% {coverage*100:>9.1f}%")

    # ================================================================
    # 7. 複合条件の探索
    # ================================================================
    print("\n" + "=" * 70)
    print("【7. 最適な自動PHISHING条件の探索】")
    print("=" * 70)

    best_conditions = []

    # グリッドサーチ
    for p_thresh in [0.2, 0.3, 0.4, 0.5, 0.6]:
        for defer_thresh in [0.6, 0.7, 0.8, 0.9]:
            condition = (handoff['ml_probability'] >= p_thresh) & (handoff['defer_score'] >= defer_thresh)
            subset = handoff[condition]
            n_total = len(subset)
            if n_total < 50:
                continue
            n_phish = len(subset[subset['y_true'] == 1])
            n_fp = n_total - n_phish
            phish_rate = n_phish / n_total

            if phish_rate >= 0.8:  # 80%以上のPhish率
                best_conditions.append({
                    'p_thresh': p_thresh,
                    'defer_thresh': defer_thresh,
                    'total': n_total,
                    'phish': n_phish,
                    'fp': n_fp,
                    'phish_rate': phish_rate
                })

    if best_conditions:
        best_df = pd.DataFrame(best_conditions).sort_values('total', ascending=False)
        print(f"\n{'p閾値':>8} {'defer閾値':>10} {'該当数':>8} {'Phish':>8} {'FP':>6} {'Phish率':>10}")
        print("-" * 55)
        for _, row in best_df.head(10).iterrows():
            print(f"{row['p_thresh']:>8.1f} {row['defer_thresh']:>10.1f} {row['total']:>8} {row['phish']:>8} {row['fp']:>6} {row['phish_rate']*100:>9.1f}%")

    print("\n" + "=" * 70)
    print("【まとめ】")
    print("=" * 70)
    print(f"""
  Phishing {len(phish):,}件の特徴:
  - 平均p1: {phish['ml_probability'].mean():.3f} (Benign: {benign['ml_probability'].mean():.3f})
  - 平均defer: {phish['defer_score'].mean():.3f} (Benign: {benign['defer_score'].mean():.3f})
  - 危険TLD率: {phish['is_dangerous_tld'].mean()*100:.1f}% (Benign: {benign['is_dangerous_tld'].mean()*100:.1f}%)
  - ブランド率: {phish['brand_hit'].mean()*100:.1f}% (Benign: {benign['brand_hit'].mean()*100:.1f}%)
""")

    return handoff, phish, benign


if __name__ == '__main__':
    artifact_dir = Path("/data/hdd/asomura/nextstep/artifacts/2026-01-10_140940")
    analyze_phishing_characteristics(artifact_dir)
