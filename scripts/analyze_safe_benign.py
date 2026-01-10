#!/usr/bin/env python3
"""
安全にAuto-BENIGNできる条件の探索

目標: Stage3に渡すBenignを減らし、Phishingは確実にStage3へ
"""

import pandas as pd
import numpy as np
from pathlib import Path

def analyze_safe_benign(artifact_dir: Path):
    """安全にAuto-BENIGNできる条件を探索"""

    results_dir = artifact_dir / "results"
    df = pd.read_csv(results_dir / "stage2_decisions_candidates_latest.csv")

    # 現在のHANDOFF
    handoff = df[df['selected'] == 1].copy()

    phish = handoff[handoff['y_true'] == 1]
    benign = handoff[handoff['y_true'] == 0]

    print("=" * 70)
    print("安全なAuto-BENIGN条件の探索")
    print("目標: Benignを減らし、Phishingは確実にStage3へ")
    print("=" * 70)
    print(f"\n  現在のHANDOFF: {len(handoff):,}件")
    print(f"  - Phishing: {len(phish):,}件 (Stage3で検出したい)")
    print(f"  - Benign:   {len(benign):,}件 (減らしたい)")

    # ================================================================
    # 1. 低Phish率TLD（0%または極めて低い）
    # ================================================================
    print("\n" + "=" * 70)
    print("【1. Phish率0%のTLD】")
    print("=" * 70)

    tld_stats = []
    for tld in handoff['tld'].unique():
        tld_data = handoff[handoff['tld'] == tld]
        n_total = len(tld_data)
        n_phish = len(tld_data[tld_data['y_true'] == 1])
        n_benign = n_total - n_phish
        phish_rate = n_phish / n_total if n_total > 0 else 0
        tld_stats.append({
            'tld': tld,
            'total': n_total,
            'phish': n_phish,
            'benign': n_benign,
            'phish_rate': phish_rate
        })

    tld_df = pd.DataFrame(tld_stats).sort_values('phish_rate')

    zero_phish_tlds = tld_df[tld_df['phish_rate'] == 0]
    print(f"\n  Phish率0%のTLD: {len(zero_phish_tlds)}個")
    print(f"  合計Benign: {zero_phish_tlds['benign'].sum():,}件")

    print(f"\n  {'TLD':<12} {'件数':>8} {'Benign':>8}")
    print("  " + "-" * 30)
    for _, row in zero_phish_tlds[zero_phish_tlds['total'] >= 10].iterrows():
        print(f"  {row['tld']:<12} {row['total']:>8} {row['benign']:>8}")

    # ================================================================
    # 2. 低p1帯の詳細分析（シナリオ5の拡張検討）
    # ================================================================
    print("\n" + "=" * 70)
    print("【2. 低p1帯の詳細分析】")
    print("=" * 70)

    print(f"\n  現在のシナリオ5: p1<0.15 AND defer<0.4")
    print(f"  → これで既に7,805件を除外済み")

    # さらに拡張できる余地を探る
    print(f"\n  ■ p1閾値を上げた場合の影響:")
    print(f"  {'条件':<30} {'削減Benign':>12} {'FN増加':>10}")
    print("  " + "-" * 55)

    # シナリオ5の拡張パターン
    extensions = [
        ("p1<0.20 AND defer<0.4", 0.20, 0.4),
        ("p1<0.15 AND defer<0.5", 0.15, 0.5),
        ("p1<0.20 AND defer<0.5", 0.20, 0.5),
        ("p1<0.10 AND defer<0.5", 0.10, 0.5),
        ("p1<0.10 AND defer<0.6", 0.10, 0.6),
    ]

    for name, p1_max, defer_max in extensions:
        condition = (handoff['ml_probability'] < p1_max) & (handoff['defer_score'] < defer_max)
        subset = handoff[condition]
        n_benign = len(subset[subset['y_true'] == 0])
        n_phish = len(subset[subset['y_true'] == 1])  # これがFN
        print(f"  {name:<30} {n_benign:>12,} {n_phish:>10}")

    # ================================================================
    # 3. 低p1 + legitimate TLD
    # ================================================================
    print("\n" + "=" * 70)
    print("【3. 低p1 + legitimate TLD】")
    print("=" * 70)

    legitimate_tlds = {'gov', 'edu', 'org', 'mil', 'int'}
    is_legit_tld = handoff['tld'].isin(legitimate_tlds)

    print(f"\n  Legitimate TLD ({', '.join(legitimate_tlds)}): {is_legit_tld.sum():,}件")

    conditions = [
        ("legit_tld AND p1<0.3", is_legit_tld & (handoff['ml_probability'] < 0.3)),
        ("legit_tld AND p1<0.2", is_legit_tld & (handoff['ml_probability'] < 0.2)),
        ("legit_tld AND p1<0.1", is_legit_tld & (handoff['ml_probability'] < 0.1)),
    ]

    print(f"\n  {'条件':<30} {'Benign削減':>12} {'FN':>8}")
    print("  " + "-" * 55)
    for name, cond in conditions:
        subset = handoff[cond]
        n_benign = len(subset[subset['y_true'] == 0])
        n_phish = len(subset[subset['y_true'] == 1])
        print(f"  {name:<30} {n_benign:>12,} {n_phish:>8}")

    # ================================================================
    # 4. 低p1 + 非dangerous TLD
    # ================================================================
    print("\n" + "=" * 70)
    print("【4. 低p1 + 非dangerous TLD】")
    print("=" * 70)

    not_dangerous = handoff['is_dangerous_tld'] == 0

    conditions = [
        ("not_dangerous AND p1<0.20 AND defer<0.5",
         not_dangerous & (handoff['ml_probability'] < 0.20) & (handoff['defer_score'] < 0.5)),
        ("not_dangerous AND p1<0.15 AND defer<0.5",
         not_dangerous & (handoff['ml_probability'] < 0.15) & (handoff['defer_score'] < 0.5)),
        ("not_dangerous AND p1<0.10 AND defer<0.5",
         not_dangerous & (handoff['ml_probability'] < 0.10) & (handoff['defer_score'] < 0.5)),
        ("not_dangerous AND p1<0.10 AND defer<0.6",
         not_dangerous & (handoff['ml_probability'] < 0.10) & (handoff['defer_score'] < 0.6)),
    ]

    print(f"\n  {'条件':<45} {'Benign':>10} {'FN':>6} {'FN率':>8}")
    print("  " + "-" * 75)
    for name, cond in conditions:
        subset = handoff[cond]
        n_total = len(subset)
        n_benign = len(subset[subset['y_true'] == 0])
        n_phish = len(subset[subset['y_true'] == 1])
        fn_rate = n_phish / n_total * 100 if n_total > 0 else 0
        print(f"  {name:<45} {n_benign:>10,} {n_phish:>6} {fn_rate:>7.2f}%")

    # ================================================================
    # 5. グリッドサーチ：最適条件探索
    # ================================================================
    print("\n" + "=" * 70)
    print("【5. 最適条件のグリッドサーチ】")
    print("  目標: FN率 < 2% で最大のBenign削減")
    print("=" * 70)

    results = []
    for p1_max in [0.05, 0.08, 0.10, 0.12, 0.15, 0.18, 0.20]:
        for defer_max in [0.35, 0.40, 0.45, 0.50, 0.55, 0.60]:
            # 基本条件
            cond = (handoff['ml_probability'] < p1_max) & (handoff['defer_score'] < defer_max)
            subset = handoff[cond]
            n_total = len(subset)
            if n_total < 100:
                continue
            n_benign = len(subset[subset['y_true'] == 0])
            n_phish = len(subset[subset['y_true'] == 1])
            fn_rate = n_phish / n_total if n_total > 0 else 0

            results.append({
                'p1_max': p1_max,
                'defer_max': defer_max,
                'total': n_total,
                'benign': n_benign,
                'fn': n_phish,
                'fn_rate': fn_rate
            })

    results_df = pd.DataFrame(results)

    # FN率 < 2% でソート
    good_results = results_df[results_df['fn_rate'] < 0.02].sort_values('benign', ascending=False)

    print(f"\n  {'p1<':>6} {'defer<':>8} {'削減数':>10} {'Benign':>10} {'FN':>6} {'FN率':>8}")
    print("  " + "-" * 55)
    for _, row in good_results.head(15).iterrows():
        print(f"  {row['p1_max']:>6.2f} {row['defer_max']:>8.2f} {row['total']:>10,} {row['benign']:>10,} {row['fn']:>6} {row['fn_rate']*100:>7.2f}%")

    # ================================================================
    # 6. 推奨条件
    # ================================================================
    print("\n" + "=" * 70)
    print("【6. 推奨条件】")
    print("=" * 70)

    if len(good_results) > 0:
        best = good_results.iloc[0]
        print(f"""
  ★ 推奨: p1 < {best['p1_max']:.2f} AND defer < {best['defer_max']:.2f}

    - 削減件数:  {best['total']:,}件
    - Benign:    {best['benign']:,}件
    - FN:        {best['fn']:.0f}件 ({best['fn_rate']*100:.2f}%)

  現在のシナリオ5との比較:
    - シナリオ5: p1<0.15 AND defer<0.40 (7,805件削減)
    - 推奨条件:  {best['total'] - 7805:+,}件 追加削減可能
""")

    return handoff


if __name__ == '__main__':
    artifact_dir = Path("/data/hdd/asomura/nextstep/artifacts/2026-01-10_140940")
    analyze_safe_benign(artifact_dir)
