#!/usr/bin/env python3
"""
高確信Auto-PHISHING分析スクリプト

シナリオ5（Auto-BENIGN）の対称として、
高確率・高defer_scoreのケースを自動PHISHINGにできるか分析する。
"""

import pandas as pd
import numpy as np
from pathlib import Path

def analyze_auto_phishing(artifact_dir: Path):
    """高確信PHISHINGケースの分析"""

    results_dir = artifact_dir / "results"

    # Stage2候補データを読み込み
    df = pd.read_csv(results_dir / "stage2_decisions_candidates_latest.csv")

    # 現在のHANDOFF（selected=1かつsafe_benign=0）
    # Note: safe_benignが適用された後のデータ
    handoff = df[df['selected'] == 1].copy()

    print("=" * 70)
    print("高確信 Auto-PHISHING 分析")
    print("=" * 70)

    print(f"\n【現在のHANDOFF】")
    print(f"  総数: {len(handoff):,}件")

    handoff_phish = handoff[handoff['y_true'] == 1]
    handoff_benign = handoff[handoff['y_true'] == 0]
    print(f"  Phishing: {len(handoff_phish):,}件 ({100*len(handoff_phish)/len(handoff):.1f}%)")
    print(f"  Benign:   {len(handoff_benign):,}件 ({100*len(handoff_benign)/len(handoff):.1f}%)")

    # 高確率帯の分析
    print("\n" + "=" * 70)
    print("【Stage1確率帯別分析（高確率側）】")
    print("=" * 70)

    thresholds = [0.7, 0.75, 0.8, 0.85, 0.9, 0.95]

    print(f"\n{'閾値':<10} {'件数':<10} {'Phish':<10} {'Benign':<10} {'Phish率':<10} {'FP数':<10}")
    print("-" * 60)

    for thresh in thresholds:
        high_p = handoff[handoff['ml_probability'] >= thresh]
        n_total = len(high_p)
        n_phish = len(high_p[high_p['y_true'] == 1])
        n_benign = n_total - n_phish
        phish_rate = n_phish / n_total if n_total > 0 else 0

        print(f"p >= {thresh:<5} {n_total:<10,} {n_phish:<10,} {n_benign:<10,} {100*phish_rate:<10.1f}% {n_benign:<10}")

    # defer_scoreも考慮した分析
    print("\n" + "=" * 70)
    print("【複合条件分析（p AND defer_score）】")
    print("=" * 70)

    scenarios = [
        (0.8, 0.9, "シナリオA"),
        (0.8, 0.8, "シナリオB"),
        (0.85, 0.9, "シナリオC"),
        (0.9, 0.9, "シナリオD"),
        (0.7, 0.95, "シナリオE"),
    ]

    print(f"\n{'シナリオ':<12} {'条件':<25} {'件数':<8} {'Phish':<8} {'FP':<6} {'Phish率':<10}")
    print("-" * 70)

    best_scenario = None
    best_score = 0

    for p_thresh, defer_thresh, name in scenarios:
        condition = (handoff['ml_probability'] >= p_thresh) & (handoff['defer_score'] >= defer_thresh)
        subset = handoff[condition]
        n_total = len(subset)
        n_phish = len(subset[subset['y_true'] == 1])
        n_benign = n_total - n_phish
        phish_rate = n_phish / n_total if n_total > 0 else 0

        cond_str = f"p>={p_thresh}, defer>={defer_thresh}"
        print(f"{name:<12} {cond_str:<25} {n_total:<8,} {n_phish:<8,} {n_benign:<6} {100*phish_rate:<10.1f}%")

        # スコア: 削減件数 × Phish率（FPを抑えつつ削減したい）
        score = n_total * phish_rate if phish_rate > 0.9 else 0
        if score > best_score:
            best_score = score
            best_scenario = (p_thresh, defer_thresh, name, n_total, n_benign)

    # 推奨シナリオ
    print("\n" + "=" * 70)
    print("【シナリオ別シミュレーション】")
    print("=" * 70)

    sim_scenarios = [
        (0.8, 0.9, "保守的"),
        (0.7, 0.9, "中間"),
        (0.6, 0.95, "積極的"),
    ]

    current_handoff = len(handoff)

    for p_thresh, defer_thresh, label in sim_scenarios:
        condition = (handoff['ml_probability'] >= p_thresh) & (handoff['defer_score'] >= defer_thresh)
        subset = handoff[condition]
        n_total = len(subset)
        n_phish = len(subset[subset['y_true'] == 1])
        n_benign = n_total - n_phish
        phish_rate = n_phish / n_total if n_total > 0 else 0

        new_handoff = current_handoff - n_total
        reduction_pct = 100 * n_total / current_handoff

        print(f"\n  【{label}】 p >= {p_thresh}, defer >= {defer_thresh}")
        print(f"    自動PHISHING:  {n_total:,}件 ({reduction_pct:.1f}%削減)")
        print(f"    FP (誤検知):   {n_benign:,}件")
        print(f"    Phish率:       {100*phish_rate:.1f}%")
        print(f"    残りHANDOFF:   {new_handoff:,}件")

    # FPケースの詳細分析
    print("\n" + "=" * 70)
    print("【FP (誤検知) ケースの分析】")
    print("=" * 70)

    # 中間シナリオ（p >= 0.7, defer >= 0.9）のFPを分析
    condition = (handoff['ml_probability'] >= 0.7) & (handoff['defer_score'] >= 0.9)
    fp_cases = handoff[condition & (handoff['y_true'] == 0)]

    if len(fp_cases) > 0:
        print(f"\n  p >= 0.7, defer >= 0.9 のFP: {len(fp_cases)}件")

        print(f"\n  ■ TLD分布:")
        tld_counts = fp_cases['tld'].value_counts().head(10)
        for tld, count in tld_counts.items():
            print(f"    {tld:15} : {count:3}件")

        print(f"\n  ■ ドメイン例（先頭10件）:")
        for _, row in fp_cases.head(10).iterrows():
            print(f"    {row['domain']:<40} p={row['ml_probability']:.3f} defer={row['defer_score']:.3f}")
    else:
        print("  FPケースなし")

    # クラスタリングのための類似性分析
    print("\n" + "=" * 70)
    print("【クラスタリング用：TLD分布分析】")
    print("=" * 70)

    print("\n  HANDOFF全体のTLD分布（上位20）:")
    tld_counts = handoff['tld'].value_counts().head(20)
    for tld, count in tld_counts.items():
        pct = 100 * count / len(handoff)
        phish_in_tld = len(handoff[(handoff['tld'] == tld) & (handoff['y_true'] == 1)])
        phish_rate = 100 * phish_in_tld / count if count > 0 else 0
        print(f"    {tld:10} : {count:5,}件 ({pct:5.1f}%) [Phish率: {phish_rate:5.1f}%]")

    return handoff


if __name__ == '__main__':
    artifact_dir = Path("/data/hdd/asomura/nextstep/artifacts/2026-01-10_140940")
    analyze_auto_phishing(artifact_dir)
