#!/usr/bin/env python3
"""
Stage2 HANDOFF分析スクリプト

Stage2でHANDOFFされるサンプルの分布を分析し、
削減可能な領域を特定する。
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from pathlib import Path

def analyze_handoff(artifact_dir: Path):
    """Stage2 HANDOFFの詳細分析"""

    results_dir = artifact_dir / "results"

    # Stage2候補データを読み込み
    df = pd.read_csv(results_dir / "stage2_decisions_candidates_latest.csv")

    print("=" * 60)
    print("Stage2 HANDOFF 分析")
    print("=" * 60)

    # 基本統計
    total = len(df)
    handoff = df[df['selected'] == 1]
    pending = df[df['selected'] == 0]

    print(f"\n【基本統計】")
    print(f"  Stage1 DEFER総数:  {total:,}")
    print(f"  → HANDOFF (Stage3): {len(handoff):,} ({100*len(handoff)/total:.1f}%)")
    print(f"  → PENDING (自動):   {len(pending):,} ({100*len(pending)/total:.1f}%)")

    # HANDOFFの内訳
    handoff_phish = handoff[handoff['y_true'] == 1]
    handoff_benign = handoff[handoff['y_true'] == 0]

    print(f"\n【HANDOFF内訳】")
    print(f"  Phishing:  {len(handoff_phish):,} ({100*len(handoff_phish)/len(handoff):.1f}%)")
    print(f"  Benign:    {len(handoff_benign):,} ({100*len(handoff_benign)/len(handoff):.1f}%)")

    # PENDINGの内訳
    pending_phish = pending[pending['y_true'] == 1]
    pending_benign = pending[pending['y_true'] == 0]

    print(f"\n【PENDING内訳】")
    print(f"  Phishing:  {len(pending_phish):,} ({100*len(pending_phish)/len(pending):.1f}%)")
    print(f"  Benign:    {len(pending_benign):,} ({100*len(pending_benign)/len(pending):.1f}%)")
    print(f"  ※PENDINGのPhishingは見逃し（FN）のリスク")

    # Stage1確率によるビン分析
    print("\n" + "=" * 60)
    print("【Stage1確率ビン別 HANDOFF分析】")
    print("=" * 60)

    bins = [0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]
    handoff['p_bin'] = pd.cut(handoff['ml_probability'], bins=bins)

    bin_analysis = []
    for bin_range in handoff['p_bin'].cat.categories:
        bin_data = handoff[handoff['p_bin'] == bin_range]
        if len(bin_data) == 0:
            continue

        n_total = len(bin_data)
        n_phish = len(bin_data[bin_data['y_true'] == 1])
        n_benign = n_total - n_phish
        phish_rate = n_phish / n_total if n_total > 0 else 0

        bin_analysis.append({
            'bin': str(bin_range),
            'total': n_total,
            'phish': n_phish,
            'benign': n_benign,
            'phish_rate': phish_rate
        })

        print(f"  {str(bin_range):12} | 件数: {n_total:5,} | "
              f"Phish: {n_phish:5,} ({100*phish_rate:5.1f}%) | "
              f"Benign: {n_benign:5,}")

    # 削減可能性の分析
    print("\n" + "=" * 60)
    print("【削減可能性分析】")
    print("=" * 60)

    # Benignが多い帯（Phish率 < 5%）
    low_phish_bins = [b for b in bin_analysis if b['phish_rate'] < 0.05]
    if low_phish_bins:
        total_low = sum(b['total'] for b in low_phish_bins)
        phish_low = sum(b['phish'] for b in low_phish_bins)
        print(f"\n  Phish率 < 5% の帯:")
        print(f"    合計件数: {total_low:,}")
        print(f"    内Phish:  {phish_low:,}")
        print(f"    → これを自動BENIGNにすると {phish_low}件のFN発生リスク")

    # Phishが多い帯（Phish率 > 95%）
    high_phish_bins = [b for b in bin_analysis if b['phish_rate'] > 0.95]
    if high_phish_bins:
        total_high = sum(b['total'] for b in high_phish_bins)
        benign_high = sum(b['benign'] for b in high_phish_bins)
        print(f"\n  Phish率 > 95% の帯:")
        print(f"    合計件数: {total_high:,}")
        print(f"    内Benign: {benign_high:,}")
        print(f"    → これを自動PHISHにすると {benign_high}件のFP発生")

    # defer_score（Stage2 LR出力）による分析
    print("\n" + "=" * 60)
    print("【defer_score（Stage2 LR出力）ビン別分析】")
    print("=" * 60)

    defer_bins = [0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]
    handoff['defer_bin'] = pd.cut(handoff['defer_score'], bins=defer_bins)

    for bin_range in handoff['defer_bin'].cat.categories:
        bin_data = handoff[handoff['defer_bin'] == bin_range]
        if len(bin_data) == 0:
            continue

        n_total = len(bin_data)
        n_phish = len(bin_data[bin_data['y_true'] == 1])
        phish_rate = n_phish / n_total if n_total > 0 else 0

        print(f"  {str(bin_range):12} | 件数: {n_total:5,} | "
              f"Phish: {n_phish:5,} ({100*phish_rate:5.1f}%)")

    # 可視化
    print("\n" + "=" * 60)
    print("【可視化】")
    print("=" * 60)

    fig, axes = plt.subplots(2, 2, figsize=(14, 10))

    # 1. Stage1確率の分布（Phish vs Benign）
    ax1 = axes[0, 0]
    ax1.hist(handoff_phish['ml_probability'], bins=50, alpha=0.7, label='Phishing', color='red')
    ax1.hist(handoff_benign['ml_probability'], bins=50, alpha=0.7, label='Benign', color='blue')
    ax1.set_xlabel('Stage1 Probability (ml_probability)')
    ax1.set_ylabel('Count')
    ax1.set_title('HANDOFF: Stage1確率分布')
    ax1.legend()
    ax1.grid(True, alpha=0.3)

    # 2. defer_scoreの分布
    ax2 = axes[0, 1]
    ax2.hist(handoff_phish['defer_score'], bins=50, alpha=0.7, label='Phishing', color='red')
    ax2.hist(handoff_benign['defer_score'], bins=50, alpha=0.7, label='Benign', color='blue')
    ax2.set_xlabel('defer_score (Stage2 LR output)')
    ax2.set_ylabel('Count')
    ax2.set_title('HANDOFF: defer_score分布')
    ax2.legend()
    ax2.grid(True, alpha=0.3)

    # 3. Stage1確率 vs Phish率
    ax3 = axes[1, 0]
    bin_centers = [(b['bin'].split(',')[0].replace('(', '')) for b in bin_analysis]
    bin_centers = [float(x) + 0.05 for x in bin_centers]
    phish_rates = [b['phish_rate'] * 100 for b in bin_analysis]
    counts = [b['total'] for b in bin_analysis]

    bars = ax3.bar(bin_centers, phish_rates, width=0.08, alpha=0.7, color='purple')
    ax3.axhline(y=5, color='green', linestyle='--', label='5% threshold')
    ax3.axhline(y=95, color='red', linestyle='--', label='95% threshold')
    ax3.set_xlabel('Stage1 Probability')
    ax3.set_ylabel('Phishing Rate (%)')
    ax3.set_title('Stage1確率帯別のPhishing率')
    ax3.set_xlim(0, 1)
    ax3.set_ylim(0, 100)
    ax3.legend()
    ax3.grid(True, alpha=0.3)

    # 各バーの上に件数を表示
    for bar, count in zip(bars, counts):
        ax3.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 2,
                f'{count:,}', ha='center', va='bottom', fontsize=8)

    # 4. 2D散布図（Stage1確率 vs defer_score）
    ax4 = axes[1, 1]
    scatter = ax4.scatter(handoff['ml_probability'], handoff['defer_score'],
                          c=handoff['y_true'], cmap='coolwarm', alpha=0.3, s=5)
    ax4.set_xlabel('Stage1 Probability')
    ax4.set_ylabel('defer_score')
    ax4.set_title('Stage1確率 vs defer_score (赤=Phish, 青=Benign)')
    ax4.grid(True, alpha=0.3)

    plt.tight_layout()

    output_path = results_dir / "handoff_analysis.png"
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    print(f"  保存: {output_path}")

    plt.close()

    # 削減シミュレーション
    print("\n" + "=" * 60)
    print("【削減シミュレーション】")
    print("=" * 60)

    # シナリオ1: 低確率帯（p < 0.2）を自動BENIGN
    low_p = handoff[handoff['ml_probability'] < 0.2]
    low_p_phish = len(low_p[low_p['y_true'] == 1])
    print(f"\n  シナリオ1: p < 0.2 を自動BENIGN")
    print(f"    削減件数: {len(low_p):,} ({100*len(low_p)/len(handoff):.1f}%)")
    print(f"    FN増加:   {low_p_phish:,}")

    # シナリオ2: 高確率帯（p > 0.8）を自動PHISHING
    high_p = handoff[handoff['ml_probability'] > 0.8]
    high_p_benign = len(high_p[high_p['y_true'] == 0])
    print(f"\n  シナリオ2: p > 0.8 を自動PHISHING")
    print(f"    削減件数: {len(high_p):,} ({100*len(high_p)/len(handoff):.1f}%)")
    print(f"    FP増加:   {high_p_benign:,}")

    # シナリオ3: defer_score < 0.3 を自動BENIGN
    low_defer = handoff[handoff['defer_score'] < 0.3]
    low_defer_phish = len(low_defer[low_defer['y_true'] == 1])
    print(f"\n  シナリオ3: defer_score < 0.3 を自動BENIGN")
    print(f"    削減件数: {len(low_defer):,} ({100*len(low_defer)/len(handoff):.1f}%)")
    print(f"    FN増加:   {low_defer_phish:,}")

    # シナリオ4: defer_score > 0.9 を自動PHISHING
    high_defer = handoff[handoff['defer_score'] > 0.9]
    high_defer_benign = len(high_defer[high_defer['y_true'] == 0])
    print(f"\n  シナリオ4: defer_score > 0.9 を自動PHISHING")
    print(f"    削減件数: {len(high_defer):,} ({100*len(high_defer)/len(handoff):.1f}%)")
    print(f"    FP増加:   {high_defer_benign:,}")

    # 複合シナリオ
    combined = handoff[(handoff['ml_probability'] < 0.15) & (handoff['defer_score'] < 0.4)]
    combined_phish = len(combined[combined['y_true'] == 1])
    print(f"\n  シナリオ5: p < 0.15 AND defer_score < 0.4 を自動BENIGN")
    print(f"    削減件数: {len(combined):,} ({100*len(combined)/len(handoff):.1f}%)")
    print(f"    FN増加:   {combined_phish:,}")

    return df, handoff


if __name__ == '__main__':
    artifact_dir = Path("/data/hdd/asomura/nextstep/artifacts/2026-01-10_140940")
    analyze_handoff(artifact_dir)
