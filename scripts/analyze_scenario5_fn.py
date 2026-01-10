#!/usr/bin/env python3
"""
シナリオ5のFN（見逃し）分析スクリプト

p < 0.15 AND defer_score < 0.4 で自動BENIGNにした場合に
見逃されるPhishingサイトを詳細分析する。
"""

import pandas as pd
import numpy as np
from pathlib import Path
from collections import Counter

def analyze_scenario5_fn(artifact_dir: Path):
    """シナリオ5で見逃されるFNを詳細分析"""

    results_dir = artifact_dir / "results"

    # Stage2候補データを読み込み
    df = pd.read_csv(results_dir / "stage2_decisions_candidates_latest.csv")

    # HANDOFFのみ
    handoff = df[df['selected'] == 1].copy()

    # シナリオ5の条件
    scenario5 = handoff[(handoff['ml_probability'] < 0.15) & (handoff['defer_score'] < 0.4)]
    fn_cases = scenario5[scenario5['y_true'] == 1]

    print("=" * 70)
    print("シナリオ5 FN（見逃し）分析")
    print("条件: p < 0.15 AND defer_score < 0.4 → 自動BENIGN")
    print("=" * 70)

    print(f"\n【基本統計】")
    print(f"  シナリオ5対象:   {len(scenario5):,}件")
    print(f"  うちPhishing:    {len(fn_cases):,}件 (これがFN)")
    print(f"  うちBenign:      {len(scenario5) - len(fn_cases):,}件")

    if len(fn_cases) == 0:
        print("\n  FNケースなし")
        return

    print("\n" + "=" * 70)
    print("【FNケースの詳細】")
    print("=" * 70)

    # TLD分析
    print("\n■ TLD分布:")
    tld_counts = fn_cases['tld'].value_counts().head(15)
    for tld, count in tld_counts.items():
        print(f"  {tld:15} : {count:3}件")

    # ドメイン長分析
    fn_cases['domain_length'] = fn_cases['domain'].str.len()
    print(f"\n■ ドメイン長:")
    print(f"  平均: {fn_cases['domain_length'].mean():.1f}")
    print(f"  中央値: {fn_cases['domain_length'].median():.1f}")
    print(f"  最小: {fn_cases['domain_length'].min()}")
    print(f"  最大: {fn_cases['domain_length'].max()}")

    # Stage1確率分布
    print(f"\n■ Stage1確率 (ml_probability):")
    print(f"  平均: {fn_cases['ml_probability'].mean():.4f}")
    print(f"  中央値: {fn_cases['ml_probability'].median():.4f}")
    print(f"  最小: {fn_cases['ml_probability'].min():.4f}")
    print(f"  最大: {fn_cases['ml_probability'].max():.4f}")

    # defer_score分布
    print(f"\n■ defer_score:")
    print(f"  平均: {fn_cases['defer_score'].mean():.4f}")
    print(f"  中央値: {fn_cases['defer_score'].median():.4f}")
    print(f"  最小: {fn_cases['defer_score'].min():.4f}")
    print(f"  最大: {fn_cases['defer_score'].max():.4f}")

    # ブランドヒット
    brand_hit = fn_cases['brand_hit'].sum()
    print(f"\n■ ブランド名含有:")
    print(f"  ブランド名あり: {brand_hit}件 ({100*brand_hit/len(fn_cases):.1f}%)")
    print(f"  ブランド名なし: {len(fn_cases) - brand_hit}件")

    # IDN（国際化ドメイン）
    idn = fn_cases['is_idn'].sum()
    print(f"\n■ IDN（国際化ドメイン）:")
    print(f"  IDN: {idn}件 ({100*idn/len(fn_cases):.1f}%)")

    # 危険TLD
    dangerous_tld = fn_cases['is_dangerous_tld'].sum()
    print(f"\n■ 危険TLD:")
    print(f"  危険TLD: {dangerous_tld}件 ({100*dangerous_tld/len(fn_cases):.1f}%)")

    # 実際のドメイン例
    print("\n" + "=" * 70)
    print("【FNドメイン例（先頭20件）】")
    print("=" * 70)
    print(f"{'domain':<50} {'p':>8} {'defer':>8} {'tld':>8}")
    print("-" * 70)
    for _, row in fn_cases.head(20).iterrows():
        domain = row['domain'][:48] + '..' if len(row['domain']) > 50 else row['domain']
        print(f"{domain:<50} {row['ml_probability']:>8.4f} {row['defer_score']:>8.4f} {row['tld']:>8}")

    # カテゴリ分類の試み
    print("\n" + "=" * 70)
    print("【FNの特徴パターン分類】")
    print("=" * 70)

    # パターン1: 短いドメイン（正規サイトっぽい）
    short_domain = fn_cases[fn_cases['domain_length'] <= 15]
    print(f"\n  パターン1: 短いドメイン (≤15文字)")
    print(f"    件数: {len(short_domain)}件 ({100*len(short_domain)/len(fn_cases):.1f}%)")
    if len(short_domain) > 0:
        print(f"    例: {', '.join(short_domain['domain'].head(5).tolist())}")

    # パターン2: 有名TLD（.com, .org, .net）
    legit_tlds = ['com', 'org', 'net', 'io', 'co']
    legit_tld_cases = fn_cases[fn_cases['tld'].isin(legit_tlds)]
    print(f"\n  パターン2: 有名TLD (.com/.org/.net/.io/.co)")
    print(f"    件数: {len(legit_tld_cases)}件 ({100*len(legit_tld_cases)/len(fn_cases):.1f}%)")

    # パターン3: ブランド名なし
    no_brand = fn_cases[fn_cases['brand_hit'] == 0]
    print(f"\n  パターン3: ブランド名なし")
    print(f"    件数: {len(no_brand)}件 ({100*len(no_brand)/len(fn_cases):.1f}%)")

    # パターン4: 複合（短い + 有名TLD + ブランドなし）
    hard_cases = fn_cases[
        (fn_cases['domain_length'] <= 20) &
        (fn_cases['tld'].isin(legit_tlds)) &
        (fn_cases['brand_hit'] == 0)
    ]
    print(f"\n  パターン4: 識別困難ケース (短い + 有名TLD + ブランドなし)")
    print(f"    件数: {len(hard_cases)}件 ({100*len(hard_cases)/len(fn_cases):.1f}%)")
    if len(hard_cases) > 0:
        print(f"    例:")
        for _, row in hard_cases.head(10).iterrows():
            print(f"      {row['domain']}")

    # 正規サイトとの比較
    print("\n" + "=" * 70)
    print("【正規サイト（同条件のBenign）との比較】")
    print("=" * 70)

    benign_cases = scenario5[scenario5['y_true'] == 0]

    print(f"\n  {'指標':<25} {'FN (Phish)':<15} {'Benign':<15}")
    print("  " + "-" * 55)
    print(f"  {'件数':<25} {len(fn_cases):<15} {len(benign_cases):<15}")
    print(f"  {'平均ドメイン長':<25} {fn_cases['domain_length'].mean():<15.1f} {benign_cases['domain'].str.len().mean():<15.1f}")
    print(f"  {'平均ml_probability':<25} {fn_cases['ml_probability'].mean():<15.4f} {benign_cases['ml_probability'].mean():<15.4f}")
    print(f"  {'平均defer_score':<25} {fn_cases['defer_score'].mean():<15.4f} {benign_cases['defer_score'].mean():<15.4f}")
    print(f"  {'ブランド名含有率':<25} {100*fn_cases['brand_hit'].mean():<15.1f}% {100*benign_cases['brand_hit'].mean():<15.1f}%")

    # 結論
    print("\n" + "=" * 70)
    print("【分析結論】")
    print("=" * 70)

    hard_ratio = len(hard_cases) / len(fn_cases) * 100 if len(fn_cases) > 0 else 0
    print(f"""
  FN {len(fn_cases)}件の内訳:

  1. 識別困難ケース（短い + 有名TLD + ブランドなし）: {len(hard_cases)}件 ({hard_ratio:.1f}%)
     → これらは特徴量だけでは正規サイトと区別不可能
     → Stage3（Webページ内容分析）でないと判定できない

  2. その他: {len(fn_cases) - len(hard_cases)}件 ({100 - hard_ratio:.1f}%)
     → 追加特徴量で改善の余地あり

  許容判断の根拠:
  - 全Phishing {handoff[handoff['y_true']==1].shape[0]}件中の{len(fn_cases)}件 = {100*len(fn_cases)/handoff[handoff['y_true']==1].shape[0]:.2f}%
  - 特徴量ベースでは識別限界のケースが多い
  - 処理時間17時間短縮とのトレードオフ
""")

    # CSVに保存
    fn_cases.to_csv(results_dir / "scenario5_fn_cases.csv", index=False)
    print(f"\n  FNケース一覧を保存: scenario5_fn_cases.csv")

    return fn_cases


if __name__ == '__main__':
    artifact_dir = Path("/data/hdd/asomura/nextstep/artifacts/2026-01-10_140940")
    analyze_scenario5_fn(artifact_dir)
