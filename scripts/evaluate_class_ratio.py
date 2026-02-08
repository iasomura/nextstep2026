#!/usr/bin/env python3
"""
現実世界のクラス比率（正規>>フィッシング）での性能推定スクリプト

50:50テストデータでのTPR/FPRは入力分布に依存しないため、
異なるクラス比率でのPrecision/Recall/F1をベイズ推定で算出する。

変更履歴:
  - 2026-02-08: 新規作成（MTG 2025-12-25 での森先生指摘への対応）
"""

import json
import csv
from pathlib import Path


def main():
    # --- 50:50 テスト結果の読み込み ---
    metrics_path = Path("docs/paper/data/statistics/system_overall_metrics.json")
    with open(metrics_path) as f:
        metrics = json.load(f)

    cm = metrics["confusion_matrix"]
    TP_50 = cm["TP"]   # 62,453
    FP_50 = cm["FP"]   # 532
    TN_50 = cm["TN"]   # 63,079
    FN_50 = cm["FN"]   # 1,158

    # クラス別の母数（50:50テストセット）
    n_phishing = TP_50 + FN_50  # 63,611
    n_benign = FP_50 + TN_50    # 63,611

    # 入力分布に依存しない指標
    TPR = TP_50 / n_phishing     # Recall = 98.18%
    FPR = FP_50 / n_benign       # FPR = 0.836%

    print(f"=== 50:50テスト結果から算出した基本レート ===")
    print(f"  TPR (Recall): {TPR*100:.2f}%")
    print(f"  FPR:          {FPR*100:.3f}%")
    print(f"  N_phishing:   {n_phishing:,}")
    print(f"  N_benign:     {n_benign:,}")
    print()

    # --- 異なるクラス比率での性能推定 ---
    # benign:phishing の比率
    ratios = [1, 5, 10, 20, 50, 100, 500, 1000]

    results = []
    print(f"{'Benign:Phish':>14} | {'N_benign':>12} | {'TP':>8} | {'FP':>8} | {'TN':>10} | {'FN':>6} | {'Precision':>10} | {'Recall':>8} | {'F1':>8} | {'FP/day*':>8}")
    print("-" * 120)

    for ratio in ratios:
        # フィッシング数は固定、正規側を比率に応じて拡大
        n_p = n_phishing
        n_b = n_phishing * ratio

        # 推定混同行列
        tp = TPR * n_p
        fn = (1 - TPR) * n_p
        fp = FPR * n_b
        tn = (1 - FPR) * n_b

        # 指標計算
        precision = tp / (tp + fp) * 100 if (tp + fp) > 0 else 0
        recall = TPR * 100
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

        # 運用想定: 1日あたりのFP数（仮に1日10,000件の新規ドメイン監視）
        daily_domains = 10000
        daily_phishing = daily_domains / (1 + ratio)
        daily_benign = daily_domains - daily_phishing
        daily_fp = FPR * daily_benign

        results.append({
            "ratio": f"1:{ratio}",
            "n_phishing": int(n_p),
            "n_benign": int(n_b),
            "TP": int(round(tp)),
            "FP": int(round(fp)),
            "TN": int(round(tn)),
            "FN": int(round(fn)),
            "Precision": round(precision, 2),
            "Recall": round(recall, 2),
            "F1": round(f1, 2),
            "daily_fp_10k": round(daily_fp, 1),
        })

        print(f"  1:{ratio:<10} | {int(n_b):>12,} | {int(round(tp)):>8,} | {int(round(fp)):>8,} | {int(round(tn)):>10,} | {int(round(fn)):>6,} | {precision:>9.2f}% | {recall:>6.2f}% | {f1:>6.2f}% | {daily_fp:>7.1f}")

    print()
    print("* FP/day: 1日10,000件の新規ドメイン監視を想定した場合の偽陽性数")

    # --- CSV出力 ---
    output_path = Path("docs/paper/data/tables/class_ratio_analysis.csv")
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)

    print(f"\n出力: {output_path}")

    # --- 要約統計 ---
    print("\n=== 要約 ===")
    print(f"Recall（全比率で一定）: {TPR*100:.2f}%")
    print(f"Precision の変化:")
    for r in results:
        print(f"  {r['ratio']:>6}: Precision={r['Precision']:.2f}%, F1={r['F1']:.2f}%")

    print(f"\n重要な閾値:")
    for r in results:
        if r["Precision"] < 90:
            print(f"  Precision < 90% になるのは比率 {r['ratio']} 以降")
            break

    for r in results:
        if r["Precision"] < 50:
            print(f"  Precision < 50% になるのは比率 {r['ratio']} 以降")
            break


if __name__ == "__main__":
    main()
