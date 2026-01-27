#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
analyze_rule_metrics.py — ルール効果分析スクリプト

評価結果からルールの効果を分析し、TP/FP/TN/FNを計算する。

使用方法:
    # 評価結果ファイルから分析
    python scripts/analyze_rule_metrics.py results.csv

    # JSON形式でエクスポート
    python scripts/analyze_rule_metrics.py results.csv --export-json rule_metrics.json

    # CSV形式でエクスポート
    python scripts/analyze_rule_metrics.py results.csv --export-csv rule_metrics.csv

    # ルールを再評価して詳細分析
    python scripts/analyze_rule_metrics.py results.csv --re-evaluate

作成日: 2026-01-28
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional
from collections import defaultdict
from dataclasses import dataclass, field

import pandas as pd

# プロジェクトルートをパスに追加
sys.path.insert(0, str(Path(__file__).parent.parent))

from phishing_agent.rules import (
    RuleEngine,
    RuleContext,
    MetricsCollector,
    create_default_engine,
)
from phishing_agent.rules.integration import (
    build_rule_context,
    evaluate_rules,
    set_metrics_collector,
    reset_default_engine,
)


@dataclass
class RuleMetricsSummary:
    """ルールメトリクスのサマリー"""
    rule_name: str
    trigger_count: int = 0
    true_positive: int = 0
    false_positive: int = 0
    true_negative: int = 0
    false_negative: int = 0

    @property
    def precision(self) -> float:
        total = self.true_positive + self.false_positive
        return self.true_positive / total if total > 0 else 0.0

    @property
    def recall(self) -> float:
        total = self.true_positive + self.false_negative
        return self.true_positive / total if total > 0 else 0.0

    @property
    def f1_score(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_name": self.rule_name,
            "trigger_count": self.trigger_count,
            "true_positive": self.true_positive,
            "false_positive": self.false_positive,
            "true_negative": self.true_negative,
            "false_negative": self.false_negative,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1_score": round(self.f1_score, 4),
        }


def analyze_from_risk_factors(
    df: pd.DataFrame,
    label_col: str = "label",
    prediction_col: str = "is_phishing",
    risk_factors_col: str = "risk_factors",
) -> Dict[str, RuleMetricsSummary]:
    """risk_factors列からルール発火を分析する。

    Args:
        df: 評価結果DataFrame
        label_col: 正解ラベル列名
        prediction_col: 予測列名
        risk_factors_col: リスク要因列名

    Returns:
        ルール名をキーとするメトリクスサマリー辞書
    """
    metrics: Dict[str, RuleMetricsSummary] = {}

    for _, row in df.iterrows():
        label = row.get(label_col, 0)
        actual_phishing = bool(label == 1 or label == "phishing")

        # risk_factors を解析
        risk_factors = row.get(risk_factors_col, [])
        if isinstance(risk_factors, str):
            try:
                risk_factors = json.loads(risk_factors)
            except (json.JSONDecodeError, TypeError):
                risk_factors = risk_factors.split(",") if risk_factors else []

        # policy: プレフィックス付きのルール名を抽出
        triggered_rules = set()
        for rf in (risk_factors or []):
            rf_str = str(rf).strip()
            if rf_str.startswith("policy:"):
                rule_name = rf_str[7:]  # "policy:" を除去
                triggered_rules.add(rule_name)

        # 全てのルールに対してメトリクスを更新
        for rule_name in triggered_rules:
            if rule_name not in metrics:
                metrics[rule_name] = RuleMetricsSummary(rule_name=rule_name)

            m = metrics[rule_name]
            m.trigger_count += 1

            if actual_phishing:
                m.true_positive += 1
            else:
                m.false_positive += 1

    return metrics


def re_evaluate_with_rules(
    df: pd.DataFrame,
    label_col: str = "label",
    domain_col: str = "domain",
    ml_col: str = "ml_probability",
    verbose: bool = False,
) -> Dict[str, RuleMetricsSummary]:
    """ドメインを再評価してルールメトリクスを収集する。

    注意: tool_results が必要なため、限定的な分析のみ可能

    Args:
        df: 評価結果DataFrame
        label_col: 正解ラベル列名
        domain_col: ドメイン列名
        ml_col: ML確率列名
        verbose: 詳細出力

    Returns:
        ルール名をキーとするメトリクスサマリー辞書
    """
    # MetricsCollectorを設定
    collector = MetricsCollector()
    set_metrics_collector(collector)
    reset_default_engine()

    engine = create_default_engine(metrics_collector=collector)

    for idx, row in df.iterrows():
        domain = row.get(domain_col, "")
        label = row.get(label_col, 0)
        actual_phishing = bool(label == 1 or label == "phishing")
        ml_probability = float(row.get(ml_col, 0.0) or 0.0)

        # 簡易コンテキスト作成（tool_results がないため限定的）
        ctx = RuleContext(
            domain=domain,
            ml_probability=ml_probability,
            # 他のフィールドは空でも評価可能な一部ルールのみ発火
        )

        result = engine.evaluate(ctx)

        # 予測を判定（force_phishing があれば phishing）
        predicted_phishing = result.force_phishing is True

        # メトリクスを記録
        engine.finalize_evaluation(
            result.eval_id,
            predicted_phishing=predicted_phishing,
            actual_phishing=actual_phishing,
        )

        if verbose and idx % 100 == 0:
            print(f"  Processed {idx + 1}/{len(df)} domains...")

    # メトリクスを集約
    metrics = {}
    for name, m in collector.get_all_metrics().items():
        metrics[name] = RuleMetricsSummary(
            rule_name=name,
            trigger_count=m.trigger_count,
            true_positive=m.true_positive,
            false_positive=m.false_positive,
            true_negative=m.true_negative,
            false_negative=m.false_negative,
        )

    return metrics


def print_metrics_summary(metrics: Dict[str, RuleMetricsSummary]):
    """メトリクスサマリーを出力する。"""
    print("\n" + "=" * 90)
    print("RULE EFFECTIVENESS SUMMARY")
    print("=" * 90)

    # トリガー数でソート
    sorted_rules = sorted(
        metrics.values(),
        key=lambda m: m.trigger_count,
        reverse=True
    )

    print(f"\n{'Rule Name':<35} {'Triggers':>8} {'TP':>6} {'FP':>6} "
          f"{'Prec':>7} {'Recall':>7} {'F1':>7}")
    print("-" * 90)

    for m in sorted_rules:
        print(
            f"{m.rule_name:<35} {m.trigger_count:>8} "
            f"{m.true_positive:>6} {m.false_positive:>6} "
            f"{m.precision:>7.3f} {m.recall:>7.3f} {m.f1_score:>7.3f}"
        )

    print("-" * 90)
    total_triggers = sum(m.trigger_count for m in sorted_rules)
    total_tp = sum(m.true_positive for m in sorted_rules)
    total_fp = sum(m.false_positive for m in sorted_rules)
    print(f"{'TOTAL':<35} {total_triggers:>8} {total_tp:>6} {total_fp:>6}")
    print("=" * 90 + "\n")


def export_to_json(metrics: Dict[str, RuleMetricsSummary], path: str):
    """メトリクスをJSONにエクスポート。"""
    data = {
        "generated_at": pd.Timestamp.now().isoformat(),
        "rules": {name: m.to_dict() for name, m in metrics.items()},
    }
    with open(path, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"Exported to {path}")


def export_to_csv(metrics: Dict[str, RuleMetricsSummary], path: str):
    """メトリクスをCSVにエクスポート。"""
    rows = [m.to_dict() for m in metrics.values()]
    df = pd.DataFrame(rows)
    df.to_csv(path, index=False)
    print(f"Exported to {path}")


def main():
    parser = argparse.ArgumentParser(
        description="ルール効果分析スクリプト",
    )
    parser.add_argument("results_file", type=str,
                        help="評価結果ファイル (CSV)")
    parser.add_argument("--export-json", type=str, default=None,
                        help="JSONエクスポート先")
    parser.add_argument("--export-csv", type=str, default=None,
                        help="CSVエクスポート先")
    parser.add_argument("--re-evaluate", action="store_true",
                        help="ルールを再評価して詳細分析")
    parser.add_argument("--label-col", type=str, default="label",
                        help="正解ラベル列名")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="詳細出力")

    args = parser.parse_args()

    # 結果ファイル読み込み
    results_path = Path(args.results_file)
    if not results_path.exists():
        print(f"Error: File not found: {results_path}")
        sys.exit(1)

    print(f"Loading results from: {results_path}")
    df = pd.read_csv(results_path)
    print(f"  Total rows: {len(df)}")

    # 分析実行
    if args.re_evaluate:
        print("\nRe-evaluating domains with rules module...")
        metrics = re_evaluate_with_rules(
            df,
            label_col=args.label_col,
            verbose=args.verbose,
        )
    else:
        print("\nAnalyzing from risk_factors column...")
        metrics = analyze_from_risk_factors(
            df,
            label_col=args.label_col,
        )

    # サマリー出力
    print_metrics_summary(metrics)

    # エクスポート
    if args.export_json:
        export_to_json(metrics, args.export_json)
    if args.export_csv:
        export_to_csv(metrics, args.export_csv)


if __name__ == "__main__":
    main()
