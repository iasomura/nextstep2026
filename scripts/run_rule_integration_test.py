#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
scripts/run_rule_integration_test.py
-------------------------------------
Run rule-specific integration tests with parallel GPU evaluation.

Usage:
    python scripts/run_rule_integration_test.py --rule-group cert_gate --ports 8000,8001
    python scripts/run_rule_integration_test.py --all --ports 8000,8001

変更履歴:
    - 2026-01-31: 初版作成（ルールモジュール移行計画用）
"""

import argparse
import asyncio
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from phishing_agent.rules import (
    RuleContextBuilder,
    RuleEngine,
    ResultApplier,
    create_phase6_engine,
)
from phishing_agent.rules.detectors.base import RuleContext
from phishing_agent.agent_foundations import PhishingAssessment


def parse_json_field(value: Any) -> Any:
    """Parse JSON string field to Python object."""
    if pd.isna(value):
        return None
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (json.JSONDecodeError, ValueError):
            # Try ast.literal_eval for Python dict string representation
            try:
                import ast
                return ast.literal_eval(value)
            except (ValueError, SyntaxError):
                return value
    return value


def build_tool_summary(row: pd.Series) -> Dict[str, Any]:
    """Build tool_summary from row data."""
    brand = parse_json_field(row.get("tool_brand_output", {})) or {}
    cert = parse_json_field(row.get("tool_cert_output", {})) or {}
    domain = parse_json_field(row.get("tool_domain_output", {})) or {}
    ctx = parse_json_field(row.get("tool_ctx_output", {})) or {}

    return {
        "brand": {
            "risk_score": brand.get("risk_score", 0.0),
            "issues": brand.get("detected_issues", []),
            "brands": brand.get("details", {}).get("detected_brands", []),
        },
        "cert": {
            "risk_score": cert.get("risk_score", 0.0),
            "issues": cert.get("detected_issues", []),
            "details": cert.get("details", {}),
        },
        "domain": {
            "risk_score": domain.get("risk_score", 0.0),
            "issues": domain.get("detected_issues", []),
            "details": domain.get("details", {}),
        },
        "contextual": {
            "risk_score": ctx.get("risk_score", 0.0) if isinstance(ctx, dict) else 0.0,
            "issues": ctx.get("detected_issues", []) if isinstance(ctx, dict) else [],
        },
    }


def build_precheck(row: pd.Series) -> Dict[str, Any]:
    """Build precheck from row data."""
    tld = str(row.get("tld", ""))
    domain = str(row.get("domain", ""))

    dangerous_tlds = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "buzz", "online"}
    tld_category = "dangerous" if tld.lower() in dangerous_tlds else "legitimate"

    return {
        "etld1": {
            "suffix": tld,
            "registered_domain": domain,
        },
        "tld_category": tld_category,
    }


def evaluate_domain_with_rules(
    row: pd.Series,
    engine: RuleEngine,
) -> Dict[str, Any]:
    """Evaluate a single domain with the rule engine."""
    domain = str(row.get("domain", ""))
    ml_prob = float(row.get("ml_probability", 0.0))

    # Build context
    tool_summary = build_tool_summary(row)
    precheck = build_precheck(row)

    # Create mock LLM assessment from row data
    ai_is_phishing = bool(row.get("ai_is_phishing", False))
    ai_confidence = float(row.get("ai_confidence", 0.5))
    ai_risk_level = str(row.get("ai_risk_level", "medium"))
    ai_reasoning = str(row.get("ai_reasoning", "")) or "Analysis completed."
    if len(ai_reasoning) < 20:
        ai_reasoning = ai_reasoning + " " * (20 - len(ai_reasoning))
    if len(ai_reasoning) > 990:
        ai_reasoning = ai_reasoning[:990] + "..."

    llm_assessment = PhishingAssessment(
        is_phishing=ai_is_phishing,
        confidence=ai_confidence,
        risk_level=ai_risk_level,
        detected_brands=list(row.get("ai_detected_brands", []) or []),
        risk_factors=list(row.get("ai_risk_factors", []) or []),
        reasoning=ai_reasoning,
    )

    # Build RuleContext
    ctx = RuleContextBuilder.build(
        domain=domain,
        ml_probability=ml_prob,
        tool_summary=tool_summary,
        precheck=precheck,
        llm_assessment=llm_assessment,
    )

    # Evaluate with engine
    start_time = time.time()
    engine_result = engine.evaluate_phased(ctx)
    eval_time = (time.time() - start_time) * 1000

    # Apply result
    trace = []
    final = ResultApplier.apply(llm_assessment, engine_result, trace)

    # Get ground truth
    y_true = bool(row.get("y_true", False))

    return {
        "domain": domain,
        "ml_probability": ml_prob,
        "ctx_score": ctx.ctx_score,
        "y_true": y_true,
        "original_is_phishing": ai_is_phishing,
        "final_is_phishing": final.is_phishing,
        "original_risk_level": ai_risk_level,
        "final_risk_level": final.risk_level,
        "triggered_rules": engine_result.triggered_rules,
        "skipped_rules": engine_result.skipped_rules,
        "force_phishing": engine_result.force_phishing,
        "force_benign": engine_result.force_benign,
        "confidence_floor": engine_result.confidence_floor,
        "confidence_ceiling": engine_result.confidence_ceiling,
        "trace": trace,
        "eval_time_ms": eval_time,
        "tld": ctx.tld,
        "issue_set": list(ctx.issue_set),
        "benign_indicators": list(ctx.benign_indicators),
        "brand_detected": bool(ctx.brand_details.get("detected_brands")),
    }


def run_rule_group_test(
    rule_group: str,
    test_data_path: str,
    output_dir: str,
    limit: Optional[int] = None,
) -> Dict[str, Any]:
    """Run integration test for a specific rule group."""
    print(f"\n{'='*60}")
    print(f"Rule Group: {rule_group}")
    print(f"{'='*60}")

    # Load test data
    if not os.path.exists(test_data_path):
        print(f"Test data not found: {test_data_path}")
        return {"error": "test_data_not_found"}

    df = pd.read_csv(test_data_path)
    if limit:
        df = df.head(limit)

    print(f"Loaded {len(df)} test domains from {test_data_path}")

    # Create engine
    engine = create_phase6_engine()
    print(f"Created Phase6 engine with {len(engine)} rules")

    # Evaluate each domain
    results = []
    for idx, row in df.iterrows():
        try:
            result = evaluate_domain_with_rules(row, engine)
            results.append(result)
        except Exception as e:
            print(f"  Error evaluating {row.get('domain', 'unknown')}: {e}")
            continue

        if (idx + 1) % 20 == 0:
            print(f"  Processed {idx + 1}/{len(df)} domains...")

    # Analyze results
    if not results:
        print("No results to analyze")
        return {"error": "no_results", "rule_group": rule_group}

    results_df = pd.DataFrame(results)

    # Calculate metrics
    triggered_any = results_df["triggered_rules"].apply(lambda x: len(x) > 0).sum()
    force_phishing_count = results_df["force_phishing"].sum()
    force_benign_count = results_df["force_benign"].sum()

    # Changes made by rules
    changed_to_phishing = (
        (~results_df["original_is_phishing"]) & results_df["final_is_phishing"]
    ).sum()
    changed_to_benign = (
        results_df["original_is_phishing"] & (~results_df["final_is_phishing"])
    ).sum()

    # Correctness analysis
    correct_before = (results_df["original_is_phishing"] == results_df["y_true"]).sum()
    correct_after = (results_df["final_is_phishing"] == results_df["y_true"]).sum()

    # Rule-specific triggered counts
    all_triggered = []
    for rules in results_df["triggered_rules"]:
        all_triggered.extend(rules)
    rule_counts = pd.Series(all_triggered).value_counts().to_dict()

    summary = {
        "rule_group": rule_group,
        "total_domains": int(len(results_df)),
        "triggered_any_rule": int(triggered_any),
        "force_phishing_count": int(force_phishing_count),
        "force_benign_count": int(force_benign_count),
        "changed_to_phishing": int(changed_to_phishing),
        "changed_to_benign": int(changed_to_benign),
        "correct_before": int(correct_before),
        "correct_after": int(correct_after),
        "accuracy_before": round(float(correct_before) / len(results_df) * 100, 2) if len(results_df) > 0 else 0,
        "accuracy_after": round(float(correct_after) / len(results_df) * 100, 2) if len(results_df) > 0 else 0,
        "rule_trigger_counts": {k: int(v) for k, v in rule_counts.items()},
    }

    # Print summary
    print(f"\n--- Summary ---")
    print(f"Total domains: {summary['total_domains']}")
    print(f"Rules triggered on: {summary['triggered_any_rule']} domains ({summary['triggered_any_rule']/summary['total_domains']*100:.1f}%)")
    print(f"Force phishing: {summary['force_phishing_count']}")
    print(f"Force benign: {summary['force_benign_count']}")
    print(f"Changed to phishing: {summary['changed_to_phishing']}")
    print(f"Changed to benign: {summary['changed_to_benign']}")
    print(f"Accuracy before rules: {summary['accuracy_before']}%")
    print(f"Accuracy after rules: {summary['accuracy_after']}%")
    print(f"Improvement: {summary['accuracy_after'] - summary['accuracy_before']:+.2f}pp")

    if rule_counts:
        print(f"\nRule trigger counts:")
        for rule, count in sorted(rule_counts.items(), key=lambda x: -x[1]):
            print(f"  {rule}: {count}")

    # Save detailed results
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, f"{rule_group}_results.jsonl")
    with open(output_file, "w") as f:
        for result in results:
            f.write(json.dumps(result, ensure_ascii=False, default=str) + "\n")
    print(f"\nDetailed results saved to: {output_file}")

    # Save summary
    summary_file = os.path.join(output_dir, f"{rule_group}_summary.json")
    with open(summary_file, "w") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    return summary


def analyze_rule_effects(results_file: str) -> None:
    """Analyze rule effects from results file."""
    results = []
    with open(results_file) as f:
        for line in f:
            results.append(json.loads(line))

    df = pd.DataFrame(results)

    print(f"\n=== Rule Effect Analysis: {results_file} ===\n")

    # Group by triggered rules
    for idx, row in df.iterrows():
        if row["triggered_rules"]:
            print(f"Domain: {row['domain']}")
            print(f"  ML: {row['ml_probability']:.3f}, CTX: {row['ctx_score']:.3f}")
            print(f"  y_true: {row['y_true']}, Original: {row['original_is_phishing']} -> Final: {row['final_is_phishing']}")
            print(f"  Triggered: {row['triggered_rules']}")
            if row["force_phishing"]:
                print(f"  Action: FORCE PHISHING")
            if row["force_benign"]:
                print(f"  Action: FORCE BENIGN")
            correct_symbol = "✓" if row["final_is_phishing"] == row["y_true"] else "✗"
            print(f"  Result: {correct_symbol}")
            print()


def main():
    parser = argparse.ArgumentParser(
        description="Run rule-specific integration tests"
    )
    parser.add_argument(
        "--rule-group",
        type=str,
        help="Rule group to test",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Test all rule groups",
    )
    parser.add_argument(
        "--test-data-dir",
        type=str,
        default="test_data/rule_tests",
        help="Directory containing test data CSVs",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="logs/rule_effects",
        help="Directory for output logs",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Limit number of domains per group",
    )
    parser.add_argument(
        "--analyze",
        type=str,
        help="Analyze results file instead of running tests",
    )

    args = parser.parse_args()

    if args.analyze:
        analyze_rule_effects(args.analyze)
        return

    rule_groups = [
        "cert_gate",
        "low_signal_gate",
        "policy",
        "ml_guard",
        "ctx_trigger",
        "gov_edu_gate",
        "brand_cert",
        "post_gates",
    ]

    if args.all:
        groups_to_test = rule_groups
    elif args.rule_group:
        groups_to_test = [args.rule_group]
    else:
        parser.error("Either --rule-group or --all is required")

    all_summaries = []
    for group in groups_to_test:
        test_data_path = os.path.join(args.test_data_dir, f"{group}_test.csv")
        summary = run_rule_group_test(
            rule_group=group,
            test_data_path=test_data_path,
            output_dir=args.output_dir,
            limit=args.limit,
        )
        all_summaries.append(summary)

    # Print overall summary
    if len(all_summaries) > 1:
        print(f"\n{'='*60}")
        print("OVERALL SUMMARY")
        print(f"{'='*60}")
        for s in all_summaries:
            if "error" not in s:
                delta = s["accuracy_after"] - s["accuracy_before"]
                print(f"{s['rule_group']:20s}: {s['accuracy_before']:.1f}% -> {s['accuracy_after']:.1f}% ({delta:+.1f}pp) [{s['total_domains']} domains]")


if __name__ == "__main__":
    main()
