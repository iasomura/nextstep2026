#!/usr/bin/env python3
"""
閾値調整のスポットテスト

2026-02-04: FP削減のための閾値調整効果を検証
対象:
  - policy_r1, policy_r2, policy_r4 の ctx閾値引き上げ
  - high_ml_override の無効化
"""

import pandas as pd
import json
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from phishing_agent.phase6_wiring import build_phase6_graph
from phishing_agent.llm_final_decision import USE_RULE_MODULES

def evaluate_domain(domain: str, graph, precheck_data: dict = None):
    """Evaluate a single domain"""
    try:
        initial_state = {
            "domain": domain,
            "messages": [],
            "precheck": precheck_data or {},
            "tool_calls": {},
            "phase": "init",
            "assessment": None,
        }

        result = graph.invoke(initial_state)

        assessment = result.get("assessment", {})
        return {
            "domain": domain,
            "is_phishing": assessment.get("is_phishing", False),
            "confidence": assessment.get("confidence", 0.0),
            "risk_level": assessment.get("risk_level", "unknown"),
            "rules_fired": result.get("phase6_rules_fired", []),
            "ctx_score": result.get("tool_summary", {}).get("contextual", {}).get("risk_score", 0.0),
            "error": None,
        }
    except Exception as e:
        return {
            "domain": domain,
            "is_phishing": None,
            "confidence": None,
            "risk_level": None,
            "rules_fired": [],
            "ctx_score": None,
            "error": str(e),
        }


def main():
    print(f"USE_RULE_MODULES: {USE_RULE_MODULES}")
    print()

    # Load test domains
    test_domains_file = Path("test_data/threshold_test_domains.txt")
    expected_file = Path("test_data/threshold_test_expected.csv")

    if not test_domains_file.exists():
        print(f"Error: {test_domains_file} not found")
        return 1

    with open(test_domains_file) as f:
        domains = [line.strip() for line in f if line.strip()]

    print(f"Loaded {len(domains)} test domains")

    # Load expected outcomes
    expected_df = pd.read_csv(expected_file)
    expected_map = {row['domain']: row for _, row in expected_df.iterrows()}

    # Build graph
    print("Building Phase6 graph...")
    graph = build_phase6_graph()

    # Evaluate domains
    results = []
    changed_count = 0
    still_fp_count = 0
    new_fn_count = 0

    print(f"\nEvaluating {len(domains)} domains...")
    print("-" * 80)

    for i, domain in enumerate(domains):
        result = evaluate_domain(domain, graph)
        results.append(result)

        expected = expected_map.get(domain, {})
        y_true = expected.get('y_true', None)
        old_rules = expected.get('trace_phase6_rules_fired', '')

        # Check if prediction changed
        is_phishing = result['is_phishing']
        rules_fired = result['rules_fired']

        # Original prediction was phishing (these were FP cases)
        # New prediction
        if is_phishing is False:
            changed_count += 1
            status = "FIXED (now benign)"
        else:
            still_fp_count += 1
            status = "STILL FP"

        # Print progress
        if (i + 1) % 10 == 0 or i == len(domains) - 1:
            print(f"Progress: {i+1}/{len(domains)}")

        # Print each result
        print(f"  {domain}: {status}")
        print(f"    Old rules: {old_rules[:100]}...")
        print(f"    New rules: {rules_fired}")
        print()

    # Summary
    print("=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"Total test domains: {len(domains)}")
    print(f"Changed to benign (FP fixed): {changed_count}")
    print(f"Still phishing (FP remains): {still_fp_count}")
    print(f"Errors: {sum(1 for r in results if r['error'])}")
    print()
    print(f"Expected FP reduction: ~{changed_count} cases")

    # Save results
    output_file = Path("test_data/threshold_test_results.csv")
    results_df = pd.DataFrame(results)
    results_df.to_csv(output_file, index=False)
    print(f"\nResults saved to {output_file}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
