#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
scripts/test_module_switch.py
------------------------------
Test that USE_RULE_MODULES=True produces the same results as inline version.

This script:
1. Forces USE_RULE_MODULES=False and runs inline version
2. Forces USE_RULE_MODULES=True and runs module version
3. Compares the results

変更履歴:
    - 2026-01-31: 新規作成（モジュール版切り替えテスト）
"""

import ast
import json
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).parent.parent))

from phishing_agent.agent_foundations import PhishingAssessment


def parse_field(value):
    """Parse JSON or Python dict string."""
    if pd.isna(value):
        return {}
    if isinstance(value, str):
        try:
            return json.loads(value)
        except:
            try:
                return ast.literal_eval(value)
            except:
                return {}
    return value


def build_inputs_from_row(row):
    """Build inputs for both inline and module versions."""
    domain = str(row.get("domain", ""))
    ml_prob = float(row.get("ml_probability", 0.0))

    # Parse tool outputs
    brand_output = parse_field(row.get("tool_brand_output", {}))
    cert_output = parse_field(row.get("tool_cert_output", {}))
    domain_output = parse_field(row.get("tool_domain_output", {}))
    ctx_output = parse_field(row.get("tool_ctx_output", {}))

    # Build tool_summary
    tool_summary = {
        "brand": {
            "risk_score": brand_output.get("risk_score", 0.0),
            "issues": brand_output.get("detected_issues", []),
            "brands": brand_output.get("details", {}).get("detected_brands", []),
        },
        "cert": {
            "risk_score": cert_output.get("risk_score", 0.0),
            "issues": cert_output.get("detected_issues", []),
            "details": cert_output.get("details", {}),
        },
        "domain": {
            "risk_score": domain_output.get("risk_score", 0.0),
            "issues": domain_output.get("detected_issues", []),
            "details": domain_output.get("details", {}),
        },
        "contextual": {
            "risk_score": ctx_output.get("risk_score", 0.0) if isinstance(ctx_output, dict) else 0.0,
            "issues": ctx_output.get("detected_issues", []) if isinstance(ctx_output, dict) else [],
        },
    }

    # Build precheck
    tld = str(row.get("tld", ""))
    dangerous_tlds = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "buzz", "online"}
    precheck = {
        "etld1": {"suffix": tld, "registered_domain": domain},
        "tld_category": "dangerous" if tld.lower() in dangerous_tlds else "legitimate",
    }

    # Build initial assessment from actual AI output
    ai_is_phishing = bool(row.get("ai_is_phishing", False))
    ai_confidence = float(row.get("ai_confidence", 0.5))
    ai_risk_level = str(row.get("ai_risk_level", "medium"))
    ai_reasoning = str(row.get("ai_reasoning", "")) or "AI assessment result."
    if len(ai_reasoning) < 20:
        ai_reasoning = ai_reasoning + " " * (20 - len(ai_reasoning))
    if len(ai_reasoning) > 990:
        ai_reasoning = ai_reasoning[:990] + "..."

    initial_assessment = PhishingAssessment(
        is_phishing=ai_is_phishing,
        confidence=ai_confidence,
        risk_level=ai_risk_level,
        detected_brands=brand_output.get("details", {}).get("detected_brands", []) or [],
        risk_factors=list(row.get("ai_risk_factors", []) or []),
        reasoning=ai_reasoning,
    )

    return {
        "domain": domain,
        "ml_probability": ml_prob,
        "tool_summary": tool_summary,
        "precheck": precheck,
        "initial_assessment": initial_assessment,
    }


def run_with_flag(inputs, use_modules: bool):
    """Run with specific USE_RULE_MODULES setting."""
    import phishing_agent.llm_final_decision as lfd

    # Save original value
    original_flag = lfd.USE_RULE_MODULES

    try:
        # Set flag
        lfd.USE_RULE_MODULES = use_modules

        # Run the functions
        trace = []
        asmt = inputs["initial_assessment"]

        asmt = lfd._apply_policy_adjustments(
            asmt=asmt,
            tool_summary=inputs["tool_summary"],
            ml_probability=inputs["ml_probability"],
            precheck=inputs["precheck"],
            trace=trace,
            domain=inputs["domain"],
        )

        asmt = lfd._apply_benign_cert_gate(
            asmt=asmt,
            tool_summary=inputs["tool_summary"],
            ml_probability=inputs["ml_probability"],
            precheck=inputs["precheck"],
            trace=trace,
        )

        asmt = lfd._apply_low_signal_phishing_gate(
            asmt=asmt,
            tool_summary=inputs["tool_summary"],
            ml_probability=inputs["ml_probability"],
            precheck=inputs["precheck"],
            trace=trace,
        )

        # Extract triggered rules from trace
        triggered_rules = []
        for t in trace:
            if "rule" in t:
                triggered_rules.append(t["rule"])

        return {
            "is_phishing": asmt.is_phishing,
            "confidence": asmt.confidence,
            "risk_level": asmt.risk_level,
            "triggered_rules": triggered_rules,
        }
    finally:
        # Restore original value
        lfd.USE_RULE_MODULES = original_flag


def main():
    # Load test data
    test_files = [
        "test_data/rule_tests/cert_gate_test.csv",
        "test_data/rule_tests/policy_test.csv",
        "test_data/rule_tests/ml_guard_test.csv",
    ]

    total = 0
    functional_match = 0
    functional_mismatches = []

    for test_file in test_files:
        try:
            df = pd.read_csv(test_file)
        except FileNotFoundError:
            print(f"ファイル未検出: {test_file}")
            continue

        print(f"\n=== {test_file} ({len(df)} ドメイン) ===")

        for idx, row in df.head(50).iterrows():
            try:
                inputs = build_inputs_from_row(row)

                # Run both versions
                inline_result = run_with_flag(inputs, use_modules=False)
                module_result = run_with_flag(inputs, use_modules=True)

                total += 1
                if inline_result["is_phishing"] == module_result["is_phishing"]:
                    functional_match += 1
                else:
                    functional_mismatches.append({
                        "domain": inputs["domain"],
                        "inline_phishing": inline_result["is_phishing"],
                        "module_phishing": module_result["is_phishing"],
                        "inline_rules": inline_result["triggered_rules"],
                        "module_rules": module_result["triggered_rules"],
                        "ml": inputs["ml_probability"],
                        "ctx": inputs["tool_summary"]["contextual"]["risk_score"],
                    })
            except Exception as e:
                print(f"  エラー {row.get('domain', 'unknown')}: {e}")
                continue

    # Summary
    print(f"\n{'='*60}")
    print(f"モジュール切り替えテスト結果")
    print(f"{'='*60}")
    print(f"テスト数: {total}")
    print(f"機能一致: {functional_match} ({functional_match/total*100:.1f}%)" if total > 0 else "")
    print(f"機能不一致: {len(functional_mismatches)}")

    if functional_mismatches:
        print(f"\n=== 不一致例 ===")
        for m in functional_mismatches[:10]:
            print(f"\n  {m['domain']}:")
            print(f"    is_phishing: インライン={m['inline_phishing']}, モジュール={m['module_phishing']}")
            print(f"    ML={m['ml']:.3f}, CTX={m['ctx']:.3f}")
            print(f"    インラインルール: {m['inline_rules'][:5]}")
            print(f"    モジュールルール: {m['module_rules'][:5]}")
    else:
        print("\n✓ 全テストで is_phishing が一致しました！")


if __name__ == "__main__":
    main()
