#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
scripts/compare_inline_vs_module.py
-----------------------------------
Compare inline implementation vs module implementation results.
"""

import ast
import json
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).parent.parent))

from phishing_agent.agent_foundations import PhishingAssessment
from phishing_agent.llm_final_decision import (
    _apply_policy_adjustments,
    _apply_benign_cert_gate,
    _apply_low_signal_phishing_gate,
)
from phishing_agent.rules import (
    RuleContextBuilder,
    ResultApplier,
    create_phase6_engine,
)


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

    # Build tool_summary for module version
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
    # Use the actual AI assessment from the row, not a neutral starting point
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
        "brand_output": brand_output,
        "cert_output": cert_output,
        "domain_output": domain_output,
        "ctx_output": ctx_output,
    }


def run_inline_version(inputs):
    """Run inline version of rules."""
    trace = []
    asmt = inputs["initial_assessment"]

    # Apply policy adjustments (inline)
    asmt = _apply_policy_adjustments(
        asmt=asmt,
        tool_summary=inputs["tool_summary"],
        ml_probability=inputs["ml_probability"],
        precheck=inputs["precheck"],
        trace=trace,
    )

    # Apply benign cert gate (inline)
    asmt = _apply_benign_cert_gate(
        asmt=asmt,
        tool_summary=inputs["tool_summary"],
        ml_probability=inputs["ml_probability"],
        precheck=inputs["precheck"],
        trace=trace,
    )

    # Apply low signal phishing gate (inline)
    asmt = _apply_low_signal_phishing_gate(
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
        "trace": trace,
    }


def run_module_version(inputs):
    """Run module version of rules."""
    engine = create_phase6_engine()

    # Build RuleContext
    ctx = RuleContextBuilder.build(
        domain=inputs["domain"],
        ml_probability=inputs["ml_probability"],
        tool_summary=inputs["tool_summary"],
        precheck=inputs["precheck"],
        llm_assessment=inputs["initial_assessment"],
    )

    # Evaluate
    engine_result = engine.evaluate_phased(ctx)

    # Apply result
    trace = []
    final = ResultApplier.apply(inputs["initial_assessment"], engine_result, trace)

    return {
        "is_phishing": final.is_phishing,
        "confidence": final.confidence,
        "risk_level": final.risk_level,
        "triggered_rules": engine_result.triggered_rules,
        "trace": trace,
    }


def compare_results(inline_result, module_result):
    """Compare inline and module results."""
    matches = {
        "is_phishing": inline_result["is_phishing"] == module_result["is_phishing"],
        "risk_level": inline_result["risk_level"] == module_result["risk_level"],
    }

    # Compare triggered rules (order independent)
    inline_rules = set(inline_result["triggered_rules"])
    module_rules = set(module_result["triggered_rules"])
    matches["triggered_rules"] = inline_rules == module_rules

    return matches, inline_rules, module_rules


def main():
    # Load test data
    test_files = [
        "test_data/rule_tests/cert_gate_test.csv",
        "test_data/rule_tests/policy_test.csv",
        "test_data/rule_tests/ml_guard_test.csv",
    ]

    total = 0
    functional_match = 0  # is_phishing same
    full_match = 0  # everything same
    functional_mismatches = []  # is_phishing differs (critical)
    rule_name_mismatches = []  # rules differ but final same (minor)

    for test_file in test_files:
        try:
            df = pd.read_csv(test_file)
        except FileNotFoundError:
            print(f"File not found: {test_file}")
            continue

        print(f"\n=== {test_file} ({len(df)} domains) ===")

        for idx, row in df.head(50).iterrows():  # Test first 50 per file
            try:
                inputs = build_inputs_from_row(row)
                inline_result = run_inline_version(inputs)
                module_result = run_module_version(inputs)

                matches, inline_rules, module_rules = compare_results(inline_result, module_result)

                total += 1
                if matches["is_phishing"]:
                    functional_match += 1
                    if all(matches.values()):
                        full_match += 1
                    else:
                        # Only rule names differ
                        rule_name_mismatches.append({
                            "domain": inputs["domain"],
                            "is_phishing": inline_result["is_phishing"],
                            "only_in_inline": list(inline_rules - module_rules),
                            "only_in_module": list(module_rules - inline_rules),
                        })
                else:
                    # Critical: is_phishing differs
                    functional_mismatches.append({
                        "domain": inputs["domain"],
                        "inline_phishing": inline_result["is_phishing"],
                        "module_phishing": module_result["is_phishing"],
                        "inline_rules": list(inline_rules),
                        "module_rules": list(module_rules),
                        "ml": inputs["ml_probability"],
                        "ctx": inputs["tool_summary"]["contextual"]["risk_score"],
                    })
            except Exception as e:
                print(f"  Error on {row.get('domain', 'unknown')}: {e}")
                continue

    # Summary
    print(f"\n{'='*60}")
    print(f"COMPARISON SUMMARY")
    print(f"{'='*60}")
    print(f"Total compared: {total}")
    print(f"Functional match (is_phishing same): {functional_match} ({functional_match/total*100:.1f}%)" if total > 0 else "No comparisons")
    print(f"Full match (all same): {full_match} ({full_match/total*100:.1f}%)" if total > 0 else "")
    print(f"Functional mismatches: {len(functional_mismatches)} (CRITICAL)")
    print(f"Rule name mismatches: {len(rule_name_mismatches)} (minor)")

    if functional_mismatches:
        print(f"\n=== CRITICAL: Functional Mismatches ===")
        for m in functional_mismatches[:10]:
            print(f"\n  {m['domain']}:")
            print(f"    is_phishing: inline={m['inline_phishing']}, module={m['module_phishing']}")
            print(f"    ML={m['ml']:.3f}, CTX={m['ctx']:.3f}")
            print(f"    inline_rules: {m['inline_rules']}")
            print(f"    module_rules: {m['module_rules']}")


if __name__ == "__main__":
    main()
