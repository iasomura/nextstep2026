#!/usr/bin/env python3
"""
閾値調整の単体テスト

2026-02-04: FP削減のための閾値調整効果を検証（ルールモジュール直接テスト）
"""

import pandas as pd
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from phishing_agent.rules.detectors.base import RuleContext
from phishing_agent.rules.detectors.policy import (
    PolicyR1Rule, PolicyR2Rule, PolicyR4Rule,
    _has_strong_evidence, _has_dv_issues
)
from phishing_agent.rules.detectors.ml_guard import (
    HighMLOverrideRule, create_ml_guard_rules
)


def create_mock_context(
    domain: str,
    ml_prob: float,
    ctx_score: float,
    issue_set: set = None,
    ctx_issues: set = None,
    cert_details: dict = None,
    brand_details: dict = None,
    tld: str = "com",
    tld_category: str = "legitimate",
    llm_is_phishing: bool = True,
    llm_risk_level: str = "medium",
) -> RuleContext:
    """Create a mock RuleContext for testing"""
    return RuleContext(
        domain=domain,
        registered_domain=domain,
        ml_probability=ml_prob,
        ctx_score=ctx_score,
        ctx_issues=ctx_issues or set(),
        cert_details=cert_details or {"issues": ["free_ca", "no_org"]},
        benign_indicators=set(),
        brand_details=brand_details or {"detected_brands": []},
        domain_details={},
        issue_set=issue_set or {"dangerous_tld"},  # Strong evidence
        tld=tld,
        is_known_legitimate=False,
        llm_is_phishing=llm_is_phishing,
        llm_confidence=0.7,
        llm_risk_level=llm_risk_level,
        precheck={"tld_category": tld_category, "domain_length_category": "normal"},
    )


def test_policy_r1_threshold():
    """Test PolicyR1Rule threshold changes"""
    print("=== PolicyR1Rule threshold test ===")
    rule = PolicyR1Rule()

    # Test case: ctx = 0.30 (old: triggered, new: not triggered for ctx_threshold)
    ctx = create_mock_context(
        domain="test.com",
        ml_prob=0.15,  # < 0.20
        ctx_score=0.30,  # was >= 0.28 (old), now < 0.32 (new)
        issue_set={"dangerous_tld"},  # strong evidence
    )

    result = rule.evaluate(ctx)
    print(f"  ctx=0.30, ML=0.15: triggered={result.triggered}")
    print(f"  Expected: NOT triggered (0.30 < 0.32 new threshold)")
    assert not result.triggered, "Rule should NOT trigger with ctx=0.30 (below new threshold 0.32)"

    # Test case: ctx = 0.35 (should still trigger)
    ctx2 = create_mock_context(
        domain="test.com",
        ml_prob=0.15,
        ctx_score=0.35,  # >= 0.32
        issue_set={"dangerous_tld"},
    )
    result2 = rule.evaluate(ctx2)
    print(f"  ctx=0.35, ML=0.15: triggered={result2.triggered}")
    print(f"  Expected: triggered (0.35 >= 0.32 new threshold)")
    assert result2.triggered, "Rule should trigger with ctx=0.35 (above new threshold)"

    print("  PASSED\n")


def test_policy_r2_threshold():
    """Test PolicyR2Rule threshold changes"""
    print("=== PolicyR2Rule threshold test ===")
    rule = PolicyR2Rule()

    # Test case: ctx = 0.36 (old: triggered, new: not triggered)
    ctx = create_mock_context(
        domain="test.com",
        ml_prob=0.25,  # < 0.30
        ctx_score=0.36,  # was >= 0.34 (old), now < 0.38 (new)
        issue_set={"dangerous_tld"},  # strong evidence
    )

    result = rule.evaluate(ctx)
    print(f"  ctx=0.36, ML=0.25: triggered={result.triggered}")
    print(f"  Expected: NOT triggered (0.36 < 0.38 new threshold)")
    assert not result.triggered, "Rule should NOT trigger with ctx=0.36 (below new threshold 0.38)"

    # Test case: ctx = 0.40 (should still trigger)
    ctx2 = create_mock_context(
        domain="test.com",
        ml_prob=0.25,
        ctx_score=0.40,  # >= 0.38
        issue_set={"dangerous_tld"},
    )
    result2 = rule.evaluate(ctx2)
    print(f"  ctx=0.40, ML=0.25: triggered={result2.triggered}")
    print(f"  Expected: triggered (0.40 >= 0.38 new threshold)")
    assert result2.triggered, "Rule should trigger with ctx=0.40 (above new threshold)"

    print("  PASSED\n")


def test_policy_r4_threshold():
    """Test PolicyR4Rule threshold changes"""
    print("=== PolicyR4Rule threshold test ===")
    rule = PolicyR4Rule()

    # Test case: ctx = 0.38 (old: triggered, new: not triggered)
    ctx = create_mock_context(
        domain="test.xyz",
        ml_prob=0.45,  # < 0.50
        ctx_score=0.38,  # was >= 0.34 (old), now < 0.40 (new)
        issue_set={"dangerous_tld"},  # strong evidence
        tld="xyz",
        tld_category="dangerous",
    )

    result = rule.evaluate(ctx)
    print(f"  ctx=0.38, ML=0.45: triggered={result.triggered}")
    print(f"  Expected: NOT triggered (0.38 < 0.40 new threshold)")
    assert not result.triggered, "Rule should NOT trigger with ctx=0.38 (below new threshold 0.40)"

    # Test case: ctx = 0.42 (should still trigger)
    ctx2 = create_mock_context(
        domain="test.xyz",
        ml_prob=0.45,
        ctx_score=0.42,  # >= 0.40
        issue_set={"dangerous_tld"},
        tld="xyz",
        tld_category="dangerous",
    )
    result2 = rule.evaluate(ctx2)
    print(f"  ctx=0.42, ML=0.45: triggered={result2.triggered}")
    print(f"  Expected: triggered (0.42 >= 0.40 new threshold)")
    assert result2.triggered, "Rule should trigger with ctx=0.42 (above new threshold)"

    print("  PASSED\n")


def test_high_ml_override_disabled():
    """Test HighMLOverrideRule is disabled by default"""
    print("=== HighMLOverrideRule disabled test ===")

    # Check that the rule is disabled in create_ml_guard_rules
    rules = create_ml_guard_rules()
    hmo_rule = next((r for r in rules if r.name == "high_ml_override"), None)

    assert hmo_rule is not None, "HighMLOverrideRule should exist"
    print(f"  HighMLOverrideRule.enabled = {hmo_rule.enabled}")
    assert not hmo_rule.enabled, "HighMLOverrideRule should be disabled by default"

    # Create a case that would trigger the rule if enabled
    ctx = create_mock_context(
        domain="test.xyz",
        ml_prob=0.50,  # >= 0.40 threshold
        ctx_score=0.35,
        issue_set={"random_pattern"},  # trigger condition
        tld="xyz",
        llm_is_phishing=False,  # benign prediction
        llm_risk_level="low",
    )

    # The disabled rule should not trigger
    result = hmo_rule.evaluate(ctx)
    print(f"  ML=0.50 with random_pattern: triggered={result.triggered}")
    print(f"  Expected: NOT triggered (rule is disabled)")
    assert not result.triggered, "Disabled rule should not trigger"

    print("  PASSED\n")


def test_with_real_fp_data():
    """Test with real FP data from evaluation"""
    print("=== Real FP data test ===")

    # Load expected file
    expected_file = Path("test_data/threshold_test_expected.csv")
    if not expected_file.exists():
        print(f"  Skipping: {expected_file} not found")
        return

    df = pd.read_csv(expected_file)

    # Filter for cases that should be fixed
    # policy_r4 with ctx in [0.34, 0.40)
    policy_r4_cases = df[
        (df['trace_phase6_rules_fired'].str.contains('policy_r4', na=False)) &
        (df['ctx_score'] >= 0.34) & (df['ctx_score'] < 0.40)
    ]

    rule = PolicyR4Rule()
    fixed_count = 0
    still_triggered = 0

    for _, row in policy_r4_cases.head(20).iterrows():
        ctx = create_mock_context(
            domain=row['domain'],
            ml_prob=row['ml_probability'],
            ctx_score=row['ctx_score'],
            issue_set={"dangerous_tld"},  # Assume strong evidence (since rule fired before)
            tld_category="dangerous",
        )

        result = rule.evaluate(ctx)
        if not result.triggered:
            fixed_count += 1
        else:
            still_triggered += 1
            print(f"  Still triggers: {row['domain']} ctx={row['ctx_score']:.3f}")

    print(f"  policy_r4 cases tested: {min(20, len(policy_r4_cases))}")
    print(f"  Fixed (no longer triggers): {fixed_count}")
    print(f"  Still triggers: {still_triggered}")
    print()


def main():
    print("=" * 60)
    print("Threshold Adjustment Unit Tests")
    print("=" * 60)
    print()

    try:
        test_policy_r1_threshold()
        test_policy_r2_threshold()
        test_policy_r4_threshold()
        test_high_ml_override_disabled()
        test_with_real_fp_data()

        print("=" * 60)
        print("ALL TESTS PASSED")
        print("=" * 60)
        return 0
    except AssertionError as e:
        print(f"\nTEST FAILED: {e}")
        return 1
    except Exception as e:
        print(f"\nERROR: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
