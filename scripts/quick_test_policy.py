#!/usr/bin/env python3
"""Quick test for policy fix"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from phishing_agent import make_phase4_agent_with_05


def main():
    run_id = "2026-01-10_140940"
    base_dir = "/data/hdd/asomura/nextstep"

    print("Creating agent...")
    agent = make_phase4_agent_with_05(
        run_id=run_id,
        base_dir=base_dir,
        strict_mode=False,
        config_path=f"{base_dir}/config.json"
    )
    print("Agent created")

    # Test a known phishing domain with ML Paradox + dangerous TLD
    test_cases = [
        ("hezemusheng.cn", 0.2364, 1),  # Phishing, cn TLD
        ("u-m.top", 0.1111, 1),  # Phishing, top TLD
        ("diary-jp.icu", 0.1894, 1),  # Phishing, icu TLD
    ]

    print("\n" + "=" * 70)
    print("Testing policy fix...")
    print("=" * 70)

    for domain, ml_prob, y_true in test_cases:
        print(f"\n--- {domain} (ml={ml_prob:.4f}, y_true={y_true}) ---")

        result = agent.evaluate(domain, ml_prob)

        if result:
            is_phish = result.get('ai_is_phishing', False)
            confidence = result.get('ai_confidence', 0.0)
            risk_level = result.get('ai_risk_level', 'unknown')
            risk_factors = result.get('risk_factors', [])

            # Trace info
            rules_fired = result.get('phase6_rules_fired', [])
            gate_info = result.get('trace_phase6_gate', {})

            print(f"  is_phishing: {is_phish}")
            print(f"  confidence: {confidence}")
            print(f"  risk_level: {risk_level}")
            print(f"  risk_factors: {risk_factors[:5]}")  # First 5
            print(f"  rules_fired: {rules_fired}")
            print(f"  gate_info: {gate_info}")
            print(f"  CORRECT: {is_phish == bool(y_true)}")
        else:
            print("  ERROR: No result")


if __name__ == "__main__":
    main()
