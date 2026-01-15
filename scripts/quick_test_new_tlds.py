#!/usr/bin/env python3
"""Quick test for newly added dangerous TLDs"""

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

    # Test the TLDs that were previously failing
    test_cases = [
        ("90phuttb.cc", 0.2074, 0),  # cc TLD - was failing
        ("ups.com-qwaf.cc", 0.1506, 1),  # cc TLD - phishing
        ("0bdypy5o.lat", 0.15, 1),  # lat TLD - was failing
        ("dniperu.online", 0.1391, 1),  # online TLD - was failing
        ("funero.shop", 0.0772, 0),  # shop TLD - benign
        ("cybernexahub.shop", 0.1138, 0),  # shop TLD - benign
    ]

    print("\n" + "=" * 70)
    print("Testing newly added dangerous TLDs...")
    print("=" * 70)

    for domain, ml_prob, y_true in test_cases:
        print(f"\n--- {domain} (ml={ml_prob:.4f}, y_true={y_true}) ---")

        result = agent.evaluate(domain, ml_prob)

        if result:
            is_phish = result.get('ai_is_phishing', False)
            confidence = result.get('ai_confidence', 0.0)
            risk_level = result.get('ai_risk_level', 'unknown')
            risk_factors = result.get('risk_factors', [])

            print(f"  is_phishing: {is_phish}")
            print(f"  confidence: {confidence}")
            print(f"  risk_level: {risk_level}")
            print(f"  risk_factors: {risk_factors[:5]}")
            print(f"  CORRECT: {is_phish == bool(y_true)}")
        else:
            print("  ERROR: No result")


if __name__ == "__main__":
    main()
