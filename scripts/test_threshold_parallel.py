#!/usr/bin/env python3
"""
閾値調整テスト（3GPU並列）

2026-02-04: FP削減のための閾値調整効果を3GPUで並列検証
"""

import json
import os
import sys
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, List, Optional
import tempfile

import pandas as pd

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))


def create_worker_config(base_config_path: Path, port: int) -> Path:
    """Create a temporary config file for a specific vLLM port"""
    with open(base_config_path) as f:
        config = json.load(f)

    # Update vLLM base_url
    if "llm" in config:
        config["llm"]["base_url"] = f"http://127.0.0.1:{port}/v1"

    # Create temp config
    temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
    json.dump(config, temp_file)
    temp_file.close()
    return Path(temp_file.name)


def evaluate_domain(domain: str, port: int, base_dir: Path) -> Dict[str, Any]:
    """Evaluate a single domain using specified vLLM port"""
    # Create config for this port
    base_config = base_dir / "_compat" / "config.json"
    if not base_config.exists():
        base_config = base_dir / "config.json"

    temp_config = create_worker_config(base_config, port)

    try:
        # Set environment
        os.environ["CONFIG_JSON"] = str(temp_config)

        # Wire Phase6
        from phishing_agent.phase6_wiring import wire_phase6
        wire_phase6(prefer_compat=True, fake_llm=False)

        # Create agent
        from phishing_agent.langgraph_module import LangGraphPhishingAgent
        agent = LangGraphPhishingAgent(
            strict_mode=True,
            use_llm_selection=True,
            use_llm_decision=True,
            config_path=str(temp_config),
        )

        # Evaluate
        start_time = time.time()
        result = agent.evaluate(domain)
        elapsed = time.time() - start_time

        return {
            "domain": domain,
            "ai_is_phishing": result.get("is_phishing", False),
            "ai_confidence": result.get("confidence", 0.0),
            "ai_risk_level": result.get("risk_level", "unknown"),
            "rules_fired": result.get("phase6_rules_fired", []),
            "processing_time": elapsed,
            "error": None,
        }
    except Exception as e:
        return {
            "domain": domain,
            "ai_is_phishing": None,
            "ai_confidence": None,
            "ai_risk_level": None,
            "rules_fired": [],
            "processing_time": 0,
            "error": str(e),
        }
    finally:
        # Clean up temp config
        try:
            os.unlink(temp_config)
        except:
            pass


def main():
    base_dir = Path(__file__).parent.parent
    ports = [8000, 8001, 8002]

    # Load test domains
    test_file = base_dir / "test_data" / "threshold_test_domains.txt"
    if not test_file.exists():
        print(f"Error: {test_file} not found")
        return 1

    with open(test_file) as f:
        domains = [line.strip() for line in f if line.strip()]

    print(f"Testing {len(domains)} domains with {len(ports)} GPU workers...")
    print(f"Ports: {ports}")
    print("-" * 60)

    # Load expected outcomes
    expected_file = base_dir / "test_data" / "threshold_test_expected.csv"
    expected_df = pd.read_csv(expected_file)
    expected_map = {row['domain']: row for _, row in expected_df.iterrows()}

    results = []
    start_time = time.time()

    # Use ThreadPoolExecutor for parallel evaluation
    with ThreadPoolExecutor(max_workers=len(ports)) as executor:
        # Submit all tasks
        futures = {}
        for i, domain in enumerate(domains):
            port = ports[i % len(ports)]
            future = executor.submit(evaluate_domain, domain, port, base_dir)
            futures[future] = domain

        # Collect results
        completed = 0
        for future in as_completed(futures):
            domain = futures[future]
            result = future.result()

            # Add ground truth
            expected = expected_map.get(domain, {})
            result['y_true'] = expected.get('y_true', -1)
            result['old_rules'] = expected.get('trace_phase6_rules_fired', '')
            result['ctx_score'] = expected.get('ctx_score', 0)

            results.append(result)
            completed += 1

            if completed % 10 == 0:
                elapsed = time.time() - start_time
                print(f"Progress: {completed}/{len(domains)} ({elapsed:.1f}s)")

    elapsed = time.time() - start_time
    print(f"\nCompleted {len(results)} evaluations in {elapsed:.1f}s")
    print("-" * 60)

    # Analyze results
    df = pd.DataFrame(results)

    # Calculate metrics
    df['predicted_phishing'] = df['ai_is_phishing'].fillna(False).astype(bool)
    df['actual_phishing'] = (df['y_true'] == 1).astype(bool)

    # All test domains were originally FP (predicted phishing, actually benign)
    now_benign = (~df['predicted_phishing']).sum()
    still_phishing = df['predicted_phishing'].sum()
    error_count = df['error'].notna().sum()

    print(f"\n=== RESULTS ===")
    print(f"Total domains: {len(df)}")
    print(f"Now BENIGN (FP fixed): {now_benign}")
    print(f"Still PHISHING: {still_phishing}")
    print(f"Errors: {error_count}")

    fix_rate = now_benign / len(df) * 100 if len(df) > 0 else 0
    print(f"FP Fix Rate: {fix_rate:.1f}%")

    # Show some examples
    print(f"\n=== Sample Fixed Cases ===")
    fixed = df[~df['predicted_phishing']].head(10)
    for _, row in fixed.iterrows():
        print(f"  {row['domain']}: ctx={row['ctx_score']:.3f}")
        print(f"    Old rules: {row['old_rules'][:80]}...")
        print(f"    New rules: {row['rules_fired']}")

    if still_phishing > 0:
        print(f"\n=== Still Phishing (not fixed) ===")
        not_fixed = df[df['predicted_phishing']].head(10)
        for _, row in not_fixed.iterrows():
            print(f"  {row['domain']}: ctx={row['ctx_score']:.3f}")
            print(f"    New rules: {row['rules_fired']}")

    # Save results
    output_file = base_dir / "test_data" / "threshold_test_results.csv"
    df.to_csv(output_file, index=False)
    print(f"\nResults saved to {output_file}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
