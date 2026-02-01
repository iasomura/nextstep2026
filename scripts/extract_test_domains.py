#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
scripts/extract_test_domains.py
--------------------------------
Extract test domains for rule-specific integration testing.

Usage:
    python scripts/extract_test_domains.py --rule-group cert_gate --limit 100 --output test_data/cert_gate_test.csv
    python scripts/extract_test_domains.py --rule-group ml_guard --limit 100 --output test_data/ml_guard_test.csv
    python scripts/extract_test_domains.py --list-groups

変更履歴:
    - 2026-01-31: 初版作成（ルールモジュール移行計画用）
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd

# Rule group extraction conditions
RULE_GROUP_CONDITIONS = {
    "cert_gate": {
        "description": "B1-B4: OV/EV cert, CRL, Wildcard, High SAN",
        "filter": lambda df: df[
            df["benign_indicators"].apply(
                lambda x: bool(set(x or []) & {"ov_ev_cert", "has_crl_dp", "wildcard_cert", "high_san_count"})
                if isinstance(x, list) else False
            )
        ],
    },
    "low_signal_gate": {
        "description": "P1-P4: Short cert validity + brand/dangerous TLD",
        "filter": lambda df: df[
            (df["cert_valid_days"] <= 90) &
            (df["brand_detected"] | df["is_dangerous_tld"])
        ],
    },
    "policy": {
        "description": "R1-R6: Ctx 0.28-0.50 with ML < 0.50",
        "filter": lambda df: df[
            (df["ctx_score"] >= 0.28) &
            (df["ctx_score"] < 0.50) &
            (df["ml_probability"] < 0.50)
        ],
    },
    "ml_guard": {
        "description": "ML Override/Block: ML >= 0.40 or ML < 0.05",
        "filter": lambda df: df[
            (df["ml_probability"] >= 0.40) |
            (df["ml_probability"] < 0.05)
        ],
    },
    "ctx_trigger": {
        "description": "CTX Trigger: ctx >= 0.50",
        "filter": lambda df: df[df["ctx_score"] >= 0.50],
    },
    "gov_edu_gate": {
        "description": "Gov/Edu Gate: government/education TLDs",
        "filter": lambda df: df[
            df["tld"].apply(
                lambda x: any(
                    p in str(x).lower()
                    for p in ["gov", "edu", "mil", "ac.", "go."]
                )
            )
        ],
    },
    "brand_cert": {
        "description": "Brand + Cert: brand detected with cert issues",
        "filter": lambda df: df[
            df["brand_detected"] &
            df["cert_issues"].apply(
                lambda x: bool(set(x or []) & {"no_cert", "no_org", "free_ca"})
                if isinstance(x, list) else False
            )
        ],
    },
    "post_gates": {
        "description": "Post Gates: random issues on legitimate TLD, no brand",
        "filter": lambda df: df[
            (df["issue_set"].apply(
                lambda x: bool(x & {"random_pattern", "consonant_cluster_random", "rare_bigram_random"})
                if isinstance(x, set) else False
            )) &
            (~df["is_dangerous_tld"]) &
            (~df["brand_detected"])
        ],
    },
}


def parse_json_field(value: Any) -> Any:
    """Parse JSON string field to Python object."""
    if pd.isna(value):
        return None
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (json.JSONDecodeError, ValueError):
            return value
    return value


def prepare_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Prepare dataframe with derived columns for filtering."""
    # Parse JSON fields where needed
    json_fields = [
        "tool_brand_output", "tool_cert_output", "tool_domain_output", "tool_ctx_output",
        "graph_state_slim_json", "trace_ctx_issues"
    ]
    for field in json_fields:
        if field in df.columns:
            df[field] = df[field].apply(parse_json_field)

    # Extract ctx_score from trace columns
    if "trace_ctx_risk_score" in df.columns:
        df["ctx_score"] = pd.to_numeric(df["trace_ctx_risk_score"], errors="coerce").fillna(0.0)
    else:
        df["ctx_score"] = 0.0

    # Extract cert info from tool_cert_output
    if "tool_cert_output" in df.columns:
        df["cert_issues"] = df["tool_cert_output"].apply(
            lambda x: x.get("detected_issues", []) if isinstance(x, dict) else []
        )
        df["cert_valid_days"] = df["tool_cert_output"].apply(
            lambda x: x.get("details", {}).get("valid_days", 365) if isinstance(x, dict) else 365
        )
        df["benign_indicators"] = df["tool_cert_output"].apply(
            lambda x: x.get("details", {}).get("benign_indicators", []) if isinstance(x, dict) else []
        )
    else:
        df["cert_issues"] = [[] for _ in range(len(df))]
        df["cert_valid_days"] = 365
        df["benign_indicators"] = [[] for _ in range(len(df))]

    # TLD - already exists in eval CSV
    if "tld" not in df.columns:
        df["tld"] = ""

    # Brand detected from tool_brand_output (more reliable than trace_precheck)
    if "tool_brand_output" in df.columns:
        df["brand_detected"] = df["tool_brand_output"].apply(
            lambda x: bool(x.get("details", {}).get("detected_brands"))
            if isinstance(x, dict) else False
        )
    elif "trace_precheck_brand_detected" in df.columns:
        df["brand_detected"] = df["trace_precheck_brand_detected"].fillna(False).astype(bool)
    else:
        df["brand_detected"] = False

    # Dangerous TLD flag
    dangerous_tlds = {
        "tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "buzz",
        "online", "site", "club", "live", "wang", "icu", "vip", "shop"
    }
    df["is_dangerous_tld"] = df["tld"].apply(lambda x: str(x).lower() in dangerous_tlds)

    # Issue set from tool_domain_output
    if "tool_domain_output" in df.columns:
        df["issue_set"] = df["tool_domain_output"].apply(
            lambda x: set(x.get("detected_issues", [])) if isinstance(x, dict) else set()
        )
    else:
        df["issue_set"] = [set() for _ in range(len(df))]

    # ML probability - already exists in eval CSV
    if "ml_probability" not in df.columns and "ml_prob" in df.columns:
        df["ml_probability"] = df["ml_prob"]
    elif "ml_probability" not in df.columns:
        df["ml_probability"] = 0.0

    return df


def extract_domains(
    input_file: str,
    rule_group: str,
    limit: int = 100,
    shuffle: bool = True,
) -> pd.DataFrame:
    """Extract domains matching rule group conditions.

    Args:
        input_file: Path to evaluation results CSV
        rule_group: Rule group name
        limit: Maximum number of domains to extract
        shuffle: Whether to shuffle results

    Returns:
        DataFrame with extracted domains
    """
    if rule_group not in RULE_GROUP_CONDITIONS:
        raise ValueError(f"Unknown rule group: {rule_group}")

    # Load data
    df = pd.read_csv(input_file)
    print(f"Loaded {len(df)} rows from {input_file}")

    # Prepare dataframe
    df = prepare_dataframe(df)

    # Apply filter
    condition = RULE_GROUP_CONDITIONS[rule_group]
    try:
        filtered = condition["filter"](df)
    except Exception as e:
        print(f"Warning: Filter failed with {e}, returning empty DataFrame")
        filtered = df.head(0)

    print(f"Filtered to {len(filtered)} rows matching {rule_group} conditions")

    # Shuffle and limit
    if shuffle and len(filtered) > 0:
        filtered = filtered.sample(frac=1, random_state=42)

    if limit and len(filtered) > limit:
        filtered = filtered.head(limit)

    return filtered


def list_rule_groups():
    """List available rule groups and their descriptions."""
    print("\nAvailable rule groups:")
    print("-" * 60)
    for name, info in RULE_GROUP_CONDITIONS.items():
        print(f"  {name:20s} {info['description']}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Extract test domains for rule-specific integration testing"
    )
    parser.add_argument(
        "--rule-group",
        type=str,
        help="Rule group to extract domains for",
    )
    parser.add_argument(
        "--input",
        type=str,
        default="artifacts/2026-01-24_213326/results/stage2_validation/eval_df__nALL__ts_20260131_015032.csv",
        help="Input evaluation results CSV",
    )
    parser.add_argument(
        "--output",
        type=str,
        help="Output CSV file path",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=100,
        help="Maximum number of domains to extract",
    )
    parser.add_argument(
        "--no-shuffle",
        action="store_true",
        help="Don't shuffle results",
    )
    parser.add_argument(
        "--list-groups",
        action="store_true",
        help="List available rule groups",
    )

    args = parser.parse_args()

    if args.list_groups:
        list_rule_groups()
        return

    if not args.rule_group:
        parser.error("--rule-group is required unless --list-groups is specified")

    # Set default output path
    if not args.output:
        os.makedirs("test_data/rule_tests", exist_ok=True)
        args.output = f"test_data/rule_tests/{args.rule_group}_test.csv"

    # Extract domains
    try:
        result = extract_domains(
            input_file=args.input,
            rule_group=args.rule_group,
            limit=args.limit,
            shuffle=not args.no_shuffle,
        )
    except FileNotFoundError:
        print(f"Error: Input file not found: {args.input}")
        sys.exit(1)

    # Save results
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    result.to_csv(args.output, index=False)
    print(f"Saved {len(result)} domains to {args.output}")


if __name__ == "__main__":
    main()
