#!/usr/bin/env python3
"""
Analyze "featureless" phishing sites in FN cases.

A featureless phishing site is one that has no distinguishing characteristics
that would allow detection based on domain and certificate features alone.

Definition criteria:
1. Low ML probability (< 0.15) - Model can't distinguish
2. Non-dangerous TLD (.com, .net, .org, etc.)
3. No brand keywords detected
4. Normal certificate (not self-signed, has CRL)
5. Normal domain characteristics (length, entropy, vowel ratio)
"""

import pandas as pd
import json
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))
from collections import Counter

# Dangerous TLDs (from pipeline)
HIGH_DANGER_TLDS = {'tk', 'ml', 'ga', 'cf', 'gq', 'icu', 'cfd', 'sbs', 'rest', 'cyou', 'pw', 'buzz', 'lat'}
MEDIUM_DANGER_TLDS = {'top', 'shop', 'xyz', 'cc', 'online', 'cn', 'tokyo', 'dev', 'me', 'vip', 'asia', 'club', 'site', 'website', 'one', 'link', 'click'}

def get_tld(domain: str) -> str:
    """Extract TLD from domain."""
    parts = domain.lower().split('.')
    return parts[-1] if parts else ''

def classify_tld_danger(tld: str) -> str:
    """Classify TLD danger level."""
    if tld in HIGH_DANGER_TLDS:
        return 'HIGH'
    elif tld in MEDIUM_DANGER_TLDS:
        return 'MEDIUM'
    else:
        return 'LOW'

def analyze_fn_samples(run_id: str = '2026-01-13_010844'):
    """Analyze FN samples to find featureless phishing."""

    base_path = Path(f'artifacts/{run_id}')

    # Load evaluation data (contains Agent predictions)
    eval_path = base_path / 'results/stage2_validation/eval_df__n17529__ts_2026-01-14_111620.csv'
    if not eval_path.exists():
        print(f"Error: {eval_path} not found")
        return

    df = pd.read_csv(eval_path)

    # Filter FN cases (phishing but Agent said benign)
    fn = df[(df['label'] == 1) & (df['final_pred'] == 0)].copy()
    print(f"=== FN Analysis: {len(fn)} samples ===\n")

    # Add TLD info
    fn['tld'] = fn['domain'].apply(get_tld)
    fn['tld_danger'] = fn['tld'].apply(classify_tld_danger)

    # Load brand keywords
    brand_path = base_path / 'models/brand_keywords.json'
    if brand_path.exists():
        with open(brand_path, 'r') as f:
            brand_keywords = set(json.load(f))
    else:
        brand_keywords = set()

    # Check brand presence
    def has_brand(domain):
        domain_lower = domain.lower()
        return any(brand in domain_lower for brand in brand_keywords)

    fn['has_brand'] = fn['domain'].apply(has_brand)

    # === Featureless criteria ===
    # 1. Low ML probability
    fn['low_ml'] = fn['ml_probability'] < 0.15

    # 2. Non-dangerous TLD
    fn['safe_tld'] = fn['tld_danger'] == 'LOW'

    # 3. No brand
    fn['no_brand'] = ~fn['has_brand']

    # 4. Valid certificate (proxy: cert_validity_days between 30-400)
    fn['normal_cert'] = (fn['cert_validity_days'] >= 30) & (fn['cert_validity_days'] <= 400)

    # === Classification ===
    # Featureless = Low ML + Safe TLD + No Brand + Normal Cert
    fn['is_featureless'] = fn['low_ml'] & fn['safe_tld'] & fn['no_brand'] & fn['normal_cert']

    # Partially featureless (missing some but not all signals)
    fn['partial_signals'] = fn['low_ml'] | fn['safe_tld'] | fn['no_brand']

    print("=== FN Classification ===\n")

    # Summary
    featureless = fn[fn['is_featureless']]
    has_some_features = fn[~fn['is_featureless']]

    print(f"Total FN: {len(fn)}")
    print(f"  Featureless (検出困難): {len(featureless)} ({100*len(featureless)/len(fn):.1f}%)")
    print(f"  Has some features: {len(has_some_features)} ({100*len(has_some_features)/len(fn):.1f}%)")

    print("\n=== Feature Distribution in FN ===\n")
    print(f"Low ML (<0.15): {fn['low_ml'].sum()} ({100*fn['low_ml'].mean():.1f}%)")
    print(f"Safe TLD (LOW): {fn['safe_tld'].sum()} ({100*fn['safe_tld'].mean():.1f}%)")
    print(f"No brand: {fn['no_brand'].sum()} ({100*fn['no_brand'].mean():.1f}%)")
    print(f"Normal cert: {fn['normal_cert'].sum()} ({100*fn['normal_cert'].mean():.1f}%)")

    print("\n=== TLD Distribution in FN ===\n")
    tld_counts = fn['tld_danger'].value_counts()
    for level, count in tld_counts.items():
        print(f"  {level}: {count} ({100*count/len(fn):.1f}%)")

    print("\n=== ML Probability Distribution in FN ===\n")
    bins = [0, 0.05, 0.10, 0.15, 0.25, 0.50, 1.0]
    labels = ['<0.05', '0.05-0.10', '0.10-0.15', '0.15-0.25', '0.25-0.50', '>=0.50']
    fn['ml_bin'] = pd.cut(fn['ml_probability'], bins=bins, labels=labels, right=False)
    ml_dist = fn['ml_bin'].value_counts().sort_index()
    for bin_label, count in ml_dist.items():
        print(f"  {bin_label}: {count} ({100*count/len(fn):.1f}%)")

    print("\n=== Featureless Phishing Examples (Top 20) ===\n")
    if len(featureless) > 0:
        cols = ['domain', 'source', 'ml_probability', 'tld', 'cert_validity_days']
        print(featureless[cols].head(20).to_string())
    else:
        print("No featureless phishing found!")

    print("\n=== Feature-rich FN (should be detectable) ===\n")
    # These have some signal but still missed
    feature_rich = fn[
        (fn['tld_danger'] != 'LOW') |  # Dangerous TLD
        fn['has_brand'] |               # Has brand
        (fn['ml_probability'] >= 0.25)  # Higher ML
    ]
    print(f"Feature-rich FN (missed despite signals): {len(feature_rich)}")
    if len(feature_rich) > 0:
        print("\nBreakdown:")
        print(f"  - Dangerous TLD: {(feature_rich['tld_danger'] != 'LOW').sum()}")
        print(f"  - Has brand: {feature_rich['has_brand'].sum()}")
        print(f"  - ML >= 0.25: {(feature_rich['ml_probability'] >= 0.25).sum()}")

        print("\nExamples (Top 10):")
        cols = ['domain', 'source', 'ml_probability', 'tld', 'tld_danger', 'has_brand']
        print(feature_rich[cols].head(10).to_string())

    # Save detailed results
    output_path = base_path / 'results/fn_featureless_analysis.csv'
    fn.to_csv(output_path, index=False)
    print(f"\nDetailed results saved to: {output_path}")

    return fn

if __name__ == '__main__':
    run_id = sys.argv[1] if len(sys.argv) > 1 else '2026-01-13_010844'
    analyze_fn_samples(run_id)
