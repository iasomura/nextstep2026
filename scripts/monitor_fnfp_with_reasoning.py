#!/usr/bin/env python3
"""
FN/FP monitoring with full reasoning output for tuning analysis.
Saves detailed logs including tool reasoning for later analysis.

Usage:
    python scripts/monitor_fnfp_with_reasoning.py [--output LOG_FILE]
"""
import os
import sys
import json
import argparse
import pandas as pd
from pathlib import Path
from datetime import datetime

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from phishing_agent.tools.short_domain_analysis import short_domain_analysis
from phishing_agent.tools.brand_impersonation_check import brand_impersonation_check
from phishing_agent.tools.contextual_risk_assessment import contextual_risk_assessment
from phishing_agent.tools.certificate_analysis import certificate_analysis

# Default paths
DEFAULT_BASE_DIR = Path("/data/hdd/asomura/nextstep/artifacts/2026-01-24_213326/results/stage2_validation")
CERT_PKL_PATH = Path("/data/hdd/asomura/nextstep/artifacts/2026-01-24_213326/processed/cert_full_info_map.pkl")
BRAND_KEYWORDS_PATH = Path("/data/hdd/asomura/nextstep/artifacts/2026-01-24_213326/models/brand_keywords.json")


def load_cert_map():
    """Load certificate features map."""
    import pickle
    if CERT_PKL_PATH.exists():
        with open(CERT_PKL_PATH, 'rb') as f:
            return pickle.load(f)
    return {}


def load_brand_keywords():
    """Load brand keywords list."""
    if BRAND_KEYWORDS_PATH.exists():
        with open(BRAND_KEYWORDS_PATH, 'r') as f:
            return json.load(f)
    return []


def load_results(base_dir: Path):
    """Load all worker results from CSV files."""
    dfs = []
    for i in range(3):
        csv_path = base_dir / f"worker_{i}_results.csv"
        if csv_path.exists():
            try:
                df = pd.read_csv(csv_path)
                df['worker_id'] = i
                dfs.append(df)
            except Exception as e:
                print(f"[WARNING] Error loading worker_{i}: {e}", file=sys.stderr)
    if dfs:
        return pd.concat(dfs, ignore_index=True)
    return pd.DataFrame()


def analyze_domain_full(domain: str, cert_map: dict, brand_keywords: list) -> dict:
    """Run full analysis on a domain and collect all reasoning."""
    result = {
        'domain': domain,
        'tools': {},
        'reasoning_summary': [],
    }

    # Short domain analysis
    try:
        sda = short_domain_analysis(domain)
        if sda.get('success'):
            data = sda['data']
            result['tools']['short_domain_analysis'] = {
                'detected_issues': data.get('detected_issues', []),
                'risk_score': data.get('risk_score', 0),
                'reasoning': data.get('reasoning', ''),
                'details': {
                    'domain_length': data.get('details', {}).get('domain_length'),
                    'tld_category': data.get('details', {}).get('tld_category'),
                    'cctld_interpretation': data.get('details', {}).get('cctld_interpretation'),
                }
            }
            if data.get('reasoning'):
                result['reasoning_summary'].append(f"[SDA] {data['reasoning']}")
    except Exception as e:
        result['tools']['short_domain_analysis'] = {'error': str(e)}

    # Brand impersonation check
    try:
        bic = brand_impersonation_check(domain, brand_keywords=brand_keywords)
        if bic.get('success'):
            data = bic['data']
            result['tools']['brand_impersonation_check'] = {
                'detected_issues': data.get('detected_issues', []),
                'risk_score': data.get('risk_score', 0),
                'reasoning': data.get('reasoning', ''),
                'details': {
                    'detected_brands': data.get('details', {}).get('detected_brands', []),
                }
            }
            if data.get('reasoning'):
                result['reasoning_summary'].append(f"[BRAND] {data['reasoning']}")
    except Exception as e:
        result['tools']['brand_impersonation_check'] = {'error': str(e)}

    # Certificate analysis
    try:
        cert_info = cert_map.get(domain, {})
        ca = certificate_analysis(domain, cert_metadata=cert_info, cert_full_info_map=cert_map)
        if ca.get('success'):
            data = ca['data']
            result['tools']['certificate_analysis'] = {
                'detected_issues': data.get('detected_issues', []),
                'benign_indicators': data.get('benign_indicators', []),
                'risk_score': data.get('risk_score', 0),
                'reasoning': data.get('reasoning', ''),
                'details': {
                    'issuer': data.get('details', {}).get('issuer'),
                    'san_count': data.get('details', {}).get('san_count'),
                    'has_crl_dp': data.get('details', {}).get('has_crl_dp'),
                    'san_interpretation': data.get('details', {}).get('san_interpretation'),
                    'ca_interpretation': data.get('details', {}).get('ca_interpretation'),
                }
            }
            if data.get('reasoning'):
                result['reasoning_summary'].append(f"[CERT] {data['reasoning']}")
    except Exception as e:
        result['tools']['certificate_analysis'] = {'error': str(e)}

    # Contextual risk assessment
    try:
        tool_results = {
            'short_domain_analysis': {'success': True, 'data': result['tools'].get('short_domain_analysis', {})},
            'brand_impersonation_check': {'success': True, 'data': result['tools'].get('brand_impersonation_check', {})},
            'certificate_analysis': {'success': True, 'data': result['tools'].get('certificate_analysis', {})},
        }
        cra = contextual_risk_assessment(
            domain=domain,
            tool_results=tool_results,
            precheck_hints={},
            cert_full_info_map=cert_map
        )
        if cra.get('success'):
            data = cra['data']
            result['tools']['contextual_risk_assessment'] = {
                'detected_issues': data.get('detected_issues', []),
                'risk_score': data.get('risk_score', 0),
                'reasoning': data.get('reasoning', ''),
            }
            if data.get('reasoning'):
                result['reasoning_summary'].append(f"[CTX] {data['reasoning']}")
    except Exception as e:
        result['tools']['contextual_risk_assessment'] = {'error': str(e)}

    return result


def main():
    parser = argparse.ArgumentParser(description="FN/FP monitoring with reasoning for tuning")
    parser.add_argument('--base-dir', type=str, default=str(DEFAULT_BASE_DIR), help='Results directory')
    parser.add_argument('--output', '-o', type=str, default='fnfp_reasoning_log.jsonl', help='Output log file')
    parser.add_argument('--max-analyze', type=int, default=50, help='Max cases to analyze in detail')
    args = parser.parse_args()

    base_dir = Path(args.base_dir)
    output_file = Path(args.output)

    print("[INFO] Loading certificate map...")
    cert_map = load_cert_map()
    print(f"[INFO] Loaded {len(cert_map)} certificate entries")

    print("[INFO] Loading brand keywords...")
    brand_keywords = load_brand_keywords()
    print(f"[INFO] Loaded {len(brand_keywords)} brand keywords")

    df = load_results(base_dir)
    if df.empty or 'y_true' not in df.columns:
        print("[INFO] No results available yet")
        return

    # Calculate stats
    fn_df = df[(df['y_true'] == 1) & (df['ai_is_phishing'] == False)]
    fp_df = df[(df['y_true'] == 0) & (df['ai_is_phishing'] == True)]
    tp = len(df[(df['y_true'] == 1) & (df['ai_is_phishing'] == True)])
    tn = len(df[(df['y_true'] == 0) & (df['ai_is_phishing'] == False)])

    total = len(df)
    fn_count = len(fn_df)
    fp_count = len(fp_df)

    recall = tp / (tp + fn_count) if (tp + fn_count) > 0 else 0
    precision = tp / (tp + fp_count) if (tp + fp_count) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    print(f"\n{'='*70}")
    print(f"FN/FP Analysis with Reasoning")
    print(f"{'='*70}")
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Total: {total}, TP: {tp}, TN: {tn}, FN: {fn_count}, FP: {fp_count}")
    print(f"Recall: {recall:.4f}, Precision: {precision:.4f}, F1: {f1:.4f}")

    # Analyze FN cases
    print(f"\n--- Analyzing FN Cases (up to {args.max_analyze}) ---")
    fn_logs = []
    for idx, (_, row) in enumerate(fn_df.head(args.max_analyze).iterrows()):
        domain = row['domain']
        print(f"  [{idx+1}/{min(fn_count, args.max_analyze)}] Analyzing FN: {domain}")
        analysis = analyze_domain_full(domain, cert_map, brand_keywords)
        analysis['case_type'] = 'FN'
        analysis['ml_probability'] = row.get('ml_probability', 0)
        analysis['ai_confidence'] = row.get('ai_confidence', 0)
        analysis['source'] = row.get('source', '')
        fn_logs.append(analysis)

    # Analyze FP cases
    print(f"\n--- Analyzing FP Cases (up to {args.max_analyze}) ---")
    fp_logs = []
    for idx, (_, row) in enumerate(fp_df.head(args.max_analyze).iterrows()):
        domain = row['domain']
        print(f"  [{idx+1}/{min(fp_count, args.max_analyze)}] Analyzing FP: {domain}")
        analysis = analyze_domain_full(domain, cert_map, brand_keywords)
        analysis['case_type'] = 'FP'
        analysis['ml_probability'] = row.get('ml_probability', 0)
        analysis['ai_confidence'] = row.get('ai_confidence', 0)
        analysis['source'] = row.get('source', '')
        fp_logs.append(analysis)

    # Save to JSONL
    all_logs = fn_logs + fp_logs
    with open(output_file, 'w') as f:
        for log in all_logs:
            f.write(json.dumps(log, ensure_ascii=False) + '\n')

    print(f"\n[INFO] Saved {len(all_logs)} analysis logs to {output_file}")

    # Print summary for FN
    print(f"\n{'='*70}")
    print(f"FN Summary (Why Missed)")
    print(f"{'='*70}")
    for log in fn_logs[:10]:
        print(f"\n[FN] {log['domain']}")
        print(f"  ML: {log['ml_probability']:.3f}, Source: {log['source']}")
        for r in log['reasoning_summary'][:3]:
            print(f"  {r[:100]}...")

    # Print summary for FP
    print(f"\n{'='*70}")
    print(f"FP Summary (Why False Positive)")
    print(f"{'='*70}")
    for log in fp_logs[:10]:
        print(f"\n[FP] {log['domain']}")
        print(f"  ML: {log['ml_probability']:.3f}, Source: {log['source']}")
        for r in log['reasoning_summary'][:3]:
            print(f"  {r[:100]}...")


if __name__ == "__main__":
    main()
