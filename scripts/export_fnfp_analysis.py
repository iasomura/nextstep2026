#!/usr/bin/env python3
"""
FN/FP分析結果をCSVにエクスポートするスクリプト

Usage:
    python scripts/export_fnfp_analysis.py [--output-dir OUTPUT_DIR]
"""
import os
import sys
import json
import pickle
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


def analyze_domain(domain: str, cert_map: dict, brand_keywords: list) -> dict:
    """Run analysis on a domain and collect tool results."""
    result = {
        'sda_issues': '',
        'sda_risk_score': 0.0,
        'sda_reasoning': '',
        'sda_domain_length': 0,
        'sda_tld_category': '',
        'brand_issues': '',
        'brand_risk_score': 0.0,
        'brand_detected': '',
        'brand_reasoning': '',
        'cert_issues': '',
        'cert_benign_indicators': '',
        'cert_risk_score': 0.0,
        'cert_issuer': '',
        'cert_san_count': 0,
        'cert_has_crl_dp': False,
        'cert_reasoning': '',
        'ctx_issues': '',
        'ctx_risk_score': 0.0,
        'ctx_reasoning': '',
    }

    # Short domain analysis
    try:
        sda = short_domain_analysis(domain)
        if sda.get('success'):
            data = sda['data']
            result['sda_issues'] = ','.join(data.get('detected_issues', []))
            result['sda_risk_score'] = data.get('risk_score', 0)
            result['sda_reasoning'] = data.get('reasoning', '')
            details = data.get('details', {}) or {}
            result['sda_domain_length'] = details.get('domain_length', 0)
            result['sda_tld_category'] = details.get('tld_category', '')
    except Exception as e:
        result['sda_reasoning'] = f'Error: {e}'

    # Brand impersonation check
    try:
        bic = brand_impersonation_check(domain, brand_keywords=brand_keywords)
        if bic.get('success'):
            data = bic['data']
            result['brand_issues'] = ','.join(data.get('detected_issues', []))
            result['brand_risk_score'] = data.get('risk_score', 0)
            result['brand_reasoning'] = data.get('reasoning', '')
            details = data.get('details', {}) or {}
            detected_brands = details.get('detected_brands', [])
            result['brand_detected'] = ','.join([str(b) for b in detected_brands]) if detected_brands else ''
    except Exception as e:
        result['brand_reasoning'] = f'Error: {e}'

    # Certificate analysis
    try:
        cert_info = cert_map.get(domain, {})
        ca = certificate_analysis(domain, cert_metadata=cert_info, cert_full_info_map=cert_map)
        if ca.get('success'):
            data = ca['data']
            result['cert_issues'] = ','.join(data.get('detected_issues', []))
            result['cert_benign_indicators'] = ','.join(data.get('benign_indicators', []))
            result['cert_risk_score'] = data.get('risk_score', 0)
            result['cert_reasoning'] = data.get('reasoning', '')
            details = data.get('details', {}) or {}
            result['cert_issuer'] = details.get('issuer', '')
            result['cert_san_count'] = details.get('san_count', 0)
            result['cert_has_crl_dp'] = details.get('has_crl_dp', False)
    except Exception as e:
        result['cert_reasoning'] = f'Error: {e}'

    # Contextual risk assessment (without full tool_results, just for reference)
    try:
        tool_results = {
            'short_domain_analysis': {'success': True, 'data': {'detected_issues': result['sda_issues'].split(',') if result['sda_issues'] else [], 'risk_score': result['sda_risk_score']}},
            'brand_impersonation_check': {'success': True, 'data': {'detected_issues': result['brand_issues'].split(',') if result['brand_issues'] else [], 'risk_score': result['brand_risk_score']}},
            'certificate_analysis': {'success': True, 'data': {'detected_issues': result['cert_issues'].split(',') if result['cert_issues'] else [], 'risk_score': result['cert_risk_score'], 'details': {'san_count': result['cert_san_count'], 'has_crl_dp': result['cert_has_crl_dp']}}},
        }
        # Note: We can't get the exact ML probability here, so we'll skip contextual risk assessment
        # The ctx columns will be filled from a separate analysis if needed
    except Exception as e:
        pass

    return result


def main():
    parser = argparse.ArgumentParser(description="Export FN/FP analysis to CSV")
    parser.add_argument('--base-dir', type=str, default=str(DEFAULT_BASE_DIR), help='Results directory')
    parser.add_argument('--output-dir', '-o', type=str, default='fnfp_analysis', help='Output directory')
    parser.add_argument('--analyze', action='store_true', help='Run full tool analysis (slower)')
    args = parser.parse_args()

    base_dir = Path(args.base_dir)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(exist_ok=True)

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

    print("[INFO] Loading results...")
    df = load_results(base_dir)
    if df.empty or 'y_true' not in df.columns:
        print("[ERROR] No results available")
        return

    # Calculate metrics
    fn_df = df[(df['y_true'] == 1) & (df['ai_is_phishing'] == False)].copy()
    fp_df = df[(df['y_true'] == 0) & (df['ai_is_phishing'] == True)].copy()
    tp = len(df[(df['y_true'] == 1) & (df['ai_is_phishing'] == True)])
    tn = len(df[(df['y_true'] == 0) & (df['ai_is_phishing'] == False)])

    total = len(df)
    fn_count = len(fn_df)
    fp_count = len(fp_df)

    recall = tp / (tp + fn_count) if (tp + fn_count) > 0 else 0
    precision = tp / (tp + fp_count) if (tp + fp_count) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    print(f"\n{'='*70}")
    print(f"Stage3 AI Agent 評価結果")
    print(f"{'='*70}")
    print(f"Total: {total}, TP: {tp}, TN: {tn}, FN: {fn_count}, FP: {fp_count}")
    print(f"Recall: {recall:.4f}, Precision: {precision:.4f}, F1: {f1:.4f}")
    print()

    # Add analysis columns
    fn_df['error_type'] = 'FN'
    fp_df['error_type'] = 'FP'

    # Add domain part analysis
    fn_df['domain_part'] = fn_df['domain'].apply(lambda x: x.split('.')[0] if '.' in x else x)
    fn_df['domain_length'] = fn_df['domain_part'].str.len()
    fp_df['domain_part'] = fp_df['domain'].apply(lambda x: x.split('.')[0] if '.' in x else x)
    fp_df['domain_length'] = fp_df['domain_part'].str.len()

    # Categorize by ML probability
    fn_df['ml_category'] = pd.cut(fn_df['ml_probability'],
                                   bins=[0, 0.1, 0.3, 0.5, 1.0],
                                   labels=['very_low', 'low', 'medium', 'high'])
    fp_df['ml_category'] = pd.cut(fp_df['ml_probability'],
                                   bins=[0, 0.1, 0.3, 0.5, 1.0],
                                   labels=['very_low', 'low', 'medium', 'high'])

    # Dangerous TLD flag
    dangerous_tlds = {'top', 'xyz', 'icu', 'buzz', 'cfd', 'cyou', 'cc', 'lat',
                      'online', 'site', 'click', 'shop', 'live', 'info', 'cn'}
    fn_df['is_dangerous_tld'] = fn_df['tld'].isin(dangerous_tlds)
    fp_df['is_dangerous_tld'] = fp_df['tld'].isin(dangerous_tlds)

    # Run tool analysis if requested
    if args.analyze:
        print("[INFO] Loading certificate map...")
        cert_map = load_cert_map()
        print(f"[INFO] Loaded {len(cert_map)} certificate entries")

        print("[INFO] Loading brand keywords...")
        brand_keywords = load_brand_keywords()
        print(f"[INFO] Loaded {len(brand_keywords)} brand keywords")

        print(f"\n[INFO] Analyzing {len(fn_df)} FN cases...")
        fn_analysis = []
        for idx, row in fn_df.iterrows():
            if idx % 50 == 0:
                print(f"  Progress: {idx}/{len(fn_df)}")
            analysis = analyze_domain(row['domain'], cert_map, brand_keywords)
            fn_analysis.append(analysis)

        fn_analysis_df = pd.DataFrame(fn_analysis)
        fn_df = pd.concat([fn_df.reset_index(drop=True), fn_analysis_df], axis=1)

        print(f"\n[INFO] Analyzing {len(fp_df)} FP cases...")
        fp_analysis = []
        for idx, row in fp_df.iterrows():
            if idx % 50 == 0:
                print(f"  Progress: {idx}/{len(fp_df)}")
            analysis = analyze_domain(row['domain'], cert_map, brand_keywords)
            fp_analysis.append(analysis)

        fp_analysis_df = pd.DataFrame(fp_analysis)
        fp_df = pd.concat([fp_df.reset_index(drop=True), fp_analysis_df], axis=1)

    # Export to CSV
    fn_output = output_dir / f"fn_analysis_{timestamp}.csv"
    fp_output = output_dir / f"fp_analysis_{timestamp}.csv"
    summary_output = output_dir / f"summary_{timestamp}.txt"

    fn_df.to_csv(fn_output, index=False)
    fp_df.to_csv(fp_output, index=False)

    print(f"\n[INFO] Exported FN analysis to {fn_output}")
    print(f"[INFO] Exported FP analysis to {fp_output}")

    # Export summary
    with open(summary_output, 'w') as f:
        f.write(f"Stage3 AI Agent 評価サマリー\n")
        f.write(f"{'='*70}\n")
        f.write(f"Timestamp: {timestamp}\n")
        f.write(f"Total: {total}, TP: {tp}, TN: {tn}, FN: {fn_count}, FP: {fp_count}\n")
        f.write(f"Recall: {recall:.4f}, Precision: {precision:.4f}, F1: {f1:.4f}\n")
        f.write(f"\n")

        f.write(f"FN Analysis ({fn_count} cases)\n")
        f.write(f"-" * 50 + "\n")
        f.write(f"By source:\n")
        f.write(fn_df['source'].value_counts().to_string() + "\n\n")
        f.write(f"By TLD (top 10):\n")
        f.write(fn_df['tld'].value_counts().head(10).to_string() + "\n\n")
        f.write(f"By ML category:\n")
        f.write(fn_df['ml_category'].value_counts().to_string() + "\n\n")
        f.write(f"By risk level:\n")
        f.write(fn_df['ai_risk_level'].value_counts().to_string() + "\n\n")

        f.write(f"FP Analysis ({fp_count} cases)\n")
        f.write(f"-" * 50 + "\n")
        f.write(f"By TLD (top 10):\n")
        f.write(fp_df['tld'].value_counts().head(10).to_string() + "\n\n")
        f.write(f"By ML category:\n")
        f.write(fp_df['ml_category'].value_counts().to_string() + "\n\n")
        f.write(f"By risk level:\n")
        f.write(fp_df['ai_risk_level'].value_counts().to_string() + "\n\n")
        f.write(f"Dangerous TLD FPs: {fp_df['is_dangerous_tld'].sum()}\n")
        f.write(f"Short domain (<=6) FPs: {(fp_df['domain_length'] <= 6).sum()}\n")

    print(f"[INFO] Exported summary to {summary_output}")
    print("\nDone!")


if __name__ == "__main__":
    main()
