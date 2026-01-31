#!/usr/bin/env python3
"""
Real-time FN/FP detailed monitoring script for Stage3 AI Agent evaluation.

Shows detailed analysis for each FN/FP case including:
- Domain structure analysis
- Certificate features
- Brand detection results
- AI Agent reasoning

Usage:
    python scripts/monitor_fnfp_detail.py [--watch] [--interval SECONDS]
"""
import os
import sys
import time
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

# Default paths
DEFAULT_BASE_DIR = Path("/data/hdd/asomura/nextstep/artifacts/2026-01-24_213326/results/stage2_validation")
CERT_PKL_PATH = Path("/data/hdd/asomura/nextstep/artifacts/2026-01-24_213326/processed/cert_full_info_map.pkl")


def load_cert_map():
    """Load certificate features map."""
    import pickle
    if CERT_PKL_PATH.exists():
        with open(CERT_PKL_PATH, 'rb') as f:
            return pickle.load(f)
    return {}


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


def analyze_domain_detail(domain: str, cert_map: dict) -> dict:
    """Run detailed analysis on a domain."""
    result = {}

    # Short domain analysis
    try:
        sda = short_domain_analysis(domain)
        if sda.get('success'):
            result['short_domain'] = sda['data']
    except Exception as e:
        result['short_domain_error'] = str(e)

    # Brand impersonation check
    try:
        bic = brand_impersonation_check(domain)
        if bic.get('success'):
            result['brand'] = bic['data']
    except Exception as e:
        result['brand_error'] = str(e)

    # Contextual risk assessment
    try:
        # Get cert info for this domain
        cert_info = cert_map.get(domain, {})
        cra = contextual_risk_assessment(
            domain=domain,
            tool_results={},
            precheck_hints={},
            cert_full_info_map=cert_map
        )
        if cra.get('success'):
            result['contextual'] = cra['data']
    except Exception as e:
        result['contextual_error'] = str(e)

    # Certificate info
    cert_info = cert_map.get(domain, {})
    if cert_info:
        result['cert'] = {
            'issuer': cert_info.get('issuer_org', 'N/A'),
            'san_count': cert_info.get('san_count', 0),
            'has_crl_dp': cert_info.get('has_crl_dp', False),
            'valid_days': cert_info.get('valid_days', 0),
            'is_wildcard': cert_info.get('is_wildcard', False),
        }

    return result


def print_fnfp_detail(row: pd.Series, analysis: dict, case_type: str):
    """Print detailed analysis for a single FN/FP case."""
    domain = row.get('domain', 'N/A')
    ml_prob = row.get('ml_probability', 0)
    ai_conf = row.get('ai_confidence', 0)
    ai_risk = row.get('ai_risk_level', 'N/A')
    tld = row.get('tld', '')
    source = row.get('source', '')

    # Color coding
    if case_type == 'FN':
        prefix = '\033[91m[FN]\033[0m'  # Red
        verdict = "AI said Benign, but actually Phishing"
    else:
        prefix = '\033[93m[FP]\033[0m'  # Yellow
        verdict = "AI said Phishing, but actually Benign"

    print(f"\n{prefix} {domain}")
    print(f"  └─ {verdict}")
    print(f"  └─ ML: {ml_prob:.3f}, AI Conf: {ai_conf:.2f}, Risk: {ai_risk}, Source: {source}")

    # Brand detection
    brand = analysis.get('brand', {})
    if brand:
        detected = brand.get('details', {}).get('detected_brands', [])
        brand_score = brand.get('risk_score', 0)
        if detected:
            print(f"  └─ 🏷️  Brand: {detected} (score={brand_score:.2f})")
        else:
            print(f"  └─ 🏷️  Brand: None detected")

    # Short domain analysis
    sda = analysis.get('short_domain', {})
    if sda:
        issues = sda.get('detected_issues', [])
        sda_score = sda.get('risk_score', 0)
        if issues:
            print(f"  └─ 📊 Domain: {issues} (score={sda_score:.2f})")

    # Certificate info
    cert = analysis.get('cert', {})
    if cert:
        print(f"  └─ 🔐 Cert: issuer={cert.get('issuer','N/A')}, SAN={cert.get('san_count',0)}, CRL_DP={cert.get('has_crl_dp',False)}")

    # Contextual assessment
    ctx = analysis.get('contextual', {})
    if ctx:
        ctx_issues = ctx.get('detected_issues', [])
        ctx_score = ctx.get('risk_score', 0)
        if ctx_issues:
            print(f"  └─ ⚠️  Context: {ctx_issues} (score={ctx_score:.2f})")

    # Assessment
    if case_type == 'FN':
        # Why was this missed?
        reasons = []
        if not brand.get('details', {}).get('detected_brands'):
            reasons.append("No brand detected")
        if cert.get('has_crl_dp'):
            reasons.append("Has CRL DP (benign indicator)")
        if cert.get('san_count', 0) == 2:
            reasons.append("SAN=2 (benign indicator)")
        if not sda.get('detected_issues'):
            reasons.append("No domain issues")
        if reasons:
            print(f"  └─ 💡 Why missed: {', '.join(reasons)}")
    else:
        # Why false positive?
        reasons = []
        if brand.get('details', {}).get('detected_brands'):
            reasons.append(f"Brand detected: {brand['details']['detected_brands']}")
        if '.xyz' in domain or '.top' in domain or '.icu' in domain:
            reasons.append("Dangerous TLD")
        sda_issues = sda.get('detected_issues', [])
        if 'random_pattern' in str(sda_issues) or 'high_entropy' in str(sda_issues):
            reasons.append("Random pattern detected")
        if reasons:
            print(f"  └─ 💡 Why FP: {', '.join(reasons)}")


def main():
    parser = argparse.ArgumentParser(description="Detailed FN/FP monitoring for Stage3 AI Agent")
    parser.add_argument('--watch', '-w', action='store_true', help='Continuous monitoring mode')
    parser.add_argument('--interval', '-i', type=int, default=60, help='Refresh interval in seconds')
    parser.add_argument('--base-dir', type=str, default=str(DEFAULT_BASE_DIR), help='Results directory')
    parser.add_argument('--max-show', type=int, default=10, help='Max cases to show per category')
    parser.add_argument('--new-only', action='store_true', help='Only show new cases since last check')
    args = parser.parse_args()

    base_dir = Path(args.base_dir)

    print("[INFO] Loading certificate map...")
    cert_map = load_cert_map()
    print(f"[INFO] Loaded {len(cert_map)} certificate entries")

    seen_fn = set()
    seen_fp = set()

    def run_check():
        nonlocal seen_fn, seen_fp

        df = load_results(base_dir)
        if df.empty:
            print("\n[INFO] Waiting for results...")
            return

        # Calculate stats
        fn_df = df[(df['y_true'] == 1) & (df['ai_is_phishing'] == False)]
        fp_df = df[(df['y_true'] == 0) & (df['ai_is_phishing'] == True)]
        tp = len(df[(df['y_true'] == 1) & (df['ai_is_phishing'] == True)])
        tn = len(df[(df['y_true'] == 0) & (df['ai_is_phishing'] == False)])

        total = len(df)
        fn_count = len(fn_df)
        fp_count = len(fp_df)

        # Metrics
        recall = tp / (tp + fn_count) if (tp + fn_count) > 0 else 0
        precision = tp / (tp + fp_count) if (tp + fp_count) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

        # Progress estimate
        total_domains = 15670
        progress = total / total_domains * 100

        print(f"\n{'='*70}")
        print(f"Stage3 AI Agent - Detailed FN/FP Monitor")
        print(f"{'='*70}")
        print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Progress: {total:,} / {total_domains:,} ({progress:.1f}%)")
        print(f"\n┌─────────────────────────────────────────────────────────────────────┐")
        print(f"│  TP: {tp:4d}  │  TN: {tn:5d}  │  FN: {fn_count:4d}  │  FP: {fp_count:4d}  │")
        print(f"│  Recall: {recall:.4f}  │  Precision: {precision:.4f}  │  F1: {f1:.4f}  │")
        print(f"└─────────────────────────────────────────────────────────────────────┘")

        # Determine which cases to show
        if args.new_only:
            new_fn = fn_df[~fn_df['domain'].isin(seen_fn)]
            new_fp = fp_df[~fp_df['domain'].isin(seen_fp)]
            seen_fn.update(fn_df['domain'].tolist())
            seen_fp.update(fp_df['domain'].tolist())
            show_fn = new_fn.tail(args.max_show)
            show_fp = new_fp.tail(args.max_show)
            fn_label = f"NEW FN Cases ({len(new_fn)} new, {fn_count} total)"
            fp_label = f"NEW FP Cases ({len(new_fp)} new, {fp_count} total)"
        else:
            show_fn = fn_df.tail(args.max_show)
            show_fp = fp_df.tail(args.max_show)
            fn_label = f"Recent FN Cases (showing {len(show_fn)} of {fn_count})"
            fp_label = f"Recent FP Cases (showing {len(show_fp)} of {fp_count})"

        # Show FN cases
        print(f"\n{'─'*70}")
        print(f"🔴 {fn_label}")
        print(f"{'─'*70}")
        if len(show_fn) > 0:
            for _, row in show_fn.iterrows():
                domain = row['domain']
                analysis = analyze_domain_detail(domain, cert_map)
                print_fnfp_detail(row, analysis, 'FN')
        else:
            print("  (none)")

        # Show FP cases
        print(f"\n{'─'*70}")
        print(f"🟡 {fp_label}")
        print(f"{'─'*70}")
        if len(show_fp) > 0:
            for _, row in show_fp.iterrows():
                domain = row['domain']
                analysis = analyze_domain_detail(domain, cert_map)
                print_fnfp_detail(row, analysis, 'FP')
        else:
            print("  (none)")

    if args.watch:
        print(f"[INFO] Watching {base_dir} (interval: {args.interval}s)")
        print("[INFO] Press Ctrl+C to stop")
        try:
            while True:
                os.system('clear')
                run_check()
                time.sleep(args.interval)
        except KeyboardInterrupt:
            print("\n[INFO] Monitoring stopped")
    else:
        run_check()


if __name__ == "__main__":
    main()
