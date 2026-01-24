#!/usr/bin/env python3
"""
VirusTotal domain check script for featureless phishing verification.

Usage:
    # Single domain check
    python virustotal_check.py example.com

    # Batch check from file
    python virustotal_check.py --batch domains.txt --output results.csv

    # Check featureless FN samples
    python virustotal_check.py --featureless --limit 50

Requirements:
    - VIRUSTOTAL_API_KEY environment variable or .env file
    - pip install requests python-dotenv
"""

import os
import sys
import time
import json
import argparse
import requests
from pathlib import Path
from datetime import datetime

# Try to load from .env
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# VirusTotal API configuration
VT_API_URL = "https://www.virustotal.com/api/v3/domains/{domain}"
VT_RATE_LIMIT = 4  # requests per minute (free tier)
VT_DAILY_LIMIT = 500  # requests per day (free tier)


def get_api_key():
    """Get VirusTotal API key from environment or file."""
    key = os.environ.get('VIRUSTOTAL_API_KEY')
    if not key:
        # Try to read from project file first
        project_key_file = Path(__file__).parent.parent / 'docs' / 'virustotal_api_key.txt'
        if project_key_file.exists():
            key = project_key_file.read_text().strip()
        else:
            # Fallback to home directory
            key_file = Path.home() / '.virustotal_api_key'
            if key_file.exists():
                key = key_file.read_text().strip()
    return key


def check_domain(domain: str, api_key: str) -> dict:
    """
    Check a domain against VirusTotal.

    Returns:
        Dict with detection results
    """
    headers = {
        "x-apikey": api_key,
        "Accept": "application/json"
    }

    try:
        response = requests.get(
            VT_API_URL.format(domain=domain),
            headers=headers,
            timeout=30
        )

        if response.status_code == 200:
            data = response.json()
            attrs = data.get('data', {}).get('attributes', {})

            # Extract key information
            stats = attrs.get('last_analysis_stats', {})
            reputation = attrs.get('reputation', 0)

            return {
                'domain': domain,
                'status': 'found',
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'harmless': stats.get('harmless', 0),
                'undetected': stats.get('undetected', 0),
                'reputation': reputation,
                'total_votes_malicious': attrs.get('total_votes', {}).get('malicious', 0),
                'total_votes_harmless': attrs.get('total_votes', {}).get('harmless', 0),
                'categories': json.dumps(attrs.get('categories', {})),
                'last_analysis_date': attrs.get('last_analysis_date', ''),
                'error': None
            }
        elif response.status_code == 404:
            return {
                'domain': domain,
                'status': 'not_found',
                'malicious': 0,
                'suspicious': 0,
                'harmless': 0,
                'undetected': 0,
                'reputation': 0,
                'total_votes_malicious': 0,
                'total_votes_harmless': 0,
                'categories': '{}',
                'last_analysis_date': '',
                'error': None
            }
        elif response.status_code == 429:
            return {
                'domain': domain,
                'status': 'rate_limited',
                'error': 'Rate limit exceeded'
            }
        else:
            return {
                'domain': domain,
                'status': 'error',
                'error': f'HTTP {response.status_code}: {response.text[:100]}'
            }

    except Exception as e:
        return {
            'domain': domain,
            'status': 'error',
            'error': str(e)
        }


def batch_check(domains: list, api_key: str, output_file: str = None, delay: float = 15.5):
    """
    Check multiple domains with rate limiting.

    Args:
        domains: List of domains to check
        api_key: VirusTotal API key
        output_file: Optional CSV output file
        delay: Delay between requests (default: 15.5s for 4 req/min limit)
    """
    results = []
    total = len(domains)

    print(f"Checking {total} domains (rate limit: {60/delay:.1f} req/min)")
    print(f"Estimated time: {total * delay / 60:.1f} minutes")
    print()

    for i, domain in enumerate(domains, 1):
        print(f"[{i}/{total}] Checking {domain}...", end=' ', flush=True)

        result = check_domain(domain, api_key)
        results.append(result)

        if result['status'] == 'found':
            mal = result['malicious']
            sus = result['suspicious']
            print(f"Malicious: {mal}, Suspicious: {sus}")
        elif result['status'] == 'not_found':
            print("Not found in VT")
        elif result['status'] == 'rate_limited':
            print("Rate limited! Waiting 60s...")
            time.sleep(60)
            # Retry
            result = check_domain(domain, api_key)
            results[-1] = result
            if result['status'] == 'found':
                print(f"  Retry OK: Malicious: {result['malicious']}")
        else:
            print(f"Error: {result.get('error', 'Unknown')}")

        # Rate limiting (except for last item)
        if i < total:
            time.sleep(delay)

    # Save results
    if output_file:
        import csv
        with open(output_file, 'w', newline='') as f:
            if results:
                writer = csv.DictWriter(f, fieldnames=results[0].keys())
                writer.writeheader()
                writer.writerows(results)
        print(f"\nResults saved to: {output_file}")

    # Summary
    print("\n=== Summary ===")
    found = [r for r in results if r['status'] == 'found']
    not_found = [r for r in results if r['status'] == 'not_found']
    detected = [r for r in found if r.get('malicious', 0) > 0 or r.get('suspicious', 0) > 0]

    print(f"Total checked: {len(results)}")
    print(f"Found in VT: {len(found)}")
    print(f"Not found: {len(not_found)}")
    print(f"Detected as malicious/suspicious: {len(detected)}")

    if found:
        avg_mal = sum(r.get('malicious', 0) for r in found) / len(found)
        print(f"Average malicious detections: {avg_mal:.2f}")

    return results


def load_featureless_domains(limit: int = None) -> list:
    """Load featureless FN domains from analysis file."""
    import pandas as pd

    path = Path('artifacts/2026-01-13_010844/results/fn_featureless_analysis.csv')
    if not path.exists():
        print(f"Error: {path} not found. Run analyze_featureless_phishing.py first.")
        return []

    df = pd.read_csv(path)
    featureless = df[df['is_featureless'] == True]['domain'].tolist()

    if limit:
        featureless = featureless[:limit]

    return featureless


def main():
    parser = argparse.ArgumentParser(description='VirusTotal domain checker')
    parser.add_argument('domain', nargs='?', help='Single domain to check')
    parser.add_argument('--batch', '-b', help='File with domains (one per line)')
    parser.add_argument('--featureless', '-f', action='store_true',
                       help='Check featureless FN domains')
    parser.add_argument('--limit', '-l', type=int, default=50,
                       help='Limit number of domains to check (default: 50)')
    parser.add_argument('--output', '-o', help='Output CSV file')
    parser.add_argument('--delay', '-d', type=float, default=15.5,
                       help='Delay between requests in seconds (default: 15.5)')

    args = parser.parse_args()

    # Get API key
    api_key = get_api_key()
    if not api_key:
        print("Error: VirusTotal API key not found.")
        print("Set VIRUSTOTAL_API_KEY environment variable or create ~/.virustotal_api_key")
        print("\nTo get a free API key:")
        print("1. Create account at https://www.virustotal.com/")
        print("2. Go to your profile -> API key")
        sys.exit(1)

    # Determine domains to check
    domains = []

    if args.domain:
        domains = [args.domain]
    elif args.batch:
        with open(args.batch) as f:
            domains = [line.strip() for line in f if line.strip()]
    elif args.featureless:
        domains = load_featureless_domains(args.limit)
        if not domains:
            sys.exit(1)
    else:
        parser.print_help()
        sys.exit(1)

    # Check domains
    if len(domains) == 1:
        result = check_domain(domains[0], api_key)
        print(json.dumps(result, indent=2))
    else:
        output = args.output or f'vt_results_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
        batch_check(domains, api_key, output, args.delay)


if __name__ == '__main__':
    main()
