#!/usr/bin/env python3
"""
Google Safe Browsing Checker using Playwright
Uses Google Transparency Report to check domain safety status.
"""

import sys
import time
import argparse
import pandas as pd
from pathlib import Path
from datetime import datetime

from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout


def check_domain_gsb(page, domain, timeout=15000):
    """
    Check a domain against Google Safe Browsing via Transparency Report.

    Returns:
        dict: {
            'domain': str,
            'gsb_status': 'unsafe'|'safe'|'unknown'|'error',
            'gsb_detail': str,
            'checked_at': str
        }
    """
    url = f"https://transparencyreport.google.com/safe-browsing/search?url=https%3A%2F%2F{domain}%2F"

    result = {
        'domain': domain,
        'gsb_status': 'unknown',
        'gsb_detail': '',
        'checked_at': datetime.now().isoformat()
    }

    try:
        # Navigate to page
        page.goto(url, timeout=timeout, wait_until='networkidle')

        # Wait for content to load
        page.wait_for_timeout(3000)  # Additional wait for JS rendering

        # Get page content
        content = page.content().lower()

        # Check for various status indicators
        # Google Transparency Report uses specific text patterns
        if 'no unsafe content found' in content:
            result['gsb_status'] = 'safe'
            result['gsb_detail'] = 'No unsafe content found'
        elif 'currently listed as' in content and 'dangerous' in content:
            result['gsb_status'] = 'unsafe'
            result['gsb_detail'] = 'Listed as dangerous'
        elif 'partially dangerous' in content:
            result['gsb_status'] = 'unsafe'
            result['gsb_detail'] = 'Partially dangerous'
        elif 'some pages on this site' in content and 'unsafe' in content:
            result['gsb_status'] = 'unsafe'
            result['gsb_detail'] = 'Some pages unsafe'
        elif 'not currently listed' in content or 'no data' in content:
            result['gsb_status'] = 'safe'
            result['gsb_detail'] = 'Not currently listed as dangerous'
        else:
            # Try to find specific elements
            try:
                # Wait for the result card to appear
                page.wait_for_selector('text=/safe|unsafe|dangerous|no data/i', timeout=5000)

                # Get visible text
                body_text = page.inner_text('body').lower()

                if 'no unsafe content found' in body_text or 'not dangerous' in body_text:
                    result['gsb_status'] = 'safe'
                    result['gsb_detail'] = 'No unsafe content found'
                elif 'dangerous' in body_text or 'unsafe' in body_text:
                    result['gsb_status'] = 'unsafe'
                    result['gsb_detail'] = 'Marked as dangerous/unsafe'
                else:
                    result['gsb_status'] = 'unknown'
                    result['gsb_detail'] = 'Could not determine status'
            except PlaywrightTimeout:
                result['gsb_status'] = 'unknown'
                result['gsb_detail'] = 'Status element not found'

    except PlaywrightTimeout:
        result['gsb_status'] = 'error'
        result['gsb_detail'] = 'Page load timeout'
    except Exception as e:
        result['gsb_status'] = 'error'
        result['gsb_detail'] = f'Error: {str(e)[:50]}'

    return result


def main():
    parser = argparse.ArgumentParser(description='Check domains against Google Safe Browsing using Playwright')
    parser.add_argument('--input', '-i', required=True, help='Input CSV file with domain column')
    parser.add_argument('--output', '-o', help='Output CSV file')
    parser.add_argument('--limit', '-n', type=int, default=0, help='Limit number of domains to check')
    parser.add_argument('--delay', '-d', type=float, default=2.0, help='Delay between checks (seconds)')
    parser.add_argument('--headed', action='store_true', help='Run with visible browser')

    args = parser.parse_args()

    # Load input
    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: Input file not found: {input_path}")
        sys.exit(1)

    df = pd.read_csv(input_path)
    if 'domain' not in df.columns:
        print("Error: Input CSV must have 'domain' column")
        sys.exit(1)

    domains = df['domain'].tolist()
    if args.limit > 0:
        domains = domains[:args.limit]

    print(f"Checking {len(domains)} domains against Google Safe Browsing...")
    print(f"Headless: {not args.headed}, Delay: {args.delay}s")

    # Output path
    if args.output:
        output_path = Path(args.output)
    else:
        output_path = input_path.parent / f"{input_path.stem}_gsb_results.csv"

    results = []

    with sync_playwright() as p:
        print("Starting browser...")
        browser = p.chromium.launch(headless=not args.headed)
        context = browser.new_context(
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        )
        page = context.new_page()

        try:
            for i, domain in enumerate(domains):
                print(f"[{i+1}/{len(domains)}] Checking {domain}...", end=' ', flush=True)

                result = check_domain_gsb(page, domain)
                results.append(result)

                status_icon = {'safe': '✓', 'unsafe': '⚠', 'unknown': '?', 'error': '✗'}.get(result['gsb_status'], '?')
                print(f"[{status_icon}] {result['gsb_status']} - {result['gsb_detail'][:40]}")

                # Delay between requests
                if i < len(domains) - 1:
                    time.sleep(args.delay)

        except KeyboardInterrupt:
            print("\nInterrupted by user")
        finally:
            browser.close()

    # Save results
    results_df = pd.DataFrame(results)

    # Merge with original data
    merged_df = df.head(len(results)).copy()
    merged_df['gsb_status'] = results_df['gsb_status'].values
    merged_df['gsb_detail'] = results_df['gsb_detail'].values
    merged_df['gsb_checked_at'] = results_df['checked_at'].values

    merged_df.to_csv(output_path, index=False)
    print(f"\nSaved results to: {output_path}")

    # Summary
    print("\n=== Summary ===")
    print(merged_df['gsb_status'].value_counts())

    # Show unsafe domains
    unsafe = merged_df[merged_df['gsb_status'] == 'unsafe']
    if len(unsafe) > 0:
        print(f"\n=== Unsafe Domains ({len(unsafe)}) ===")
        for _, row in unsafe.iterrows():
            print(f"  ⚠ {row['domain']}: {row['gsb_detail']}")

    return 0


if __name__ == '__main__':
    sys.exit(main())
