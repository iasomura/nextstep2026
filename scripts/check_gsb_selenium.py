#!/usr/bin/env python3
"""
Google Safe Browsing Checker using Selenium
Uses Google Transparency Report to check domain safety status.
"""

import sys
import time
import json
import argparse
import pandas as pd
from pathlib import Path
from datetime import datetime

from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.firefox.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException


def create_driver(headless=True):
    """Create Firefox WebDriver."""
    options = Options()
    if headless:
        options.add_argument('--headless')
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')
    options.set_preference('permissions.default.image', 2)  # Disable images for speed

    try:
        driver = webdriver.Firefox(options=options)
        driver.set_page_load_timeout(30)
        return driver
    except Exception as e:
        print(f"Error creating driver: {e}")
        # Try with geckodriver from webdriver-manager
        from webdriver_manager.firefox import GeckoDriverManager
        service = Service(GeckoDriverManager().install())
        driver = webdriver.Firefox(service=service, options=options)
        driver.set_page_load_timeout(30)
        return driver


def check_domain_gsb(driver, domain, timeout=15):
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
        driver.get(url)

        # Wait for the page to load and results to appear
        wait = WebDriverWait(driver, timeout)

        # Try to find the status text
        # The page structure may vary, so we try multiple selectors
        time.sleep(3)  # Initial wait for JS to execute

        # Get page source for analysis
        page_source = driver.page_source.lower()

        # Check for various indicators in the page
        if 'no unsafe content found' in page_source or 'not currently listed' in page_source:
            result['gsb_status'] = 'safe'
            result['gsb_detail'] = 'No unsafe content found'
        elif 'unsafe' in page_source and ('malware' in page_source or 'phishing' in page_source or 'harmful' in page_source):
            result['gsb_status'] = 'unsafe'
            # Try to get more detail
            if 'phishing' in page_source:
                result['gsb_detail'] = 'Phishing detected'
            elif 'malware' in page_source:
                result['gsb_detail'] = 'Malware detected'
            else:
                result['gsb_detail'] = 'Unsafe content detected'
        elif 'site status' in page_source:
            # Page loaded but status unclear
            result['gsb_status'] = 'unknown'
            result['gsb_detail'] = 'Status unclear from page'
        else:
            result['gsb_status'] = 'unknown'
            result['gsb_detail'] = 'Could not determine status'

        # Try to find specific elements
        try:
            # Look for status elements
            status_elements = driver.find_elements(By.CSS_SELECTOR, '[class*="status"], [class*="result"], [class*="verdict"]')
            for elem in status_elements:
                text = elem.text.lower()
                if 'unsafe' in text or 'dangerous' in text:
                    result['gsb_status'] = 'unsafe'
                    result['gsb_detail'] = elem.text[:100]
                    break
                elif 'safe' in text or 'no unsafe' in text:
                    result['gsb_status'] = 'safe'
                    result['gsb_detail'] = elem.text[:100]
                    break
        except Exception:
            pass

    except TimeoutException:
        result['gsb_status'] = 'error'
        result['gsb_detail'] = 'Page load timeout'
    except WebDriverException as e:
        result['gsb_status'] = 'error'
        result['gsb_detail'] = f'WebDriver error: {str(e)[:50]}'
    except Exception as e:
        result['gsb_status'] = 'error'
        result['gsb_detail'] = f'Error: {str(e)[:50]}'

    return result


def main():
    parser = argparse.ArgumentParser(description='Check domains against Google Safe Browsing')
    parser.add_argument('--input', '-i', required=True, help='Input CSV file with domain column')
    parser.add_argument('--output', '-o', help='Output CSV file (default: input_gsb_results.csv)')
    parser.add_argument('--limit', '-n', type=int, default=0, help='Limit number of domains to check')
    parser.add_argument('--headless', action='store_true', default=True, help='Run in headless mode')
    parser.add_argument('--no-headless', action='store_false', dest='headless', help='Run with visible browser')
    parser.add_argument('--delay', '-d', type=float, default=2.0, help='Delay between checks (seconds)')

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
    print(f"Headless: {args.headless}, Delay: {args.delay}s")

    # Output path
    if args.output:
        output_path = Path(args.output)
    else:
        output_path = input_path.parent / f"{input_path.stem}_gsb_results.csv"

    # Create driver
    print("Starting browser...")
    driver = create_driver(headless=args.headless)

    results = []
    try:
        for i, domain in enumerate(domains):
            print(f"[{i+1}/{len(domains)}] Checking {domain}...", end=' ', flush=True)

            result = check_domain_gsb(driver, domain)
            results.append(result)

            status_icon = {'safe': '✓', 'unsafe': '⚠', 'unknown': '?', 'error': '✗'}.get(result['gsb_status'], '?')
            print(f"[{status_icon}] {result['gsb_status']} - {result['gsb_detail'][:40]}")

            # Delay between requests
            if i < len(domains) - 1:
                time.sleep(args.delay)

    except KeyboardInterrupt:
        print("\nInterrupted by user")
    finally:
        driver.quit()

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
    print(results_df['gsb_status'].value_counts())

    return 0


if __name__ == '__main__':
    sys.exit(main())
