#!/usr/bin/env python3
"""
URLScan.io API を使用してドメインのフィッシング判定を確認する

Usage:
    python scripts/check_urlscan.py --input domains.csv --output results.csv --api-key YOUR_KEY

    # FNドメインをチェック
    python scripts/check_urlscan.py \
        --input docs/analysis/fn_gsb_verification/stage1_fn_for_gsb_check.csv \
        --output docs/analysis/fn_gsb_verification/fn_urlscan_results.csv \
        --api-key YOUR_API_KEY
"""

import argparse
import csv
import time
import requests
from datetime import datetime
from pathlib import Path


def search_domain(domain: str, api_key: str) -> dict:
    """
    URLScan.io で既存のスキャン結果を検索

    Returns:
        dict with keys: found, malicious, verdict, scan_date, url
    """
    url = "https://urlscan.io/api/v1/search/"
    headers = {"API-Key": api_key}
    params = {
        "q": f"domain:{domain}",
        "size": 10  # 最新10件を取得
    }

    try:
        response = requests.get(url, headers=headers, params=params, timeout=30)

        if response.status_code == 429:
            # Rate limited
            return {"found": False, "status": "rate_limited", "error": "Rate limit exceeded"}

        if response.status_code != 200:
            return {"found": False, "status": "error", "error": f"HTTP {response.status_code}"}

        data = response.json()
        results = data.get("results", [])

        if not results:
            return {"found": False, "status": "not_found"}

        # 最新のスキャン結果を確認
        malicious_count = 0
        verdicts = []
        latest_scan = None

        for result in results:
            verdict_info = result.get("verdicts", {})
            overall = verdict_info.get("overall", {})

            if overall.get("malicious", False):
                malicious_count += 1

            # Collect verdict categories
            categories = overall.get("categories", [])
            if categories:
                verdicts.extend(categories)

            # Get latest scan info
            if latest_scan is None:
                latest_scan = result

        # Determine overall status
        is_malicious = malicious_count > 0
        unique_verdicts = list(set(verdicts))

        return {
            "found": True,
            "status": "malicious" if is_malicious else "safe",
            "malicious_scans": malicious_count,
            "total_scans": len(results),
            "verdicts": ",".join(unique_verdicts) if unique_verdicts else "",
            "latest_scan_date": latest_scan.get("task", {}).get("time", "") if latest_scan else "",
            "latest_scan_url": latest_scan.get("result", "") if latest_scan else ""
        }

    except requests.exceptions.Timeout:
        return {"found": False, "status": "timeout", "error": "Request timeout"}
    except Exception as e:
        return {"found": False, "status": "error", "error": str(e)}


def check_domains(input_file: str, output_file: str, api_key: str,
                  domain_column: str = "domain", delay: float = 1.0,
                  limit: int = None):
    """
    CSVファイルからドメインを読み込み、URLScan.ioでチェック
    """
    # Read input
    domains_data = []
    with open(input_file, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            domains_data.append(row)

    if limit:
        domains_data = domains_data[:limit]

    total = len(domains_data)
    print(f"Checking {total} domains against URLScan.io...")
    print(f"API Key: {api_key[:8]}...{api_key[-4:]}")
    print(f"Delay: {delay}s between requests")
    print()

    results = []
    stats = {"found": 0, "not_found": 0, "malicious": 0, "safe": 0, "error": 0}

    for i, row in enumerate(domains_data, 1):
        domain = row.get(domain_column, "").strip()
        if not domain:
            continue

        # Search URLScan.io
        result = search_domain(domain, api_key)

        # Update stats
        if result.get("found"):
            stats["found"] += 1
            if result.get("status") == "malicious":
                stats["malicious"] += 1
                icon = "⚠"
            else:
                stats["safe"] += 1
                icon = "✓"
        elif result.get("status") == "not_found":
            stats["not_found"] += 1
            icon = "?"
        else:
            stats["error"] += 1
            icon = "✗"

        # Print progress
        status_str = result.get("status", "unknown")
        verdicts = result.get("verdicts", "")
        print(f"[{i}/{total}] {domain}: [{icon}] {status_str}" +
              (f" - {verdicts}" if verdicts else ""))

        # Combine original data with results
        combined = {**row}
        combined["urlscan_status"] = result.get("status", "")
        combined["urlscan_found"] = result.get("found", False)
        combined["urlscan_malicious_scans"] = result.get("malicious_scans", 0)
        combined["urlscan_total_scans"] = result.get("total_scans", 0)
        combined["urlscan_verdicts"] = result.get("verdicts", "")
        combined["urlscan_latest_date"] = result.get("latest_scan_date", "")
        combined["urlscan_checked_at"] = datetime.now().isoformat()

        results.append(combined)

        # Rate limiting
        if i < total:
            time.sleep(delay)

    # Save results
    if results:
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        fieldnames = list(results[0].keys())
        with open(output_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(results)

        print(f"\nSaved results to: {output_file}")

    # Print summary
    print("\n" + "=" * 60)
    print("URLScan.io Check Summary")
    print("=" * 60)
    print(f"  Total checked: {total}")
    print(f"  Found in URLScan: {stats['found']} ({100*stats['found']/total:.1f}%)")
    print(f"    - Malicious: {stats['malicious']}")
    print(f"    - Safe: {stats['safe']}")
    print(f"  Not found: {stats['not_found']} ({100*stats['not_found']/total:.1f}%)")
    print(f"  Errors: {stats['error']}")

    return results


def main():
    parser = argparse.ArgumentParser(description="Check domains against URLScan.io")
    parser.add_argument("--input", required=True, help="Input CSV file with domains")
    parser.add_argument("--output", required=True, help="Output CSV file for results")
    parser.add_argument("--api-key", required=True, help="URLScan.io API key")
    parser.add_argument("--domain-column", default="domain", help="Column name for domain")
    parser.add_argument("--delay", type=float, default=1.0, help="Delay between requests (seconds)")
    parser.add_argument("--limit", type=int, help="Limit number of domains to check")

    args = parser.parse_args()

    check_domains(
        input_file=args.input,
        output_file=args.output,
        api_key=args.api_key,
        domain_column=args.domain_column,
        delay=args.delay,
        limit=args.limit
    )


if __name__ == "__main__":
    main()
