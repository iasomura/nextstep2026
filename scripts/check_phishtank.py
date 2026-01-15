#!/usr/bin/env python3
"""
PhishTank API を使用してURLがフィッシングデータベースに存在するか確認する

Usage:
    python scripts/check_phishtank.py --input domains.csv --output results.csv
"""

import argparse
import csv
import time
import requests
import base64
from datetime import datetime
from pathlib import Path


def check_url_phishtank(domain: str, app_key: str = None) -> dict:
    """
    PhishTank APIでURLをチェック

    Returns:
        dict with status info
    """
    url = "https://checkurl.phishtank.com/checkurl/"

    # URLを構築（http://をつける）
    check_url = f"http://{domain}/"

    headers = {
        "User-Agent": "phishtank/research_project"
    }

    data = {
        "url": base64.b64encode(check_url.encode()).decode(),
        "format": "json"
    }

    if app_key:
        data["app_key"] = app_key

    try:
        response = requests.post(url, data=data, headers=headers, timeout=30)

        if response.status_code == 509:
            return {"status": "rate_limited", "error": "Rate limit exceeded"}

        if response.status_code != 200:
            return {"status": "error", "error": f"HTTP {response.status_code}"}

        result = response.json()
        results = result.get("results", {})

        in_database = results.get("in_database", False)

        if in_database:
            phish_detail = results.get("phish_detail_page", "")
            verified = results.get("verified", False)
            valid = results.get("valid", False)

            if valid:
                status = "phishing_valid"
            elif verified:
                status = "phishing_verified"
            else:
                status = "phishing_unverified"

            return {
                "status": status,
                "in_database": True,
                "verified": verified,
                "valid": valid,
                "detail_url": phish_detail
            }
        else:
            return {
                "status": "not_in_database",
                "in_database": False
            }

    except requests.exceptions.Timeout:
        return {"status": "timeout", "error": "Request timeout"}
    except Exception as e:
        return {"status": "error", "error": str(e)}


def check_domains(input_file: str, output_file: str, app_key: str = None,
                  domain_column: str = "domain", delay: float = 2.0,
                  limit: int = None):
    """
    CSVファイルからドメインを読み込み、PhishTankでチェック
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
    print(f"Checking {total} domains against PhishTank...")
    print(f"Delay: {delay}s between requests")
    print()

    results = []
    stats = {
        "phishing_valid": 0,
        "phishing_verified": 0,
        "phishing_unverified": 0,
        "not_in_database": 0,
        "error": 0
    }

    for i, row in enumerate(domains_data, 1):
        domain = row.get(domain_column, "").strip()
        if not domain:
            continue

        result = check_url_phishtank(domain, app_key)
        status = result.get("status", "unknown")

        if status in stats:
            stats[status] += 1
        else:
            stats["error"] += 1

        # Icon
        if "phishing" in status:
            icon = "⚠"
        elif status == "not_in_database":
            icon = "✓"
        else:
            icon = "?"

        print(f"[{i}/{total}] {domain}: [{icon}] {status}")

        # Combine results
        combined = {**row}
        combined["phishtank_status"] = status
        combined["phishtank_in_database"] = result.get("in_database", False)
        combined["phishtank_verified"] = result.get("verified", False)
        combined["phishtank_valid"] = result.get("valid", False)
        combined["phishtank_checked_at"] = datetime.now().isoformat()

        results.append(combined)

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

    # Summary
    print("\n" + "=" * 60)
    print("PhishTank Check Summary")
    print("=" * 60)
    print(f"  Total checked: {total}")
    print(f"  Phishing (valid): {stats['phishing_valid']}")
    print(f"  Phishing (verified): {stats['phishing_verified']}")
    print(f"  Phishing (unverified): {stats['phishing_unverified']}")
    print(f"  Not in database: {stats['not_in_database']}")
    print(f"  Errors: {stats['error']}")

    return results


def main():
    parser = argparse.ArgumentParser(description="Check domains against PhishTank")
    parser.add_argument("--input", required=True, help="Input CSV file")
    parser.add_argument("--output", required=True, help="Output CSV file")
    parser.add_argument("--app-key", help="PhishTank API key (optional)")
    parser.add_argument("--domain-column", default="domain", help="Column name for domain")
    parser.add_argument("--delay", type=float, default=2.0, help="Delay between requests")
    parser.add_argument("--limit", type=int, help="Limit number of domains")

    args = parser.parse_args()

    check_domains(
        input_file=args.input,
        output_file=args.output,
        app_key=args.app_key,
        domain_column=args.domain_column,
        delay=args.delay,
        limit=args.limit
    )


if __name__ == "__main__":
    main()
