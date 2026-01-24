#!/usr/bin/env python3
"""
VirusTotal Batch Investigation Script

Features:
- Multiple API keys support for parallel processing
- Incremental saving after each result
- Resume capability after server restart
- Progress tracking and ETA estimation

Usage:
    # Single API key (from file or env)
    python scripts/vt_batch_investigation.py

    # Multiple API keys for parallel processing
    python scripts/vt_batch_investigation.py --keys key1,key2,key3

    # Specify input/output files
    python scripts/vt_batch_investigation.py \
        --input artifacts/.../stage1_fp_fn_domains.csv \
        --output artifacts/.../vt_investigation_results.csv

    # Resume from checkpoint
    python scripts/vt_batch_investigation.py --resume

Author: AI Assistant
Date: 2026-01-20
"""

import os
import sys
import time
import json
import argparse
import requests
import threading
import queue
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import csv

# Try to load from .env
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


# ============================================================================
# Configuration
# ============================================================================
VT_API_URL = "https://www.virustotal.com/api/v3/domains/{domain}"
VT_RATE_LIMIT_DELAY = 15.5  # seconds between requests (4 req/min limit)
VT_DAILY_LIMIT = 500  # requests per day per key (free tier)
DEFAULT_INPUT = "artifacts/2026-01-17_132657/results/stage1_fp_fn_domains.csv"
DEFAULT_OUTPUT = "artifacts/2026-01-17_132657/results/vt_investigation_results.csv"
CHECKPOINT_FILE = "artifacts/2026-01-17_132657/results/vt_investigation_checkpoint.json"


# ============================================================================
# API Key Management
# ============================================================================
def load_api_keys(keys_arg: Optional[str] = None) -> List[str]:
    """
    Load API keys from multiple sources.
    Priority: command line > env var > key file
    """
    keys = []

    # 1. From command line argument
    if keys_arg:
        keys.extend([k.strip() for k in keys_arg.split(',') if k.strip()])

    # 2. From environment variable (comma-separated)
    env_keys = os.environ.get('VIRUSTOTAL_API_KEYS', '')
    if env_keys:
        keys.extend([k.strip() for k in env_keys.split(',') if k.strip()])

    # 3. From single key env var
    single_key = os.environ.get('VIRUSTOTAL_API_KEY', '')
    if single_key and single_key not in keys:
        keys.append(single_key)

    # 4. From key file (one key per line)
    key_files = [
        Path(__file__).parent.parent / 'docs' / 'virustotal_api_keys.txt',
        Path(__file__).parent.parent / 'docs' / 'virustotal_api_key.txt',
        Path.home() / '.virustotal_api_keys',
        Path.home() / '.virustotal_api_key',
    ]

    for key_file in key_files:
        if key_file.exists():
            with open(key_file) as f:
                for line in f:
                    key = line.strip()
                    if key and not key.startswith('#') and key not in keys:
                        keys.append(key)

    # Remove duplicates while preserving order
    seen = set()
    unique_keys = []
    for k in keys:
        if k not in seen:
            seen.add(k)
            unique_keys.append(k)

    return unique_keys


# ============================================================================
# VirusTotal API
# ============================================================================
def check_domain(domain: str, api_key: str) -> Dict:
    """Check a single domain against VirusTotal."""
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
            stats = attrs.get('last_analysis_stats', {})

            return {
                'domain': domain,
                'status': 'found',
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'harmless': stats.get('harmless', 0),
                'undetected': stats.get('undetected', 0),
                'reputation': attrs.get('reputation', 0),
                'categories': json.dumps(attrs.get('categories', {})),
                'last_analysis_date': attrs.get('last_analysis_date', ''),
                'error': None,
                'checked_at': datetime.now().isoformat()
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
                'categories': '{}',
                'last_analysis_date': '',
                'error': None,
                'checked_at': datetime.now().isoformat()
            }
        elif response.status_code == 429:
            return {
                'domain': domain,
                'status': 'rate_limited',
                'error': 'Rate limit exceeded',
                'checked_at': datetime.now().isoformat()
            }
        else:
            return {
                'domain': domain,
                'status': 'error',
                'error': f'HTTP {response.status_code}',
                'checked_at': datetime.now().isoformat()
            }

    except Exception as e:
        return {
            'domain': domain,
            'status': 'error',
            'error': str(e),
            'checked_at': datetime.now().isoformat()
        }


# ============================================================================
# Checkpoint Management
# ============================================================================
def load_checkpoint(checkpoint_file: str) -> Dict:
    """Load checkpoint from file."""
    path = Path(checkpoint_file)
    if path.exists():
        with open(path) as f:
            return json.load(f)
    return {'checked_domains': [], 'start_time': None}


def save_checkpoint(checkpoint_file: str, checked_domains: List[str], start_time: str):
    """Save checkpoint to file (atomic write for crash safety)."""
    path = Path(checkpoint_file)
    path.parent.mkdir(parents=True, exist_ok=True)

    checkpoint = {
        'checked_domains': checked_domains,
        'start_time': start_time,
        'last_update': datetime.now().isoformat(),
        'count': len(checked_domains)
    }

    # Write to temp file first, then rename (atomic operation)
    temp_path = path.with_suffix('.tmp')
    with open(temp_path, 'w') as f:
        json.dump(checkpoint, f, indent=2)
        f.flush()
        os.fsync(f.fileno())

    # Atomic rename
    temp_path.rename(path)


def load_existing_results(output_file: str) -> set:
    """Load already checked domains from existing results file."""
    checked = set()
    path = Path(output_file)

    if path.exists():
        try:
            with open(path, 'r', newline='') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if row.get('domain'):
                        checked.add(row['domain'])
        except Exception as e:
            print(f"[WARN] Error reading results file (may be corrupted): {e}")
            print(f"[WARN] Will try to recover from checkpoint instead.")
            # Try to recover by reading line by line
            try:
                with open(path, 'r') as f:
                    lines = f.readlines()
                    if len(lines) > 1:  # Has header + some data
                        for line in lines[1:]:  # Skip header
                            parts = line.strip().split(',')
                            if parts and parts[0]:
                                checked.add(parts[0])
                print(f"[INFO] Recovered {len(checked)} domains from partial file.")
            except Exception as e2:
                print(f"[WARN] Could not recover: {e2}")

    return checked


# ============================================================================
# Result Writer (Thread-safe)
# ============================================================================
class ResultWriter:
    """Thread-safe CSV writer with incremental saving."""

    def __init__(self, output_file: str):
        self.output_file = output_file
        self.lock = threading.Lock()
        self.fieldnames = [
            'domain', 'error_type', 'ml_probability', 'source', 'y_true',
            'status', 'malicious', 'suspicious', 'harmless', 'undetected',
            'reputation', 'categories', 'last_analysis_date', 'error', 'checked_at'
        ]
        self._init_file()

    def _init_file(self):
        """Initialize CSV file with headers if it doesn't exist."""
        path = Path(self.output_file)
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=self.fieldnames)
                writer.writeheader()

    def write_result(self, result: Dict, domain_info: Dict):
        """Write a single result to CSV (thread-safe, with flush for crash safety)."""
        with self.lock:
            row = {**domain_info, **result}
            with open(self.output_file, 'a', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=self.fieldnames)
                writer.writerow({k: row.get(k, '') for k in self.fieldnames})
                f.flush()  # Flush to OS buffer
                os.fsync(f.fileno())  # Force write to disk


# ============================================================================
# Worker Thread
# ============================================================================
class VTWorker(threading.Thread):
    """Worker thread for VirusTotal API calls."""

    def __init__(self, worker_id: int, api_key: str, task_queue: queue.Queue,
                 result_writer: ResultWriter, checkpoint_file: str,
                 checked_domains: List[str], lock: threading.Lock,
                 stats: Dict, daily_limit: int = VT_DAILY_LIMIT):
        super().__init__(daemon=True)
        self.worker_id = worker_id
        self.api_key = api_key
        self.task_queue = task_queue
        self.result_writer = result_writer
        self.checkpoint_file = checkpoint_file
        self.checked_domains = checked_domains
        self.lock = lock
        self.stats = stats
        self.daily_limit = daily_limit
        self.daily_count = 0
        self.running = True

    def run(self):
        while self.running:
            try:
                # Check daily limit
                if self.daily_count >= self.daily_limit:
                    print(f"[Worker {self.worker_id}] Daily limit reached ({self.daily_limit}). Stopping.")
                    # Put remaining tasks back (if any) for other workers or next run
                    break

                # Get task with timeout
                task = self.task_queue.get(timeout=1)
                if task is None:  # Poison pill
                    break

                domain, domain_info = task

                # Check domain
                result = check_domain(domain, self.api_key)
                self.daily_count += 1

                # Handle rate limiting
                if result['status'] == 'rate_limited':
                    print(f"[Worker {self.worker_id}] Rate limited, waiting 60s...")
                    time.sleep(60)
                    result = check_domain(domain, self.api_key)

                # Write result
                self.result_writer.write_result(result, domain_info)

                # Update checkpoint (save after EVERY domain for crash safety)
                with self.lock:
                    self.checked_domains.append(domain)
                    self.stats['completed'] += 1

                    # Save checkpoint after every domain for crash safety
                    save_checkpoint(
                        self.checkpoint_file,
                        self.checked_domains,
                        self.stats['start_time']
                    )

                # Print progress
                self._print_progress(domain, result)

                # Rate limiting
                time.sleep(VT_RATE_LIMIT_DELAY)

                self.task_queue.task_done()

            except queue.Empty:
                continue
            except Exception as e:
                print(f"[Worker {self.worker_id}] Error: {e}")

    def _print_progress(self, domain: str, result: Dict):
        completed = self.stats['completed']
        total = self.stats['total']
        elapsed = time.time() - self.stats['start_timestamp']

        if completed > 0:
            rate = completed / elapsed  # domains per second
            remaining = total - completed
            eta_seconds = remaining / rate if rate > 0 else 0
            eta = str(timedelta(seconds=int(eta_seconds)))
        else:
            eta = "calculating..."

        status = result.get('status', 'unknown')
        mal = result.get('malicious', 0)
        sus = result.get('suspicious', 0)

        print(f"[{completed}/{total}] [W{self.worker_id}] {domain}: "
              f"mal={mal}, sus={sus} | ETA: {eta}")

    def stop(self):
        self.running = False


# ============================================================================
# Main Investigation
# ============================================================================
def run_investigation(input_file: str, output_file: str, checkpoint_file: str,
                      api_keys: List[str], resume: bool = True,
                      daily_limit: int = VT_DAILY_LIMIT):
    """Run the VirusTotal investigation with multiple workers."""

    print("=" * 70)
    print("VirusTotal Batch Investigation")
    print("=" * 70)

    # Load input domains
    import pandas as pd
    df = pd.read_csv(input_file)
    total_domains = len(df)
    print(f"Total domains to check: {total_domains}")

    # Load already checked domains
    checked_set = set()
    if resume:
        checked_set = load_existing_results(output_file)
        checkpoint = load_checkpoint(checkpoint_file)
        checked_set.update(checkpoint.get('checked_domains', []))
        print(f"Already checked (resuming): {len(checked_set)}")

    # Filter out already checked
    remaining = df[~df['domain'].isin(checked_set)]
    print(f"Remaining to check: {len(remaining)}")

    if len(remaining) == 0:
        print("All domains already checked!")
        return

    # Setup workers
    num_workers = len(api_keys)
    daily_capacity = num_workers * daily_limit
    estimated_days = (len(remaining) + daily_capacity - 1) // daily_capacity  # ceiling division

    print(f"API keys available: {num_workers}")
    print(f"Daily capacity: {daily_capacity} domains/day ({daily_limit}/key)")
    print(f"Estimated days: {estimated_days} days")
    print()

    # Initialize
    task_queue = queue.Queue()
    result_writer = ResultWriter(output_file)
    checked_domains = list(checked_set)
    lock = threading.Lock()
    stats = {
        'completed': 0,
        'total': len(remaining),
        'start_time': datetime.now().isoformat(),
        'start_timestamp': time.time()
    }

    # Create workers
    workers = []
    for i, key in enumerate(api_keys):
        worker = VTWorker(
            worker_id=i,
            api_key=key,
            task_queue=task_queue,
            result_writer=result_writer,
            checkpoint_file=checkpoint_file,
            checked_domains=checked_domains,
            lock=lock,
            stats=stats,
            daily_limit=daily_limit
        )
        workers.append(worker)
        worker.start()

    # Add tasks to queue
    for _, row in remaining.iterrows():
        domain_info = {
            'domain': row['domain'],
            'error_type': row.get('error_type', ''),
            'ml_probability': row.get('ml_probability', ''),
            'source': row.get('source', ''),
            'y_true': row.get('y_true', '')
        }
        task_queue.put((row['domain'], domain_info))

    # Add poison pills to stop workers
    for _ in workers:
        task_queue.put(None)

    # Wait for completion
    try:
        for worker in workers:
            worker.join()
    except KeyboardInterrupt:
        print("\n\nInterrupted! Saving checkpoint...")
        for worker in workers:
            worker.stop()
        save_checkpoint(checkpoint_file, checked_domains, stats['start_time'])
        print(f"Checkpoint saved. Checked {len(checked_domains)} domains.")
        print(f"Run again with --resume to continue.")
        sys.exit(1)

    # Final checkpoint
    save_checkpoint(checkpoint_file, checked_domains, stats['start_time'])

    # Summary
    print()
    print("=" * 70)
    print("Investigation Complete!")
    print("=" * 70)
    print(f"Total checked: {stats['completed']}")
    print(f"Results saved to: {output_file}")
    print(f"Checkpoint saved to: {checkpoint_file}")


# ============================================================================
# Main
# ============================================================================
def main():
    parser = argparse.ArgumentParser(
        description='VirusTotal Batch Investigation (Parallel & Resumable)',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('--input', '-i', default=DEFAULT_INPUT,
                       help=f'Input CSV file (default: {DEFAULT_INPUT})')
    parser.add_argument('--output', '-o', default=DEFAULT_OUTPUT,
                       help=f'Output CSV file (default: {DEFAULT_OUTPUT})')
    parser.add_argument('--checkpoint', '-c', default=CHECKPOINT_FILE,
                       help=f'Checkpoint file (default: {CHECKPOINT_FILE})')
    parser.add_argument('--keys', '-k',
                       help='Comma-separated API keys for parallel processing')
    parser.add_argument('--resume', '-r', action='store_true', default=True,
                       help='Resume from checkpoint (default: True)')
    parser.add_argument('--no-resume', action='store_true',
                       help='Start fresh, ignore existing results')
    parser.add_argument('--daily-limit', '-d', type=int, default=VT_DAILY_LIMIT,
                       help=f'Daily limit per API key (default: {VT_DAILY_LIMIT})')

    args = parser.parse_args()

    # Load API keys
    api_keys = load_api_keys(args.keys)

    if not api_keys:
        print("Error: No VirusTotal API keys found.")
        print("\nTo configure API keys:")
        print("  1. Set VIRUSTOTAL_API_KEY environment variable")
        print("  2. Create docs/virustotal_api_key.txt (one key per line)")
        print("  3. Use --keys key1,key2,key3 command line argument")
        sys.exit(1)

    print(f"Loaded {len(api_keys)} API key(s)")

    # Run investigation
    run_investigation(
        input_file=args.input,
        output_file=args.output,
        checkpoint_file=args.checkpoint,
        api_keys=api_keys,
        resume=not args.no_resume,
        daily_limit=args.daily_limit
    )


if __name__ == '__main__':
    main()
