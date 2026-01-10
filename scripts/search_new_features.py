#!/usr/bin/env python3
"""
Feature Exploration Script

Evaluates the impact of adding/removing features on XGBoost performance.
Tests new candidate features derived from certificate and domain data.
"""

import sys
import json
import argparse
import math
from pathlib import Path
from collections import Counter
from datetime import datetime

import numpy as np
import pandas as pd
import joblib
import psycopg2
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import roc_auc_score
import xgboost as xgb

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    char_counts = Counter(text)
    length = len(text)
    entropy = 0.0
    for count in char_counts.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def extract_new_domain_features(domain: str, dangerous_tlds: set = None) -> dict:
    """
    Extract new candidate domain features not in current feature set.
    """
    features = {}

    if not domain:
        return {
            'new_consonant_ratio': 0.0,
            'new_char_diversity': 0.0,
            'new_numeric_ratio': 0.0,
            'new_tld_risk': 0,
            'new_has_numbers_in_sld': 0,
            'new_repeating_chars': 0,
        }

    domain = domain.lower()

    # Consonant ratio (excluding dots and hyphens)
    alpha_chars = [c for c in domain if c.isalpha()]
    consonants = sum(1 for c in alpha_chars if c not in 'aeiou')
    features['new_consonant_ratio'] = consonants / len(alpha_chars) if alpha_chars else 0.0

    # Character diversity (unique chars / total chars)
    features['new_char_diversity'] = len(set(domain)) / len(domain) if domain else 0.0

    # Numeric ratio in SLD (second-level domain)
    parts = domain.split('.')
    sld = parts[-2] if len(parts) >= 2 else domain
    digits_in_sld = sum(c.isdigit() for c in sld)
    features['new_numeric_ratio'] = digits_in_sld / len(sld) if sld else 0.0

    # TLD risk score
    tld = parts[-1] if parts else ''
    if dangerous_tlds:
        features['new_tld_risk'] = 1 if tld in dangerous_tlds else 0
    else:
        # Default dangerous TLDs
        risky_tlds = {'xyz', 'top', 'club', 'online', 'site', 'work', 'click', 'link', 'info', 'buzz'}
        features['new_tld_risk'] = 1 if tld in risky_tlds else 0

    # Has numbers in SLD
    features['new_has_numbers_in_sld'] = 1 if any(c.isdigit() for c in sld) else 0

    # Repeating characters (e.g., "aaa", "111")
    max_repeat = 1
    current_repeat = 1
    for i in range(1, len(domain)):
        if domain[i] == domain[i-1]:
            current_repeat += 1
            max_repeat = max(max_repeat, current_repeat)
        else:
            current_repeat = 1
    features['new_repeating_chars'] = max_repeat

    return features


def extract_new_cert_features(cert_data: bytes, domain: str = None) -> dict:
    """
    Extract new candidate certificate features from raw cert data.
    """
    features = {
        'new_cert_issuer_type': 0,  # 0=unknown, 1=LE, 2=Google, 3=Cloudflare, 4=Commercial
        'new_cert_remaining_days': 0,
        'new_cert_serial_entropy': 0.0,
        'new_cert_has_ext_key_usage': 0,
        'new_cert_has_policies': 0,
        'new_cert_key_bits_normalized': 0.0,
        'new_cert_issuer_country_code': 0,  # 0=unknown, 1=US, 2=other
    }

    if cert_data is None:
        return features

    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.x509.oid import ExtensionOID, NameOID
        from datetime import datetime, timezone

        # Parse certificate
        cert_bytes = bytes(cert_data) if not isinstance(cert_data, bytes) else cert_data

        try:
            cert = x509.load_der_x509_certificate(cert_bytes, default_backend())
        except:
            try:
                cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())
            except:
                return features

        # Issuer type
        issuer_str = str(cert.issuer).lower()
        if "let's encrypt" in issuer_str or 'letsencrypt' in issuer_str:
            features['new_cert_issuer_type'] = 1
        elif 'google' in issuer_str:
            features['new_cert_issuer_type'] = 2
        elif 'cloudflare' in issuer_str:
            features['new_cert_issuer_type'] = 3
        elif any(ca in issuer_str for ca in ['digicert', 'comodo', 'sectigo', 'geotrust', 'thawte']):
            features['new_cert_issuer_type'] = 4

        # Remaining validity days
        try:
            now = datetime.now(timezone.utc)
            remaining = cert.not_valid_after_utc - now
            features['new_cert_remaining_days'] = max(0, remaining.days)
        except:
            pass

        # Serial number entropy
        serial_hex = format(cert.serial_number, 'x')
        features['new_cert_serial_entropy'] = calculate_entropy(serial_hex)

        # Extended Key Usage
        try:
            cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
            features['new_cert_has_ext_key_usage'] = 1
        except:
            pass

        # Certificate Policies
        try:
            cert.extensions.get_extension_for_oid(ExtensionOID.CERTIFICATE_POLICIES)
            features['new_cert_has_policies'] = 1
        except:
            pass

        # Key size normalized (0-1 scale, 2048=0.5, 4096=1.0, 256=0.25 for EC)
        try:
            key_size = cert.public_key().key_size
            if key_size <= 256:  # EC keys
                features['new_cert_key_bits_normalized'] = key_size / 512
            else:  # RSA keys
                features['new_cert_key_bits_normalized'] = min(key_size / 4096, 1.0)
        except:
            pass

        # Issuer country
        try:
            country_attrs = cert.issuer.get_attributes_for_oid(NameOID.COUNTRY_NAME)
            if country_attrs:
                country = country_attrs[0].value.upper()
                features['new_cert_issuer_country_code'] = 1 if country == 'US' else 2
        except:
            pass

    except Exception as e:
        pass

    return features


def load_data_with_certs(artifact_dir: Path, db_config: dict, limit: int = None):
    """
    Load training data and fetch certificate data from database.
    """
    processed_dir = artifact_dir / "processed"

    # Load existing training data
    train_data = joblib.load(processed_dir / "train_data.pkl")
    X = train_data['X']
    y = train_data['y']
    domains = train_data['domains']
    feature_names = train_data['feature_names']

    print(f"Loaded {len(X)} samples with {len(feature_names)} features")

    if limit:
        X = X[:limit]
        y = y[:limit]
        domains = domains[:limit]
        print(f"Limited to {limit} samples for testing")

    # Connect to database and fetch certificate data
    print("Fetching certificate data from database...")
    conn = psycopg2.connect(**db_config)
    cur = conn.cursor()

    # Create domain -> cert_data mapping
    cert_map = {}

    # Fetch from phishtank_entries
    cur.execute("""
        SELECT cert_domain, cert_data
        FROM phishtank_entries
        WHERE cert_data IS NOT NULL AND cert_domain IS NOT NULL
    """)
    for domain, cert_data in cur.fetchall():
        if domain:
            cert_map[domain.lower()] = bytes(cert_data)

    # Fetch from trusted_certificates (if domain info available)
    # Note: May need to join with another table to get domains

    print(f"Found {len(cert_map)} certificates in database")
    conn.close()

    return X, y, domains, feature_names, cert_map


def evaluate_feature_set(X, y, feature_names, n_splits=3):
    """
    Evaluate a feature set using cross-validation.
    """
    from sklearn.model_selection import StratifiedKFold

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42)
    auc_scores = []

    for train_idx, val_idx in skf.split(X_scaled, y):
        X_tr, X_val = X_scaled[train_idx], X_scaled[val_idx]
        y_tr, y_val = y[train_idx], y[val_idx]

        # Split for early stopping
        X_tr2, X_es, y_tr2, y_es = train_test_split(
            X_tr, y_tr, test_size=0.1, random_state=42, stratify=y_tr
        )

        model = xgb.XGBClassifier(
            n_estimators=200,
            max_depth=8,
            learning_rate=0.1,
            random_state=42,
            eval_metric='logloss',
            early_stopping_rounds=20,
            tree_method='hist',
            device='cuda',
            verbosity=0
        )
        model.fit(X_tr2, y_tr2, eval_set=[(X_es, y_es)], verbose=False)

        y_pred = model.predict_proba(X_val)[:, 1]
        auc = roc_auc_score(y_val, y_pred)
        auc_scores.append(auc)

    return np.mean(auc_scores), np.std(auc_scores)


def run_feature_search(artifact_dir: Path, db_config: dict, output_file: Path = None):
    """
    Run feature exploration.
    """
    print("=" * 60)
    print("Feature Exploration")
    print("=" * 60)

    # Load data
    X, y, domains, feature_names, cert_map = load_data_with_certs(
        artifact_dir, db_config, limit=50000  # Limit for faster testing
    )

    # Baseline evaluation
    print("\n" + "-" * 40)
    print("Evaluating baseline (current features)...")
    baseline_auc, baseline_std = evaluate_feature_set(X, y, feature_names)
    print(f"Baseline AUC: {baseline_auc:.4f} (+/- {baseline_std:.4f})")

    results = [{
        'feature_set': 'baseline',
        'n_features': len(feature_names),
        'auc': baseline_auc,
        'std': baseline_std,
        'improvement': 0.0
    }]

    # Extract new features
    print("\n" + "-" * 40)
    print("Extracting new candidate features...")

    new_domain_features = []
    new_cert_features = []

    for i, domain in enumerate(domains):
        if i % 10000 == 0:
            print(f"  Processing {i}/{len(domains)}...")

        # Domain features
        dom_feat = extract_new_domain_features(str(domain))
        new_domain_features.append(dom_feat)

        # Certificate features
        cert_data = cert_map.get(str(domain).lower())
        cert_feat = extract_new_cert_features(cert_data, str(domain))
        new_cert_features.append(cert_feat)

    # Convert to arrays
    domain_feat_names = list(new_domain_features[0].keys())
    cert_feat_names = list(new_cert_features[0].keys())

    X_new_domain = np.array([[f[k] for k in domain_feat_names] for f in new_domain_features])
    X_new_cert = np.array([[f[k] for k in cert_feat_names] for f in new_cert_features])

    print(f"  New domain features: {domain_feat_names}")
    print(f"  New cert features: {cert_feat_names}")

    # Test adding domain features
    print("\n" + "-" * 40)
    print("Testing new domain features...")
    for i, feat_name in enumerate(domain_feat_names):
        X_test = np.hstack([X, X_new_domain[:, i:i+1]])
        test_names = feature_names + [feat_name]
        auc, std = evaluate_feature_set(X_test, y, test_names)
        improvement = auc - baseline_auc
        print(f"  +{feat_name}: AUC={auc:.4f} (change: {improvement:+.4f})")
        results.append({
            'feature_set': f'+{feat_name}',
            'n_features': len(test_names),
            'auc': auc,
            'std': std,
            'improvement': improvement
        })

    # Test adding cert features
    print("\n" + "-" * 40)
    print("Testing new certificate features...")
    for i, feat_name in enumerate(cert_feat_names):
        X_test = np.hstack([X, X_new_cert[:, i:i+1]])
        test_names = feature_names + [feat_name]
        auc, std = evaluate_feature_set(X_test, y, test_names)
        improvement = auc - baseline_auc
        print(f"  +{feat_name}: AUC={auc:.4f} (change: {improvement:+.4f})")
        results.append({
            'feature_set': f'+{feat_name}',
            'n_features': len(test_names),
            'auc': auc,
            'std': std,
            'improvement': improvement
        })

    # Test adding all new features
    print("\n" + "-" * 40)
    print("Testing all new features combined...")
    X_all_new = np.hstack([X, X_new_domain, X_new_cert])
    all_names = feature_names + domain_feat_names + cert_feat_names
    auc, std = evaluate_feature_set(X_all_new, y, all_names)
    improvement = auc - baseline_auc
    print(f"  All new features: AUC={auc:.4f} (change: {improvement:+.4f})")
    results.append({
        'feature_set': 'all_new',
        'n_features': len(all_names),
        'auc': auc,
        'std': std,
        'improvement': improvement
    })

    # Test removing low-importance features
    print("\n" + "-" * 40)
    print("Testing removal of low-importance features...")
    low_importance = [
        'subdomain_count', 'non_alphanumeric_count', 'cert_san_dns_count',
        'cert_sig_algo_weak', 'cert_san_ip_count', 'cert_san_matches_etld1',
        'cert_is_self_signed', 'cert_key_type_code'
    ]
    keep_idx = [i for i, name in enumerate(feature_names) if name not in low_importance]
    X_reduced = X[:, keep_idx]
    reduced_names = [feature_names[i] for i in keep_idx]
    auc, std = evaluate_feature_set(X_reduced, y, reduced_names)
    improvement = auc - baseline_auc
    print(f"  Removed {len(low_importance)} low-importance: AUC={auc:.4f} (change: {improvement:+.4f})")
    results.append({
        'feature_set': 'remove_low_importance',
        'n_features': len(reduced_names),
        'auc': auc,
        'std': std,
        'improvement': improvement
    })

    # Summary
    print("\n" + "=" * 60)
    print("RESULTS SUMMARY")
    print("=" * 60)

    # Sort by improvement
    results_sorted = sorted(results, key=lambda x: x['improvement'], reverse=True)

    print("\nTop improvements:")
    for r in results_sorted[:10]:
        print(f"  {r['feature_set']:30} AUC={r['auc']:.4f} ({r['improvement']:+.4f})")

    # Save results
    if output_file:
        with open(output_file, 'w') as f:
            json.dump({
                'timestamp': datetime.now().isoformat(),
                'baseline_auc': baseline_auc,
                'results': results_sorted
            }, f, indent=2)
        print(f"\nResults saved to: {output_file}")

    return results_sorted


def main():
    parser = argparse.ArgumentParser(description='Search for new features')
    parser.add_argument('--artifact-dir', type=str, required=True,
                        help='Path to artifact directory')
    parser.add_argument('--output', type=str, default=None,
                        help='Output JSON file for results')

    args = parser.parse_args()

    artifact_dir = Path(args.artifact_dir)
    output_file = Path(args.output) if args.output else None

    # Database config
    db_config = {
        'host': 'localhost',
        'port': 5432,
        'dbname': 'rapids_data',
        'user': 'postgres',
        'password': 'asomura'
    }

    results = run_feature_search(artifact_dir, db_config, output_file)

    return results


if __name__ == '__main__':
    main()
