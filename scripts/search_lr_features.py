#!/usr/bin/env python3
"""
Stage2 LR Feature Search Script

Automatically search for the best feature combination for Stage2 LR model.
Evaluates different feature sets and finds the one that minimizes DEFER count
while keeping AUTO error rate below a threshold.
"""

import sys
import json
import argparse
import itertools
from pathlib import Path

import numpy as np
import pandas as pd
import joblib
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import StratifiedKFold

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))


def load_data(artifact_dir: Path):
    """Load training data from artifacts."""
    # Load XGB model and scaler
    models_dir = artifact_dir / "models"
    processed_dir = artifact_dir / "processed"

    xgb_model = joblib.load(models_dir / "xgboost_model.pkl")
    xgb_scaler = joblib.load(models_dir / "scaler.pkl")

    # Load training data
    # Structure: {'X', 'y', 'domains', 'sources', 'tlds', 'feature_names'}
    train_data = joblib.load(processed_dir / "train_data.pkl")

    X_train = train_data['X']
    y_train = train_data['y']
    feature_names = train_data.get('feature_names', [])

    # Load brand keywords
    with open(models_dir / "brand_keywords.json", "r") as f:
        brand_keywords = json.load(f)

    return X_train, y_train, feature_names, xgb_model, xgb_scaler, brand_keywords


def compute_candidate_features(p1_proba: np.ndarray) -> dict:
    """
    Compute candidate features derived from Stage1 predictions.

    Returns dict of feature_name -> feature_values
    """
    eps = 1e-7  # Avoid log(0) and extreme logit values

    features = {}

    # 1. Raw probability
    features['p1_proba'] = p1_proba.copy()

    # 2. Uncertainty (distance from decision boundary)
    features['uncertainty'] = 1.0 - np.abs(p1_proba - 0.5) * 2.0

    # 3. Squared probability (captures non-linearity)
    features['p1_sq'] = p1_proba ** 2

    # 4. Logit transformation (clipped to avoid infinity)
    p_clipped = np.clip(p1_proba, eps, 1 - eps)
    logit_vals = np.log(p_clipped / (1 - p_clipped))
    # Clip extreme values
    features['logit'] = np.clip(logit_vals, -15, 15)

    # 5. Entropy (maximum at 0.5)
    entropy_vals = -(p_clipped * np.log(p_clipped) +
                     (1 - p_clipped) * np.log(1 - p_clipped))
    features['entropy'] = np.nan_to_num(entropy_vals, nan=0.0)

    # 6. Absolute distance from 0.5
    features['abs_dist'] = np.abs(p1_proba - 0.5)

    # 7. Confidence (how far from 0.5, scaled 0-1)
    features['confidence'] = np.abs(p1_proba - 0.5) * 2.0

    # 8. Binned probability (categorical-like)
    features['p1_bin'] = np.digitize(p1_proba, bins=[0.2, 0.4, 0.6, 0.8]).astype(float)

    return features


def train_lr_oof_with_features(X_base: np.ndarray,
                                extra_features: np.ndarray,
                                err_train: np.ndarray,
                                n_folds: int = 5) -> tuple:
    """
    Train LR with OOF and return predictions.

    Returns: (oof_predictions, final_model, final_scaler)
    """
    # Combine base features with extra features
    if extra_features is not None and extra_features.shape[1] > 0:
        X = np.hstack([X_base, extra_features])
    else:
        X = X_base

    # Scale features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # OOF predictions
    oof_preds = np.zeros(len(X))
    skf = StratifiedKFold(n_splits=n_folds, shuffle=True, random_state=42)

    for fold, (train_idx, val_idx) in enumerate(skf.split(X_scaled, err_train)):
        X_tr, X_val = X_scaled[train_idx], X_scaled[val_idx]
        y_tr = err_train[train_idx]

        model = LogisticRegression(
            max_iter=1000,
            random_state=42,
            class_weight='balanced'
        )
        model.fit(X_tr, y_tr)
        oof_preds[val_idx] = model.predict_proba(X_val)[:, 1]

    # Train final model
    final_model = LogisticRegression(
        max_iter=1000,
        random_state=42,
        class_weight='balanced'
    )
    final_model.fit(X_scaled, err_train)

    return oof_preds, final_model, scaler


def evaluate_threshold(p_error: np.ndarray,
                       p1_proba: np.ndarray,
                       y_true: np.ndarray,
                       tau: float) -> dict:
    """
    Evaluate a threshold setting.

    Returns dict with metrics.
    """
    # Stage1 predictions
    stage1_pred = (p1_proba >= 0.5).astype(int)
    stage1_correct = (stage1_pred == y_true)

    # DEFER mask (p_error >= tau means defer to Stage3)
    defer_mask = p_error >= tau
    auto_mask = ~defer_mask

    # AUTO errors (Stage1 wrong AND we didn't defer)
    auto_errors = np.sum(~stage1_correct & auto_mask)
    n_auto = np.sum(auto_mask)
    n_defer = np.sum(defer_mask)

    auto_error_rate = auto_errors / n_auto if n_auto > 0 else 0.0

    return {
        'tau': tau,
        'n_auto': int(n_auto),
        'n_defer': int(n_defer),
        'auto_errors': int(auto_errors),
        'auto_error_rate': float(auto_error_rate),
        'defer_rate': float(n_defer / len(p_error))
    }


def search_best_tau(p_error: np.ndarray,
                    p1_proba: np.ndarray,
                    y_true: np.ndarray,
                    max_error_rate: float = 0.002) -> dict:
    """
    Search for the best tau that minimizes DEFER while keeping error rate low.
    """
    best_result = None

    # Try different tau values
    for tau in np.arange(0.1, 0.95, 0.05):
        result = evaluate_threshold(p_error, p1_proba, y_true, tau)

        if result['auto_error_rate'] <= max_error_rate:
            if best_result is None or result['n_defer'] < best_result['n_defer']:
                best_result = result

    # If no valid tau found, find the one with lowest defer that's closest to constraint
    if best_result is None:
        results = []
        for tau in np.arange(0.1, 0.95, 0.05):
            result = evaluate_threshold(p_error, p1_proba, y_true, tau)
            results.append(result)
        # Sort by error rate, then by defer count
        results.sort(key=lambda x: (x['auto_error_rate'], x['n_defer']))
        best_result = results[0]

    return best_result


def run_feature_search(artifact_dir: Path,
                       max_error_rate: float = 0.002,
                       output_file: Path = None):
    """
    Run the full feature search.
    """
    print("=" * 60)
    print("Stage2 LR Feature Search")
    print("=" * 60)

    # Load data
    print("\nLoading data...")
    X_base, y_true, feature_names, xgb_model, xgb_scaler, brand_keywords = load_data(artifact_dir)

    X_scaled = xgb_scaler.transform(X_base)

    # Get Stage1 predictions
    p1_proba = xgb_model.predict_proba(X_scaled)[:, 1]

    # Compute Stage1 errors
    stage1_pred = (p1_proba >= 0.5).astype(int)
    err_train = (stage1_pred != y_true).astype(int)

    print(f"Total samples: {len(X_base)}")
    print(f"Stage1 errors: {err_train.sum()} ({err_train.mean()*100:.2f}%)")
    print(f"Max allowed AUTO error rate: {max_error_rate*100:.2f}%")

    # Compute candidate features
    print("\nComputing candidate features...")
    candidate_features = compute_candidate_features(p1_proba)
    feature_names = list(candidate_features.keys())
    print(f"Candidate features: {feature_names}")

    # Test all combinations
    results = []

    # Baseline: no extra features
    print("\n" + "-" * 40)
    print("Testing baseline (no extra features)...")
    oof_preds, _, _ = train_lr_oof_with_features(X_base, None, err_train)
    best_tau_result = search_best_tau(oof_preds, p1_proba, y_true, max_error_rate)
    baseline_result = {
        'features': [],
        'feature_str': 'baseline',
        **best_tau_result
    }
    results.append(baseline_result)
    print(f"  Baseline: DEFER={best_tau_result['n_defer']}, "
          f"AUTO_errors={best_tau_result['auto_errors']}, "
          f"tau={best_tau_result['tau']:.2f}")

    # Test each single feature
    print("\n" + "-" * 40)
    print("Testing single features...")
    for fname in feature_names:
        extra = candidate_features[fname].reshape(-1, 1)
        oof_preds, _, _ = train_lr_oof_with_features(X_base, extra, err_train)
        best_tau_result = search_best_tau(oof_preds, p1_proba, y_true, max_error_rate)

        result = {
            'features': [fname],
            'feature_str': fname,
            **best_tau_result
        }
        results.append(result)
        print(f"  +{fname}: DEFER={best_tau_result['n_defer']}, "
              f"AUTO_errors={best_tau_result['auto_errors']}, "
              f"tau={best_tau_result['tau']:.2f}")

    # Test combinations of 2 features (most promising ones)
    print("\n" + "-" * 40)
    print("Testing feature pairs...")

    # Select top features based on single-feature results
    single_results = [r for r in results if len(r['features']) == 1]
    single_results.sort(key=lambda x: x['n_defer'])
    top_features = [r['features'][0] for r in single_results[:5]]

    for combo in itertools.combinations(top_features, 2):
        extra_cols = [candidate_features[f] for f in combo]
        extra = np.column_stack(extra_cols)

        oof_preds, _, _ = train_lr_oof_with_features(X_base, extra, err_train)
        best_tau_result = search_best_tau(oof_preds, p1_proba, y_true, max_error_rate)

        result = {
            'features': list(combo),
            'feature_str': '+'.join(combo),
            **best_tau_result
        }
        results.append(result)
        print(f"  +{result['feature_str']}: DEFER={best_tau_result['n_defer']}, "
              f"AUTO_errors={best_tau_result['auto_errors']}, "
              f"tau={best_tau_result['tau']:.2f}")

    # Test combinations of 3 features
    print("\n" + "-" * 40)
    print("Testing feature triplets...")

    for combo in itertools.combinations(top_features[:4], 3):
        extra_cols = [candidate_features[f] for f in combo]
        extra = np.column_stack(extra_cols)

        oof_preds, _, _ = train_lr_oof_with_features(X_base, extra, err_train)
        best_tau_result = search_best_tau(oof_preds, p1_proba, y_true, max_error_rate)

        result = {
            'features': list(combo),
            'feature_str': '+'.join(combo),
            **best_tau_result
        }
        results.append(result)
        print(f"  +{result['feature_str']}: DEFER={best_tau_result['n_defer']}, "
              f"AUTO_errors={best_tau_result['auto_errors']}, "
              f"tau={best_tau_result['tau']:.2f}")

    # Find best result
    print("\n" + "=" * 60)
    print("RESULTS SUMMARY")
    print("=" * 60)

    # Sort by n_defer (ascending)
    valid_results = [r for r in results if r['auto_error_rate'] <= max_error_rate]
    if valid_results:
        valid_results.sort(key=lambda x: x['n_defer'])
        best = valid_results[0]
    else:
        results.sort(key=lambda x: (x['auto_error_rate'], x['n_defer']))
        best = results[0]
        print("\nWARNING: No configuration met the error rate constraint!")

    print(f"\nBest configuration:")
    print(f"  Features: {best['feature_str']}")
    print(f"  Tau: {best['tau']:.2f}")
    print(f"  N_DEFER: {best['n_defer']} ({best['defer_rate']*100:.1f}%)")
    print(f"  N_AUTO: {best['n_auto']}")
    print(f"  AUTO_errors: {best['auto_errors']} ({best['auto_error_rate']*100:.3f}%)")

    # Compare to baseline
    baseline = results[0]
    improvement = baseline['n_defer'] - best['n_defer']
    print(f"\nImprovement over baseline:")
    print(f"  DEFER reduced by: {improvement} ({improvement/baseline['n_defer']*100:.1f}%)")

    # Top 5 results
    print("\n" + "-" * 40)
    print("Top 5 configurations:")
    for i, r in enumerate(valid_results[:5] if valid_results else results[:5]):
        print(f"  {i+1}. {r['feature_str']}: DEFER={r['n_defer']}, "
              f"errors={r['auto_errors']}, tau={r['tau']:.2f}")

    # Save results
    if output_file:
        output_data = {
            'max_error_rate': max_error_rate,
            'best': best,
            'all_results': results
        }
        with open(output_file, 'w') as f:
            json.dump(output_data, f, indent=2)
        print(f"\nResults saved to: {output_file}")

    return best, results


def main():
    parser = argparse.ArgumentParser(description='Search for best LR features')
    parser.add_argument('--artifact-dir', type=str, required=True,
                        help='Path to artifact directory')
    parser.add_argument('--max-error-rate', type=float, default=0.002,
                        help='Maximum allowed AUTO error rate (default: 0.002 = 0.2%%)')
    parser.add_argument('--output', type=str, default=None,
                        help='Output JSON file for results')

    args = parser.parse_args()

    artifact_dir = Path(args.artifact_dir)
    output_file = Path(args.output) if args.output else None

    if not artifact_dir.exists():
        print(f"ERROR: Artifact directory not found: {artifact_dir}")
        sys.exit(1)

    best, results = run_feature_search(
        artifact_dir,
        max_error_rate=args.max_error_rate,
        output_file=output_file
    )

    return best


if __name__ == '__main__':
    main()
