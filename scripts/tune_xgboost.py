#!/usr/bin/env python3
"""
XGBoost Hyperparameter Tuning Script using Optuna

Automatically searches for optimal XGBoost hyperparameters
to minimize Stage1 errors while maximizing AUTO coverage.
"""

import sys
import json
import argparse
from pathlib import Path
from datetime import datetime

import numpy as np
import joblib
import optuna
from optuna.samplers import TPESampler
import xgboost as xgb
from sklearn.model_selection import StratifiedKFold, train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import roc_auc_score, log_loss, precision_recall_curve

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))


def load_data(artifact_dir: Path):
    """Load training data from artifacts."""
    processed_dir = artifact_dir / "processed"

    train_data = joblib.load(processed_dir / "train_data.pkl")

    X = train_data['X']
    y = train_data['y']
    feature_names = train_data.get('feature_names', [])

    return X, y, feature_names


def compute_stage1_metrics(y_true, y_proba, t_low=0.001, t_high=0.99):
    """
    Compute Stage1-style metrics:
    - auto_benign: p < t_low → predict benign
    - auto_phish: p >= t_high → predict phish
    - defer: t_low <= p < t_high → uncertain

    Returns dict with metrics.
    """
    n = len(y_true)

    auto_benign_mask = y_proba < t_low
    auto_phish_mask = y_proba >= t_high
    defer_mask = ~auto_benign_mask & ~auto_phish_mask

    # AUTO predictions
    auto_mask = auto_benign_mask | auto_phish_mask
    auto_pred = np.where(auto_phish_mask, 1, 0)

    # Errors in AUTO region
    auto_errors = np.sum((auto_pred != y_true) & auto_mask)
    n_auto = np.sum(auto_mask)

    # Phishing missed in auto_benign (FN)
    fn_auto_benign = np.sum((y_true == 1) & auto_benign_mask)

    # Benign marked as phish in auto_phish (FP)
    fp_auto_phish = np.sum((y_true == 0) & auto_phish_mask)

    return {
        'n_auto': int(n_auto),
        'n_defer': int(np.sum(defer_mask)),
        'auto_rate': float(n_auto / n),
        'auto_errors': int(auto_errors),
        'auto_error_rate': float(auto_errors / n_auto) if n_auto > 0 else 0.0,
        'fn_auto_benign': int(fn_auto_benign),
        'fp_auto_phish': int(fp_auto_phish),
    }


def find_optimal_thresholds(y_true, y_proba,
                            max_risk_benign=0.001,
                            max_risk_phish=0.0002,
                            min_samples=200):
    """
    Find optimal t_low and t_high using Wilson score upper bound.
    Similar to select_route1_thresholds in 02_main.py.
    """
    from scipy.stats import norm

    def wilson_upper(k, n, alpha=0.05):
        if n == 0:
            return 1.0
        z = norm.ppf(1 - alpha/2)
        p_hat = k / n
        denom = 1 + z**2 / n
        center = (p_hat + z**2 / (2*n)) / denom
        margin = z * np.sqrt((p_hat*(1-p_hat) + z**2/(4*n)) / n) / denom
        return min(center + margin, 1.0)

    # Sort by probability
    order = np.argsort(y_proba)
    y_sorted = y_true[order]
    p_sorted = y_proba[order]

    n = len(y_true)

    # Find t_low (for auto_benign)
    t_low = 0.001
    cum_phish = 0
    for i in range(n):
        if y_sorted[i] == 1:
            cum_phish += 1
        n_below = i + 1
        if n_below >= min_samples:
            risk = wilson_upper(cum_phish, n_below)
            if risk <= max_risk_benign:
                t_low = p_sorted[i]

    # Find t_high (for auto_phish)
    t_high = 0.999
    cum_benign = 0
    for i in range(n-1, -1, -1):
        if y_sorted[i] == 0:
            cum_benign += 1
        n_above = n - i
        if n_above >= min_samples:
            risk = wilson_upper(cum_benign, n_above)
            if risk <= max_risk_phish:
                t_high = p_sorted[i]

    return t_low, t_high


class XGBoostObjective:
    """Optuna objective for XGBoost hyperparameter tuning."""

    def __init__(self, X, y, n_folds=5, optimize_for='balanced', use_gpu=True):
        self.X = X
        self.y = y
        self.n_folds = n_folds
        self.optimize_for = optimize_for  # 'auc', 'auto_rate', 'balanced'
        self.scaler = StandardScaler()
        self.use_gpu = use_gpu

    def __call__(self, trial):
        # Hyperparameters to tune
        params = {
            'n_estimators': trial.suggest_int('n_estimators', 100, 1000, step=100),
            'max_depth': trial.suggest_int('max_depth', 3, 10),
            'learning_rate': trial.suggest_float('learning_rate', 0.01, 0.3, log=True),
            'min_child_weight': trial.suggest_int('min_child_weight', 1, 10),
            'subsample': trial.suggest_float('subsample', 0.6, 1.0),
            'colsample_bytree': trial.suggest_float('colsample_bytree', 0.6, 1.0),
            'gamma': trial.suggest_float('gamma', 0, 5),
            'reg_alpha': trial.suggest_float('reg_alpha', 1e-8, 10, log=True),
            'reg_lambda': trial.suggest_float('reg_lambda', 1e-8, 10, log=True),
        }

        # Cross-validation
        skf = StratifiedKFold(n_splits=self.n_folds, shuffle=True, random_state=42)

        auc_scores = []
        auto_rates = []
        error_rates = []

        for fold, (train_idx, val_idx) in enumerate(skf.split(self.X, self.y)):
            X_train, X_val = self.X[train_idx], self.X[val_idx]
            y_train, y_val = self.y[train_idx], self.y[val_idx]

            # Scale
            scaler = StandardScaler()
            X_train_scaled = scaler.fit_transform(X_train)
            X_val_scaled = scaler.transform(X_val)

            # Split train for early stopping
            X_tr, X_es, y_tr, y_es = train_test_split(
                X_train_scaled, y_train,
                test_size=0.1, random_state=42, stratify=y_train
            )

            # Train model with GPU if available
            gpu_params = {}
            if self.use_gpu:
                gpu_params = {
                    'tree_method': 'hist',
                    'device': 'cuda',
                }

            model = xgb.XGBClassifier(
                **params,
                **gpu_params,
                random_state=42,
                eval_metric='logloss',
                early_stopping_rounds=30,
                verbosity=0
            )

            model.fit(X_tr, y_tr, eval_set=[(X_es, y_es)], verbose=False)

            # Predict
            y_proba = model.predict_proba(X_val_scaled)[:, 1]

            # Compute metrics
            auc = roc_auc_score(y_val, y_proba)
            auc_scores.append(auc)

            # Find thresholds and compute Stage1 metrics
            t_low, t_high = find_optimal_thresholds(y_val, y_proba)
            metrics = compute_stage1_metrics(y_val, y_proba, t_low, t_high)

            auto_rates.append(metrics['auto_rate'])
            error_rates.append(metrics['auto_error_rate'])

        # Aggregate metrics
        mean_auc = np.mean(auc_scores)
        mean_auto_rate = np.mean(auto_rates)
        mean_error_rate = np.mean(error_rates)

        # Store for later analysis
        trial.set_user_attr('auc', mean_auc)
        trial.set_user_attr('auto_rate', mean_auto_rate)
        trial.set_user_attr('error_rate', mean_error_rate)

        # Objective based on optimization mode
        if self.optimize_for == 'auc':
            return mean_auc  # Maximize
        elif self.optimize_for == 'auto_rate':
            # Maximize auto_rate while keeping error_rate low
            if mean_error_rate > 0.005:  # Penalty for high error rate
                return mean_auto_rate * 0.5
            return mean_auto_rate
        else:  # balanced
            # Combined score: high AUC + high auto_rate + low error_rate
            score = mean_auc * 0.5 + mean_auto_rate * 0.3 + (1 - mean_error_rate) * 0.2
            return score


def run_tuning(artifact_dir: Path,
               n_trials: int = 50,
               n_folds: int = 5,
               optimize_for: str = 'balanced',
               use_gpu: bool = True,
               output_file: Path = None):
    """
    Run hyperparameter tuning.
    """
    print("=" * 60)
    print("XGBoost Hyperparameter Tuning with Optuna")
    print("=" * 60)

    # Load data
    print("\nLoading data...")
    X, y, feature_names = load_data(artifact_dir)
    print(f"Samples: {len(X)}, Features: {len(feature_names)}")
    print(f"Class distribution: {np.bincount(y)}")

    # Create objective
    print(f"\nOptimization mode: {optimize_for}")
    print(f"N trials: {n_trials}")
    print(f"N folds: {n_folds}")
    print(f"GPU: {'enabled' if use_gpu else 'disabled'}")

    objective = XGBoostObjective(X, y, n_folds=n_folds, optimize_for=optimize_for, use_gpu=use_gpu)

    # Create study
    direction = 'maximize'
    sampler = TPESampler(seed=42)
    study = optuna.create_study(direction=direction, sampler=sampler)

    # Run optimization
    print("\n" + "-" * 40)
    print("Starting optimization...")

    study.optimize(
        objective,
        n_trials=n_trials,
        show_progress_bar=True,
        callbacks=[lambda study, trial: print(
            f"  Trial {trial.number}: score={trial.value:.4f}, "
            f"auc={trial.user_attrs.get('auc', 0):.4f}, "
            f"auto_rate={trial.user_attrs.get('auto_rate', 0):.3f}, "
            f"error_rate={trial.user_attrs.get('error_rate', 0):.4f}"
        )]
    )

    # Results
    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)

    best_trial = study.best_trial
    print(f"\nBest trial: #{best_trial.number}")
    print(f"Best score: {best_trial.value:.4f}")
    print(f"  AUC: {best_trial.user_attrs.get('auc', 0):.4f}")
    print(f"  AUTO rate: {best_trial.user_attrs.get('auto_rate', 0):.3f}")
    print(f"  Error rate: {best_trial.user_attrs.get('error_rate', 0):.4f}")

    print("\nBest hyperparameters:")
    for key, value in best_trial.params.items():
        print(f"  {key}: {value}")

    # Top 5 trials
    print("\n" + "-" * 40)
    print("Top 5 trials:")
    trials_df = study.trials_dataframe()
    trials_df = trials_df.sort_values('value', ascending=False)

    for i, (_, row) in enumerate(trials_df.head(5).iterrows()):
        print(f"  {i+1}. score={row['value']:.4f}, "
              f"auc={row['user_attrs_auc']:.4f}, "
              f"auto_rate={row['user_attrs_auto_rate']:.3f}")

    # Compare with baseline
    print("\n" + "-" * 40)
    print("Comparison with current settings:")
    print("  Current: n_estimators=300, max_depth=8, learning_rate=0.1")
    print(f"  Best:    n_estimators={best_trial.params['n_estimators']}, "
          f"max_depth={best_trial.params['max_depth']}, "
          f"learning_rate={best_trial.params['learning_rate']:.4f}")

    # Save results
    if output_file:
        results = {
            'timestamp': datetime.now().isoformat(),
            'n_trials': n_trials,
            'n_folds': n_folds,
            'optimize_for': optimize_for,
            'best_trial': {
                'number': best_trial.number,
                'score': best_trial.value,
                'auc': best_trial.user_attrs.get('auc'),
                'auto_rate': best_trial.user_attrs.get('auto_rate'),
                'error_rate': best_trial.user_attrs.get('error_rate'),
                'params': best_trial.params
            },
            'top_5_trials': [
                {
                    'number': int(row['number']),
                    'score': float(row['value']),
                    'auc': float(row['user_attrs_auc']),
                    'auto_rate': float(row['user_attrs_auto_rate']),
                    'error_rate': float(row['user_attrs_error_rate']),
                }
                for _, row in trials_df.head(5).iterrows()
            ]
        }

        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\nResults saved to: {output_file}")

    return best_trial.params, study


def main():
    parser = argparse.ArgumentParser(description='Tune XGBoost hyperparameters')
    parser.add_argument('--artifact-dir', type=str, required=True,
                        help='Path to artifact directory')
    parser.add_argument('--n-trials', type=int, default=50,
                        help='Number of Optuna trials (default: 50)')
    parser.add_argument('--n-folds', type=int, default=5,
                        help='Number of CV folds (default: 5)')
    parser.add_argument('--optimize-for', type=str, default='balanced',
                        choices=['auc', 'auto_rate', 'balanced'],
                        help='Optimization objective (default: balanced)')
    parser.add_argument('--no-gpu', action='store_true',
                        help='Disable GPU acceleration')
    parser.add_argument('--output', type=str, default=None,
                        help='Output JSON file for results')

    args = parser.parse_args()

    artifact_dir = Path(args.artifact_dir)
    output_file = Path(args.output) if args.output else None

    if not artifact_dir.exists():
        print(f"ERROR: Artifact directory not found: {artifact_dir}")
        sys.exit(1)

    best_params, study = run_tuning(
        artifact_dir,
        n_trials=args.n_trials,
        n_folds=args.n_folds,
        optimize_for=args.optimize_for,
        use_gpu=not args.no_gpu,
        output_file=output_file
    )

    return best_params


if __name__ == '__main__':
    main()
