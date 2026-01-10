"""
XGBoost training module for Stage1 classifier.

This module handles Stage1 XGBoost model training with
early stopping and GPU support.
"""

import xgboost as xgb
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from typing import Tuple, Dict, Any, Optional, List
from pathlib import Path
import json


class Stage1Trainer:
    """
    Stage1 XGBoost trainer.

    Example:
        >>> from src.config import load_config
        >>> cfg = load_config()
        >>> trainer = Stage1Trainer(cfg.xgboost)
        >>> model, metrics = trainer.train(df_train, feature_cols)
    """

    def __init__(self, config):
        """
        Initialize trainer.

        Args:
            config: XGBoostConfig object from src.config
        """
        self.config = config
        self.model = None
        self.feature_names = None
        self.training_history = None

    def train(
        self,
        df_train: pd.DataFrame,
        feature_cols: List[str],
        gpu_available: bool = False
    ) -> Tuple[xgb.Booster, Dict[str, Any]]:
        """
        Train XGBoost model with early stopping.

        Args:
            df_train: Training DataFrame with features and 'y_true' column
            feature_cols: List of feature column names
            gpu_available: Whether GPU is available

        Returns:
            Tuple of (trained model, metrics dict)
        """
        print("\n" + "="*80)
        print("🚀 XGBoost Training (Stage1)")
        print("="*80)

        # Extract features and labels
        X = df_train[feature_cols].values
        y = df_train['y_true'].values

        print(f"📊 Training data: {len(df_train):,} samples")
        print(f"   Phish: {(y == 1).sum():,} ({(y == 1).mean()*100:.1f}%)")
        print(f"   Benign: {(y == 0).sum():,} ({(y == 0).mean()*100:.1f}%)")
        print(f"   Features: {len(feature_cols)}")

        # Train/validation split
        X_tr, X_val, y_tr, y_val = train_test_split(
            X, y,
            test_size=self.config.val_size,
            random_state=self.config.random_state,
            stratify=y
        )

        print(f"\n📊 Split:")
        print(f"   Train: {len(X_tr):,} samples")
        print(f"   Val:   {len(X_val):,} samples")

        # XGBoost parameters
        params = {
            'max_depth': self.config.max_depth,
            'learning_rate': self.config.learning_rate,
            'objective': self.config.objective,
            'eval_metric': self.config.eval_metric,
            'subsample': self.config.subsample,
            'colsample_bytree': self.config.colsample_bytree,
            'random_state': self.config.random_state,
            'verbosity': self.config.verbosity,
        }

        # GPU settings
        if gpu_available:
            params['tree_method'] = 'gpu_hist'
            params['device'] = 'cuda'
            print("🎮 GPU training enabled (gpu_hist)")
        else:
            params['tree_method'] = 'hist'
            params['device'] = 'cpu'
            print("💻 CPU training (hist)")

        print(f"\n🔧 Hyperparameters:")
        for key, value in params.items():
            print(f"   {key}: {value}")

        # Create DMatrix
        dtrain = xgb.DMatrix(X_tr, label=y_tr, feature_names=feature_cols)
        dval = xgb.DMatrix(X_val, label=y_val, feature_names=feature_cols)

        # Training
        print(f"\n🏋️ Training...")
        evals = [(dtrain, 'train'), (dval, 'val')]
        evals_result = {}

        self.model = xgb.train(
            params,
            dtrain,
            num_boost_round=self.config.n_estimators,
            evals=evals,
            early_stopping_rounds=self.config.early_stopping_rounds,
            verbose_eval=50,
            evals_result=evals_result
        )

        self.feature_names = feature_cols
        self.training_history = evals_result

        # Compute metrics
        metrics = {
            'best_iteration': self.model.best_iteration,
            'best_score': self.model.best_score,
            'train_logloss': evals_result['train'][self.config.eval_metric][-1],
            'val_logloss': evals_result['val'][self.config.eval_metric][-1],
            'n_features': len(feature_cols),
            'n_train': len(X_tr),
            'n_val': len(X_val),
            'train_pos_rate': float((y_tr == 1).mean()),
            'val_pos_rate': float((y_val == 1).mean()),
        }

        print(f"\n✅ Training completed!")
        print(f"   Best iteration: {metrics['best_iteration']}")
        print(f"   Best score: {metrics['best_score']:.4f}")
        print(f"   Train logloss: {metrics['train_logloss']:.4f}")
        print(f"   Val logloss: {metrics['val_logloss']:.4f}")

        return self.model, metrics

    def predict_proba(
        self,
        df: pd.DataFrame,
        feature_cols: List[str]
    ) -> np.ndarray:
        """
        Predict probabilities for Stage1.

        Args:
            df: DataFrame with features
            feature_cols: List of feature column names

        Returns:
            Array of predicted probabilities
        """
        if self.model is None:
            raise ValueError("Model not trained yet. Call train() first.")

        X = df[feature_cols].values

        # Handle both XGBClassifier (sklearn API) and Booster (core API)
        if isinstance(self.model, xgb.XGBClassifier):
            # sklearn API: predict_proba returns (n_samples, n_classes)
            proba = self.model.predict_proba(X)
            return proba[:, 1]  # Return probability of positive class
        else:
            # Core Booster API: predict returns probabilities directly
            dtest = xgb.DMatrix(X, feature_names=feature_cols)
            return self.model.predict(dtest)

    def save_model(self, path: Path) -> None:
        """
        Save model to file.

        Args:
            path: Path to save model
        """
        if self.model is None:
            raise ValueError("Model not trained yet. Call train() first.")

        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self.model.save_model(str(path))
        print(f"💾 Model saved to: {path}")

    def load_model(self, path: Path) -> None:
        """
        Load model from file.

        Supports both XGBoost native format (.json, .ubj) and pickle format (.pkl).

        Args:
            path: Path to load model from
        """
        import joblib

        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Model file not found: {path}")

        # Check file extension
        if path.suffix == '.pkl':
            # Pickle format
            self.model = joblib.load(path)
        else:
            # XGBoost native format
            self.model = xgb.Booster()
            self.model.load_model(str(path))

        print(f"📂 Model loaded from: {path}")

    def save_training_history(self, path: Path) -> None:
        """
        Save training history to JSON.

        Args:
            path: Path to save history
        """
        if self.training_history is None:
            raise ValueError("No training history available.")

        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, 'w') as f:
            json.dump(self.training_history, f, indent=2)
        print(f"💾 Training history saved to: {path}")

    def get_feature_importance(self, importance_type: str = 'gain') -> pd.DataFrame:
        """
        Get feature importance.

        Args:
            importance_type: Type of importance ('gain', 'weight', 'cover')

        Returns:
            DataFrame with feature names and importance scores
        """
        if self.model is None:
            raise ValueError("Model not trained yet. Call train() first.")

        importance_dict = self.model.get_score(importance_type=importance_type)

        # Convert to DataFrame
        df_importance = pd.DataFrame([
            {'feature': k, 'importance': v}
            for k, v in importance_dict.items()
        ])

        # Sort by importance
        df_importance = df_importance.sort_values('importance', ascending=False)
        df_importance = df_importance.reset_index(drop=True)

        return df_importance

    def print_feature_importance(self, top_n: int = 20) -> None:
        """
        Print top feature importance.

        Args:
            top_n: Number of top features to print
        """
        df_importance = self.get_feature_importance()

        print(f"\n📊 Top {top_n} Feature Importance:")
        print("-"*60)
        for i, row in df_importance.head(top_n).iterrows():
            print(f"  {i+1:2d}. {row['feature']:<30} {row['importance']:>10.1f}")


def check_gpu_availability() -> bool:
    """
    Check if GPU is available for XGBoost.

    Returns:
        True if GPU is available
    """
    try:
        import xgboost as xgb
        # Try to create a small DMatrix and train with gpu_hist
        X = np.random.rand(100, 10)
        y = np.random.randint(0, 2, 100)
        dtrain = xgb.DMatrix(X, label=y)

        params = {
            'tree_method': 'gpu_hist',
            'device': 'cuda',
            'max_depth': 3,
            'objective': 'binary:logistic',
        }

        xgb.train(params, dtrain, num_boost_round=1, verbose_eval=False)
        return True
    except Exception:
        return False


def prepare_training_data(
    df: pd.DataFrame,
    feature_engineer,
    brand_keywords: List[str]
) -> pd.DataFrame:
    """
    Prepare training data by extracting features.

    Args:
        df: DataFrame with 'domain', 'cert_data', 'label' columns
        feature_engineer: FeatureEngineer instance
        brand_keywords: List of brand keywords

    Returns:
        DataFrame with feature columns added
    """
    print("\n🔄 Extracting features...")

    features_list = []
    for idx, row in df.iterrows():
        if idx % 10000 == 0 and idx > 0:
            print(f"  Progress: {idx:,}/{len(df):,}")

        domain = row['domain']
        cert_data = row.get('cert_data', None)
        features = feature_engineer.extract_features(domain, cert_data)
        features_list.append(features)

    # Add features to DataFrame
    feature_names = feature_engineer.get_feature_names()
    feature_matrix = np.array(features_list)

    for i, feature_name in enumerate(feature_names):
        df[feature_name] = feature_matrix[:, i]

    # Add y_true column
    df['y_true'] = df['label'].values

    print(f"✅ Features extracted: {len(df):,} samples")
    print(f"   Feature columns: {len(feature_names)}")

    return df
