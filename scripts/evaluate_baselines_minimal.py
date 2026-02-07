#!/usr/bin/env python3
"""
最小ベースライン比較スクリプト（Appendix用）

Stage1 XGBoost と同一の 42 特徴量・同一 Train/Test split で
LightGBM / RandomForest を学習・評価し、Appendix 表を生成する。

目的: 査読で「分類器優劣」に論点をずらされないための防御線。
      勝つことが目的ではない。

制約:
  - 特徴量追加なし（既存 42 個のみ）
  - モデル 2 本固定（LightGBM + RandomForest）
  - ハイパラ探索は最小（各 2 設定、計 4 + XGBoost参照 = 5 行）
  - 指標: F1 / FPR / FNR + 混同行列

Usage:
    python scripts/evaluate_baselines_minimal.py

出力:
    docs/paper/data/tables/appendix_baselines.csv

変更履歴:
  - 2026-02-07: 新規作成（TODO-1）
"""

import sys
import time
import pickle
from pathlib import Path

import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import confusion_matrix
import lightgbm as lgb

# ── Paths ──
# 論文の評価パイプラインと同一の artifacts から読む
PROJECT_ROOT = Path(__file__).parent.parent
ARTIFACTS_DIR = PROJECT_ROOT / "artifacts" / "2026-02-02_224105"
TRAIN_PKL = ARTIFACTS_DIR / "processed" / "train_data.pkl"
TEST_PKL = ARTIFACTS_DIR / "processed" / "test_data.pkl"
XGBOOST_MODEL = ARTIFACTS_DIR / "models" / "xgboost_model.pkl"
SCALER_PKL = ARTIFACTS_DIR / "models" / "scaler.pkl"
OUTPUT_CSV = PROJECT_ROOT / "docs" / "paper" / "data" / "tables" / "appendix_baselines.csv"

SEED = 42


def load_data():
    """Train/Test データを読み込む（論文と同一の split, n=127,222）。

    XGBoost は StandardScaler 適用後のデータで学習されているため、
    全ベースラインで同じ scaler を適用して公平性を担保する。
    """
    print("Loading data...")
    train = joblib.load(TRAIN_PKL)
    test = joblib.load(TEST_PKL)

    X_train_raw = np.array(train["X"])
    y_train = np.array(train["y"])
    X_test_raw = np.array(test["X"])
    y_test = np.array(test["y"])

    print(f"  Train: {X_train_raw.shape[0]:,} x {X_train_raw.shape[1]} (balanced: {int(y_train.sum()):,} phish)")
    print(f"  Test:  {X_test_raw.shape[0]:,} x {X_test_raw.shape[1]} (balanced: {int(y_test.sum()):,} phish)")

    # 論文パイプラインと同一の StandardScaler を適用
    scaler = joblib.load(SCALER_PKL)
    X_train = scaler.transform(X_train_raw)
    X_test = scaler.transform(X_test_raw)
    print(f"  Scaler applied (loaded from {SCALER_PKL.name})")

    return X_train, y_train, X_test, y_test


def calc_metrics(y_true, y_pred, model_name, params_summary, elapsed):
    """混同行列と指標を算出"""
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0
    return {
        "model": model_name,
        "params_summary": params_summary,
        "TP": int(tp),
        "FP": int(fp),
        "TN": int(tn),
        "FN": int(fn),
        "Precision": round(precision * 100, 2),
        "Recall": round(recall * 100, 2),
        "F1": round(f1 * 100, 2),
        "FPR": round(fpr * 100, 2),
        "FNR": round(fnr * 100, 2),
        "train_time_sec": round(elapsed, 1),
    }


def evaluate_xgboost_reference(X_test, y_test):
    """既存 XGBoost モデル（Stage1）の参照値"""
    print("\n[1/5] XGBoost (Stage1 reference)...")
    with open(XGBOOST_MODEL, "rb") as f:
        model = pickle.load(f)
    y_pred = (model.predict_proba(X_test)[:, 1] >= 0.5).astype(int)
    return calc_metrics(y_test, y_pred, "XGBoost (Stage1)", "depth=8, lr=0.1, n=500", 0)


def evaluate_lightgbm(X_train, y_train, X_test, y_test):
    """LightGBM 2設定"""
    configs = [
        {
            "name": "LightGBM-A",
            "params_summary": "leaves=31, depth=8, lr=0.1, n=500",
            "params": {
                "objective": "binary",
                "metric": "binary_logloss",
                "num_leaves": 31,
                "max_depth": 8,
                "learning_rate": 0.1,
                "n_estimators": 500,
                "random_state": SEED,
                "verbose": -1,
                "n_jobs": -1,
            },
        },
        {
            "name": "LightGBM-B",
            "params_summary": "leaves=63, depth=12, lr=0.05, n=800",
            "params": {
                "objective": "binary",
                "metric": "binary_logloss",
                "num_leaves": 63,
                "max_depth": 12,
                "learning_rate": 0.05,
                "n_estimators": 800,
                "random_state": SEED,
                "verbose": -1,
                "n_jobs": -1,
            },
        },
    ]

    results = []
    for i, cfg in enumerate(configs):
        idx = i + 2  # [2/5], [3/5]
        print(f"\n[{idx}/5] {cfg['name']} ({cfg['params_summary']})...")
        model = lgb.LGBMClassifier(**cfg["params"])
        t0 = time.time()
        model.fit(X_train, y_train)
        elapsed = time.time() - t0
        y_pred = model.predict(X_test)
        row = calc_metrics(y_test, y_pred, cfg["name"], cfg["params_summary"], elapsed)
        print(f"  F1={row['F1']}%, FPR={row['FPR']}%, FNR={row['FNR']}% ({elapsed:.1f}s)")
        results.append(row)
    return results


def evaluate_random_forest(X_train, y_train, X_test, y_test):
    """RandomForest 2設定"""
    configs = [
        {
            "name": "RandomForest-A",
            "params_summary": "trees=500, depth=None, features=sqrt",
            "params": {
                "n_estimators": 500,
                "max_depth": None,
                "max_features": "sqrt",
                "random_state": SEED,
                "n_jobs": -1,
            },
        },
        {
            "name": "RandomForest-B",
            "params_summary": "trees=500, depth=20, features=sqrt",
            "params": {
                "n_estimators": 500,
                "max_depth": 20,
                "max_features": "sqrt",
                "random_state": SEED,
                "n_jobs": -1,
            },
        },
    ]

    results = []
    for i, cfg in enumerate(configs):
        idx = i + 4  # [4/5], [5/5]
        print(f"\n[{idx}/5] {cfg['name']} ({cfg['params_summary']})...")
        model = RandomForestClassifier(**cfg["params"])
        t0 = time.time()
        model.fit(X_train, y_train)
        elapsed = time.time() - t0
        y_pred = model.predict(X_test)
        row = calc_metrics(y_test, y_pred, cfg["name"], cfg["params_summary"], elapsed)
        print(f"  F1={row['F1']}%, FPR={row['FPR']}%, FNR={row['FNR']}% ({elapsed:.1f}s)")
        results.append(row)
    return results


def main():
    print("=" * 60)
    print("Minimal Baseline Comparison (Appendix)")
    print("Models: XGBoost (ref) + LightGBM x2 + RandomForest x2")
    print("Features: 42 (same as Stage1), Seed: 42")
    print("=" * 60)

    X_train, y_train, X_test, y_test = load_data()

    rows = []

    # XGBoost reference
    rows.append(evaluate_xgboost_reference(X_test, y_test))

    # LightGBM
    rows.extend(evaluate_lightgbm(X_train, y_train, X_test, y_test))

    # RandomForest
    rows.extend(evaluate_random_forest(X_train, y_train, X_test, y_test))

    # Output
    df = pd.DataFrame(rows)
    OUTPUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(OUTPUT_CSV, index=False)
    print(f"\n{'=' * 60}")
    print(f"Results saved to: {OUTPUT_CSV}")
    print(f"{'=' * 60}")
    print(df.to_string(index=False))

    # Summary
    print(f"\n--- Summary ---")
    best = df.loc[df["F1"].idxmax()]
    print(f"Best F1: {best['model']} ({best['F1']}%)")
    xgb_f1 = df[df["model"] == "XGBoost (Stage1)"]["F1"].iloc[0]
    print(f"XGBoost (Stage1) F1: {xgb_f1}%")
    print("Note: All models use the same 42 features and Train/Test split.")
    print("The cascade system's contribution is handoff control + rule integration, not classifier choice.")


if __name__ == "__main__":
    main()
