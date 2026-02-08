#!/usr/bin/env python3
"""
SHAP analysis for Stage1 XGBoost model.

Generates:
  1. Global feature importance (bar plot)
  2. SHAP beeswarm summary plot
  3. High-confidence misclassification analysis

Output:
  docs/paper/images/shap_global_importance.png
  docs/paper/images/shap_beeswarm.png
  docs/reports/shap_analysis_report.md

変更履歴:
  - 2026-02-08: 初版作成（MTG 2025-12-25 アクションアイテムA2対応）
"""

import pickle
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import shap

# ---------- paths ----------
PROJECT = Path(__file__).resolve().parent.parent
RUN_ID = "2026-02-02_224105"
ARTIFACTS = PROJECT / "artifacts" / RUN_ID
MODEL_PATH = ARTIFACTS / "models" / "xgboost_model.pkl"
TEST_PATH  = ARTIFACTS / "processed" / "test_data.pkl"
STAGE1_CSV = ARTIFACTS / "results" / "stage1_decisions_latest.csv"
IMG_DIR    = PROJECT / "docs" / "paper" / "images"
REPORT_DIR = PROJECT / "docs" / "reports"

# Feature order (from features.py)
FEATURE_ORDER = [
    'domain_length', 'dot_count', 'hyphen_count', 'digit_count', 'digit_ratio',
    'tld_length', 'subdomain_count', 'longest_part_length', 'entropy',
    'vowel_ratio', 'max_consonant_length', 'has_special_chars',
    'non_alphanumeric_count', 'contains_brand', 'has_www',
    'cert_validity_days', 'cert_is_wildcard', 'cert_san_count',
    'cert_issuer_length', 'cert_is_self_signed',
    'cert_cn_length', 'cert_subject_has_org', 'cert_subject_org_length',
    'cert_san_dns_count', 'cert_san_ip_count', 'cert_cn_matches_domain',
    'cert_san_matches_domain', 'cert_san_matches_etld1', 'cert_has_ocsp',
    'cert_has_crl_dp', 'cert_has_sct', 'cert_sig_algo_weak',
    'cert_pubkey_size', 'cert_key_type_code', 'cert_is_lets_encrypt',
    'cert_key_bits_normalized', 'cert_issuer_country_code', 'cert_serial_entropy',
    'cert_has_ext_key_usage', 'cert_has_policies', 'cert_issuer_type',
    'cert_is_le_r3',
]

DOMAIN_FEATURES = set(FEATURE_ORDER[:15])
CERT_FEATURES   = set(FEATURE_ORDER[15:])


def load_data():
    """Load model and test data from stage1_decisions CSV."""
    print(f"Loading model from {MODEL_PATH}")
    with open(MODEL_PATH, "rb") as f:
        model = pickle.load(f)

    print(f"Loading test data from {STAGE1_CSV}")
    df = pd.read_csv(STAGE1_CSV)
    print(f"  CSV rows: {len(df)}")

    # Extract 42 ML feature columns (ml_ prefix, excluding ml_probability)
    ml_cols = [f"ml_{f}" for f in FEATURE_ORDER]
    feature_names = FEATURE_ORDER  # display names without ml_ prefix

    X_array = df[ml_cols].values
    y_array = df["y_true"].values

    proba = df["ml_probability"].values

    print(f"  X_test shape: {X_array.shape}, y_test shape: {y_array.shape}")
    print(f"  Features: {len(feature_names)}")
    return model, X_array, y_array, feature_names, proba


def compute_shap(model, X, feature_names):
    """Compute SHAP values using TreeExplainer."""
    print("Computing SHAP values (TreeExplainer)...")
    explainer = shap.TreeExplainer(model)
    shap_values = explainer.shap_values(X)
    print(f"  SHAP values shape: {shap_values.shape}")
    return explainer, shap_values


def plot_global_importance(shap_values, feature_names, save_path):
    """Bar chart of mean |SHAP| values."""
    mean_abs = np.abs(shap_values).mean(axis=0)
    order = np.argsort(mean_abs)[::-1]

    top_n = 20
    idx = order[:top_n]

    fig, ax = plt.subplots(figsize=(10, 8))
    names = [feature_names[i] for i in idx]
    vals  = mean_abs[idx]

    colors = ["#1f77b4" if feature_names[i] in DOMAIN_FEATURES else "#ff7f0e"
              for i in idx]

    bars = ax.barh(range(top_n), vals[::-1], color=colors[::-1])
    ax.set_yticks(range(top_n))
    ax.set_yticklabels(names[::-1], fontsize=10)
    ax.set_xlabel("Mean |SHAP value|", fontsize=12)
    ax.set_title("Top-20 Feature Importance (SHAP)", fontsize=14)

    # legend
    from matplotlib.patches import Patch
    ax.legend(handles=[
        Patch(facecolor="#1f77b4", label="Domain features"),
        Patch(facecolor="#ff7f0e", label="Certificate features"),
    ], loc="lower right", fontsize=10)

    plt.tight_layout()
    fig.savefig(save_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  Saved: {save_path}")

    return [(feature_names[i], mean_abs[i]) for i in order]


def plot_beeswarm(shap_values, X, feature_names, save_path):
    """SHAP beeswarm plot (top 20)."""
    fig = plt.figure(figsize=(10, 8))
    shap.summary_plot(
        shap_values, X,
        feature_names=feature_names,
        max_display=20,
        show=False,
        plot_size=None,
    )
    plt.title("SHAP Summary (Beeswarm)", fontsize=14)
    plt.tight_layout()
    fig.savefig(save_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  Saved: {save_path}")


def analyze_misclassifications(model, X, y, feature_names, shap_values, proba):
    """Analyze high-confidence misclassifications using SHAP."""

    # High-confidence errors
    # Auto-phishing errors: proba >= 0.957 but y=0
    auto_phish_fp = (proba >= 0.957) & (y == 0)
    # Auto-benign errors: proba <= 0.001 but y=1
    auto_benign_fn = (proba <= 0.001) & (y == 1)

    report_lines = []
    report_lines.append("# SHAP Analysis Report — Stage1 XGBoost\n")
    report_lines.append(f"作成日: 2026-02-08")
    report_lines.append(f"目的: MTG 2025-12-25 アクションアイテムA2「高確信度誤判定の抽出と特徴分析」への対応\n")
    report_lines.append("---\n")

    # Global importance
    mean_abs = np.abs(shap_values).mean(axis=0)
    order = np.argsort(mean_abs)[::-1]

    report_lines.append("## 1. 全体の特徴量重要度（Top-20）\n")
    report_lines.append("| 順位 | 特徴量 | 種別 | Mean |SHAP| |")
    report_lines.append("|------|--------|------|------------|")
    for rank, i in enumerate(order[:20], 1):
        kind = "Domain" if feature_names[i] in DOMAIN_FEATURES else "Cert"
        report_lines.append(f"| {rank} | {feature_names[i]} | {kind} | {mean_abs[i]:.4f} |")

    report_lines.append(f"\n全42特徴量のうち、ドメイン特徴量 Top-20内: "
                        f"{sum(1 for i in order[:20] if feature_names[i] in DOMAIN_FEATURES)}個、"
                        f"証明書特徴量 Top-20内: "
                        f"{sum(1 for i in order[:20] if feature_names[i] in CERT_FEATURES)}個\n")

    # High-confidence errors
    report_lines.append("---\n")
    report_lines.append("## 2. 高確信度誤判定の分析\n")
    report_lines.append(f"### 2.1 Auto-phishing FP（p₁ ≥ 0.957 かつ y=0）: {auto_phish_fp.sum()}件\n")

    if auto_phish_fp.sum() > 0:
        fp_shap = shap_values[auto_phish_fp]
        fp_mean = fp_shap.mean(axis=0)
        fp_order = np.argsort(np.abs(fp_mean))[::-1]
        report_lines.append("FPを引き起こした上位特徴量（SHAP平均値、正=フィッシング方向）:\n")
        report_lines.append("| 特徴量 | Mean SHAP | 方向 |")
        report_lines.append("|--------|-----------|------|")
        for i in fp_order[:10]:
            direction = "→phishing" if fp_mean[i] > 0 else "→benign"
            report_lines.append(f"| {feature_names[i]} | {fp_mean[i]:+.4f} | {direction} |")
    else:
        report_lines.append("該当なし\n")

    report_lines.append(f"\n### 2.2 Auto-benign FN（p₁ ≤ 0.001 かつ y=1）: {auto_benign_fn.sum()}件\n")

    if auto_benign_fn.sum() > 0:
        fn_shap = shap_values[auto_benign_fn]
        fn_mean = fn_shap.mean(axis=0)
        fn_order = np.argsort(np.abs(fn_mean))[::-1]
        report_lines.append("FNを引き起こした上位特徴量（SHAP平均値、負=正規方向）:\n")
        report_lines.append("| 特徴量 | Mean SHAP | 方向 |")
        report_lines.append("|--------|-----------|------|")
        for i in fn_order[:10]:
            direction = "→phishing" if fn_mean[i] > 0 else "→benign"
            report_lines.append(f"| {feature_names[i]} | {fn_mean[i]:+.4f} | {direction} |")
    else:
        report_lines.append("該当なし\n")

    # Gray zone summary
    gray = (proba > 0.001) & (proba < 0.957)
    report_lines.append("---\n")
    report_lines.append("## 3. Gray zone（handoff領域）の特徴量分析\n")
    report_lines.append(f"Gray zone 件数: {gray.sum()}件（全{len(y)}件中 {gray.sum()/len(y)*100:.1f}%）\n")

    gray_shap = shap_values[gray]
    gray_mean_abs = np.abs(gray_shap).mean(axis=0)
    gray_order = np.argsort(gray_mean_abs)[::-1]

    report_lines.append("Gray zone で判定に最も寄与した特徴量:\n")
    report_lines.append("| 順位 | 特徴量 | Mean |SHAP| (gray) | Mean |SHAP| (全体) | 比率 |")
    report_lines.append("|------|--------|-------------------|------------------|------|")
    for rank, i in enumerate(gray_order[:10], 1):
        ratio = gray_mean_abs[i] / mean_abs[i] if mean_abs[i] > 0 else 0
        report_lines.append(
            f"| {rank} | {feature_names[i]} | {gray_mean_abs[i]:.4f} | {mean_abs[i]:.4f} | {ratio:.2f}x |"
        )

    # Summary
    report_lines.append("\n---\n")
    report_lines.append("## 4. まとめ\n")
    report_lines.append("- 全体重要度は `docs/paper/images/shap_global_importance.png` を参照")
    report_lines.append("- Beeswarm plot は `docs/paper/images/shap_beeswarm.png` を参照")
    report_lines.append(f"- Auto-decision errors（高確信度誤判定）は合計 {auto_phish_fp.sum() + auto_benign_fn.sum()} 件")
    report_lines.append(f"  - Auto-phishing FP: {auto_phish_fp.sum()}件")
    report_lines.append(f"  - Auto-benign FN: {auto_benign_fn.sum()}件")
    report_lines.append("- これらは Stage1 単体の高確信度誤判定であり、Stage2+3 で一部が救済される")

    return "\n".join(report_lines)


def main():
    IMG_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    model, X, y, feature_names, proba = load_data()

    # SHAP
    explainer, shap_values = compute_shap(model, X, feature_names)

    # Plots
    plot_global_importance(
        shap_values, feature_names,
        IMG_DIR / "shap_global_importance.png"
    )
    plot_beeswarm(
        shap_values, X, feature_names,
        IMG_DIR / "shap_beeswarm.png"
    )

    # Misclassification analysis + report
    report = analyze_misclassifications(model, X, y, feature_names, shap_values, proba)
    report_path = REPORT_DIR / "shap_analysis_report.md"
    with open(report_path, "w") as f:
        f.write(report)
    print(f"\nReport saved: {report_path}")

    print("\nDone.")


if __name__ == "__main__":
    main()
