#!/usr/bin/env python3
"""
論文用図表生成スクリプト

生成する図:
  fig01_s3.1_cascade_architecture.png  - 3段カスケードアーキテクチャ
  fig02_s4.2_learning_curve.png        - XGBoost学習曲線
  fig03_s4.2_feature_importance.png    - 特徴量重要度 Top 15
  fig04_s4.4.3_fn_ml_score_dist.png    - 偽陰性MLスコア分布
  fig05_s3.4_agent_flow.png            - AI Agent解析フロー
  fig06_s4.5.1_processing_flow.png     - 処理フロー全体像
  fig07_s4.4.2_detection_pattern.png   - Stage3検知パターン

Usage:
    python scripts/generate_paper_figures.py
    python scripts/generate_paper_figures.py --fig 3   # 特定の図のみ
    python scripts/generate_paper_figures.py --lang ja  # 日本語ラベル（デフォルト）
    python scripts/generate_paper_figures.py --lang en  # 英語ラベル
"""

import sys
import os
import argparse
import pickle
import json
from pathlib import Path

import numpy as np
import pandas as pd
import joblib
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
import matplotlib.patheffects as pe

# Project root
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Paths
ARTIFACTS_DIR = PROJECT_ROOT / "artifacts" / "2026-02-02_224105"
MODEL_PATH = ARTIFACTS_DIR / "models" / "xgboost_model.pkl"
EVAL_CSV = ARTIFACTS_DIR / "results" / "stage2_validation" / "eval_20260205_230157" / "eval_df__nALL__ts_20260205_230158.csv"
TRAIN_DATA_PATH = PROJECT_ROOT / "artifacts" / "00-firststep" / "processed" / "train_data.pkl"
TEST_DATA_PATH = PROJECT_ROOT / "artifacts" / "00-firststep" / "processed" / "test_data.pkl"
OUTPUT_DIR = PROJECT_ROOT / "docs" / "paper" / "images"
LEARNING_CURVE_CACHE = OUTPUT_DIR / ".learning_curve_cache.pkl"

# Feature names (from 02_stage1_stage2/src/features.py)
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

# Display name mapping for features (shorter names for figure readability)
FEATURE_DISPLAY_NAMES = {
    'cert_is_le_r3': "LE R3 intermediate",
    'cert_has_crl_dp': "CRL distribution point",
    'cert_serial_entropy': "Serial number entropy",
    'cert_san_count': "SAN count",
    'cert_validity_days': "Certificate validity (days)",
    'cert_issuer_length': "Issuer name length",
    'cert_is_lets_encrypt': "Let's Encrypt issuer",
    'cert_cn_length': "Common Name length",
    'cert_issuer_type': "Issuer type (DV/OV/EV)",
    'cert_has_sct': "SCT presence",
    'cert_key_bits_normalized': "Key size (normalized)",
    'cert_subject_has_org': "Has organization",
    'cert_has_ocsp': "OCSP responder",
    'cert_issuer_country_code': "Issuer country",
    'cert_is_wildcard': "Wildcard certificate",
    'cert_san_dns_count': "SAN DNS count",
    'cert_san_ip_count': "SAN IP count",
    'cert_cn_matches_domain': "CN matches domain",
    'cert_san_matches_domain': "SAN matches domain",
    'cert_san_matches_etld1': "SAN matches eTLD+1",
    'cert_sig_algo_weak': "Weak signature algorithm",
    'cert_pubkey_size': "Public key size",
    'cert_key_type_code': "Key type code",
    'cert_is_self_signed': "Self-signed",
    'cert_subject_org_length': "Organization name length",
    'cert_has_ext_key_usage': "Extended Key Usage",
    'cert_has_policies': "Certificate Policies",
    'domain_length': "Domain length",
    'dot_count': "Dot count",
    'hyphen_count': "Hyphen count",
    'digit_count': "Digit count",
    'digit_ratio': "Digit ratio",
    'tld_length': "TLD length",
    'subdomain_count': "Subdomain count",
    'longest_part_length': "Longest label length",
    'entropy': "Domain entropy",
    'vowel_ratio': "Vowel ratio",
    'max_consonant_length': "Max consonant sequence",
    'has_special_chars': "Has special chars",
    'non_alphanumeric_count': "Non-alphanumeric count",
    'contains_brand': "Contains brand keyword",
    'has_www': "Has www prefix",
}


def setup_style():
    """Set up matplotlib style for paper figures."""
    # Use Noto Sans CJK JP for Japanese support, fallback to DejaVu Sans
    import matplotlib.font_manager as fm
    jp_fonts = [f.name for f in fm.fontManager.ttflist if 'Noto Sans CJK JP' in f.name]
    if jp_fonts:
        font_family = 'Noto Sans CJK JP'
    else:
        font_family = 'DejaVu Sans'
    plt.rcParams.update({
        'figure.dpi': 300,
        'savefig.dpi': 300,
        'font.family': font_family,
        'font.size': 10,
        'axes.unicode_minus': False,
        'axes.labelsize': 11,
        'axes.titlesize': 13,
        'xtick.labelsize': 9,
        'ytick.labelsize': 9,
        'legend.fontsize': 9,
        'figure.titlesize': 14,
    })


# ============================================================
# Fig 1: 3-Stage Cascade Architecture
# ============================================================
def generate_fig01(output_dir: Path, lang='ja'):
    """3段カスケードアーキテクチャ図"""
    fig, ax = plt.subplots(figsize=(12, 7))
    ax.set_xlim(0, 12)
    ax.set_ylim(0, 7)
    ax.axis('off')

    # Color scheme
    c_stage1 = '#4472C4'    # Blue
    c_stage2 = '#ED7D31'    # Orange
    c_stage3 = '#70AD47'    # Green
    c_input = '#A5A5A5'     # Gray
    c_output_p = '#FF6B6B'  # Red (phishing)
    c_output_b = '#4ECDC4'  # Teal (benign)
    c_text = 'white'

    def draw_box(x, y, w, h, color, text, fontsize=10, alpha=1.0):
        box = FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.1",
                             facecolor=color, edgecolor='black', linewidth=1.2, alpha=alpha)
        ax.add_patch(box)
        ax.text(x + w/2, y + h/2, text, ha='center', va='center',
                fontsize=fontsize, fontweight='bold', color=c_text,
                path_effects=[pe.withStroke(linewidth=2, foreground='black')])

    def draw_arrow(x1, y1, x2, y2, text='', color='black'):
        ax.annotate('', xy=(x2, y2), xytext=(x1, y1),
                    arrowprops=dict(arrowstyle='->', color=color, lw=1.5))
        if text:
            mx, my = (x1+x2)/2, (y1+y2)/2
            ax.text(mx, my + 0.15, text, ha='center', va='bottom',
                    fontsize=8, color='#333333',
                    bbox=dict(boxstyle='round,pad=0.2', facecolor='white', edgecolor='gray', alpha=0.9))

    # Input
    draw_box(0.3, 3.0, 2.0, 1.0, c_input,
             'Input\n127,754 domains' if lang == 'en' else '入力\n127,754件', fontsize=9)

    # Stage 1
    draw_box(3.2, 3.0, 2.2, 1.0, c_stage1,
             'Stage 1\nXGBoost' if lang == 'en' else 'Stage 1\nXGBoost', fontsize=10)
    ax.text(4.3, 2.7, '42 features, threshold-based routing' if lang == 'en'
            else '42特徴量, 確信度ベース振分', ha='center', fontsize=7, color='#555555')

    # Stage 1 outputs
    draw_box(3.2, 5.2, 2.2, 0.7, c_output_p,
             'auto_phishing\n60,614 (47.4%)' if lang == 'en' else 'auto_phishing\n60,614件 (47.4%)', fontsize=8)
    draw_box(3.2, 0.8, 2.2, 0.7, c_output_b,
             'auto_benign\n6,166 (4.8%)' if lang == 'en' else 'auto_benign\n6,166件 (4.8%)', fontsize=8)

    draw_arrow(4.3, 4.0, 4.3, 5.2)
    draw_arrow(4.3, 3.0, 4.3, 1.5)

    # Handoff arrow Stage1 -> Stage2
    draw_arrow(5.4, 3.5, 6.2, 3.5, 'handoff\n60,974 (47.7%)')

    # Stage 2
    draw_box(6.2, 3.0, 2.2, 1.0, c_stage2,
             'Stage 2\nLR + Cert Gate' if lang == 'en' else 'Stage 2\nLR + 証明書Gate', fontsize=9)
    ax.text(7.3, 2.7, 'Error probability estimation + certificate rules' if lang == 'en'
            else '誤り確率推定 + 証明書属性ルール', ha='center', fontsize=7, color='#555555')

    # Stage 2 output (benign)
    draw_box(6.2, 0.8, 2.2, 0.7, c_output_b,
             'safe_benign\n45,304 (35.5%)' if lang == 'en' else 'safe_benign\n45,304件 (35.5%)', fontsize=8)
    draw_arrow(7.3, 3.0, 7.3, 1.5)

    # Handoff arrow Stage2 -> Stage3
    draw_arrow(8.4, 3.5, 9.2, 3.5,
               'handoff\n15,670 (12.3%)' if lang == 'en' else 'handoff\n15,670件 (12.3%)')

    # Stage 3
    draw_box(9.2, 3.0, 2.5, 1.0, c_stage3,
             'Stage 3\nLLM + Rule Engine' if lang == 'en' else 'Stage 3\nLLM + ルールエンジン', fontsize=9)
    ax.text(10.45, 2.7, 'Qwen3-4B + 35 domain knowledge rules' if lang == 'en'
            else 'Qwen3-4B + ドメイン知識ルール35件', ha='center', fontsize=7, color='#555555')

    # Stage 3 outputs
    draw_box(9.2, 5.2, 2.5, 0.7, c_output_p,
             'phishing: 2,446\n(TP:1,781 / FP:665)' if lang == 'en'
             else 'phishing: 2,446件\n(TP:1,781 / FP:665)', fontsize=8)
    draw_box(9.2, 0.8, 2.5, 0.7, c_output_b,
             'benign: 13,224\n(TN:12,266 / FN:958)' if lang == 'en'
             else 'benign: 13,224件\n(TN:12,266 / FN:958)', fontsize=8)
    draw_arrow(10.45, 4.0, 10.45, 5.2)
    draw_arrow(10.45, 3.0, 10.45, 1.5)

    # Title
    title = 'Three-Stage Cascade Architecture' if lang == 'en' else '3段カスケードアーキテクチャ'
    ax.set_title(title, fontsize=14, fontweight='bold', pad=20)

    # Legend for colors
    legend_elements = [
        mpatches.Patch(facecolor=c_output_p, label='Phishing judgment' if lang == 'en' else 'Phishing判定'),
        mpatches.Patch(facecolor=c_output_b, label='Benign judgment' if lang == 'en' else 'Benign判定'),
    ]
    ax.legend(handles=legend_elements, loc='upper left', fontsize=9,
              framealpha=0.9, edgecolor='gray')

    # System performance annotation
    perf_text = ('System: F1 98.66%, Precision 99.15%, Recall 98.18%' if lang == 'en'
                 else 'システム全体: F1 98.66%, Precision 99.15%, Recall 98.18%')
    ax.text(6.0, 6.5, perf_text, ha='center', fontsize=10,
            bbox=dict(boxstyle='round,pad=0.4', facecolor='lightyellow', edgecolor='goldenrod'))

    plt.tight_layout()
    out = output_dir / 'fig01_s3.1_cascade_architecture.png'
    plt.savefig(out, dpi=300, bbox_inches='tight', facecolor='white')
    plt.close()
    print(f"  -> {out}")


# ============================================================
# Fig 2: XGBoost Learning Curve (sklearn learning_curve)
# ============================================================
def generate_fig02(output_dir: Path, lang='ja'):
    """XGBoost学習曲線（訓練データ量 vs Accuracy/AUC、過学習検証）

    CSS2025 図2と同形式。sklearn.model_selection.learning_curve() を使用。
    GPU (CUDA) で XGBoost を実行。計算結果はキャッシュされ、2回目以降は高速。

    変更履歴:
      - 2026-02-06: 検証logloss収束図 → sklearn learning_curve (Acc+AUC) に変更
    """
    from sklearn.model_selection import learning_curve
    import xgboost as xgb
    import gc

    # Check cache
    if LEARNING_CURVE_CACHE.exists():
        print("    Loading cached learning curve data...")
        cache = joblib.load(LEARNING_CURVE_CACHE)
        train_sizes_abs = cache['train_sizes_abs']
        train_scores_acc = cache['train_scores_acc']
        val_scores_acc = cache['val_scores_acc']
        train_scores_auc = cache['train_scores_auc']
        val_scores_auc = cache['val_scores_auc']
    else:
        print("    Loading training data...")
        train_data = joblib.load(TRAIN_DATA_PATH)
        X_train = train_data['X']
        y_train = train_data['y']
        print(f"    Training data: {X_train.shape[0]:,} samples x {X_train.shape[1]} features")

        # Detect GPU
        try:
            import torch
            gpu_available = torch.cuda.is_available()
        except ImportError:
            gpu_available = False
        device = 'cuda' if gpu_available else 'cpu'
        print(f"    Device: {device}")

        train_sizes = np.linspace(0.1, 1.0, 10)

        xgb_params = dict(
            n_estimators=100,  # Reduced for learning_curve speed
            max_depth=8,
            learning_rate=0.1,
            random_state=42,
            device=device,
        )

        # Accuracy learning curve
        print("    Computing learning curve (Accuracy)... This may take several minutes.")
        train_sizes_abs, train_scores_acc, val_scores_acc = learning_curve(
            xgb.XGBClassifier(**xgb_params),
            X_train, y_train,
            cv=5, train_sizes=train_sizes,
            scoring='accuracy', n_jobs=1, return_times=False,
        )

        # AUC learning curve
        print("    Computing learning curve (AUC)...")
        _, train_scores_auc, val_scores_auc = learning_curve(
            xgb.XGBClassifier(**xgb_params),
            X_train, y_train,
            cv=5, train_sizes=train_sizes,
            scoring='roc_auc', n_jobs=1, return_times=False,
        )

        gc.collect()

        # Cache results
        joblib.dump({
            'train_sizes_abs': train_sizes_abs,
            'train_scores_acc': train_scores_acc,
            'val_scores_acc': val_scores_acc,
            'train_scores_auc': train_scores_auc,
            'val_scores_auc': val_scores_auc,
        }, LEARNING_CURVE_CACHE)
        print(f"    Cached to {LEARNING_CURVE_CACHE}")

    # Plot
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))

    # Accuracy
    train_mean_acc = train_scores_acc.mean(axis=1)
    train_std_acc = train_scores_acc.std(axis=1)
    val_mean_acc = val_scores_acc.mean(axis=1)
    val_std_acc = val_scores_acc.std(axis=1)

    ax1.plot(train_sizes_abs, train_mean_acc, 'o-', color='#4472C4', label='Train Accuracy', linewidth=2)
    ax1.plot(train_sizes_abs, val_mean_acc, 's-', color='#ED7D31', label='Validation Accuracy', linewidth=2)
    ax1.fill_between(train_sizes_abs, train_mean_acc - train_std_acc,
                     train_mean_acc + train_std_acc, alpha=0.1, color='#4472C4')
    ax1.fill_between(train_sizes_abs, val_mean_acc - val_std_acc,
                     val_mean_acc + val_std_acc, alpha=0.1, color='#ED7D31')
    ax1.set_xlabel('Training set size')
    ax1.set_ylabel('Accuracy')
    ax1.set_title('Learning Curve (Accuracy)', fontweight='bold')
    ax1.legend(loc='lower right', fontsize=9)
    ax1.grid(True, alpha=0.3)

    # Gap annotation
    gap_acc = train_mean_acc[-1] - val_mean_acc[-1]
    ax1.text(0.03, 0.03, f'Gap: {gap_acc:.4f}',
             transform=ax1.transAxes, fontsize=9,
             bbox=dict(boxstyle='round,pad=0.3', facecolor='lightyellow', alpha=0.8))

    # AUC
    train_mean_auc = train_scores_auc.mean(axis=1)
    train_std_auc = train_scores_auc.std(axis=1)
    val_mean_auc = val_scores_auc.mean(axis=1)
    val_std_auc = val_scores_auc.std(axis=1)

    ax2.plot(train_sizes_abs, train_mean_auc, 'o-', color='#4472C4', label='Train AUC', linewidth=2)
    ax2.plot(train_sizes_abs, val_mean_auc, 's-', color='#ED7D31', label='Validation AUC', linewidth=2)
    ax2.fill_between(train_sizes_abs, train_mean_auc - train_std_auc,
                     train_mean_auc + train_std_auc, alpha=0.1, color='#4472C4')
    ax2.fill_between(train_sizes_abs, val_mean_auc - val_std_auc,
                     val_mean_auc + val_std_auc, alpha=0.1, color='#ED7D31')
    ax2.set_xlabel('Training set size')
    ax2.set_ylabel('ROC-AUC')
    ax2.set_title('Learning Curve (AUC)', fontweight='bold')
    ax2.legend(loc='lower right', fontsize=9)
    ax2.grid(True, alpha=0.3)

    gap_auc = train_mean_auc[-1] - val_mean_auc[-1]
    ax2.text(0.03, 0.03, f'Gap: {gap_auc:.4f}',
             transform=ax2.transAxes, fontsize=9,
             bbox=dict(boxstyle='round,pad=0.3', facecolor='lightyellow', alpha=0.8))

    plt.suptitle('Model Performance: Learning Curves (5-fold CV)',
                 fontsize=14, fontweight='bold', y=1.02)
    plt.tight_layout()
    out = output_dir / 'fig02_s4.2_learning_curve.png'
    plt.savefig(out, dpi=300, bbox_inches='tight', facecolor='white')
    plt.close()
    print(f"  -> {out}")


# ============================================================
# Fig 3: Feature Importance Top 15
# ============================================================
def generate_fig03(output_dir: Path, lang='ja'):
    """特徴量重要度 Top 15"""
    with open(MODEL_PATH, 'rb') as f:
        model = pickle.load(f)

    fi = model.feature_importances_
    importance_df = pd.DataFrame({
        'feature': FEATURE_ORDER,
        'importance': fi
    }).sort_values('importance', ascending=True)  # ascending for horizontal bar

    top15 = importance_df.tail(15)

    fig, ax = plt.subplots(figsize=(9, 6))

    colors = ['#70AD47' if 'cert_' in feat else '#4472C4' for feat in top15['feature']]
    display_names = [FEATURE_DISPLAY_NAMES.get(f, f) for f in top15['feature']]

    bars = ax.barh(range(len(top15)), top15['importance'], color=colors, edgecolor='white', linewidth=0.5)
    ax.set_yticks(range(len(top15)))
    ax.set_yticklabels(display_names, fontsize=9)
    ax.set_xlabel('Feature Importance (Gain)' if lang == 'en' else '特徴量重要度 (Gain)')
    ax.set_title('Feature Importance Top 15 - XGBoost' if lang == 'en'
                 else '特徴量重要度 Top 15 - XGBoost', fontweight='bold')

    # Value labels
    for i, (idx, row) in enumerate(top15.iterrows()):
        ax.text(row['importance'] + 0.003, i, f'{row["importance"]:.3f}',
                va='center', fontsize=8)

    # Legend
    legend_elements = [
        mpatches.Patch(facecolor='#4472C4', label='Domain features' if lang == 'en' else 'ドメイン特徴量'),
        mpatches.Patch(facecolor='#70AD47', label='Certificate features' if lang == 'en' else '証明書特徴量'),
    ]
    ax.legend(handles=legend_elements, loc='lower right', fontsize=9)
    ax.grid(axis='x', alpha=0.3)

    # Count annotation
    cert_count = sum(1 for f in top15['feature'] if 'cert_' in f)
    domain_count = len(top15) - cert_count
    ax.text(0.97, 0.03, f'Certificate: {cert_count}/15, Domain: {domain_count}/15',
            transform=ax.transAxes, ha='right', va='bottom', fontsize=8,
            bbox=dict(boxstyle='round,pad=0.3', facecolor='lightyellow', alpha=0.8))

    plt.tight_layout()
    out = output_dir / 'fig03_s4.2_feature_importance.png'
    plt.savefig(out, dpi=300, bbox_inches='tight', facecolor='white')
    plt.close()
    print(f"  -> {out}")


# ============================================================
# Fig 4: Prediction Probability Distribution (CSS2025 Fig4 style)
# ============================================================
def generate_fig04(output_dir: Path, lang='ja'):
    """予測確率分布 + FN分布（CSS2025 図4 と同形式）

    左パネル: 全体の予測確率分布（Normal vs Phishing）
    右パネル: FNの予測確率分布（低確率域に偏在することを示す）

    変更履歴:
      - 2026-02-06: FN vs TP → CSS2025形式（全体分布 + FN分布）に変更
    """
    print("    Loading test data and model for prediction distribution...")

    # Load test data
    test_data = joblib.load(TEST_DATA_PATH)
    X_test = test_data['X']
    y_test = test_data['y']

    # Load model and predict
    with open(MODEL_PATH, 'rb') as f:
        model = pickle.load(f)

    y_pred_proba = model.predict_proba(X_test)[:, 1]
    y_pred = (y_pred_proba >= 0.5).astype(int)

    # FN: actual phishing but predicted benign
    fn_mask = (y_test == 1) & (y_pred == 0)
    fn_probs = y_pred_proba[fn_mask]
    n_fn = fn_mask.sum()

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5))

    # Left: Overall prediction probability distribution
    bins = np.linspace(0, 1, 51)
    ax1.hist(y_pred_proba[y_test == 0], bins=bins, alpha=0.5, color='#4472C4',
             label=f'Benign (n={sum(y_test == 0):,})', density=True)
    ax1.hist(y_pred_proba[y_test == 1], bins=bins, alpha=0.5, color='#FF6B6B',
             label=f'Phishing (n={sum(y_test == 1):,})', density=True)
    ax1.axvline(x=0.5, color='black', linestyle='--', linewidth=1.2, label='Threshold (0.5)')
    ax1.set_xlabel('ML Prediction Probability')
    ax1.set_ylabel('Density')
    ax1.set_title('Distribution of Prediction Probabilities', fontweight='bold')
    ax1.legend(fontsize=9)
    ax1.grid(True, alpha=0.3)

    # Right: FN prediction probability distribution
    ax2.hist(fn_probs, bins=30, color='#FF6B6B', alpha=0.7, edgecolor='white', linewidth=0.5)
    ax2.axvline(x=0.5, color='black', linestyle='--', linewidth=1.2, label='Threshold (0.5)')
    ax2.axvline(x=0.2, color='red', linestyle=':', linewidth=1.2, alpha=0.7, label='p = 0.2')
    ax2.set_xlabel('ML Prediction Probability')
    ax2.set_ylabel('Count')
    ax2.set_title(f'False Negative Prediction Probabilities (n={n_fn:,})', fontweight='bold')
    ax2.legend(fontsize=9)
    ax2.grid(True, alpha=0.3)

    # Stats annotation
    n_below_02 = sum(fn_probs < 0.2)
    stats_text = (f'Mean: {fn_probs.mean():.3f}\n'
                  f'Median: {np.median(fn_probs):.3f}\n'
                  f'p < 0.2: {n_below_02:,} ({n_below_02/n_fn*100:.1f}%)')
    ax2.text(0.97, 0.95, stats_text, transform=ax2.transAxes,
             ha='right', va='top', fontsize=9,
             bbox=dict(boxstyle='round,pad=0.4', facecolor='white', edgecolor='gray', alpha=0.9))

    plt.tight_layout()
    out = output_dir / 'fig04_s4.4.3_fn_ml_score_dist.png'
    plt.savefig(out, dpi=300, bbox_inches='tight', facecolor='white')
    plt.close()
    print(f"  -> {out}")


# ============================================================
# Fig 5: AI Agent Analysis Trace (concrete case, CSS2025 Fig5 style)
# ============================================================
def generate_fig05(output_dir: Path, lang='ja'):
    """AI Agent解析トレース事例（CSS2025 図5 と同形式）

    評価データから代表的なフィッシング検知事例を抽出し、
    ツール実行結果とスコアを可視化する。

    変更履歴:
      - 2026-02-06: 汎用フロー図 → 具体事例ベースのトレース図に変更
    """
    print("    Loading evaluation CSV for case example...")
    df = pd.read_csv(EVAL_CSV)

    # Find a good case: Stage3-only TP, multiple tools, interesting scores
    # Criteria: y_true=1, ai_is_phishing=True, stage1_pred=0, ml < 0.3
    candidates = df[
        (df['y_true'] == 1) &
        (df['ai_is_phishing'] == True) &
        (df['stage1_pred'] == 0) &
        (df['ml_probability'] < 0.35) &
        (df['ai_confidence'] >= 0.7) &
        (df['trace_brand_risk_score'].notna()) &
        (df['trace_cert_risk_score'].notna()) &
        (df['trace_ctx_risk_score'].notna())
    ].copy()

    if len(candidates) == 0:
        # Fallback: any TP with good data
        candidates = df[
            (df['y_true'] == 1) & (df['ai_is_phishing'] == True) &
            (df['trace_brand_risk_score'].notna())
        ].copy()

    # Pick the case with highest confidence and brand detection
    candidates = candidates.sort_values('ai_confidence', ascending=False)
    case = candidates.iloc[0]

    domain = case['domain']
    ml_prob = case['ml_probability']
    confidence = case['ai_confidence']
    risk_level = case['ai_risk_level']
    brand_score = case.get('trace_brand_risk_score', 0)
    cert_score = case.get('trace_cert_risk_score', 0)
    domain_score = case.get('trace_domain_risk_score', 0)
    ctx_score = case.get('trace_ctx_risk_score', 0)
    tools_used = case.get('trace_selected_tools', '')
    rules_fired = case.get('trace_phase6_rules_fired', '[]')

    # Parse rules
    try:
        rules_list = json.loads(rules_fired) if isinstance(rules_fired, str) else []
    except (json.JSONDecodeError, TypeError):
        rules_list = []

    # Create figure
    fig, ax = plt.subplots(figsize=(11, 8))
    ax.set_xlim(0, 11)
    ax.set_ylim(0, 8.5)
    ax.axis('off')

    c_input = '#A5A5A5'
    c_tool = '#FFC000'
    c_llm = '#70AD47'
    c_rule = '#ED7D31'
    c_output = '#C00000'

    def draw_box(x, y, w, h, color, text, fontsize=9, alpha=0.85):
        box = FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.08",
                             facecolor=color, edgecolor='black', linewidth=1.0, alpha=alpha)
        ax.add_patch(box)
        ax.text(x + w/2, y + h/2, text, ha='center', va='center',
                fontsize=fontsize, fontweight='bold', color='white',
                path_effects=[pe.withStroke(linewidth=1.5, foreground='black')])

    def score_color(score):
        if score >= 0.7:
            return '#C00000'
        elif score >= 0.4:
            return '#ED7D31'
        else:
            return '#70AD47'

    # Title
    ax.set_title(f'AI Agent Analysis Trace: {domain}', fontsize=13, fontweight='bold', pad=15)

    # 1. Input + LLM Tool Selection
    draw_box(0.5, 7.5, 4.5, 0.7, c_input,
             f'LLM Autonomous\nTool Selection', fontsize=9)
    ax.text(6.5, 7.85, f'ML Prob: {ml_prob:.3f}', fontsize=10, fontweight='bold',
            bbox=dict(boxstyle='round,pad=0.3', facecolor='lightyellow', edgecolor='gray'))

    # 2. Tool results (4 boxes with scores)
    tool_y = 5.8
    tool_h = 1.2
    tool_w = 2.2
    tool_gap = 0.3

    tool_data = [
        ('Brand Check', brand_score),
        ('Certificate\nAnalysis', cert_score),
        ('Short Domain', domain_score),
        ('Context Risk', ctx_score),
    ]

    for i, (tname, tscore) in enumerate(tool_data):
        tx = 0.3 + i * (tool_w + tool_gap)
        sc = score_color(tscore)
        # Tool box
        box = FancyBboxPatch((tx, tool_y), tool_w, tool_h, boxstyle="round,pad=0.08",
                             facecolor='white', edgecolor=sc, linewidth=2.5)
        ax.add_patch(box)

        # Tool name (circled number)
        ax.text(tx + tool_w/2, tool_y + tool_h - 0.25, f'{i+1}  {tname}',
                ha='center', va='center', fontsize=8, fontweight='bold', color='#333333')

        # Score
        score_label = 'Very High' if tscore >= 0.8 else 'High' if tscore >= 0.6 else 'Medium' if tscore >= 0.3 else 'Low'
        ax.text(tx + tool_w/2, tool_y + 0.35,
                f'Score: {tscore:.2f}\n({score_label})',
                ha='center', va='center', fontsize=9, fontweight='bold', color=sc)

        # Arrow from input
        ax.annotate('', xy=(tx + tool_w/2, tool_y + tool_h), xytext=(tx + tool_w/2, 7.5),
                    arrowprops=dict(arrowstyle='->', color='#999999', lw=1.0))

    # 3. Merge arrows down to Final Decision
    for i in range(4):
        tx = 0.3 + i * (tool_w + tool_gap) + tool_w/2
        ax.annotate('', xy=(5.5, 4.7), xytext=(tx, tool_y),
                    arrowprops=dict(arrowstyle='->', color='#999999', lw=0.8))

    # 4. LLM Final Decision box
    draw_box(2.5, 3.8, 6.0, 0.8, c_llm,
             f'LLM Decision: is_phishing=True, confidence={confidence:.2f}, risk={risk_level}',
             fontsize=9)
    ax.annotate('', xy=(5.5, 3.8), xytext=(5.5, 4.6),
                arrowprops=dict(arrowstyle='->', color='#333333', lw=1.5))

    # 5. Rule Engine
    rules_str = ', '.join(rules_list[:4]) if rules_list else 'none'
    if len(rules_list) > 4:
        rules_str += f' +{len(rules_list)-4} more'
    draw_box(2.5, 2.5, 6.0, 0.8, c_rule,
             f'Rule Engine: [{rules_str}]', fontsize=8)
    ax.annotate('', xy=(5.5, 2.5 + 0.8), xytext=(5.5, 3.8),
                arrowprops=dict(arrowstyle='->', color='#333333', lw=1.5))

    # 6. Final output
    draw_box(3.0, 1.2, 5.0, 0.8, c_output,
             f'Final Decision\nPhishing (confidence: {confidence:.2f})', fontsize=10)
    ax.annotate('', xy=(5.5, 1.2 + 0.8), xytext=(5.5, 2.5),
                arrowprops=dict(arrowstyle='->', color='#333333', lw=1.5))

    # Key insight annotation
    ax.text(5.5, 0.4,
            f'ML probability ({ml_prob:.3f}) < 0.5 threshold: Stage 1 missed this phishing.\n'
            f'Stage 3 detected it via multi-tool analysis + rule engine.',
            ha='center', fontsize=9, style='italic', color='#333333',
            bbox=dict(boxstyle='round,pad=0.4', facecolor='lightyellow', edgecolor='goldenrod', alpha=0.9))

    plt.tight_layout()
    out = output_dir / 'fig05_s3.4_agent_flow.png'
    plt.savefig(out, dpi=300, bbox_inches='tight', facecolor='white')
    plt.close()
    print(f"  -> {out} (case: {domain})")


# ============================================================
# Fig 6: Processing Flow (Stage Counts)
# ============================================================
def generate_fig06(output_dir: Path, lang='ja'):
    """処理フロー全体像（各Stageの件数遷移）"""
    fig, ax = plt.subplots(figsize=(12, 6))
    ax.set_xlim(0, 12)
    ax.set_ylim(0, 6)
    ax.axis('off')

    # Data from progress report
    # Stage1: 127,754 -> auto_phishing 60,614 / auto_benign 6,166 / handoff 60,974
    # Stage2: 60,974 -> safe_benign 45,304 / handoff 15,670
    # Stage3: 15,670 -> phishing 2,446 / benign 13,224

    c_flow = '#5B9BD5'
    c_phishing = '#FF6B6B'
    c_benign = '#4ECDC4'
    c_handoff = '#FFC000'

    def draw_rbox(x, y, w, h, color, text, fontsize=8, alpha=0.85):
        box = FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.08",
                             facecolor=color, edgecolor='black', linewidth=1.0, alpha=alpha)
        ax.add_patch(box)
        ax.text(x + w/2, y + h/2, text, ha='center', va='center',
                fontsize=fontsize, color='white',
                fontweight='bold',
                path_effects=[pe.withStroke(linewidth=1.5, foreground='black')])

    # Stage columns
    stages_x = [0.5, 4.0, 7.5]
    stage_names = ['Stage 1\nXGBoost', 'Stage 2\nLR + Gate', 'Stage 3\nLLM + Rules']
    stage_colors = ['#4472C4', '#ED7D31', '#70AD47']

    for i, (sx, sn, sc) in enumerate(zip(stages_x, stage_names, stage_colors)):
        # Stage header
        draw_rbox(sx, 5.0, 3.0, 0.7, sc, sn, fontsize=10)

    # Stage1 results
    draw_rbox(0.5, 3.8, 1.4, 0.5, c_phishing, 'auto_phishing\n60,614', fontsize=7)
    draw_rbox(0.5, 2.3, 1.4, 0.5, c_benign, 'auto_benign\n6,166', fontsize=7)
    draw_rbox(2.1, 3.1, 1.4, 0.5, c_handoff, 'handoff\n60,974', fontsize=7)

    # Arrow Stage1 -> Stage2
    ax.annotate('', xy=(4.0, 3.35), xytext=(3.5, 3.35),
                arrowprops=dict(arrowstyle='->', color='#333333', lw=2.0))

    # Stage2 results
    draw_rbox(4.0, 2.3, 1.4, 0.5, c_benign, 'safe_benign\n45,304', fontsize=7)
    draw_rbox(5.6, 3.1, 1.4, 0.5, c_handoff, 'handoff\n15,670', fontsize=7)

    # Arrow Stage2 -> Stage3
    ax.annotate('', xy=(7.5, 3.35), xytext=(7.0, 3.35),
                arrowprops=dict(arrowstyle='->', color='#333333', lw=2.0))

    # Stage3 results
    draw_rbox(7.5, 3.8, 1.4, 0.5, c_phishing, 'phishing\n2,446', fontsize=7)
    draw_rbox(7.5, 2.3, 1.4, 0.5, c_benign, 'benign\n13,224', fontsize=7)

    # TP/FP/TN/FN annotations
    annot_style = dict(fontsize=6, color='#333333',
                       bbox=dict(boxstyle='round,pad=0.15', facecolor='white', alpha=0.9, edgecolor='gray'))

    ax.text(1.95, 4.0, 'TP:60,612\nFP:2', **annot_style)
    ax.text(1.95, 2.45, 'TN:6,158\nFN:8', **annot_style)
    ax.text(5.45, 2.45, 'TN:44,786\nFN:518', **annot_style)
    ax.text(8.95, 4.0, 'TP:1,781\nFP:665', **annot_style)
    ax.text(8.95, 2.45, 'TN:12,266\nFN:958', **annot_style)

    # Bottom summary bar
    summary_y = 0.5
    # Percentage bars
    total = 127754
    widths = [60614/total*10, 6166/total*10, 45304/total*10, 2446/total*10, 13224/total*10]
    labels = ['auto_phishing\n47.4%', 'auto_benign\n4.8%', 'safe_benign\n35.5%',
              'phishing\n1.9%', 'benign\n10.4%']
    colors = [c_phishing, c_benign, c_benign, c_phishing, c_benign]
    alphas = [0.9, 0.9, 0.7, 0.9, 0.7]

    x_pos = 1.0
    for w, lbl, clr, alp in zip(widths, labels, colors, alphas):
        box = FancyBboxPatch((x_pos, summary_y), w, 0.5, boxstyle="square,pad=0",
                             facecolor=clr, edgecolor='white', linewidth=1, alpha=alp)
        ax.add_patch(box)
        if w > 0.3:
            ax.text(x_pos + w/2, summary_y + 0.25, lbl,
                    ha='center', va='center', fontsize=6, fontweight='bold', color='white',
                    path_effects=[pe.withStroke(linewidth=1, foreground='black')])
        x_pos += w

    # Summary label
    ax.text(0.5, summary_y + 0.25,
            'Volume\nShare' if lang == 'en' else '処理\n割合',
            ha='center', va='center', fontsize=7, fontweight='bold')

    # Title
    title = ('Processing Flow: Domain Count Transition by Stage' if lang == 'en'
             else '処理フロー: Stage別ドメイン件数の遷移')
    ax.set_title(title, fontsize=13, fontweight='bold', pad=15)

    # Input annotation
    ax.text(2.0, 5.5,
            f'Input: 127,754 domains' if lang == 'en' else f'入力: 127,754件',
            ha='center', fontsize=9, fontweight='bold',
            bbox=dict(boxstyle='round,pad=0.3', facecolor='lightyellow', edgecolor='goldenrod'))

    plt.tight_layout()
    out = output_dir / 'fig06_s4.5.1_processing_flow.png'
    plt.savefig(out, dpi=300, bbox_inches='tight', facecolor='white')
    plt.close()
    print(f"  -> {out}")


# ============================================================
# Fig 7: Stage3 Detection Patterns
# ============================================================
def generate_fig07(output_dir: Path, lang='ja'):
    """Stage3検知パターンの分類"""
    # Data from stage3_detection_advantage.md
    # 327 domains that only Stage3 detected (Stage1 FN -> Stage3 TP)

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

    # Left: Detection pattern categories
    if lang == 'en':
        categories = ['DV/Free CA\ncertificate', 'Dangerous\nTLD', 'ML Paradox\n(low ML, high ctx)',
                       'Brand + low\nquality cert']
        xlabel = 'Detection count'
        title1 = 'Stage3 Detection Patterns (n=327)'
    else:
        categories = ['DV/Free CA\n証明書問題', '危険TLD\n検出', 'ML Paradox\n(低ML高ctx)',
                       'ブランド偽装+\n低品質証明書']
        xlabel = '検知件数'
        title1 = 'Stage3 検知パターン (n=327件)'

    values = [295, 223, 98, 78]
    colors = ['#FF6B6B', '#FFC000', '#5B9BD5', '#70AD47']

    bars = ax1.barh(range(len(categories)), values, color=colors, edgecolor='white', linewidth=0.5)
    ax1.set_yticks(range(len(categories)))
    ax1.set_yticklabels(categories, fontsize=9)
    ax1.set_xlabel(xlabel)
    ax1.set_title(title1, fontweight='bold')

    for i, v in enumerate(values):
        ax1.text(v + 3, i, str(v), va='center', fontsize=9, fontweight='bold')

    ax1.grid(axis='x', alpha=0.3)

    # Note about overlapping categories
    ax1.text(0.95, 0.05,
             '* Categories overlap\n  (one domain may match multiple)' if lang == 'en'
             else '※カテゴリは重複あり\n  (1ドメインが複数に該当)',
             transform=ax1.transAxes, ha='right', va='bottom', fontsize=7,
             color='#555555', style='italic')

    # Right: Top rule firings (for Stage3-only detections)
    if lang == 'en':
        rules = ['policy_r4', 'policy_r2', 'soft_ctx_trigger', 'policy_r5',
                 'policy_r1', 'policy_r6', 'brand_cert_high', 'policy_r3',
                 'hard_ctx_trigger', 'high_ml_ctx_rescue']
        title2 = 'Rule Firings in Stage3-Only Detections'
    else:
        rules = ['policy_r4', 'policy_r2', 'soft_ctx_trigger', 'policy_r5',
                 'policy_r1', 'policy_r6', 'brand_cert_high', 'policy_r3',
                 'hard_ctx_trigger', 'high_ml_ctx_rescue']
        title2 = 'Stage3固有検知のルール発動ランキング'

    rule_counts = [142, 100, 87, 79, 77, 64, 52, 42, 16, 6]

    # Color by rule category
    rule_colors = []
    for r in rules:
        if 'policy' in r:
            rule_colors.append('#4472C4')
        elif 'ctx' in r:
            rule_colors.append('#ED7D31')
        elif 'brand' in r:
            rule_colors.append('#70AD47')
        elif 'ml' in r:
            rule_colors.append('#5B9BD5')
        else:
            rule_colors.append('#A5A5A5')

    bars2 = ax2.barh(range(len(rules)-1, -1, -1), rule_counts, color=rule_colors,
                     edgecolor='white', linewidth=0.5)
    ax2.set_yticks(range(len(rules)-1, -1, -1))
    ax2.set_yticklabels(rules, fontsize=8, fontfamily='monospace')
    ax2.set_xlabel('Firing count' if lang == 'en' else '発動件数')
    ax2.set_title(title2, fontweight='bold')

    for i, v in enumerate(rule_counts):
        ax2.text(v + 1, len(rules)-1-i, str(v), va='center', fontsize=8)

    ax2.grid(axis='x', alpha=0.3)

    # Rule category legend
    legend_elements = [
        mpatches.Patch(facecolor='#4472C4', label='Policy rules'),
        mpatches.Patch(facecolor='#ED7D31', label='CTX trigger'),
        mpatches.Patch(facecolor='#70AD47', label='Brand-cert'),
        mpatches.Patch(facecolor='#5B9BD5', label='ML guard'),
    ]
    ax2.legend(handles=legend_elements, loc='lower right', fontsize=7)

    plt.tight_layout()
    out = output_dir / 'fig07_s4.4.2_detection_pattern.png'
    plt.savefig(out, dpi=300, bbox_inches='tight', facecolor='white')
    plt.close()
    print(f"  -> {out}")


# ============================================================
# Main
# ============================================================
def main():
    parser = argparse.ArgumentParser(description='Generate paper figures')
    parser.add_argument('--fig', type=int, help='Generate specific figure only (1-7)')
    parser.add_argument('--lang', choices=['ja', 'en'], default='ja',
                        help='Language for labels (default: ja)')
    args = parser.parse_args()

    setup_style()
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    generators = {
        1: ('Fig 1: Cascade Architecture', generate_fig01),
        2: ('Fig 2: XGBoost Learning Curve', generate_fig02),
        3: ('Fig 3: Feature Importance', generate_fig03),
        4: ('Fig 4: FN ML Score Distribution', generate_fig04),
        5: ('Fig 5: AI Agent Flow', generate_fig05),
        6: ('Fig 6: Processing Flow', generate_fig06),
        7: ('Fig 7: Detection Patterns', generate_fig07),
    }

    if args.fig:
        if args.fig in generators:
            name, func = generators[args.fig]
            print(f"Generating {name}...")
            func(OUTPUT_DIR, lang=args.lang)
        else:
            print(f"Error: --fig must be 1-7, got {args.fig}")
            sys.exit(1)
    else:
        print(f"Generating all 7 figures (lang={args.lang})...")
        print(f"Output: {OUTPUT_DIR}/")
        print()
        for num, (name, func) in sorted(generators.items()):
            print(f"[{num}/7] {name}...")
            func(OUTPUT_DIR, lang=args.lang)

    print(f"\nDone! All figures saved to: {OUTPUT_DIR}/")


if __name__ == '__main__':
    main()
