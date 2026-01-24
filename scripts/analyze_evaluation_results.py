#!/usr/bin/env python3
"""
Evaluation Results Analysis Script
Based on 05_pipeline_analysis.ipynb
"""

import os
import json
import pickle
from pathlib import Path
from datetime import datetime

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    confusion_matrix, classification_report,
    precision_recall_curve, roc_curve, auc,
    f1_score, precision_score, recall_score
)

# Japanese font support
plt.rcParams['font.family'] = ['DejaVu Sans', 'Hiragino Sans', 'Yu Gothic', 'Meiryo', 'sans-serif']
plt.rcParams['axes.unicode_minus'] = False

# Display settings
pd.set_option('display.max_columns', 50)
pd.set_option('display.max_rows', 100)
pd.set_option('display.width', 200)

# Configuration
RUN_ID = os.environ.get('RUN_ID', '2026-01-17_132657')
BASE_DIR = Path('/data/hdd/asomura/nextstep')
ARTIFACTS_DIR = BASE_DIR / f'artifacts/{RUN_ID}'
RESULTS_DIR = ARTIFACTS_DIR / 'results'
OUTPUT_DIR = RESULTS_DIR / 'analysis_visualizations'
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

print("=" * 80)
print("Evaluation Results Analysis")
print("=" * 80)
print(f"RUN_ID: {RUN_ID}")
print(f"ARTIFACTS_DIR: {ARTIFACTS_DIR}")
print(f"OUTPUT_DIR: {OUTPUT_DIR}")

# TLD classification
HIGH_DANGER_TLDS = frozenset([
    'tk', 'ml', 'ga', 'cf', 'gq',  # Free TLDs
    'icu', 'cfd', 'sbs', 'rest', 'cyou',  # Phishing-specific
    'pw', 'buzz', 'lat',  # High phishing rate
])

MEDIUM_DANGER_TLDS = frozenset([
    'top', 'shop', 'xyz', 'cc', 'online', 'site', 'website',
    'club', 'vip', 'asia', 'one', 'link', 'click', 'live',
    'cn', 'tokyo', 'dev', 'me', 'pe', 'ar', 'cl', 'mw', 'ci',
])

def extract_tld(domain):
    """Extract TLD from domain"""
    import re
    match = re.search(r'\.([^.]+)$', str(domain))
    return match.group(1) if match else ''

def classify_tld(tld):
    """Classify TLD danger level"""
    tld = tld.lower()
    if tld in HIGH_DANGER_TLDS:
        return 'high_danger'
    elif tld in MEDIUM_DANGER_TLDS:
        return 'medium_danger'
    else:
        return 'non_danger'

# Load summary
summary_files = list((RESULTS_DIR / 'stage2_validation').glob('summary__*.json'))
if summary_files:
    summary_file = max(summary_files, key=lambda x: x.stat().st_mtime)
    with open(summary_file, 'r') as f:
        summary = json.load(f)
    print(f"\nLoaded summary: {summary_file.name}")
else:
    print("No summary file found!")
    exit(1)

# Load evaluation data
eval_files = list((RESULTS_DIR / 'stage2_validation').glob('eval_df__*.csv'))
if eval_files:
    eval_file = max(eval_files, key=lambda x: x.stat().st_mtime)
    eval_df = pd.read_csv(eval_file)
    print(f"Loaded evaluation data: {eval_file.name} ({len(eval_df)} rows)")
else:
    print("No evaluation data found!")
    exit(1)

# Load Stage1/Stage2 decisions
try:
    stage1_df = pd.read_csv(RESULTS_DIR / 'stage1_decisions_latest.csv')
    print(f"Stage1 decisions: {len(stage1_df)} rows")
except FileNotFoundError:
    stage1_df = None
    print("Stage1 decisions not found")

try:
    with open(RESULTS_DIR / 'route1_thresholds.json', 'r') as f:
        route1_thresholds = json.load(f)
    print(f"Route1 thresholds: t_low={route1_thresholds['t_low']:.4f}, t_high={route1_thresholds['t_high']:.4f}")
except FileNotFoundError:
    route1_thresholds = None

# ============================================================================
# SECTION 1: Summary Metrics Display
# ============================================================================
print("\n" + "=" * 80)
print("SECTION 1: SUMMARY METRICS")
print("=" * 80)

print("\n[All Test Set Metrics]")
print(f"  Total samples: {summary['n_all_test']:,}")
print(f"  Handoff samples: {summary['n_stage2_handoff']:,}")
print(f"  Agent evaluated: {summary['agent_covered']:,}")

print("\n[Stage1 vs Final Comparison - All Test]")
m1 = summary['metrics_stage1_all']
mf = summary['metrics_final_all']
print(f"           {'Stage1':>12} {'Final':>12} {'Diff':>12}")
print(f"  Precision: {m1['precision']:.4f}      {mf['precision']:.4f}      {mf['precision']-m1['precision']:+.4f}")
print(f"  Recall:    {m1['recall']:.4f}      {mf['recall']:.4f}      {mf['recall']-m1['recall']:+.4f}")
print(f"  F1:        {m1['f1']:.4f}      {mf['f1']:.4f}      {mf['f1']-m1['f1']:+.4f}")

print("\n[Handoff Subset Metrics]")
m1h = summary['metrics_stage1_handoff']
mfh = summary['metrics_final_handoff']
print(f"           {'Stage1':>12} {'Final':>12} {'Diff':>12}")
print(f"  Precision: {m1h['precision']:.4f}      {mfh['precision']:.4f}      {mfh['precision']-m1h['precision']:+.4f}")
print(f"  Recall:    {m1h['recall']:.4f}      {mfh['recall']:.4f}      {mfh['recall']-m1h['recall']:+.4f}")
print(f"  F1:        {m1h['f1']:.4f}      {mfh['f1']:.4f}      {mfh['f1']-m1h['f1']:+.4f}")

print("\n[Gate Metrics]")
gm = summary['gate_metrics']
print(f"  TP captured errors: {gm['TP_captured_errors']}")
print(f"  FP unneeded handoff: {gm['FP_unneeded_handoff']}")
print(f"  FN missed errors: {gm['FN_missed_errors']}")
print(f"  Error capture recall: {gm['error_capture_recall']:.4f}")
print(f"  Handoff precision: {gm['handoff_precision']:.4f}")

print("\n[Cost Analysis]")
cost = summary['cost']
print(f"  FN Cost: {cost['fn_cost']}, FP Cost: {cost['fp_cost']}")
print(f"  Stage1 only cost: {cost['stage1_only']:.0f}")
print(f"  Final cost: {cost['final']:.0f}")
print(f"  Cost reduction: {cost['stage1_only'] - cost['final']:.0f} ({(cost['stage1_only'] - cost['final'])/cost['stage1_only']*100:.1f}%)")

# ============================================================================
# SECTION 2: Confusion Matrix Visualization
# ============================================================================
print("\n" + "=" * 80)
print("SECTION 2: CONFUSION MATRIX VISUALIZATION")
print("=" * 80)

# Prepare data
eval_df['tld'] = eval_df['domain'].apply(extract_tld)
eval_df['tld_class'] = eval_df['tld'].apply(classify_tld)
eval_df['short_cert'] = eval_df['cert_validity_days'] <= 90

y_true = eval_df['y_true']
y_agent = eval_df['agent_pred'].astype(int)
y_stage1 = eval_df['stage1_pred'].astype(int)

# Create figure with subplots
fig, axes = plt.subplots(1, 2, figsize=(14, 5))

# Stage1 confusion matrix
cm1 = confusion_matrix(y_true, y_stage1)
sns.heatmap(cm1, annot=True, fmt='d', cmap='Blues', ax=axes[0],
            xticklabels=['Benign', 'Phishing'],
            yticklabels=['Benign', 'Phishing'])
axes[0].set_xlabel('Predicted')
axes[0].set_ylabel('Actual')
axes[0].set_title('Stage1 (XGBoost) Confusion Matrix')

# AI Agent confusion matrix
cm2 = confusion_matrix(y_true, y_agent)
sns.heatmap(cm2, annot=True, fmt='d', cmap='Oranges', ax=axes[1],
            xticklabels=['Benign', 'Phishing'],
            yticklabels=['Benign', 'Phishing'])
axes[1].set_xlabel('Predicted')
axes[1].set_ylabel('Actual')
axes[1].set_title('AI Agent Confusion Matrix')

plt.tight_layout()
plt.savefig(OUTPUT_DIR / 'confusion_matrices.png', dpi=150, bbox_inches='tight')
print(f"Saved: confusion_matrices.png")
plt.close()

# ============================================================================
# SECTION 3: FP/FN Analysis
# ============================================================================
print("\n" + "=" * 80)
print("SECTION 3: FP/FN ANALYSIS")
print("=" * 80)

# Calculate metrics
agent_tp = ((y_agent == 1) & (y_true == 1)).sum()
agent_fp = ((y_agent == 1) & (y_true == 0)).sum()
agent_tn = ((y_agent == 0) & (y_true == 0)).sum()
agent_fn = ((y_agent == 0) & (y_true == 1)).sum()

stage1_tp = ((y_stage1 == 1) & (y_true == 1)).sum()
stage1_fp = ((y_stage1 == 1) & (y_true == 0)).sum()
stage1_tn = ((y_stage1 == 0) & (y_true == 0)).sum()
stage1_fn = ((y_stage1 == 0) & (y_true == 1)).sum()

print(f"\n[Stage1 vs AI Agent Comparison]")
print(f"             {'Stage1':>10} {'AI Agent':>10} {'Diff':>10}")
print(f"  TP:        {stage1_tp:>10} {agent_tp:>10} {agent_tp-stage1_tp:>+10}")
print(f"  FP:        {stage1_fp:>10} {agent_fp:>10} {agent_fp-stage1_fp:>+10}")
print(f"  TN:        {stage1_tn:>10} {agent_tn:>10} {agent_tn-stage1_tn:>+10}")
print(f"  FN:        {stage1_fn:>10} {agent_fn:>10} {agent_fn-stage1_fn:>+10}")

# FP Analysis
fp_cases = eval_df[(eval_df['agent_pred'] == True) & (eval_df['y_true'] == 0)].copy()
fn_cases = eval_df[(eval_df['agent_pred'] == False) & (eval_df['y_true'] == 1)].copy()

print(f"\n[FP Analysis - {len(fp_cases)} cases]")
print("  By TLD class:")
for tld_class in ['non_danger', 'medium_danger', 'high_danger']:
    count = (fp_cases['tld_class'] == tld_class).sum()
    pct = count / len(fp_cases) * 100 if len(fp_cases) > 0 else 0
    print(f"    {tld_class}: {count} ({pct:.1f}%)")

print("\n  By ML probability:")
ml_bins = [0, 0.15, 0.20, 0.30, 0.50, 1.0]
fp_cases['ml_bin'] = pd.cut(fp_cases['ml_probability'], bins=ml_bins)
for bin_label, count in fp_cases['ml_bin'].value_counts().sort_index().items():
    print(f"    {bin_label}: {count}")

print(f"\n[FN Analysis - {len(fn_cases)} cases]")
print("  By TLD class:")
for tld_class in ['non_danger', 'medium_danger', 'high_danger']:
    count = (fn_cases['tld_class'] == tld_class).sum()
    pct = count / len(fn_cases) * 100 if len(fn_cases) > 0 else 0
    print(f"    {tld_class}: {count} ({pct:.1f}%)")

# ============================================================================
# SECTION 4: Extra FP Analysis
# ============================================================================
print("\n" + "=" * 80)
print("SECTION 4: EXTRA FP ANALYSIS (Agent adds incorrect PHISH)")
print("=" * 80)

# Extra FP: Stage1 = BENIGN (correct), Agent = PHISH (wrong)
extra_fp = eval_df[
    (eval_df['stage1_pred'] == 0) &
    (eval_df['agent_pred'] == True) &
    (eval_df['y_true'] == 0)
].copy()

# Extra TP: Stage1 = BENIGN (wrong), Agent = PHISH (correct)
extra_tp = eval_df[
    (eval_df['stage1_pred'] == 0) &
    (eval_df['agent_pred'] == True) &
    (eval_df['y_true'] == 1)
].copy()

print(f"\nExtra FP (Agent adds): {len(extra_fp)}")
print(f"Extra TP (Agent saves): {len(extra_tp)}")
print(f"Net benefit: {len(extra_tp) - len(extra_fp)} TP gained (considering FN cost)")

if len(extra_fp) > 0:
    print("\n[Extra FP by TLD class]")
    for tld_class in ['non_danger', 'medium_danger', 'high_danger']:
        count = (extra_fp['tld_class'] == tld_class).sum()
        pct = count / len(extra_fp) * 100
        print(f"  {tld_class}: {count} ({pct:.1f}%)")

    print("\n[Extra FP ML distribution]")
    extra_fp['ml_bin'] = pd.cut(extra_fp['ml_probability'], bins=ml_bins)
    for bin_label, count in extra_fp['ml_bin'].value_counts().sort_index().items():
        print(f"  {bin_label}: {count}")

    # Sample Extra FP
    print("\n[Sample Extra FP (non-danger TLD, ML < 0.35)]")
    sample_extra_fp = extra_fp[
        (extra_fp['tld_class'] == 'non_danger') &
        (extra_fp['ml_probability'] < 0.35)
    ][['domain', 'ml_probability', 'cert_validity_days', 'cert_san_count']].head(10)
    if len(sample_extra_fp) > 0:
        for _, row in sample_extra_fp.iterrows():
            print(f"  {row['domain']:<45} ML={row['ml_probability']:.3f} cert={row['cert_validity_days']:.0f}d SAN={row['cert_san_count']:.0f}")

# ============================================================================
# SECTION 5: Gate Configuration Simulation
# ============================================================================
print("\n" + "=" * 80)
print("SECTION 5: GATE CONFIGURATION SIMULATION")
print("=" * 80)

def calc_metrics(y_pred, y_true):
    tp = ((y_pred == 1) & (y_true == 1)).sum()
    fp = ((y_pred == 1) & (y_true == 0)).sum()
    tn = ((y_pred == 0) & (y_true == 0)).sum()
    fn = ((y_pred == 0) & (y_true == 1)).sum()
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    return {'TP': tp, 'FP': fp, 'TN': tn, 'FN': fn, 'Precision': precision, 'Recall': recall, 'F1': f1}

# Current metrics
current = calc_metrics(y_agent, y_true)
stage1_only = calc_metrics(y_stage1, y_true)

# Gate simulations
gate_configs = [
    ('Current (AI Agent)', None),
    ('Stage1 Only', None),
    ('Gate A: non_danger + ML<0.30', lambda df: (df['tld_class'] == 'non_danger') & (df['ml_probability'] < 0.30)),
    ('Gate B: non_danger + ML<0.35', lambda df: (df['tld_class'] == 'non_danger') & (df['ml_probability'] < 0.35)),
    ('Gate C: non_danger + ML<0.40', lambda df: (df['tld_class'] == 'non_danger') & (df['ml_probability'] < 0.40)),
]

results = []
for name, condition_fn in gate_configs:
    if name == 'Current (AI Agent)':
        metrics = current.copy()
    elif name == 'Stage1 Only':
        metrics = stage1_only.copy()
    else:
        y_sim = y_agent.copy()
        block_mask = (eval_df['agent_pred'] == True) & condition_fn(eval_df)
        y_sim[block_mask] = 0
        metrics = calc_metrics(y_sim, y_true)
    metrics['Config'] = name
    results.append(metrics)

results_df = pd.DataFrame(results)
results_df = results_df[['Config', 'TP', 'FP', 'TN', 'FN', 'Precision', 'Recall', 'F1']]

print("\n[Gate Configuration Comparison]")
print("-" * 90)
print(f"{'Config':<30} {'TP':>6} {'FP':>6} {'TN':>6} {'FN':>6} {'Prec':>8} {'Recall':>8} {'F1':>8}")
print("-" * 90)
for _, row in results_df.iterrows():
    print(f"{row['Config']:<30} {row['TP']:>6} {row['FP']:>6} {row['TN']:>6} {row['FN']:>6} {row['Precision']:>8.4f} {row['Recall']:>8.4f} {row['F1']:>8.4f}")
print("-" * 90)

# ============================================================================
# SECTION 6: Visualization - ML Distribution
# ============================================================================
print("\n" + "=" * 80)
print("SECTION 6: ML PROBABILITY DISTRIBUTION")
print("=" * 80)

fig, axes = plt.subplots(2, 2, figsize=(14, 10))

# Plot 1: ML distribution by actual class
ax = axes[0, 0]
for label, name, color in [(0, 'Benign', 'blue'), (1, 'Phishing', 'red')]:
    subset = eval_df[eval_df['y_true'] == label]['ml_probability']
    ax.hist(subset, bins=50, alpha=0.6, label=f'{name} (n={len(subset)})', color=color)
ax.set_xlabel('ML Probability')
ax.set_ylabel('Count')
ax.set_title('ML Probability Distribution by Actual Class')
ax.legend()

# Plot 2: ML distribution for FP and FN
ax = axes[0, 1]
if len(fp_cases) > 0:
    ax.hist(fp_cases['ml_probability'], bins=30, alpha=0.6, label=f'FP (n={len(fp_cases)})', color='orange')
if len(fn_cases) > 0:
    ax.hist(fn_cases['ml_probability'], bins=30, alpha=0.6, label=f'FN (n={len(fn_cases)})', color='purple')
ax.set_xlabel('ML Probability')
ax.set_ylabel('Count')
ax.set_title('ML Probability Distribution for Errors')
ax.legend()

# Plot 3: FP by TLD class
ax = axes[1, 0]
tld_fp_counts = fp_cases['tld_class'].value_counts()
colors = {'non_danger': 'green', 'medium_danger': 'yellow', 'high_danger': 'red'}
bars = ax.bar(tld_fp_counts.index, tld_fp_counts.values,
              color=[colors.get(x, 'gray') for x in tld_fp_counts.index])
ax.set_xlabel('TLD Class')
ax.set_ylabel('Count')
ax.set_title('FP by TLD Class')
for bar, val in zip(bars, tld_fp_counts.values):
    ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1, str(val), ha='center')

# Plot 4: FN by TLD class
ax = axes[1, 1]
tld_fn_counts = fn_cases['tld_class'].value_counts()
bars = ax.bar(tld_fn_counts.index, tld_fn_counts.values,
              color=[colors.get(x, 'gray') for x in tld_fn_counts.index])
ax.set_xlabel('TLD Class')
ax.set_ylabel('Count')
ax.set_title('FN by TLD Class')
for bar, val in zip(bars, tld_fn_counts.values):
    ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1, str(val), ha='center')

plt.tight_layout()
plt.savefig(OUTPUT_DIR / 'ml_distribution_analysis.png', dpi=150, bbox_inches='tight')
print(f"Saved: ml_distribution_analysis.png")
plt.close()

# ============================================================================
# SECTION 7: Certificate Analysis
# ============================================================================
print("\n" + "=" * 80)
print("SECTION 7: CERTIFICATE ANALYSIS")
print("=" * 80)

fig, axes = plt.subplots(1, 2, figsize=(14, 5))

# Cert validity distribution
ax = axes[0]
for label, name, color in [(0, 'Benign', 'blue'), (1, 'Phishing', 'red')]:
    subset = eval_df[eval_df['y_true'] == label]['cert_validity_days']
    ax.hist(subset, bins=50, alpha=0.6, label=f'{name}', color=color, range=(0, 400))
ax.axvline(90, color='green', linestyle='--', label='90 days (Let\'s Encrypt)')
ax.set_xlabel('Certificate Validity Days')
ax.set_ylabel('Count')
ax.set_title('Certificate Validity Distribution')
ax.legend()

# SAN count distribution
ax = axes[1]
san_data = eval_df[eval_df['cert_san_count'] <= 20]  # Limit for visibility
for label, name, color in [(0, 'Benign', 'blue'), (1, 'Phishing', 'red')]:
    subset = san_data[san_data['y_true'] == label]['cert_san_count']
    ax.hist(subset, bins=20, alpha=0.6, label=f'{name}', color=color)
ax.set_xlabel('SAN Count')
ax.set_ylabel('Count')
ax.set_title('Certificate SAN Count Distribution')
ax.legend()

plt.tight_layout()
plt.savefig(OUTPUT_DIR / 'certificate_analysis.png', dpi=150, bbox_inches='tight')
print(f"Saved: certificate_analysis.png")
plt.close()

# ============================================================================
# SECTION 8: Summary Report
# ============================================================================
print("\n" + "=" * 80)
print("SUMMARY REPORT")
print("=" * 80)

print(f"""
RUN_ID: {RUN_ID}
Timestamp: {summary['timestamp']}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

=== PIPELINE OVERVIEW ===
Total Test Samples: {summary['n_all_test']:,}
Stage2 Handoff Candidates: {summary['n_stage2_handoff']:,}
AI Agent Evaluated: {summary['agent_covered']:,}

=== PERFORMANCE METRICS (All Test) ===
                  Stage1        Final         Diff
Precision:        {m1['precision']:.4f}       {mf['precision']:.4f}       {mf['precision']-m1['precision']:+.4f}
Recall:           {m1['recall']:.4f}       {mf['recall']:.4f}       {mf['recall']-m1['recall']:+.4f}
F1:               {m1['f1']:.4f}       {mf['f1']:.4f}       {mf['f1']-m1['f1']:+.4f}

=== PERFORMANCE METRICS (Handoff Subset) ===
                  Stage1        Final         Diff
Precision:        {m1h['precision']:.4f}       {mfh['precision']:.4f}       {mfh['precision']-m1h['precision']:+.4f}
Recall:           {m1h['recall']:.4f}       {mfh['recall']:.4f}       {mfh['recall']-m1h['recall']:+.4f}
F1:               {m1h['f1']:.4f}       {mfh['f1']:.4f}       {mfh['f1']-m1h['f1']:+.4f}

=== COST ANALYSIS ===
Stage1 Only Cost: {cost['stage1_only']:.0f}
Final Cost:       {cost['final']:.0f}
Cost Reduction:   {cost['stage1_only'] - cost['final']:.0f} ({(cost['stage1_only'] - cost['final'])/cost['stage1_only']*100:.1f}%)

=== ERROR ANALYSIS (Handoff Subset) ===
Stage1:  TP={stage1_tp}, FP={stage1_fp}, FN={stage1_fn}
Agent:   TP={agent_tp}, FP={agent_fp}, FN={agent_fn}
Extra TP (Agent saves): {len(extra_tp)}
Extra FP (Agent adds):  {len(extra_fp)}

=== KEY FINDINGS ===
1. AI Agent improves recall by {(agent_tp - stage1_tp)} TP
2. AI Agent adds {len(extra_fp)} extra FP
3. Net cost improvement: {cost['stage1_only'] - cost['final']:.0f} (FN×3 + FP×1)

=== VISUALIZATIONS SAVED ===
- {OUTPUT_DIR / 'confusion_matrices.png'}
- {OUTPUT_DIR / 'ml_distribution_analysis.png'}
- {OUTPUT_DIR / 'certificate_analysis.png'}
""")

print("\n[DONE] Analysis complete.")
