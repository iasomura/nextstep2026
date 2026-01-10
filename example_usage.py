#!/usr/bin/env python3
"""
Phase 2.0 モジュールの実使用例

このスクリプトは、Phase 2.0で作成したモジュールを使って
実際にフィッシング検出パイプラインを実行する方法を示します。
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent / "02_stage1_stage2"))

import numpy as np
import pandas as pd
import json
import joblib

from src.config import load_config
from src.features import FeatureEngineer
from src.train_xgb import Stage1Trainer
from src.route1 import Route1ThresholdSelector
from src.stage2_gate import Stage2Gate

print("="*80)
print("Phase 2.0 モジュール使用例")
print("="*80)

# ========================================
# Step 1: 設定とアーティファクトの読み込み
# ========================================
print("\n📋 Step 1: 設定の読み込み")

# YAMLから設定を読み込み
config_path = "02_stage1_stage2/configs/default.yaml"
cfg = load_config(config_path)
print(f"✅ Config loaded from: {config_path}")

# 既存のartifactsを使用（または新しいRUN_IDを指定）
RUN_ID = "2026-01-10_140940"  # 最新のRUN_IDに変更可能
artifacts_dir = Path("artifacts") / RUN_ID

# ブランドキーワードを読み込み
brand_keywords_path = artifacts_dir / "models" / "brand_keywords.json"
with open(brand_keywords_path) as f:
    brand_keywords = json.load(f)
print(f"✅ Brand keywords loaded: {len(brand_keywords)} keywords")

# ========================================
# Step 2: Feature Engineerの初期化
# ========================================
print("\n🔧 Step 2: Feature Engineerの初期化")

engineer = FeatureEngineer(brand_keywords=brand_keywords)
print(f"✅ FeatureEngineer created")
print(f"   Total features: {len(engineer.get_feature_names())}")

# ========================================
# Step 3: 新しいドメインから特徴量を抽出
# ========================================
print("\n🎯 Step 3: 特徴量抽出の例")

# 例: 新しいドメインのリスト
new_domains = [
    'google.com',
    'paypal-secure.tk',
    'amazon-verify.ml',
    'microsoft-login.xyz',
    'legitimate-site.org'
]

# 特徴量を抽出（実際にはCSVやDBから読み込むことが多い）
features_list = []
for domain in new_domains:
    features = engineer.extract_features(domain, cert_data=None)
    features_list.append(features)

# DataFrameに変換
df_new = pd.DataFrame(
    features_list,
    columns=engineer.get_feature_names()
)
df_new['domain'] = new_domains

print(f"✅ 特徴量抽出完了: {len(df_new)} domains")
print(f"\n   サンプル:")
print(df_new[['domain', 'domain_length', 'contains_brand', 'tld_length']].head())

# ========================================
# Step 4: Stage1 XGBoostモデルで予測
# ========================================
print("\n🤖 Step 4: Stage1 予測")

# モデルを読み込み
model_path = artifacts_dir / "models" / "xgboost_model_baseline.pkl"
trainer = Stage1Trainer(cfg.xgboost)
trainer.load_model(model_path)

# 特徴量の順序を読み込み
feature_order_path = artifacts_dir / "models" / "feature_order.json"
with open(feature_order_path) as f:
    feature_order = json.load(f)

# 予測
p1 = trainer.predict_proba(df_new, feature_order)
df_new['p1_score'] = p1

print(f"✅ Stage1 predictions:")
for idx, row in df_new.iterrows():
    print(f"   {row['domain']:30s} → {row['p1_score']:.4f}")

# ========================================
# Step 5: Route1 閾値で分類
# ========================================
print("\n🚦 Step 5: Route1 閾値適用")

# 既存の閾値を読み込み（または新しく選択）
route1_path = artifacts_dir / "results" / "route1_thresholds.json"
if route1_path.exists():
    with open(route1_path) as f:
        thresholds = json.load(f)

    selector = Route1ThresholdSelector(cfg.route1)
    selector.t_low = thresholds['t_low']
    selector.t_high = thresholds['t_high']
    selector.selection_meta = thresholds

    print(f"✅ Thresholds loaded:")
    print(f"   t_low:  {selector.t_low:.6f}")
    print(f"   t_high: {selector.t_high:.6f}")
else:
    # デフォルト値を使用
    print("ℹ️  閾値ファイルが見つかりません。デフォルト値を使用します。")
    selector = Route1ThresholdSelector(cfg.route1)
    selector.t_low = 0.2
    selector.t_high = 0.8
    selector.selection_meta = {'t_low': 0.2, 't_high': 0.8}

# 閾値を適用して分類
decisions = selector.apply_thresholds(p1)
df_new['route1_decision'] = decisions

# 分類結果をラベルに変換
decision_map = {0: 'AUTO_BENIGN', 1: 'DEFER', 2: 'AUTO_PHISH'}
df_new['route1_label'] = df_new['route1_decision'].map(decision_map)

print(f"\n✅ Route1 分類結果:")
print(f"   AUTO_BENIGN: {(decisions == 0).sum()}")
print(f"   DEFER:       {(decisions == 1).sum()}")
print(f"   AUTO_PHISH:  {(decisions == 2).sum()}")

print(f"\n   詳細:")
for idx, row in df_new.iterrows():
    print(f"   {row['domain']:30s} → {row['route1_label']:12s} (p={row['p1_score']:.4f})")

# ========================================
# Step 6: DEFER領域をStage2で選別
# ========================================
print("\n🚪 Step 6: Stage2 Gate適用")

# DEFER領域のみを抽出
df_defer = df_new[df_new['route1_decision'] == 1].copy()

if len(df_defer) > 0:
    print(f"✅ DEFER candidates: {len(df_defer)}")

    # Stage2 Gateを適用
    gate = Stage2Gate(cfg.stage2, brand_keywords)

    # DEFER領域の予測スコア（Stage1を再利用）
    p2 = df_defer['p1_score'].values

    # segment_priority選択を適用
    df_defer = gate.select_segment_priority(df_defer, p2)

    # 結果をマージ
    df_new.loc[df_defer.index, 'stage2_decision'] = df_defer['stage2_decision']

    # 最終決定を作成
    df_new['final_decision'] = df_new['route1_label'].copy()
    handoff_mask = df_new['stage2_decision'] == 'handoff'
    df_new.loc[handoff_mask, 'final_decision'] = 'HANDOFF_TO_STAGE3'

    print(f"\n✅ Stage2 選択結果:")
    print(f"   Handoff to Stage3: {handoff_mask.sum()}")
    print(f"   PENDING: {(df_new['stage2_decision'] == 'drop_to_auto').sum()}")
else:
    print(f"ℹ️  DEFER candidates: 0 (全てAUTO分類)")
    df_new['stage2_decision'] = None
    df_new['final_decision'] = df_new['route1_label'].copy()

# ========================================
# Step 7: 最終結果の表示
# ========================================
print("\n" + "="*80)
print("📊 最終結果")
print("="*80)

print("\n各ドメインの最終判定:")
for idx, row in df_new.iterrows():
    print(f"{row['domain']:30s} → {row['final_decision']:20s} (Stage1: {row['p1_score']:.4f})")

print(f"\n全体の統計:")
print(df_new['final_decision'].value_counts().to_string())

# ========================================
# Step 8: 結果の保存（オプション）
# ========================================
print("\n💾 結果の保存")

output_dir = Path("results") / "manual_run"
output_dir.mkdir(parents=True, exist_ok=True)

# CSVで保存
output_path = output_dir / "predictions.csv"
df_new.to_csv(output_path, index=False)
print(f"✅ Results saved to: {output_path}")

# 統計をJSONで保存
stats = {
    'total_domains': len(df_new),
    'auto_benign': int((df_new['route1_decision'] == 0).sum()),
    'auto_phish': int((df_new['route1_decision'] == 2).sum()),
    'defer': int((df_new['route1_decision'] == 1).sum()),
    'handoff_to_stage3': int((df_new.get('stage2_decision') == 'handoff').sum()),
    'pending': int((df_new.get('stage2_decision') == 'drop_to_auto').sum())
}

stats_path = output_dir / "stats.json"
with open(stats_path, 'w') as f:
    json.dump(stats, f, indent=2)
print(f"✅ Statistics saved to: {stats_path}")

print("\n" + "="*80)
print("✨ 完了!")
print("="*80)
print("\n使い方:")
print("  1. new_domainsリストを実際のドメインに変更")
print("  2. 必要に応じてRUN_IDを最新のものに変更")
print("  3. python example_usage.py で実行")
print("="*80)
