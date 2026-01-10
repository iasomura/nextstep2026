#!/usr/bin/env python3
"""クイックスタート: 最小限のコードで予測を実行"""

import sys
from pathlib import Path
sys.path.insert(0, "02_stage1_stage2")

from src.config import load_config
from src.features import FeatureEngineer
from src.train_xgb import Stage1Trainer
from src.route1 import Route1ThresholdSelector
import json
import pandas as pd

# ========== 設定 ==========
RUN_ID = "2026-01-10_140940"
artifacts_dir = Path(f"artifacts/{RUN_ID}")

# ========== 初期化 ==========
cfg = load_config("02_stage1_stage2/configs/default.yaml")

with open(artifacts_dir / "models/brand_keywords.json") as f:
    brand_keywords = json.load(f)

engineer = FeatureEngineer(brand_keywords)
trainer = Stage1Trainer(cfg.xgboost)
trainer.load_model(artifacts_dir / "models/xgboost_model_baseline.pkl")

with open(artifacts_dir / "models/feature_order.json") as f:
    feature_order = json.load(f)

with open(artifacts_dir / "results/route1_thresholds.json") as f:
    thresholds = json.load(f)

selector = Route1ThresholdSelector(cfg.route1)
selector.t_low = thresholds['t_low']
selector.t_high = thresholds['t_high']

# ========== ここを変更 ==========
# 分類したいドメインのリスト
YOUR_DOMAINS = [
    'example.com',
    'google.com',
    'suspicious-login.tk',
    'paypal-verify.ml',
]

# ========== 予測実行 ==========
# 特徴量抽出
features = [engineer.extract_features(d, None) for d in YOUR_DOMAINS]
df = pd.DataFrame(features, columns=engineer.get_feature_names())

# 予測
predictions = trainer.predict_proba(df, feature_order)
decisions = selector.apply_thresholds(predictions)

# 結果表示
print("\n予測結果:")
print("="*70)
for domain, pred, dec in zip(YOUR_DOMAINS, predictions, decisions):
    label = ['🟢 AUTO_BENIGN', '🟡 DEFER', '🔴 AUTO_PHISH'][dec]
    print(f"{domain:40s} {label:20s} (score={pred:.4f})")
print("="*70)

# 統計
print(f"\n統計:")
print(f"  AUTO_BENIGN: {(decisions == 0).sum()}")
print(f"  DEFER:       {(decisions == 1).sum()}")
print(f"  AUTO_PHISH:  {(decisions == 2).sum()}")
