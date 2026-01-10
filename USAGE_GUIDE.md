# Phase 2.1 モジュール使用ガイド

Phase 2.1で完成した統合スクリプトとモジュールの使い方を説明します。

---

## 📖 目次

1. [基本的な使い方（新しいドメインを分類）](#1-基本的な使い方)
2. [既存データで評価](#2-既存データで評価)
3. [バッチ処理](#3-バッチ処理)
4. [カスタマイズ](#4-カスタマイズ)
5. [Phase 2.1での改善予定](#5-phase-21での改善予定)

---

## 1. 基本的な使い方

### ✨ Phase 2.1 NEW: 統合スクリプト `02_main.py`

**最も推奨される方法です！** 1コマンドで完全なパイプラインが実行できます。

#### 予測モード（CSVファイルから）

```bash
# CSVファイルのドメインを分類
python 02_main.py --predict --input domains.csv --output results.csv

# 例: テストドメインで実行
echo "domain
google.com
paypal-secure.tk
example.com" > /tmp/test.csv

python 02_main.py --predict --input /tmp/test.csv
```

**結果**:
- `results/predictions_<RUN_ID>.csv` - 全ての特徴量と分類結果
- `results/stats_<RUN_ID>.json` - 統計情報

#### インタラクティブモード

```bash
# 対話的にドメインを分類
python 02_main.py --interactive

# 実行例:
# Domain: paypal-secure.tk
#    Result: 🔴 AUTO_PHISH
#    Score:  0.9999
#    Thresholds: t_low=0.0003, t_high=0.9885
```

#### オプション

```bash
# 特定のRUN_IDを使用
python 02_main.py --predict --input domains.csv --run-id 2026-01-10_140940

# Stage2をスキップ
python 02_main.py --predict --input domains.csv --skip-stage2

# Stage2予算を変更
python 02_main.py --predict --input domains.csv --stage2-budget 10000
```

---

### 従来の方法（Phase 2.0）

以下の方法も引き続き使用できます。

#### 簡単な例（`quick_start.py`を使用）

```bash
# 1. サンプルスクリプトを実行
python quick_start.py

# 2. 結果を確認
cat results/manual_run/predictions.csv
cat results/manual_run/stats.json
```

### コードをカスタマイズして使用

```python
import sys
from pathlib import Path
sys.path.insert(0, "02_stage1_stage2")

from src.config import load_config
from src.features import FeatureEngineer
from src.train_xgb import Stage1Trainer
from src.route1 import Route1ThresholdSelector
from src.stage2_gate import Stage2Gate
import json
import pandas as pd

# 設定読み込み
cfg = load_config("02_stage1_stage2/configs/default.yaml")

# Artifactsから必要なファイルを読み込み
RUN_ID = "2026-01-10_140940"  # 最新のものに変更可能
artifacts_dir = Path(f"artifacts/{RUN_ID}")

# ブランドキーワード
with open(artifacts_dir / "models/brand_keywords.json") as f:
    brand_keywords = json.load(f)

# 特徴量エンジニア
engineer = FeatureEngineer(brand_keywords)

# 新しいドメインから特徴量抽出
domains = ['example.com', 'suspicious-site.tk']
features = [engineer.extract_features(d, None) for d in domains]
df = pd.DataFrame(features, columns=engineer.get_feature_names())
df['domain'] = domains

# Stage1予測
trainer = Stage1Trainer(cfg.xgboost)
trainer.load_model(artifacts_dir / "models/xgboost_model_baseline.pkl")

with open(artifacts_dir / "models/feature_order.json") as f:
    feature_order = json.load(f)

predictions = trainer.predict_proba(df, feature_order)

# Route1分類
with open(artifacts_dir / "results/route1_thresholds.json") as f:
    thresholds = json.load(f)

selector = Route1ThresholdSelector(cfg.route1)
selector.t_low = thresholds['t_low']
selector.t_high = thresholds['t_high']
decisions = selector.apply_thresholds(predictions)

# 結果表示
for domain, pred, dec in zip(domains, predictions, decisions):
    label = ['AUTO_BENIGN', 'DEFER', 'AUTO_PHISH'][dec]
    print(f"{domain}: {label} (score={pred:.4f})")
```

---

## 2. 既存データで評価

既存のartifactsデータを使って評価する場合:

```python
import joblib

# テストデータを読み込み
test_data_path = Path(f"artifacts/{RUN_ID}/processed/test_data.pkl")
test_data = joblib.load(test_data_path)

# データを展開
X_test = test_data['X']
y_test = test_data['y']
domains = test_data.get('domains', [])
feature_names = test_data.get('feature_names', [])

# DataFrameに変換
df_test = pd.DataFrame(X_test, columns=feature_names)
df_test['y_true'] = y_test
if len(domains) > 0:
    df_test['domain'] = domains

# サンプルを取得（全データは多すぎる場合）
df_sample = df_test.head(1000)

# Stage1予測
trainer = Stage1Trainer(cfg.xgboost)
trainer.load_model(artifacts_dir / "models/xgboost_model_baseline.pkl")

with open(artifacts_dir / "models/feature_order.json") as f:
    feature_order = json.load(f)

predictions = trainer.predict_proba(df_sample, feature_order)

# Route1適用
selector = Route1ThresholdSelector(cfg.route1)
with open(artifacts_dir / "results/route1_thresholds.json") as f:
    thresholds = json.load(f)
selector.t_low = thresholds['t_low']
selector.t_high = thresholds['t_high']

decisions = selector.apply_thresholds(predictions)

# 評価
from sklearn.metrics import classification_report, confusion_matrix

# AUTO_BENIGN/AUTO_PHISHのみを評価
auto_mask = decisions != 1  # DEFER以外
y_pred = (decisions[auto_mask] == 2).astype(int)
y_true = df_sample.loc[auto_mask, 'y_true'].values

print("Auto classification metrics:")
print(classification_report(y_true, y_pred))
print("\nConfusion matrix:")
print(confusion_matrix(y_true, y_pred))

# DEFER領域のStage2評価
df_defer = df_sample[decisions == 1].copy()
if len(df_defer) > 0:
    gate = Stage2Gate(cfg.stage2, brand_keywords)
    p_defer = predictions[decisions == 1]
    df_defer = gate.select_segment_priority(df_defer, p_defer)

    print(f"\nStage2 selection:")
    print(f"  Handoff: {(df_defer['stage2_decision'] == 'handoff').sum()}")
    print(f"  PENDING: {(df_defer['stage2_decision'] == 'drop_to_auto').sum()}")
```

---

## 3. バッチ処理

大量のドメインを処理する場合:

```python
def process_domains_batch(domains, batch_size=1000):
    """
    大量のドメインをバッチ処理

    Args:
        domains: List of domain names
        batch_size: Batch size for processing

    Returns:
        DataFrame with predictions
    """
    results = []

    for i in range(0, len(domains), batch_size):
        batch = domains[i:i+batch_size]
        print(f"Processing batch {i//batch_size + 1}/{(len(domains)-1)//batch_size + 1}")

        # 特徴量抽出
        features = [engineer.extract_features(d, None) for d in batch]
        df_batch = pd.DataFrame(features, columns=engineer.get_feature_names())
        df_batch['domain'] = batch

        # 予測
        predictions = trainer.predict_proba(df_batch, feature_order)
        decisions = selector.apply_thresholds(predictions)

        df_batch['prediction'] = predictions
        df_batch['decision'] = decisions

        results.append(df_batch)

    return pd.concat(results, ignore_index=True)

# 使用例
domains_list = [...]  # 大量のドメインリスト
df_results = process_domains_batch(domains_list)

# 結果を保存
df_results.to_csv('batch_predictions.csv', index=False)
```

---

## 4. カスタマイズ

### 4.1 閾値を変更

```python
# 独自の閾値を使用
selector = Route1ThresholdSelector(cfg.route1)
selector.t_low = 0.1   # より多くをAUTO_BENIGNに
selector.t_high = 0.9  # より少なくをAUTO_PHISHに
selector.selection_meta = {'t_low': 0.1, 't_high': 0.9, 'mode': 'manual'}

decisions = selector.apply_thresholds(predictions)
```

### 4.2 Stage2予算を変更

```python
# Stage2の予算を変更（一時的に）
from dataclasses import replace

custom_stage2_config = replace(cfg.stage2, max_budget=10000)
gate = Stage2Gate(custom_stage2_config, brand_keywords)

# または設定ファイルを直接編集
# 02_stage1_stage2/configs/default.yaml の stage2.max_budget を変更
```

### 4.3 証明書データを使用

```python
# 証明書データがある場合
cert_data = {
    'not_before': '2024-01-01',
    'not_after': '2025-01-01',
    'issuer': 'Let\'s Encrypt',
    'subject': {'CN': 'example.com'},
    'san': ['example.com', 'www.example.com'],
    # ... その他の証明書情報
}

features = engineer.extract_features('example.com', cert_data)
```

---

## 5. Phase 2.1での改善 ✅

**Phase 2.1 完了！** 以下の改善が実装されました:

### 5.1 統合スクリプト `02_main.py` ✅

```bash
# ✅ 実装済み！
python 02_main.py --predict --input domains.csv --output results.csv
python 02_main.py --interactive
```

**実装された機能**:
- ✅ 予測モード（CSVファイルから）
- ✅ インタラクティブモード（対話的分類）
- ✅ 自動RUN_ID検出
- ✅ Stage2予算カスタマイズ
- ✅ 統計情報の自動保存

### 5.2 完全なデータパイプライン ✅

```
✅ 入力CSV → 特徴量抽出 → Stage1予測 → Route1分類 → Stage2選択 → 結果出力
```

全体が1コマンドで実行可能になりました！

### 5.3 Regression Test ✅

```bash
# Notebookとの結果を比較するテスト
python test_regression.py
```

**検証項目**:
- ✅ Stage1予測の一致性
- ✅ Route1閾値の正確性
- ✅ Stage2選択の動作確認
- ✅ 特徴量の整合性

### 5.4 Phase 2.2以降の予定

**実験フレームワーク** (Phase 2.2で実装予定):

```bash
# 異なる設定で実験を実行
python run_experiment.py --config configs/experiment1.yaml
python run_experiment.py --config configs/experiment2.yaml

# 結果を比較
python compare_results.py --run1 exp1 --run2 exp2
```

---

## 📁 ファイル構成

現在の使用に必要なファイル:

```
nextstep/
├── 02_stage1_stage2/
│   ├── src/
│   │   ├── config.py           # 設定管理
│   │   ├── features.py         # 特徴量抽出
│   │   ├── train_xgb.py        # Stage1訓練・予測
│   │   ├── route1.py           # Route1閾値
│   │   └── stage2_gate.py      # Stage2ゲート
│   └── configs/
│       └── default.yaml        # デフォルト設定
├── artifacts/
│   └── {RUN_ID}/
│       ├── models/
│       │   ├── xgboost_model_baseline.pkl
│       │   ├── brand_keywords.json
│       │   └── feature_order.json
│       └── results/
│           └── route1_thresholds.json
├── example_usage.py            # 使用例スクリプト
└── test_integration.py         # 統合テスト
```

---

## 🔧 トラブルシューティング

### Q1: モデルが読み込めない

```python
# エラー: UnicodeDecodeError
# 解決: load_model()が自動的に.pklを検出するはず

# 手動で読み込む場合
import joblib
model = joblib.load('artifacts/.../xgboost_model_baseline.pkl')
trainer.model = model
```

### Q2: 予測値が全て同じ

証明書データがない場合、特徴量が不完全になります:
- 証明書特徴量（20個）が全てデフォルト値になる
- ドメイン特徴量（15個）のみで予測される

→ より正確な予測には証明書データが必要

### Q3: GPU warningが出る

```python
# CPU使用を明示
import os
os.environ['CUDA_VISIBLE_DEVICES'] = ''

# またはモデルのデバイスを変更（Phase 2.1で対応予定）
```

---

## 📞 サポート

問題や質問がある場合:
1. `test_integration.py`を実行して基本動作を確認
2. `example_usage.py`を参考に実装
3. Phase 2.1の完成を待つ（統合スクリプトが利用可能に）

---

**Last updated**: 2026-01-10
**Phase**: 2.1 (Full Integration Complete) ✅
**Next Phase**: 2.2 (Experimentation Framework)
