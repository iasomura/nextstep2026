# 02_main.py 仕様書

**作成日**: 2026-01-10
**基準ノートブック**: 02_original.ipynb (43 cells)
**目的**: 02_original.ipynbと完全に同じ動作をするPythonスクリプトを作成

---

## 1. 処理フロー概要

```
┌─────────────────────────────────────────────────────────────────────┐
│                        02_main.py 処理フロー                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. 初期化                                                          │
│     ├── RUN_ID解決 (env → _current → latest → new)                  │
│     ├── ディレクトリ作成 (artifacts/<RUN_ID>/*)                      │
│     └── 設定読み込み (cfg dict or YAML)                              │
│                                                                     │
│  2. LLMブランドキーワード抽出 [Cell 15]                              │
│     ├── PostgreSQL接続 (phishtank_entries, jpcert_phishing_urls)    │
│     ├── vLLM/OpenAI SDK経由でQwen3-14B-FP8呼び出し                   │
│     └── BRAND_KEYWORDS リスト生成                                    │
│                                                                     │
│  3. データ読み込み・特徴量抽出 [Cell 13, 17, 19]                     │
│     ├── prepared_data.pkl 読み込み                                   │
│     ├── ドメイン特徴量 (15個) + 証明書特徴量 (20個) = 35特徴量        │
│     ├── Train/Test分割                                               │
│     └── train_data.pkl, test_data.pkl 保存                           │
│                                                                     │
│  4. XGBoost学習 (Stage1) [Cell 22]                                  │
│     ├── Early stopping付き学習                                       │
│     ├── Platt calibration (オプション)                               │
│     └── xgboost_model.pkl, scaler.pkl 保存                           │
│                                                                     │
│  5. Route1閾値選択 [Cell 23]                                         │
│     ├── Wilson score上側信頼区間で t_low, t_high 決定                │
│     └── route1_thresholds.json 保存                                  │
│                                                                     │
│  6. Stage1決定 [Cell 25]                                             │
│     ├── p ≤ t_low → auto_benign                                      │
│     ├── p ≥ t_high → auto_phishing                                   │
│     ├── otherwise → handoff_to_agent (DEFER)                         │
│     └── stage1_decisions_latest.csv 保存                             │
│                                                                     │
│  7. Stage2ゲート (LR Defer Gate) [Cell 37]                          │
│     ├── OOF Logistic Regression学習                                  │
│     ├── segment_priority モード:                                     │
│     │   ├── Priority pool: dangerous_tld ∪ IDN ∪ brand_hit           │
│     │   └── Optional pool: unknown TLD                               │
│     ├── 選択: gray zone (tau < p2) + override rescue                 │
│     └── lr_defer_model.pkl, stage2_decisions_*.csv 保存              │
│                                                                     │
│  8. Handoff出力 (03系インタフェース) [Cell 37末尾]                   │
│     ├── handoff_candidates_latest.pkl (payload形式)                  │
│     ├── handoff_candidates_latest.csv                                │
│     └── false_negatives_reconstructed.pkl (compat)                   │
│                                                                     │
│  9. 評価・可視化 [Cell 40]                                           │
│     ├── stage2_budget_eval.json                                      │
│     ├── viz_stage2_summary.csv                                       │
│     └── 各種プロット (PNG/PDF)                                       │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 2. 入力ファイル

| ファイル | 場所 | 説明 |
|---------|------|------|
| prepared_data.pkl | `artifacts/<RUN_ID>/raw/` | 01で作成した前処理済みデータ |
| .env | プロジェクトルート | DB接続情報、LLM設定 |
| 02_config.yaml (オプション) | プロジェクトルート | 設定ファイル |

### .env必須項目
```bash
# PostgreSQL
DB_HOST=localhost
DB_PORT=5432
DB_NAME=phishing_db
DB_USER=...
DB_PASSWORD=...

# vLLM
VLLM_BASE_URL=http://192.168.100.71:30000/v1
BRAND_LLM_MODEL=Qwen/Qwen3-14B-FP8
VLLM_API_KEY=EMPTY
```

---

## 3. 出力ファイル

### 3.1 artifacts/<RUN_ID>/ 構造

```
artifacts/<RUN_ID>/
├── raw/
│   └── prepared_data.pkl          # 入力（01で作成）
├── processed/
│   ├── train_data.pkl             # 学習データ
│   └── test_data.pkl              # テストデータ
├── models/
│   ├── xgboost_model.pkl          # Stage1モデル
│   ├── xgboost_model_baseline.pkl # 同上（別名）
│   ├── scaler.pkl                 # StandardScaler
│   ├── brand_keywords.json        # ブランドキーワード
│   ├── feature_order.json         # 特徴量順序
│   ├── lr_defer_model.pkl         # Stage2 LRモデル
│   └── lr_defer_scaler.pkl        # Stage2 Scaler
├── results/
│   ├── stage1_decisions_latest.csv
│   ├── stage2_decisions_latest.csv
│   ├── stage2_decisions_candidates_latest.csv
│   ├── stage2_pending_latest.csv
│   ├── route1_thresholds.json
│   ├── stage2_budget_eval.json
│   ├── false_negatives_reconstructed.pkl
│   └── training_metrics.json
└── handoff/
    ├── handoff_candidates_latest.csv
    ├── handoff_candidates_latest.pkl
    ├── handoff_candidates_tl{t_low}_th{t_high}.csv
    └── handoff_candidates_tl{t_low}_th{t_high}.pkl
```

### 3.2 互換出力（03系用）
```
results/<RUN_ID>/
└── false_negatives_reconstructed.pkl
```

---

## 4. 出力ファイル詳細フォーマット

### 4.1 stage1_decisions_latest.csv
```csv
domain,source,ml_probability,stage1_decision,y_true
example.com,trusted,0.123,auto_benign,0
phishing.xyz,jpcert,0.987,auto_phishing,1
unknown.site,certificates,0.456,handoff_to_agent,0
```

### 4.2 stage2_decisions_latest.csv
```csv
idx,domain,source,ml_probability,stage1_decision,y_true,stage2_candidate,stage2_selected,stage2_decision,stage1_pred
0,example.com,trusted,0.123,auto_benign,0,0,0,not_candidate,0
1,unknown.site,certificates,0.456,handoff_to_agent,0,1,1,handoff_to_agent,0
2,other.site,jpcert,0.555,handoff_to_agent,1,1,0,drop_to_auto,1
```

### 4.3 stage2_decisions_candidates_latest.csv
```csv
idx,domain,tld,ml_probability,stage1_pred,y_true,p_error,uncertainty,defer_score,is_dangerous_tld,is_idn,brand_hit,pool_priority,pool_optional,selected,selected_priority,selected_optional
```

### 4.4 handoff_candidates_latest.pkl (payload構造)
```python
{
    "analysis_df": pd.DataFrame({
        "domain": [...],
        "source": [...],
        "prediction_proba": [...],   # ← 03系用に prediction_proba
        "stage1_decision": [...],
        "y_true": [...],
    }),
    "meta": {
        "t_low": float,
        "t_high": float,
        "created_at": str,  # ISO format
        "note": str,
        "stage2": {
            "method": str,
            "select_mode": str,
            "max_budget": int,
            "handoff_budget": int,
            "oof_folds": int,
            "features": list,
            "select_stats": dict,
        },
    },
}
```

### 4.5 route1_thresholds.json
```json
{
    "t_low": 0.001,
    "t_high": 0.988,
    "low_n": 7595,
    "low_k": 0,
    "low_risk_point": 0.0,
    "low_risk_est": 0.0005,
    "high_n": 60101,
    "high_k": 12,
    "high_risk_point": 0.0002,
    "high_risk_est": 0.0003,
    "n": 51226,
    "coverage": 0.528
}
```

### 4.6 stage2_budget_eval.json
```json
{
    "N_all": 128067,
    "N_stage1_handoff_region": 60371,
    "N_stage2_handoff": 2604,
    "N_auto": 125463,
    "auto_errors": 1234,
    "auto_error_rate": 0.0098,
    "stage2_select": {
        "mode": "segment_priority",
        "max_budget": 5000,
        "priority_pool": 267,
        "optional_pool": 1500,
        "selected_priority": 200,
        "selected_optional": 2404,
        "selected_final": 2604
    },
    "gate_all": {
        "tn": 120000,
        "fp": 2000,
        "fn": 1234,
        "tp": 604,
        "precision": 0.232,
        "recall": 0.329,
        "f1": 0.272
    }
}
```

---

## 5. 設定パラメータ

### 5.1 環境変数（優先）
```bash
# RUN_ID
RUN_ID=2026-01-10_140940

# XGBoost
XGB_VAL_SIZE=0.10
XGB_N_ESTIMATORS=500
XGB_MAX_DEPTH=6
XGB_LEARNING_RATE=0.1
XGB_EARLY_STOPPING_ROUNDS=50

# Route1
XGB_T_MODE=auto_from_val
XGB_RISK_MAX_AUTO_BENIGN=0.001
XGB_RISK_MAX_AUTO_PHISH=0.0002
XGB_MIN_AUTO_SAMPLES=200
XGB_RISK_USE_UPPER=1
XGB_RISK_ALPHA=0.05

# Stage2 (02_original.ipynb Cell 37 defaults)
STAGE2_SELECT_MODE=threshold_cap  # default
STAGE2_MAX_BUDGET=0               # 0 = disabled (variable-size handoff)
STAGE2_TAU=0.60
STAGE2_OVERRIDE_TAU=0.30
STAGE2_PHI_PHISH=0.99
STAGE2_PHI_BENIGN=0.01
STAGE2_OOF_FOLDS=5
STAGE2_GATE_MODE=lr               # Cell 39: 'lr' (default) or 'two_model_hash'
```

### 5.2 デフォルト設定 (Python dict)
```python
DEFAULT_CONFIG = {
    # XGBoost
    'xgb_val_size': 0.10,
    'xgb_n_estimators': 500,
    'xgb_max_depth': 6,
    'xgb_learning_rate': 0.1,
    'xgb_early_stopping_rounds': 50,

    # Route1 thresholds
    'xgb_t_mode': 'auto_from_val',
    'xgb_risk_max_auto_benign': 0.001,
    'xgb_risk_max_auto_phish': 0.0002,
    'xgb_min_auto_samples': 200,
    'xgb_risk_use_upper': True,
    'xgb_risk_alpha': 0.05,

    # Stage2 (02_original.ipynb Cell 37 defaults)
    'stage2_select_mode': 'threshold_cap',  # default in notebook
    'stage2_max_budget': 0,  # 0 = disabled (variable-size handoff)
    'stage2_tau': 0.60,  # default tau for gray zone
    'stage2_override_tau': 0.30,  # override rescue threshold
    'stage2_phi_phish': 0.99,
    'stage2_phi_benign': 0.01,
    'stage2_seg_only_benign': False,
    'stage2_seg_optional': True,
    'stage2_seg_include_idn': True,
    'stage2_seg_include_brand': True,
    'stage2_seg_min_p1': 0.00,
    'stage2_oof_folds': 5,

    # Dangerous TLDs
    'dangerous_tlds': [
        'icu', 'top', 'xyz', 'buzz', 'cfd', 'cyou', 'rest',
        'tk', 'ml', 'ga', 'cf', 'gq', 'sbs', 'click', 'link',
        'online', 'site', 'website'
    ],

    # LLM
    'llm_enabled': True,
    'llm_base_url': 'http://192.168.100.71:30000/v1',
    'llm_model': 'Qwen/Qwen3-14B-FP8',
    'llm_api_key': 'EMPTY',

    # Brand keywords (CHANGELOG 2026-01-10: max_brands=0 means unlimited)
    'brand_min_count': 2,
    'brand_max_brands': 0,  # 0 = unlimited
    'brand_dynamic': True,
}
```

---

## 6. 主要関数・クラス

### 6.1 既存モジュール (02_stage1_stage2/src/)

| モジュール | クラス/関数 | 用途 | 完成度 |
|-----------|------------|------|--------|
| `config.py` | `load_config()` | YAML設定読み込み | ✅ 完成 |
| `features.py` | `FeatureEngineer` | 35特徴量抽出 | ✅ 完成 |
| `features.py` | `extract_features()` | 単体特徴量抽出 | ✅ 完成 |
| `train_xgb.py` | `Stage1Trainer` | XGBoost学習 | ✅ 完成 |
| `route1.py` | `Route1ThresholdSelector` | Wilson閾値選択 | ✅ 完成 |
| `stage2_gate.py` | `Stage2Gate` | LR Deferゲート | ⚠️ 要確認 |
| `brand_extraction.py` | `BrandExtractor` | ブランド抽出 | ❌ LLM未実装 |

### 6.2 追加実装が必要な機能

1. **LLMブランドキーワード抽出** (Cell 15)
   - PostgreSQL接続
   - vLLM/OpenAI SDK呼び出し
   - バッチ処理 + リトライロジック

2. **segment_priorityモード** (Cell 37)
   - Priority pool構築 (dangerous_tld ∪ IDN ∪ brand)
   - Optional pool構築 (unknown TLD)
   - Gray zone + override rescue選択

3. **OOF Logistic Regression** (Cell 37)
   - K-Fold OOF予測
   - p_error (誤り確率) 推定

---

## 7. 02_main.py 実装方針

### 7.1 モード

```bash
# フルパイプライン実行（LLM含む）
python 02_main.py --run

# 特定RUN_ID指定
python 02_main.py --run --run-id 2026-01-10_140940

# 設定ファイル指定
python 02_main.py --run --config 02_config.yaml
```

**注意**: LLMブランドキーワード抽出は必須です。vLLM/PostgreSQL接続が必要です。

### 7.2 モジュール活用

```python
# 既存モジュールをインポート
from 02_stage1_stage2.src.config import load_config
from 02_stage1_stage2.src.features import FeatureEngineer, FEATURE_ORDER
from 02_stage1_stage2.src.train_xgb import Stage1Trainer
from 02_stage1_stage2.src.route1 import Route1ThresholdSelector
from 02_stage1_stage2.src.stage2_gate import Stage2Gate

# LLMブランド抽出は新規実装
from 02_stage1_stage2.src.brand_extraction_llm import extract_brands_via_llm
```

### 7.3 処理フロー（擬似コード）

```python
def run_pipeline(run_id, cfg):
    # 1. ディレクトリ準備
    setup_directories(run_id)

    # 2. LLMブランドキーワード抽出（必須）
    brand_keywords = extract_brands_via_llm(cfg)
    save_brand_keywords(brand_keywords, run_id)

    # 3. データ読み込み
    prepared_data = load_prepared_data(run_id)

    # 4. 特徴量抽出
    engineer = FeatureEngineer(brand_keywords)
    X_train, X_test, y_train, y_test, domains, sources, tlds = \
        build_features(prepared_data, engineer)
    save_processed_data(X_train, X_test, y_train, y_test, ...)

    # 5. XGBoost学習
    trainer = Stage1Trainer(cfg)
    model, metrics = trainer.train(X_train, y_train)
    save_model(model, run_id)

    # 6. Route1閾値選択
    selector = Route1ThresholdSelector(cfg)
    t_low, t_high, route1_meta = selector.select_thresholds(y_val, p_val)
    save_route1_thresholds(route1_meta, run_id)

    # 7. Stage1決定
    p_test = model.predict_proba(X_test)[:, 1]
    stage1_decision = classify_stage1(p_test, t_low, t_high)
    save_stage1_decisions(domains, sources, p_test, stage1_decision, y_test, run_id)

    # 8. Stage2ゲート
    gate = Stage2Gate(cfg, brand_keywords)
    selected_mask, gate_trace, stats = gate.select_segment_priority(
        df_defer, p_test_defer, y_defer, domains_defer, tlds_defer
    )
    save_stage2_decisions(...)

    # 9. Handoff出力
    save_handoff_candidates(df_handoff, t_low, t_high, stats, run_id)
    save_false_negatives_reconstructed(df_handoff, t_low, t_high, stats, run_id)

    # 10. 評価JSON
    save_stage2_budget_eval(eval_metrics, run_id)
```

---

## 8. 03系インタフェース要件

### 8.1 必須ファイル
- `results/<RUN_ID>/false_negatives_reconstructed.pkl`
- `artifacts/<RUN_ID>/handoff/handoff_candidates_latest.pkl`

### 8.2 必須カラム (analysis_df)
- `domain`: ドメイン名
- `source`: データソース (jpcert, phishtank, trusted, certificates)
- `prediction_proba`: ML予測確率 (0.0-1.0)
- `stage1_decision`: Stage1決定 (handoff_to_agent)
- `y_true`: 正解ラベル (0=benign, 1=phishing)

### 8.3 必須メタデータ
- `t_low`: auto_benign閾値
- `t_high`: auto_phishing閾値
- `created_at`: ISO形式タイムスタンプ

---

## 9. テスト・検証

### 9.1 出力一致テスト
```bash
# Notebook実行
jupyter nbconvert --execute 02_original.ipynb

# Python実行
python 02_main.py --run --run-id TEST_RUN

# 出力比較
diff artifacts/TEST_RUN/results/stage1_decisions_latest.csv \
     artifacts/NOTEBOOK_RUN/results/stage1_decisions_latest.csv
```

### 9.2 検証項目
- [ ] stage1_decisions_latest.csv の行数・カラム一致
- [ ] stage2_decisions_latest.csv の行数・カラム一致
- [ ] handoff_candidates_latest.pkl のpayload構造一致
- [ ] route1_thresholds.json の値が同等（小数点誤差許容）
- [ ] 03系（03_ai_agent_analysis_part1.ipynb）で読み込み成功

---

## 10. 変更履歴

| 日付 | 変更内容 |
|------|---------|
| 2026-01-10 | 初版作成 |
