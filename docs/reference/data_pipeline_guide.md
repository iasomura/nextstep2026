# データパイプラインガイド

更新日: 2026-02-01

## 概要

本ドキュメントは、フィッシング検出システムのデータパイプラインを説明する。
Notebookファイル（01*.ipynb〜05*.ipynb）を順に実行することで、データの準備から評価までの全処理を行う。

---

## アーキテクチャ全体像

```
[PostgreSQL]
     │
     ▼
┌─────────────────────────────────────────────────────────────┐
│ 01_data_preparation                                         │
│ - データ抽出（phishing/benign）                              │
│ - 特徴量計算（31特徴量）                                     │
│ - RUN_ID発行                                                │
└─────────────────────────────────────────────────────────────┘
     │ artifacts/{RUN_ID}/data/full_df.csv
     ▼
┌─────────────────────────────────────────────────────────────┐
│ 02_main                                                     │
│ - Stage1: XGBoost学習・推論                                  │
│ - Stage2: Gate/ルール適用                                    │
│ - handoff候補の選定                                          │
└─────────────────────────────────────────────────────────────┘
     │ artifacts/{RUN_ID}/handoff/handoff_candidates_latest.csv
     │ artifacts/{RUN_ID}/results/stage1_decisions_latest.csv
     ▼
┌─────────────────────────────────────────────────────────────┐
│ 03_ai_agent (Part1〜3)                                      │
│ - 証明書情報の取得                                           │
│ - ブランドキーワード設定                                     │
│ - LLMツール設定                                             │
└─────────────────────────────────────────────────────────────┘
     │ artifacts/{RUN_ID}/handoff/*.pkl
     ▼
┌─────────────────────────────────────────────────────────────┐
│ 04-1〜04-3                                                  │
│ - 設定統合・検証                                             │
│ - 統計分析                                                  │
│ - LLMツールセットアップ                                      │
└─────────────────────────────────────────────────────────────┘
     │ artifacts/{RUN_ID}/handoff/04-3_llm_tools_setup_with_tools.pkl
     ▼
┌─────────────────────────────────────────────────────────────┐
│ scripts/evaluate_e2e_parallel.py                            │
│ - Stage3 AI Agent評価（3GPU並列）                            │
│ - 最終判定                                                  │
└─────────────────────────────────────────────────────────────┘
     │ artifacts/{RUN_ID}/results/stage2_validation/
     ▼
┌─────────────────────────────────────────────────────────────┐
│ 05_pipeline_analysis                                        │
│ - 性能分析                                                  │
│ - FP/FN分析                                                 │
│ - ゲートシミュレーション                                     │
└─────────────────────────────────────────────────────────────┘
```

---

## Notebook詳細

### 01_data_preparation

**ファイル**: `01_data_preparation_fixed_patched_nocert_full_artifacts_unified.ipynb`

**目的**: PostgreSQLからデータを抽出し、ML用の特徴量を計算

**入力**:
- PostgreSQL `phishing_data` テーブル（フィッシングドメイン）
- PostgreSQL `benign_data` テーブル（正規ドメイン）
- 外部ドメインリスト

**出力**:
| ファイル | 説明 |
|---------|------|
| `artifacts/{RUN_ID}/data/full_df.csv` | 全ドメインの特徴量データ |
| `artifacts/{RUN_ID}/raw/` | 生データ |
| `artifacts/_current/run_id.txt` | RUN_ID登録 |

**主要処理**:
1. RUN_ID発行（タイムスタンプベース）
2. PostgreSQL接続・データ抽出
3. 31特徴量の計算（ドメイン特徴、証明書特徴）
4. バランスデータセット作成（phishing:benign = 1:1）

---

### 02_main

**ファイル**: `02_main.ipynb`

**目的**: Stage1（XGBoost）とStage2（Gate）の学習・推論

**入力**:
- `artifacts/{RUN_ID}/data/full_df.csv`
- `02_stage1_stage2/configs/default.yaml`（設定ファイル）

**出力**:
| ファイル | 説明 |
|---------|------|
| `artifacts/{RUN_ID}/models/xgb_model.pkl` | 学習済みXGBoostモデル |
| `artifacts/{RUN_ID}/results/stage1_decisions_latest.csv` | Stage1決定結果 |
| `artifacts/{RUN_ID}/results/stage2_decisions_latest.csv` | Stage2決定結果 |
| `artifacts/{RUN_ID}/results/route1_thresholds.json` | 閾値設定 |
| `artifacts/{RUN_ID}/handoff/handoff_candidates_latest.csv` | Stage3へのhandoff候補 |

**主要処理**:
1. 設定ファイル読み込み（YAML）
2. XGBoostモデル学習
3. 確率予測と閾値決定
4. Stage1決定（auto_phishing / auto_benign / handoff_to_agent）
5. Stage2フィルタリング（証明書ルール）
6. handoff候補の出力

**Stage1決定の分類**:
```
ML確率 p に基づく判定:
- p >= t_high → auto_phishing（自動phishing判定）
- p <= t_low  → auto_benign（自動benign判定）
- otherwise  → handoff_to_agent（Stage2/3へ委譲）
```

---

### 03_ai_agent (Part1〜3)

**ファイル**:
- `03_ai_agent_analysis_part1.ipynb` - 設定とAPI準備
- `03_ai_agent_analysis_part2_full_HardFail_patched.ipynb` - 証明書情報取得
- `03_ai_agent_analysis_part3_config_api.ipynb` - LLMツール設定

**目的**: AI Agent（Stage3）の準備

**Part2 出力**:
| ファイル | 説明 |
|---------|------|
| `artifacts/{RUN_ID}/handoff/cert_full_info_map.pkl` | ドメイン→証明書情報マッピング |

**主要処理**:
1. PostgreSQLから証明書詳細情報を取得
2. ブランドキーワードリストの設定
3. 危険TLD/正規TLDリストの設定
4. LLM API設定の検証

---

### 04-1〜04-3

**ファイル**:
- `04-1_config_and_data_preparation.ipynb` - 設定統合
- `04-2_statistical_analysis_*.ipynb` - 統計分析
- `04-3_llm_tools_setup.ipynb` - LLMツールセットアップ

**目的**: Stage3評価の準備

**04-1 出力**:
| ファイル | 説明 |
|---------|------|
| `artifacts/{RUN_ID}/handoff/04-1_config_and_data_preparation.pkl` | 統合設定データ |

**04-3 出力**:
| ファイル | 説明 |
|---------|------|
| `artifacts/{RUN_ID}/handoff/04-3_llm_tools_setup_with_tools.pkl` | LLMツール設定 |

**pkl内容**:
```python
{
    'fn_features_df': DataFrame,      # 特徴量データ
    'cert_full_info_map': dict,       # 証明書情報マップ
    'brand_keywords': list,           # ブランドキーワード
    'DANGEROUS_TLDS': set,            # 危険TLDリスト
    'LEGITIMATE_TLDS': set,           # 正規TLDリスト
    'external_data': dict,            # 外部データ
}
```

---

### 05_pipeline_analysis

**ファイル**: `05_pipeline_analysis.ipynb`

**目的**: パイプライン全体の性能分析

**入力**:
- `artifacts/{RUN_ID}/results/stage1_decisions_latest.csv`
- `artifacts/{RUN_ID}/results/stage2_validation/eval_df__*.csv`
- `artifacts/{RUN_ID}/handoff/04-1_*.pkl`

**分析内容**:
1. **Stage1分析**: XGBoostの性能、閾値スイープ
2. **Stage2分析**: Handoff領域の分布
3. **Stage3分析**: AI Agentの性能
4. **FP/FN分析**: 誤分類パターンの特定
5. **ゲートシミュレーション**: 閾値変更の影響

---

## 評価スクリプト

### scripts/evaluate_e2e_parallel.py

**目的**: Stage3 AI Agentの並列評価

**使用方法**:
```bash
# 3GPU並列で全件評価
python scripts/evaluate_e2e_parallel.py \
    --n-sample ALL \
    --ports 8000,8001,8002 \
    --output artifacts/{RUN_ID}/results/stage2_validation/
```

**出力**:
| ファイル | 説明 |
|---------|------|
| `worker_0_results.csv` | Worker 0の結果 |
| `worker_1_results.csv` | Worker 1の結果 |
| `worker_2_results.csv` | Worker 2の結果 |

---

## データフロー詳細

### 1. データ準備フェーズ

```
PostgreSQL
    │
    ├─ phishing_data → 63,877件
    └─ benign_data   → 63,877件
    │
    ▼
full_df.csv (127,754件)
    │
    ├─ domain: ドメイン名
    ├─ label: 0=benign, 1=phishing
    ├─ ml_*: ML特徴量（31種類）
    └─ cert_*: 証明書特徴量
```

### 2. Stage1/Stage2フェーズ

```
full_df.csv (127,754件)
    │
    ▼ XGBoost予測
    │
    ├─ auto_phishing: 60,614件 (TP:60,612 / FP:2)
    ├─ auto_benign:    6,166件 (TN:6,158 / FN:8)
    └─ handoff_to_agent: 60,974件
          │
          ▼ Stage2フィルタ
          │
          ├─ safe_benign: 45,304件 (TN:44,786 / FN:518)
          └─ handoff → Stage3: 15,670件
```

### 3. Stage3評価フェーズ

```
handoff_candidates_latest.csv (15,670件)
    │
    ├─ phishing: 2,739件
    └─ benign: 12,931件
    │
    ▼ AI Agent評価（3GPU並列）
    │
    ├─ phishing判定: 2,446件 (TP:1,781 / FP:665)
    └─ benign判定: 13,224件 (TN:12,266 / FN:958)
```

---

## artifacts ディレクトリ構造

```
artifacts/{RUN_ID}/
├── raw/                          # 生データ
├── data/
│   └── full_df.csv              # 全ドメイン特徴量
├── models/
│   └── xgb_model.pkl            # XGBoostモデル
├── results/
│   ├── stage1_decisions_latest.csv
│   ├── stage2_decisions_latest.csv
│   ├── route1_thresholds.json
│   └── stage2_validation/       # Stage3評価結果
│       ├── eval_df__nALL__*.csv
│       └── worker_*_results.csv
├── handoff/
│   ├── handoff_candidates_latest.csv
│   ├── cert_full_info_map.pkl
│   ├── 04-1_config_and_data_preparation.pkl
│   └── 04-3_llm_tools_setup_with_tools.pkl
├── logs/
└── traces/
```

---

## 主要CSVカラム

### stage1_decisions_latest.csv

| カラム | 説明 |
|-------|------|
| domain | ドメイン名 |
| ml_probability | ML予測確率 (0.0-1.0) |
| stage1_decision | auto_phishing / auto_benign / handoff_to_agent |
| stage1_pred | 予測ラベル (0=benign, 1=phishing) |
| y_true | 正解ラベル |
| label | 正解ラベル (0/1) |

### handoff_candidates_latest.csv

| カラム | 説明 |
|-------|------|
| domain | ドメイン名 |
| ml_probability | ML予測確率 |
| y_true | 正解ラベル |
| tld | トップレベルドメイン |
| cert_* | 証明書特徴量 |

### eval_df (Stage3評価結果)

| カラム | 説明 |
|-------|------|
| domain | ドメイン名 |
| ai_is_phishing | AI Agent判定 (True/False) |
| ai_confidence | 確信度 (0.0-1.0) |
| ai_risk_level | リスクレベル (low/medium/high/critical) |
| y_true | 正解ラベル |
| processing_time | 処理時間（秒） |

---

## 関連ドキュメント

| ドキュメント | 内容 |
|------------|------|
| `docs/specs/stage3_ai_agent_spec.md` | AI Agent仕様 |
| `docs/specs/parallel_evaluation_spec.md` | 並列評価仕様 |
| `docs/specs/rules_modularization_spec.md` | ルールモジュール仕様 |
| `docs/analysis/02_improvement_analysis.md` | 改善効果分析 |
| `docs/reference/program_inventory.md` | プログラム一覧 |

---

## 変更履歴

- 2026-02-01: 初版作成
