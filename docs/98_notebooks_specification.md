# 98-*.ipynb AI Agent実行ノートブック仕様

作成日: 2026-01-12

## 概要

`98-*.ipynb` ノートブックは、Stage3 AI Agentを実際に実行し、評価を行うためのノートブック群です。
3種類存在し、それぞれ目的と機能が異なります。

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     98-*.ipynb ノートブック比較                          │
├─────────────────────────────────────────────────────────────────────────┤
│  ノートブック                │ 目的              │ 主な用途            │
├─────────────────────────────────────────────────────────────────────────┤
│  98-20251221-3              │ 基本評価          │ 開発・デバッグ      │
│  98-randomN_for_paper_v6    │ 論文用フル評価    │ 本番評価・論文      │
│  98-stage2-handoff-validation│ Gate+E2E評価     │ Stage2品質検証     │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 1. 98-20251221-3.ipynb

### 1.1 目的
- AI Agentの基本的な動作確認と評価
- ランダムサンプルに対するAgent実行

### 1.2 主要機能
- N_SAMPLE件のランダムサンプル評価
- N_BENIGN_SAMPLE件のbenign評価
- 単一ドメインデバッグ機能 (`debug_one_domain()`)
- ツール別統計サマリー

### 1.3 セル構成

| セル | 内容 |
|------|------|
| Cell 0 | 実験件数設定 (N_SAMPLE, N_BENIGN_SAMPLE) |
| Cell 1 | 環境設定・RUN_ID決定 |
| Cell 2 | External Data読み込み (04-3 handoff) |
| Cell 3 | 04-2からの不足データ補完 |
| Cell 4 | External Dataサマリー |
| Cell 5 | Randomサンプルデータ準備 |
| Cell 6 | LangGraphエージェント初期化 |
| Cell 7 | TLDリスト動的生成 (DB) |
| Cell 8 | サンプル評価実行 |
| Cell 9 | 単一ドメインデバッグ |
| Cell 10 | graph.stream デバッグ |
| Cell 11 | ツール別統計サマリー |
| Cell 12-14 | Benignサンプル評価 |

### 1.4 入出力

**入力（依存ファイル）**:
```
artifacts/{RUN_ID}/handoff/04-3_llm_tools_setup_with_tools.pkl
artifacts/{RUN_ID}/handoff/04-2_statistical_analysis.pkl (補助)
artifacts/{RUN_ID}/processed/test_data.pkl
artifacts/{RUN_ID}/models/xgboost_model.pkl
```

**出力**:
```
{BASE_DIR}/random{N}_eval__evalid_{id}__ts_{ts}.csv
{BASE_DIR}/benign{N}_eval__evalid_{id}__ts_{ts}.csv
```

### 1.5 パラメータ

| パラメータ | デフォルト | 説明 |
|-----------|-----------|------|
| N_SAMPLE | 500 | Phishing/Randomサンプル数 |
| N_BENIGN_SAMPLE | 500 | Benignサンプル数 |
| RANDOM_STATE | 42 | 乱数シード |

---

## 2. 98-randomN_for_paper_v6_*.ipynb

### 2.1 目的
- **論文用の本格評価**
- Phase6ポリシー検証
- 再現性確保（フィンガープリント）
- 大規模バッチ処理

### 2.2 主要機能（98-20251221-3との差分）

| 機能 | 98-20251221-3 | 98-randomN_for_paper_v6 |
|------|---------------|-------------------------|
| Phase6 Preflight検証 | なし | あり |
| フィンガープリント | なし | あり |
| 進捗表示・一時停止 | 基本 | 高度（pauseファイル対応） |
| debug_log分割保存 | なし | あり |
| benign_hard評価 | 基本 | 専用セル |
| eval_id管理 | 基本 | 詳細 |

### 2.3 セル構成

| セル | 内容 |
|------|------|
| Cell 0 | 実験件数設定 (N_SAMPLE=10) |
| Cell 1 | 環境設定・RUN_ID決定 |
| Cell 2 | External Data読み込み |
| Cell 3 | 04-2データ補完 |
| Cell 4 | External Dataサマリー |
| Cell 5 | Randomサンプル準備 |
| Cell 6 | LangGraphエージェント初期化 |
| Cell 7 | TLDリスト動的生成 (DB) |
| **Cell 8** | **Preflight検証（Phase6 wiring確認）** |
| Cell 9 | サンプル評価実行（進捗・一時停止対応） |
| Cell 10 | ツール別統計サマリー |
| Cell 11-12 | XGBoost再計算 |
| Cell 13 | Benignサンプリング |
| Cell 14 | Benign評価（進捗・一時停止対応） |
| Cell 15 | Benign結果CSV保存 |
| Cell 16 | Hard-negative benign作成 |
| Cell 17 | Benign_hard評価 |
| Cell 18 | Benign_hard結果CSV保存 |
| Cell 19 | FNサンプル整形 |

### 2.4 Preflight検証 (Cell 8)

```python
# 検証項目:
# 1. Phase6 wiring が正しく当たっているか（静的チェック）
# 2. Phase6ノードが実際に踏まれるか（実行時チェック）
# 3. phase6_policy_version / decision_trace の存在確認
```

### 2.5 進捗・一時停止機能

```python
# pauseファイルが置かれたら安全停止 + partial保存
# debug_log は CSV に全文を載せず、ファイルへ分割保存
```

### 2.6 パラメータ

| パラメータ | デフォルト | 説明 |
|-----------|-----------|------|
| N_SAMPLE | 10 | Phishing/Randomサンプル数 |
| N_BENIGN_SAMPLE | 10 | Benignサンプル数 |
| N_BENIGN_HARD_SAMPLE | 10 | Hard Benignサンプル数 |
| RANDOM_STATE | 42 | 乱数シード |

### 2.7 出力ファイル

```
{BASE_DIR}/random{N}_eval__evalid_{id}__ts_{ts}.csv
{BASE_DIR}/random{N}_full_eval__evalid_{id}__ts_{ts}.csv
{BASE_DIR}/benign{N}_eval__evalid_{id}__ts_{ts}.csv
{BASE_DIR}/benign{N}_full_eval__evalid_{id}__ts_{ts}.csv
{BASE_DIR}/benign_hard{N}_eval__evalid_{id}__ts_{ts}.csv
{BASE_DIR}/benign_hard{N}_full_eval__evalid_{id}__ts_{ts}.csv
artifacts/{RUN_ID}/traces/debug_log_{domain}_{ts}.json  # 分割ログ
```

---

## 3. 98-stage2-handoff-validation_v3_orthodox.ipynb

### 3.1 目的
- **Stage-2 Handoffの品質検証**（学術的に筋の良い評価）
- Gate評価（Stage-2の選別品質）
- End-to-End評価（最終判定品質）

### 3.2 評価フレームワーク

```
┌─────────────────────────────────────────────────────────────────┐
│                    評価フレームワーク                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  [Gate評価]                                                     │
│    Stage-1の誤り err = (stage1_pred != y_true) を               │
│    どれだけ handoff に回収できたか                              │
│    - error_capture_recall: 誤り回収率                           │
│    - handoff_precision: handoff精度                             │
│                                                                 │
│  [End-to-End評価]                                               │
│    Stage-2 handoff → Agent実行 → Stage-1予測を上書き            │
│    取れなかった場合は Stage-1へフォールバック                    │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 3.3 セル構成

| セル | 内容 |
|------|------|
| Cell 0 | Markdown説明 |
| Cell 1 | ChangeLog |
| Cell 2 | パラメータ設定 |
| Cell 3 | 環境設定・RUN_ID決定 |
| Cell 4 | 指標計算ヘルパー (ConfusionResult, Fβ等) |
| Cell 5 | データ読込 + Gate評価 + target_df作成 |
| Cell 6 | external_dataロード |
| Cell 7 | TLDリスト動的生成 (オプション) |
| Cell 8 | Agent初期化 (Phase6 wiring) |
| Cell 9 | サンプル評価実行 |
| Cell 10 | Agent結果結合・評価用DataFrame作成 |
| Cell 11 | End-to-End評価 (ALL test) |
| Cell 12 | 結果保存 |

### 3.4 Gate評価指標

```python
@dataclass
class ConfusionResult:
    TP: int      # True Positive
    FP: int      # False Positive
    TN: int      # True Negative
    FN: int      # False Negative
    precision: float
    recall: float
    f1: float
    fbeta: float  # Fβスコア
    fpr: float    # False Positive Rate

# Gate指標:
# - error_capture_recall: Stage-1誤りのうち、handoffに入った割合
# - handoff_precision: handoff集合のうち、実際にStage-1が間違っていた割合
```

### 3.5 End-to-End評価

```python
# Stage-2 handoff → Agent実行 → 予測上書き
# Agent結果が取れなかった場合 → Stage-1予測にフォールバック

# コスト関数:
cost = FN_COST * FN + FP_COST * FP + HANDOFF_COST * handoff_count
```

### 3.6 パラメータ

| パラメータ | デフォルト | 説明 |
|-----------|-----------|------|
| N_SAMPLE | 3000 | Handoffサンプル数 |
| N_BENIGN_SAMPLE | 0 | 追加Benignサンプル数 |
| N_BENIGN_HARD_SAMPLE | 0 | Hard Benignサンプル数 |
| FN_COST | 3.0 | FNコスト係数 |
| FP_COST | 1.0 | FPコスト係数 |
| HANDOFF_COST | 0.1 | Handoffコスト係数 |
| RANDOM_STATE | 42 | 乱数シード |

### 3.7 出力ファイル

```
artifacts/{RUN_ID}/results/stage2_validation/
├── eval_df__n{N}__ts_{ts}.csv        # Agent評価結果
├── all_test_merged__ts_{ts}.csv      # ALL test End-to-End結果
└── summary__ts_{ts}.json             # 評価サマリー
```

---

## 使い分けガイド

### 開発・デバッグ時
→ **98-20251221-3.ipynb**
- シンプルな構成
- 単一ドメインデバッグ機能
- 素早く動作確認

### 論文用評価・本番評価
→ **98-randomN_for_paper_v6_*.ipynb**
- Phase6 Preflight検証
- フィンガープリントによる再現性確保
- 大規模バッチ処理（進捗・一時停止対応）
- 詳細ログ分割保存

### Stage-2品質検証
→ **98-stage2-handoff-validation_v3_orthodox.ipynb**
- Gate評価（error_capture_recall, handoff_precision）
- End-to-End評価（フォールバック含む）
- コスト関数による総合評価
- 学術的に筋の良い評価フレームワーク

---

## 実行順序（全体パイプライン内での位置）

```
01_data_preparation_*.ipynb
    ↓
02_main.ipynb
    ↓
03_ai_agent_analysis_part1.ipynb
    ↓
03_ai_agent_analysis_part2.ipynb
    ↓
03_ai_agent_analysis_part3.ipynb
    ↓
04-1_config_and_data_preparation.ipynb
    ↓
04-2_statistical_analysis_*.ipynb
    ↓
04-3_llm_tools_setup.ipynb
    ↓
┌─────────────────────────────────────────┐
│  98-*.ipynb (いずれかを選択)            │
│    - 98-20251221-3 (開発用)            │
│    - 98-randomN_for_paper_v6 (論文用)  │
│    - 98-stage2-handoff-validation (検証)│
└─────────────────────────────────────────┘
```

---

## 共通の依存ファイル

すべての98-*.ipynbは以下のhandoffファイルに依存：

```
artifacts/{RUN_ID}/handoff/
├── 04-3_llm_tools_setup_with_tools.pkl  # 必須
├── 04-2_statistical_analysis.pkl        # 補助
└── 03_ai_agent_analysis_part3.pkl       # TLD情報

artifacts/{RUN_ID}/processed/
└── test_data.pkl                        # テストデータ

artifacts/{RUN_ID}/models/
├── xgboost_model.pkl                    # Stage1モデル
└── scaler.pkl                           # スケーラー
```
