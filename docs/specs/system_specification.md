# フィッシング検知システム仕様概要

作成日: 2026-01-12
更新日: 2026-02-08

## 1. システム概要

本システムは、ドメイン名とSSL/TLS証明書の特徴量を用いてフィッシングサイトを検知する3ステージパイプラインです。

```
[入力: ドメイン名 + 証明書データ]
         ↓
   ┌─────────────────┐
   │  Stage1 (XGBoost)│ → AUTO_PHISH / AUTO_BENIGN / DEFER
   └─────────────────┘
         ↓ (DEFER のみ)
   ┌─────────────────┐
   │  Stage2 (LR)    │ → AUTO_PHISH_2 / AUTO_BENIGN_2 / DEFER2
   └─────────────────┘
         ↓ (DEFER2 のみ)
   ┌─────────────────┐
   │  Stage3 (AI Agent)│ → PHISHING / BENIGN
   └─────────────────┘
         ↓
[出力: 最終判定 + 信頼度 + 根拠]
```

## 2. ディレクトリ構成

```
nextstep/
├── 01_data_preparation_*.ipynb     # データ準備
├── 02_main.ipynb / 02_main.py      # Stage1 + Stage2 パイプライン
├── 03_ai_agent_analysis_*.ipynb    # Stage3 AI Agent
├── 04-*_*.ipynb                    # 統計分析・LLMツール設定
├── 02_stage1_stage2/
│   └── src/features.py             # 特徴量抽出
├── phishing_agent/                 # Stage3 AI Agent 実装
│   ├── langgraph_module.py         # LangGraph状態管理
│   ├── precheck_module.py          # 事前チェック
│   ├── tools_module.py             # ツール定義
│   ├── llm_final_decision.py       # LLM最終判定
│   ├── rules/                      # ルールエンジン (モジュール化)
│   └── tools/                      # 分析ツール群
│       ├── brand_impersonation_check.py
│       ├── certificate_analysis.py
│       ├── short_domain_analysis.py
│       └── contextual_risk_assessment.py
├── future/                         # 将来実装予定
│   └── stage2_v2/                  # 新設計Stage2 (未統合)
├── _compat/
│   ├── config.json                 # システム設定
│   └── paths.py                    # パス管理
├── artifacts/{RUN_ID}/             # 実行時成果物
│   ├── raw/                        # 生データ
│   ├── processed/                  # 処理済みデータ
│   ├── models/                     # 学習済みモデル
│   ├── results/                    # 結果
│   ├── handoff/                    # ノートブック間引き継ぎ
│   ├── logs/                       # ログ
│   └── traces/                     # トレース
└── docs/
    └── analysis/                   # 検証結果
```

## 3. Stage1: XGBoost分類器

### 3.1 概要
- **目的**: 高精度で大部分のサンプルを自動判定
- **アルゴリズム**: XGBoost (Gradient Boosting)
- **出力**: 確率値 p1 → 閾値で AUTO_PHISH / AUTO_BENIGN / DEFER に分類

### 3.2 特徴量 (`02_stage1_stage2/src/features.py`)

**総特徴量数**: 15（ドメイン） + 27（証明書） = 42

#### ドメイン特徴量 (15)
| # | 特徴量名 | 説明 |
|---|----------|------|
| 1 | domain_length | ドメイン文字数 |
| 2 | dot_count | ドット数 |
| 3 | hyphen_count | ハイフン数 |
| 4 | digit_count | 数字の個数 |
| 5 | digit_ratio | 数字の割合 |
| 6 | tld_length | TLDの文字数 |
| 7 | subdomain_count | サブドメイン数 |
| 8 | longest_part_length | 最長パート文字数 |
| 9 | entropy | シャノンエントロピー |
| 10 | vowel_ratio | 母音の割合 |
| 11 | max_consonant_length | 最長子音連続数 |
| 12 | has_special_chars | 特殊文字の有無 |
| 13 | non_alphanumeric_count | 非英数字の数 |
| 14 | contains_brand | ブランドキーワード含有 |
| 15 | has_www | www有無 |

#### 証明書特徴量 (27)
| # | 特徴量名 | 説明 |
|---|----------|------|
| 1 | cert_validity_days | 証明書有効期間（日） |
| 2 | cert_is_wildcard | ワイルドカード証明書 |
| 3 | cert_san_count | SAN数 |
| 4 | cert_issuer_length | 発行者名長 |
| 5 | cert_is_self_signed | 自己署名 |
| 6 | cert_cn_length | CN長 |
| 7 | cert_subject_has_org | 組織名有無 |
| 8 | cert_subject_org_length | 組織名長 |
| 9 | cert_san_dns_count | SAN DNS数 |
| 10 | cert_san_ip_count | SAN IP数 |
| 11 | cert_cn_matches_domain | CNがドメインと一致 |
| 12 | cert_san_matches_domain | SANがドメインと一致 |
| 13 | cert_san_matches_etld1 | SANがeTLD+1と一致 |
| 14 | cert_has_ocsp | OCSP有無 |
| 15 | cert_has_crl_dp | CRL配布点有無 |
| 16 | cert_has_sct | SCT有無 |
| 17 | cert_sig_algo_weak | 弱い署名アルゴリズム |
| 18 | cert_pubkey_size | 公開鍵サイズ |
| 19 | cert_key_type_code | 鍵種別コード |
| 20 | cert_is_lets_encrypt | Let's Encrypt発行 |
| 21 | cert_key_bits_normalized | 正規化鍵ビット数 |
| 22 | cert_issuer_country_code | 発行者国コード |
| 23 | cert_serial_entropy | シリアル番号エントロピー |
| 24 | cert_has_ext_key_usage | 拡張キー使用法有無 |
| 25 | cert_has_policies | ポリシー有無 |
| 26 | cert_issuer_type | 発行者タイプ |
| 27 | cert_is_le_r3 | Let's Encrypt R3/E1中間CA発行（フィッシング33% vs 正規0%） |

### 3.3 XGBoost学習手順

#### ハイパーパラメータ（Optuna Trial 25で最適化, `scripts/tune_xgboost.py`）

| パラメータ | 値 | 探索範囲 |
|-----------|-----|---------|
| n_estimators | 500 | 100-1000 |
| max_depth | 10 | 3-10 |
| learning_rate | 0.206 | 0.01-0.3 (log) |
| min_child_weight | 6 | 1-10 |
| subsample | 0.77 | 0.6-1.0 |
| colsample_bytree | 0.70 | 0.6-1.0 |
| gamma | 2.38 | 0-5 |
| reg_alpha | 0.11 | 1e-8 to 10 (log) |
| reg_lambda | 2.37 | 1e-8 to 10 (log) |
| early_stopping_rounds | 50 | − |
| eval_metric | logloss | − |
| tree_method | hist (CUDA) | − |

#### 学習・分割

- **データ分割**: 80/20 stratified split (`random_state=42`)
- **前処理**: StandardScaler正規化
- **早期停止**: 訓練データの10%をバリデーションに使用
- **scale_pos_weight**: 不使用（50:50バランスデータのため不要）
- **チューニング**: 5-fold StratifiedKFold（Optunaスクリプト内のみ）

### 3.4 閾値設計（Wilson score confidence interval）

**目的**: 自動判定の誤り率を統計的に保証する閾値を自動選択。

```python
# xgb_risk_max_auto_benign  = 0.001  # auto-benign区間の最大FNR
# xgb_risk_max_auto_phish   = 0.0002 # auto-phishing区間の最大FPR
# xgb_risk_alpha             = 0.05   # Wilson信頼水準
# xgb_min_auto_samples       = 200    # 最小サンプル数
```

**アルゴリズム**:
1. **t_low**: バリデーション集合（テストの40%）の予測値を昇順に走査。Wilson上界FNR ≤ 0.001 かつ n ≥ 200 を満たす最大の閾値を選択
2. **t_high**: 降順に走査。Wilson上界FPR ≤ 0.0002 かつ n ≥ 200 を満たす最小の閾値を選択

**結果**:
```
t_low  = 0.001  → auto_benign:  8,464件 (6.7%)
t_high = 0.957  → auto_phishing: 60,767件 (47.8%)
handoff:         57,991件 (45.6%)
```

## 4. Stage2: ロジスティック回帰 + 証明書ルール

### 4.1 概要
- **目的**: Stage1のDEFERをさらにフィルタリングし、Stage3投入を最小化
- **入力**: Stage1 DEFER集合 (57,991件; テスト127,222件中45.6%)
- **出力**: handoff_to_agent / drop_to_auto
- **実装**: `02_main.py` 内の `run_stage2_gate()` 関数

### 4.2 LR誤り確率推定

LRモデルは**Stage1の誤り確率 (p_error)** を予測するメタ学習器:

- **学習目標**: `err = (stage1_pred != y_true)` — Stage1が間違えたかどうか
- **特徴量**: 42基本特徴量 + 2派生特徴量 = **44特徴量**
  - `entropy`: `-(p*log(p) + (1-p)*log(1-p))` — p=0.5で最大
  - `uncertainty`: `1.0 - |p1 - 0.5| * 2.0` — p=0.5で1.0、端で0.0
- **学習**: 5-fold StratifiedKFold OOF、`LogisticRegression(max_iter=1000, class_weight='balanced')`
- **推論**: `p_error = lr.predict_proba(X)[:, 1]` — 高いほどStage1が間違えている可能性が高い

### 4.3 ゲート判定ロジック

**主要パラメータ**:

| パラメータ | 値 | 意味 |
|-----------|-----|------|
| stage2_tau | 0.40 | handoff最低defer_score |
| stage2_override_tau | 0.30 | p_error救済閾値 |
| stage2_phi_phish | 0.99 | p1 ≥ 0.99 = 確定phishing |
| stage2_phi_benign | 0.01 | p1 ≤ 0.01 = 確定benign |

**判定フロー**:

```
入力: p1 (Stage1予測確率), p_error (LR誤り確率), 証明書特徴量

1. clear判定: p1 >= 0.99 or p1 <= 0.01 → Stage1の判定を確定
2. override: p_error >= 0.30 → Stage3へ強制送信（Stage1が間違えている可能性が高い）
3. gray: defer_score >= 0.40 → Stage3へ送信

4. Scenario 5: Safe BENIGN — p1 < 0.15 かつ defer_score < 0.40 → auto benign
   ※危険TLDは除外、中立TLDはp1 < 0.03を要求

5. Scenario 6: 証明書ハードゲート（4 safe-benign + 2 safe-phishing ルール）

6. Scenario 8: 高ML救済 — p1 >= 0.50 かつ cert_benignでない → Stage3へ

最終判定: auto_decided = safe_benign | safe_phishing
          picked = (override | gray | high_ml_rescue) & ~auto_decided
```

### 4.4 証明書ハードゲート（Scenario 6）

**Safe-BENIGNルール**（Stage3をスキップ、benign確定）:

| ルール | 条件 | 効果 |
|--------|------|------|
| CRL | has_crl AND p1 < 0.30 | benign確定 |
| OV/EV | has_org AND p1 < 0.50 | benign確定 |
| Wildcard | is_wildcard AND NOT dangerous_tld | benign確定 |
| Long Validity | validity_days > 180 AND p1 < 0.25 | benign確定 |

**Safe-PHISHINGルール**（Stage3をスキップ、phishing確定）:

| ルール | 条件 | 効果 |
|--------|------|------|
| Tier1 TLD + LE | TLD ∈ {gq,ga,ci,cfd,tk} AND is_lets_encrypt | phishing確定 |
| Dynamic DNS + 高SAN | Dynamic DNS suffix AND san_count >= 20 | phishing確定 |

**TLDフィルタリング（Scenario 7）**: 危険TLD (42種) では safe-benign ルールを無効化（Stage3へ送る）。

### 4.4 フィルタリング実績

| 指標 | 値 |
|------|-----|
| Stage1 handoff | 57,991件 (45.6%) |
| cert gate safe化 | +12,992件 |
| 高ML救済 override | 1,718件 |
| Stage2 drop_to_auto | 46,039件 (36.2%) |
| **Stage3投入** | **11,952件 (9.4%)** |

### 4.5 設計の変遷

Stage2は当初LRベースの誤り確率推定のみだったが、以下の改善を統合：

- Wilson score confidence intervalによる統計的閾値選択（t_high/t_low）
- 証明書ハードゲート（CRL/OV・EV/Wildcard/長期有効）
- TLD分類による証明書ルール無効化（危険TLD → ゲート適用除外）
- 高ML救済（ML ≥ 0.50 → Stage3へ強制送信）

## 5. Stage3: AI Agent (LangGraph)

### 5.1 概要
- **目的**: Stage2のDEFER2に対してLLMベースの最終判定
- **フレームワーク**: LangGraph (状態機械)
- **LLM**: vLLM (JunHowie/Qwen3-4B-Thinking-2507-GPTQ-Int8)
- **ルール**: 27ルールモジュール (`phishing_agent/rules/detectors/`)
- **評価**: 3GPU並列 (`bash scripts/run_eval_3gpu.sh`)

### 5.2 アーキテクチャ (`phishing_agent/langgraph_module.py`)

```
START
  ↓
[precheck] → 事前ヒント生成（TLD、ブランド、証明書情報）
  ↓
[tool_selection] → 実行ツールの選択 (Structured Output)
  ↓
[fanout] → 並列ツール実行
  ↓
[aggregate] → 結果集約
  ↓
[contextual_check] → コンテキストリスク評価（条件付き）
  ↓
[final_decision] → 最終判定 (Phase6 Policy)
  ↓
END
```

### 5.3 分析ツール (`phishing_agent/tools/`)

| ツール | ファイル | 目的 |
|--------|----------|------|
| Brand Impersonation | brand_impersonation_check.py | ブランド偽装検出 |
| Certificate Analysis | certificate_analysis.py | 証明書詳細分析 |
| Short Domain | short_domain_analysis.py | 短いドメイン分析 |
| Contextual Risk | contextual_risk_assessment.py | 総合リスク評価 |

### 5.4 出力形式
```python
{
    "domain": "example.com",
    "ml_probability": 0.65,
    "is_phishing": True,
    "confidence": 0.78,
    "risk_level": "high",  # "low" / "medium" / "high"
    "risk_score": 0.78,
    "final_label": "phishing",  # "phishing" / "benign"
    "reasoning": "...",
    "tools_executed": ["brand", "certificate"],
    "phase6_rules_fired": [...],
}
```

## 6. データ処理パイプライン

### 6.1 ノートブック実行順序

```
01_data_preparation_*.ipynb
    ↓ (prepared_data.pkl, brand_keywords.json)
02_main.ipynb
    ↓ (models/, handoff/*.pkl)
03_ai_agent_analysis_part1.ipynb
    ↓ (handoff/03_ai_agent_analysis_part1.pkl)
03_ai_agent_analysis_part2.ipynb
    ↓ (handoff/03_ai_agent_analysis_part2.pkl)
03_ai_agent_analysis_part3.ipynb
    ↓ (handoff/03_ai_agent_analysis_part3.pkl)
04-1_config_and_data_preparation.ipynb
    ↓ (handoff/04-1_config_and_data_preparation.pkl)
04-2_statistical_analysis_*.ipynb
    ↓ (handoff/04-2_statistical_analysis.pkl)
04-3_llm_tools_setup.ipynb
    ↓ (handoff/04-3_llm_tools_setup_with_tools.pkl)
┌──────────────────────────────────────────────┐
│  Stage3 評価 (スクリプトベース)                │
│    bash scripts/run_eval_3gpu.sh [件数]       │
│    → 3GPU並列 (Port 8000/8001/8002)          │
│    → チェックポイント・リトライ自動化          │
└──────────────────────────────────────────────┘
    ↓ (評価結果CSV, results/)
```

### 6.2 Handoff形式

各ノートブックは `handoff/*.pkl` を通じてデータを引き継ぎ：

| 送信元 | ファイル | 主要キー |
|--------|----------|----------|
| Part1 | 03_ai_agent_analysis_part1.pkl | false_negatives_df, brand_keywords |
| Part2 | 03_ai_agent_analysis_part2.pkl | cert_full_info_map, fn_features_df |
| Part3 | 03_ai_agent_analysis_part3.pkl | DANGEROUS_TLDS, LEGITIMATE_TLDS |
| 04-1 | 04-1_config_and_data_preparation.pkl | cfg, DB_CONFIG, RUN_ID |

## 7. データ収集・構築パイプライン

### 7.1 データソース

| ソース | テーブル | 生レコード | 証明書あり (SUCCESS) | 収集期間 |
|--------|---------|-----------|---------------------|---------|
| PhishTank | phishtank_entries | 94,295 | 52,805 | 2011-2025 (verified) |
| JPCERT/CC | jpcert_phishing_urls | 222,984 | 115,620 | 2019-01 〜 2025-03 |
| JPCERT→証明書 | certificates | 532,117 | 196,083 | 2025-03 〜 2025-08 |
| Tranco (正規) | trusted_certificates | 554,801 | 450,545 | 2025-04 〜 2025-07 |

### 7.2 証明書取得

- **ソース**: crt.sh（Certificate Transparency Log）
- **保存形式**: DER形式 X.509バイナリ (`cert_data bytea`)
- **ステータス**: SUCCESS / NOT_FOUND / DOWNLOAD_ERROR / UNKNOWN_ERROR / SEARCH_ERROR
- **使用条件**: ステータス=SUCCESS かつ cert_data NOT NULL のみ

### 7.3 データ構築フロー (`01_data_preparation_*.ipynb`)

```
1. PostgreSQLから取得: フィッシング 365,351件 + 正規 450,545件

2. ソース間重複排除（優先: phishtank > jpcert > certificates）:
   phishtank: 53,327 → 17,140
   jpcert:   115,866 → 111,755
   certificates: 196,158 → 190,075
   → フィッシング合計: 318,970件

3. クラス間重複除去: 243ドメインが両方に存在 → フィッシングから除去

4. バランシング: 少数クラスに合わせてダウンサンプル（50:50）
   → 318,727件 × 2 = 637,454件

5. 学習/テスト分割: 80/20 stratified (random_state=42)
   → 学習: ~510,000件 / テスト: ~127,000件

6. 証明書パース不能レコードを除外
   → テスト: 127,222件（最終）
```

## 8. 設定ファイル (`_compat/config.json`)

```json
{
  "system": {
    "cert_only_mode": true,
    "seed": 42
  },
  "db": {
    "dbname": "rapids_data",
    "user": "postgres",
    "host": "localhost",
    "port": "5432"
  },
  "llm": {
    "enabled": true,
    "provider": "vllm",
    "base_url": "http://localhost:8000/v1",
    "model": "JunHowie/Qwen3-4B-Thinking-2507-GPTQ-Int8"
  },
  "tld_analysis": {
    "enabled": true,
    "max_dangerous_tlds": 30,
    "max_legitimate_tlds": 30
  },
  "engine": {
    "max_concurrent": 20,
    "max_retries": 3
  }
}
```

## 9. RUN_ID管理 (`run_id_registry.py`)

実行ごとに一意のRUN_IDを生成し、成果物を分離管理：

```python
RUN_ID = "2026-01-10_140940"
ARTIFACTS = f"artifacts/{RUN_ID}/"
```

解決優先順位:
1. 環境変数 `RUN_ID`
2. `artifacts/_current/run_id.txt`
3. Part3 handoff
4. 最新のartifacts
5. 新規生成

## 10. 検証プログラム (`docs/analysis/`)

| ディレクトリ/ファイル | 内容 |
|----------------------|------|
| stage2_independent_eval/ | Stage2証明書ルール独立評価 |
| fn_gsb_verification/ | False Negative GSB検証 |
| certificate_analysis_report.md | 証明書特徴量分析レポート |

## 11. 主要クラス・関数

### 11.1 特徴量抽出 (`02_stage1_stage2/src/features.py`)
- `extract_features(domain, cert_data, brand_keywords)` → numpy.ndarray
- `extract_domain_features(domain, brand_keywords)` → dict
- `extract_certificate_features(cert_data)` → dict

### 11.2 AI Agent (`phishing_agent/langgraph_module.py`)
- `LangGraphPhishingAgent` クラス
  - `evaluate(domain, ml_probability, cert_data)` → dict
  - `_build_graph()` → StateGraph

### 11.3 Stage2決定器

**現行実装**: `02_main.py` 内の `run_stage2_gate()` 関数
- Logistic Regression ベース
- p_error (Stage1誤り確率) を予測
- 証明書ルール + TLDルール + シナリオ群

**将来実装 (未統合)**: `future/stage2_v2/stage2_decider_v2.py`
- `train_stage2_xgb(X2_train, y_train)` → XGBClassifier
- `Stage2Thresholds` データクラス

## 12. システム性能（最新評価）

| 項目 | 値 |
|------|-----|
| テストデータ | 127,222件（balanced） |
| System F1 | 98.67% |
| Precision | 99.16% |
| Recall | 98.18% |
| 自動判定率 | 90.6% |
| Stage3投入率 | 9.4% (11,952件) |

---

## 付録: プログラム一覧

### Notebooks (*.ipynb)
| ファイル | 目的 |
|----------|------|
| 01_data_preparation_*.ipynb | データ準備・前処理 |
| 02_main.ipynb | Stage1/Stage2パイプライン |
| 03_ai_agent_analysis_part1.ipynb | Part1: Config・FN分析 |
| 03_ai_agent_analysis_part2.ipynb | Part2: 証明書マッピング |
| 03_ai_agent_analysis_part3.ipynb | Part3: TLD分析 |
| 04-1_config_and_data_preparation.ipynb | 設定・データ準備 |
| 04-2_statistical_analysis_*.ipynb | 統計分析 |
| 04-3_llm_tools_setup.ipynb | LLMツール設定 |
| 98-20251221-3.ipynb | AI Agent基本評価（開発・デバッグ用） |
| 98-randomN_for_paper_v6_*.ipynb | AI Agent論文用フル評価 |
| 98-stage2-handoff-validation_*.ipynb | Stage2 Gate+E2E評価 |

**注**: 98-*.ipynbは `scripts/evaluate_e2e_parallel.py` に置き換え済み（`bash scripts/run_eval_3gpu.sh` で実行）

### Python Modules (*.py)
| ファイル | 目的 |
|----------|------|
| 02_main.py | Stage1/Stage2スタンドアロン |
| run_id_registry.py | RUN_ID管理 |
| _compat/paths.py | パス管理 |
| 02_stage1_stage2/src/features.py | 特徴量抽出 |
| phishing_agent/langgraph_module.py | LangGraph状態管理 |
| phishing_agent/precheck_module.py | 事前チェック |
| phishing_agent/tools_module.py | ツール定義 |
| phishing_agent/llm_final_decision.py | LLM最終判定 |
| phishing_agent/rules/detectors/ | ルールモジュール (27ルール) |
| phishing_agent/tools/*.py | 分析ツール群 |
| scripts/evaluate_e2e.py | 単一GPU評価スクリプト |
| scripts/evaluate_e2e_parallel.py | 3GPU並列評価スクリプト |
| scripts/run_eval_3gpu.sh | 評価実行ラッパー（必須） |
