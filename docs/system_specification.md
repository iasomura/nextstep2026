# フィッシング検知システム仕様概要

作成日: 2026-01-12

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
│   ├── stage2_decider_v2.py        # Stage2決定器
│   ├── llm_final_decision.py       # LLM最終判定
│   └── tools/                      # 分析ツール群
│       ├── brand_impersonation_check.py
│       ├── certificate_analysis.py
│       ├── short_domain_analysis.py
│       └── contextual_risk_assessment.py
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

**総特徴量数**: 35 + 6 = 41

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

#### 証明書特徴量 (20 + 6)
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

### 3.3 閾値設計
```python
theta_low = 0.15   # AUTO_BENIGN閾値
theta_high = 0.85  # AUTO_PHISH閾値
```

## 4. Stage2: ロジスティック回帰 + 証明書ルール

### 4.1 概要
- **目的**: Stage1のDEFERをさらにフィルタリング
- **入力**: Stage1 DEFER集合
- **出力**: p2 → AUTO_PHISH_2 / AUTO_BENIGN_2 / DEFER2

### 4.2 証明書ルール (`stage2_decider_v2.py`)

以下のいずれかを満たす場合、Benign（正規）と判定：

| ルール | 条件 | 識別力 |
|--------|------|--------|
| CRL | cert_has_crl_dp = True | 83.5% |
| OV/EV | cert_subject_has_org = True | 5.9% |
| Wildcard | cert_is_wildcard = True | 11.0% |
| Long Validity | cert_validity_days > 180 | 19.4% |

### 4.3 独立評価結果 (2026-01-12)

| 指標 | 元の評価 | 独立評価 |
|------|----------|----------|
| フィルタリング率 | 93.0% | **53.3%** |
| 精度 | 96.6% | 90.7% |

**注意**: 93%フィルタリングは過学習の結果。独立データでは53%程度。

## 5. Stage3: AI Agent (LangGraph)

### 5.1 概要
- **目的**: Stage2のDEFER2に対してLLMベースの最終判定
- **フレームワーク**: LangGraph (状態機械)
- **LLM**: vLLM / Ollama (Qwen3-14B-FP8等)

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
┌─────────────────────────────────────────────┐
│  98-*.ipynb (AI Agent実行 - 目的に応じて選択) │
│    - 98-20251221-3 (開発・デバッグ)         │
│    - 98-randomN_for_paper_v6 (論文用評価)   │
│    - 98-stage2-handoff-validation (検証)    │
└─────────────────────────────────────────────┘
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

## 7. データソース

### 7.1 PostgreSQLテーブル

| テーブル | 内容 | レコード数 |
|----------|------|------------|
| phishtank_entries | PhishTankフィッシングURL | ~54,000 |
| jpcert_phishing_urls | JPCERTフィッシングURL | ~116,000 |
| certificates | フィッシング証明書 | ~196,000 |
| trusted_certificates | 正規サイト証明書 | ~450,000 |

### 7.2 prepared_data.pkl
- フィッシング: ~320,000 ドメイン
- 正規サイト: ~320,000 ドメイン（バランス調整後）

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
    "model": "Qwen/Qwen3-14B-FP8"
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

### 11.3 Stage2決定器 (`phishing_agent/stage2_decider_v2.py`)
- `train_stage2_xgb(X2_train, y_train)` → XGBClassifier
- `Stage2Thresholds` データクラス

## 12. 改善課題

1. **Stage2過学習対策**: 証明書ルールの閾値を独立データで再調整
2. **TLD分析強化**: 危険TLDリストの定期更新機構
3. **LLM最適化**: プロンプトチューニング、モデル選定

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

**注**: 98-*.ipynbの詳細は [98_notebooks_specification.md](98_notebooks_specification.md) を参照

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
| phishing_agent/stage2_decider_v2.py | Stage2決定器 |
| phishing_agent/llm_final_decision.py | LLM最終判定 |
| phishing_agent/tools/*.py | 分析ツール群 |
