# データ仕様設計書 (Draft)

## 1. 概要

### 1.1 目的

- 特徴量がパイプラインを通過する際に脱落しない
- 各Stageの判定結果を追跡可能にする
- 分析・デバッグ・論文執筆に必要な情報を保持する

### 1.2 設計原則

1. **特徴量の一元管理**: 特徴量は最初に抽出し、以降は参照のみ
2. **判定結果の累積**: 各Stageの結果は上書きせず追加
3. **追跡可能性**: 全ての判定の根拠を追跡可能に
4. **主キー**: `domain` を一意識別子とする

---

## 2. テーブル構成

### 2.1 全体構成

```
artifacts/{RUN_ID}/
│
├── features/                          # 特徴量（不変）
│   │
│   │  [生データ]
│   ├── raw_cert_info.parquet          # cert_full_info_map (11項目)
│   │
│   │  [ML特徴量 - XGBoost用42項目]
│   ├── ml_features.parquet            # 全42特徴量
│   │
│   │  [分析用追加特徴量]
│   ├── analysis_features.parquet      # tld_category, brand_detected等
│   │
│   └── features_manifest.json         # 特徴量メタデータ
│
├── predictions/                       # 各Stageの判定結果
│   ├── stage1_results.parquet         # Stage1 (XGBoost) 結果
│   ├── stage2_results.parquet         # Stage2 (Gate) 結果
│   └── stage3_results.parquet         # Stage3 (Agent) 結果
│
├── unified/                           # 統合ビュー
│   └── unified_results.parquet        # 全特徴量 + 全Stage結果
│
└── metadata/
    ├── experiment_config.yaml         # 実験設定
    └── run_info.json                  # 実行情報
```

### 2.2 特徴量の分類

| カテゴリ | ファイル | 項目数 | 内容 |
|----------|----------|--------|------|
| 生データ | raw_cert_info.parquet | 11 | cert_full_info_map の全項目 |
| ML特徴量 | ml_features.parquet | 42 | XGBoostで使用する全特徴量 |
| 分析用 | analysis_features.parquet | 5+ | tld_category, brand等 |

---

## 3. 特徴量テーブル (features/)

### 3.0 ml_features.parquet (ML特徴量 - 42項目)

XGBoostモデルで使用する全特徴量。**現状はX_testとしてnumpy配列で保持されているが、これをDataFrameとして保存**。

#### ドメイン関連 (8項目)

| # | カラム名 | 型 | 説明 |
|---|----------|-----|------|
| 0 | domain_length | int | ドメイン文字数 |
| 2 | hyphen_count | int | ハイフン数 |
| 3 | digit_count | int | 数字の個数 |
| 4 | digit_ratio | float | 数字の割合 |
| 5 | tld_length | int | TLDの文字数 |
| 6 | subdomain_count | int | サブドメイン数 |
| 7 | longest_part_length | int | 最長パート長 |
| 10 | max_consonant_length | int | 最長子音連続数 |

#### 証明書関連 (27項目)

| # | カラム名 | 型 | 説明 |
|---|----------|-----|------|
| 15 | cert_validity_days | int | 証明書有効期間（日） |
| 16 | cert_is_wildcard | bool | ワイルドカード証明書 |
| 17 | cert_san_count | int | SAN数 |
| 18 | cert_issuer_length | int | 発行者名の長さ |
| 19 | cert_is_self_signed | bool | 自己署名 |
| 20 | cert_cn_length | int | Common Name長 |
| 21 | cert_subject_has_org | bool | Subject組織名有無 |
| 22 | cert_subject_org_length | int | Subject組織名長 |
| 23 | cert_san_dns_count | int | SAN DNS数 |
| 24 | cert_san_ip_count | int | SAN IP数 |
| 25 | cert_cn_matches_domain | bool | CNがドメインと一致 |
| 26 | cert_san_matches_domain | bool | SANがドメインと一致 |
| 27 | cert_san_matches_etld1 | bool | SANがeTLD+1と一致 |
| 28 | cert_has_ocsp | bool | OCSP有無 |
| 29 | cert_has_crl_dp | bool | CRL配布点有無 |
| 30 | cert_has_sct | bool | SCT有無 |
| 31 | cert_sig_algo_weak | bool | 弱い署名アルゴリズム |
| 32 | cert_pubkey_size | int | 公開鍵サイズ |
| 33 | cert_key_type_code | int | 鍵タイプコード |
| 34 | cert_is_lets_encrypt | bool | Let's Encrypt発行 |
| 35 | cert_key_bits_normalized | float | 正規化鍵ビット数 |
| 36 | cert_issuer_country_code | int | 発行者国コード |
| 37 | cert_serial_entropy | float | シリアル番号エントロピー |
| 38 | cert_has_ext_key_usage | bool | 拡張鍵用途有無 |
| 39 | cert_has_policies | bool | ポリシー有無 |
| 40 | cert_issuer_type | int | 発行者タイプ |
| 41 | cert_is_le_r3 | bool | Let's Encrypt R3 |

#### その他 (7項目)

| # | カラム名 | 型 | 説明 |
|---|----------|-----|------|
| 1 | dot_count | int | ドット数 |
| 8 | entropy | float | 文字列エントロピー |
| 9 | vowel_ratio | float | 母音の割合 |
| 11 | has_special_chars | bool | 特殊文字有無 |
| 12 | non_alphanumeric_count | int | 非英数字数 |
| 13 | contains_brand | bool | ブランド文字列含有 |
| 14 | has_www | bool | www有無 |

### 3.1 raw_cert_info.parquet (生の証明書情報)

cert_full_info_map の全項目を保持。**分析・デバッグ用の人間可読な情報**。

| カラム名 | 型 | 説明 | 例 |
|----------|-----|------|-----|
| domain | string | ドメイン名（主キー） | "example.com" |
| issuer_org | string | 発行者組織名 | "Let's Encrypt" |
| cert_age_days | int | 発行からの経過日数 | 45 |
| is_free_ca | bool | 無料CA判定 | true |
| san_count | int | SAN数 | 2 |
| is_wildcard | bool | ワイルドカード | false |
| is_self_signed | bool | 自己署名 | false |
| has_organization | bool | 組織名有無 | false |
| not_before | datetime | 証明書発行日 | "2024-01-01" |
| not_after | datetime | 証明書有効期限 | "2024-04-01" |
| has_certificate | bool | 証明書の有無 | true |
| source | string | データソース | "certificates" |

**注意**: ml_features の cert_* 項目とは計算方法が異なる場合がある。
- `raw_cert_info.san_count` = 証明書から直接取得
- `ml_features.cert_san_count` = 特徴量抽出ロジックで計算

### 3.2 analysis_features.parquet (分析用追加特徴量)

分析・可視化のために追加で計算する特徴量。

| カラム名 | 型 | 説明 | 例 |
|----------|-----|------|-----|
| domain | string | ドメイン名（主キー） | "example.com" |
| tld | string | TLD | "com" |
| tld_category | string | TLD危険度分類 | "non_danger" |
| brand_detected | string | 検出ブランド | "paypal" |
| brand_match_type | string | マッチタイプ | "exact" / "fuzzy" |
| brand_score | float | ブランドスコア | 0.72 |

---

### 3.3 domain_features.parquet (廃止予定)

ドメイン名から抽出される特徴量。

| カラム名 | 型 | 説明 | 例 |
|----------|-----|------|-----|
| domain | string | ドメイン名（主キー） | "example.com" |
| tld | string | トップレベルドメイン | "com" |
| tld_category | string | TLD危険度分類 | "non_danger" / "medium_danger" / "high_danger" |
| domain_length | int | ドメイン文字数 | 11 |
| subdomain_count | int | サブドメイン数 | 0 |
| digit_ratio | float | 数字の割合 | 0.0 |
| hyphen_count | int | ハイフン数 | 0 |
| has_brand_substring | bool | ブランド文字列含有 | false |
| source | string | データソース | "phishtank" / "benign" |
| y_true | int | 正解ラベル | 0 / 1 |

### 3.2 cert_features.parquet

証明書から抽出される特徴量。**cert_full_info_map の全項目を保持**。

| カラム名 | 型 | 説明 | 例 |
|----------|-----|------|-----|
| domain | string | ドメイン名（主キー） | "example.com" |
| has_certificate | bool | 証明書の有無 | true |
| issuer_org | string | 発行者組織名 | "Let's Encrypt" |
| cert_validity_days | int | 証明書有効期間（日） | 90 |
| cert_age_days | int | 発行からの経過日数 | 45 |
| san_count | int | SAN数 | 2 |
| is_free_ca | bool | 無料CA判定 | true |
| is_wildcard | bool | ワイルドカード証明書 | false |
| is_self_signed | bool | 自己署名判定 | false |
| has_organization | bool | 組織名の有無 (OV/EV判定) | false |
| not_before | datetime | 証明書発行日 | "2024-01-01T00:00:00" |
| not_after | datetime | 証明書有効期限 | "2024-04-01T00:00:00" |

---

## 4. 判定結果テーブル (predictions/)

### 4.1 stage1_results.parquet

Stage1 (XGBoost) の判定結果。

| カラム名 | 型 | 説明 | 例 |
|----------|-----|------|-----|
| domain | string | ドメイン名（主キー） | "example.com" |
| stage1_proba | float | フィッシング確率 | 0.847 |
| stage1_pred | int | 予測ラベル (threshold=0.5) | 1 |
| stage1_decision | string | 判定区分 | "auto_phishing" / "auto_benign" / "handoff" |
| stage1_confidence | string | 確信度区分 | "high" / "medium" / "low" |

**stage1_decision の定義**:
- `auto_phishing`: proba >= t_high → 自動でフィッシング判定
- `auto_benign`: proba <= t_low → 自動でbenign判定
- `handoff`: t_low < proba < t_high → Stage2へ

### 4.2 stage2_results.parquet

Stage2 (Gate/Selection) の判定結果。

| カラム名 | 型 | 説明 | 例 |
|----------|-----|------|-----|
| domain | string | ドメイン名（主キー） | "example.com" |
| stage2_candidate | bool | Handoff候補か | true |
| stage2_selected | bool | 実際にHandoffされたか | true |
| stage2_decision | string | 判定区分 | "handoff_to_agent" / "auto_by_stage1" |
| stage2_reason | string | 選択理由 | "segment_priority" / "budget_limit" |
| stage2_lr_proba | float | LR予測確率（該当時） | 0.65 |

### 4.3 stage3_results.parquet

Stage3 (AI Agent) の判定結果。

| カラム名 | 型 | 説明 | 例 |
|----------|-----|------|-----|
| domain | string | ドメイン名（主キー） | "example.com" |
| agent_pred | int | Agent予測 | 1 |
| agent_confidence | float | Agent確信度 | 0.85 |
| agent_reasoning | string | 判定理由（LLM出力） | "Brand impersonation detected..." |
| gate_fired | string | 発火したゲート | "P1_LOW_SIGNAL" / "B2_NON_DANGER" / null |
| gate_decision | int | ゲート判定（発火時） | 1 |
| llm_raw_decision | int | LLM生判定（ゲート前） | 0 |
| brand_detected | string | 検出ブランド | "paypal" |
| brand_score | float | ブランドスコア | 0.72 |
| tool_calls | json/string | 使用したツール | ["cert_analysis", "brand_check"] |
| processing_time_ms | int | 処理時間（ミリ秒） | 2340 |
| error | string | エラー（発生時） | null |

---

## 5. 統合ビュー (unified/)

### 5.1 unified_results.parquet

全特徴量と全Stage結果を結合した分析用ビュー。

**構成**: domain_features + cert_features + stage1_results + stage2_results + stage3_results

| カラム名 | 型 | 説明 |
|----------|-----|------|
| domain | string | ドメイン名（主キー） |
| --- | --- | **[domain_features]** |
| tld | string | TLD |
| tld_category | string | TLD危険度 |
| ... | ... | ... |
| --- | --- | **[cert_features]** |
| issuer_org | string | 発行者 |
| cert_validity_days | int | 有効期間 |
| ... | ... | ... |
| --- | --- | **[stage1_results]** |
| stage1_proba | float | Stage1確率 |
| stage1_decision | string | Stage1判定 |
| --- | --- | **[stage2_results]** |
| stage2_selected | bool | Handoff有無 |
| stage2_decision | string | Stage2判定 |
| --- | --- | **[stage3_results]** |
| agent_pred | int | Agent予測 |
| gate_fired | string | 発火ゲート |
| --- | --- | **[final]** |
| final_pred | int | 最終予測 |
| final_source | string | 最終判定の出処 | "stage1" / "stage3" |

---

## 6. 最終予測の決定ロジック

```python
def compute_final_prediction(row):
    """最終予測を計算"""
    if row['stage2_decision'] == 'auto_by_stage1':
        # Stage1で自動判定
        return row['stage1_pred'], 'stage1_auto'
    elif row['stage3_agent_pred'] is not None:
        # Stage3で判定
        return row['agent_pred'], 'stage3_agent'
    else:
        # フォールバック: Stage1予測を使用
        return row['stage1_pred'], 'stage1_fallback'
```

---

## 7. エラー分析用ビュー

### 7.1 必要な派生カラム

| カラム名 | 型 | 計算式 |
|----------|-----|--------|
| is_tp | bool | final_pred == 1 AND y_true == 1 |
| is_fp | bool | final_pred == 1 AND y_true == 0 |
| is_tn | bool | final_pred == 0 AND y_true == 0 |
| is_fn | bool | final_pred == 0 AND y_true == 1 |
| stage1_correct | bool | stage1_pred == y_true |
| agent_correct | bool | agent_pred == y_true (where applicable) |
| agent_flipped | bool | agent_pred != stage1_pred |
| agent_improved | bool | agent_correct AND NOT stage1_correct |
| agent_degraded | bool | NOT agent_correct AND stage1_correct |

---

## 8. メタデータ

### 8.1 experiment_config.yaml

```yaml
run_id: "2026-01-17_132657"
created_at: "2026-01-17T13:26:57"

pipeline:
  stage1:
    model: "xgboost"
    threshold_low: 0.001
    threshold_high: 0.997559
  stage2:
    method: "segment_priority"
    max_budget: 20000
  stage3:
    llm_provider: "vllm"
    llm_model: "Qwen3-4B-Thinking-GPTQ-Int8"
    policy_version: "v1.6.3-fn-rescue"

data:
  total_samples: 128067
  train_samples: 102453
  test_samples: 25614
  handoff_candidates: 19479

features:
  domain_features: 10
  cert_features: 12
  ml_features: 20
```

### 8.2 features_manifest.json

```json
{
  "domain_features": {
    "version": "1.0",
    "columns": ["domain", "tld", "tld_category", ...],
    "row_count": 128067,
    "created_at": "2026-01-17T13:30:00"
  },
  "cert_features": {
    "version": "1.0",
    "columns": ["domain", "issuer_org", "cert_validity_days", ...],
    "row_count": 128067,
    "created_at": "2026-01-17T13:30:00",
    "source": "cert_full_info_map"
  }
}
```

---

## 9. 実装優先順位

| 優先度 | 項目 | 理由 |
|--------|------|------|
| **P0** | cert_features.parquet 作成 | 現在脱落している情報の保持 |
| **P1** | stage3_results.parquet 作成 | Agent判定の詳細追跡 |
| **P2** | unified_results.parquet 作成 | 分析の効率化 |
| **P3** | 02_main.py 修正 | パイプラインで自動生成 |
| **P4** | FeatureStore クラス実装 | 統一アクセスインターフェース |

---

## 10. マイグレーション計画

### 現状 → 新仕様への移行

1. **Phase 1**: 既存データから特徴量テーブルを生成（後方互換）
2. **Phase 2**: 02_main.py を修正して新形式で出力
3. **Phase 3**: evaluate_e2e.py を修正して新形式に対応
4. **Phase 4**: 分析ノートブックを新形式に対応

### 後方互換性

- 既存の CSV ファイルは引き続き生成（deprecation warning付き）
- 新形式への完全移行後に削除
