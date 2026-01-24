# E2E評価スクリプト仕様書

**更新日**: 2026-01-24
**対象**: `scripts/evaluate_e2e.py`

---

## 1. 概要

Stage1 → Stage2 (handoff gate) → Stage3 (AI Agent) → 最終判定のパイプライン全体を評価するスクリプト。handoff候補のドメインに対してAI Agentを実行し、性能指標を算出する。

## 2. CLI インタフェース

```bash
python scripts/evaluate_e2e.py [OPTIONS]
```

| オプション | 説明 | デフォルト |
|-----------|------|-----------|
| `--n-sample N` | 評価サンプル数 (数値 or "ALL") | 100 |
| `--n-benign N` | 追加benignサンプル数 | 0 |
| `--n-benign-hard N` | 追加hard benignサンプル数 | 0 |
| `--random-state N` | 乱数シード | 42 |
| `--fn-cost F` | FNコスト係数 | 3.0 |
| `--fp-cost F` | FPコスト係数 | 1.0 |
| `--handoff-cost F` | Handoffコスト係数 | 0.0 |
| `--enable-db-tld` | DBからTLDリスト動的生成 | False |
| `--verbose` | 詳細ログ出力 | False |

## 3. 処理フロー

```
1. 引数パース
2. RUN_ID・パス解決
3. データ読込
   - handoff_candidates_latest.csv (Stage2 handoff候補)
   - 04-3_llm_tools_setup_with_tools.pkl (外部データ: TLD, brand等)
4. 評価データ構築
   - stage2_handoff からサンプリング
   - benign_random / benign_hard 追加 (オプション)
5. AI Agent初期化 (LangGraphPhishingAgent)
6. 全ドメイン評価ループ
   - evaluate_single_domain()
   - 結果をDataFrameに蓄積
7. 性能指標算出
   - TP/FP/TN/FN, Precision, Recall, F1
   - Gate指標 (error_capture_recall, handoff_precision)
   - コスト関数
8. 結果保存
```

## 4. 入力データ

### 4.1 handoff_candidates_latest.csv

Stage2がhandoffと判定したドメイン一覧。

| カラム | 型 | 説明 |
|--------|-----|------|
| `domain` | str | ドメイン名 |
| `source` | str | データソース (trusted/phishtank/jpcert) |
| `y_true` | int | 正解ラベル (0: benign, 1: phishing) |
| `ml_probability` | float | Stage1 ML確率 |
| `prediction_proba` | float | Stage2予測確率 |
| `cert_*` | various | 証明書関連特徴量 (20+カラム) |
| `ml_*` | various | ML特徴量 (30+カラム) |

### 4.2 外部データ (04-3_llm_tools_setup_with_tools.pkl)

| キー | 内容 |
|------|------|
| `tld_sets` | TLD分類 (dangerous, legitimate等) |
| `brand_keywords` | ブランドキーワードリスト |
| `high_risk_words` | 高リスクワード |
| `KNOWN_DOMAINS` | 既知正規ドメイン |
| `cert_map` | 証明書データマッピング |

## 5. 評価グループ

| グループ | 説明 | ラベル分布 |
|----------|------|-----------|
| `stage2_handoff` | Stage2 handoff候補 | phishing多め |
| `benign_random` | ランダムbenignサンプル | 全件benign |
| `benign_hard` | 困難benignサンプル (ML高スコア) | 全件benign |

## 6. 出力

### 6.1 ファイル

```
artifacts/{RUN_ID}/results/stage2_validation/
├── eval_df__n{N}__ts_{timestamp}.csv    # 評価結果
├── all_test_merged__ts_{timestamp}.csv  # 全テストデータ
└── summary__ts_{timestamp}.json         # サマリ
```

### 6.2 eval_df カラム

| カラム | 型 | 説明 |
|--------|-----|------|
| `domain` | str | ドメイン名 |
| `ml_probability` | float | Stage1 ML確率 |
| `ai_is_phishing` | bool | AI Agent判定 |
| `ai_confidence` | float | 信頼度 |
| `ai_risk_level` | str | リスクレベル |
| `processing_time` | float | 処理時間 (秒) |
| `error` | str | エラー情報 |
| `source` | str | データソース |
| `y_true` | int | 正解ラベル |
| `stage1_pred` | int | Stage1予測 |
| `tld` | str | TLD |

### 6.3 summary.json

```json
{
  "n_sample": 3000,
  "total_evaluated": 3000,
  "metrics": {
    "precision": 0.916,
    "recall": 0.600,
    "f1": 0.725,
    "accuracy": 0.907
  },
  "confusion_matrix": {"TP": 2145, "FP": 196, "TN": 13665, "FN": 1428},
  "cost": {"fn_cost": 3.0, "fp_cost": 1.0, "total": 4480.0},
  "elapsed_hours": 17.64
}
```

## 7. 性能指標

### 7.1 基本指標

- **Precision**: TP / (TP + FP)
- **Recall**: TP / (TP + FN)
- **F1 Score**: 2 * Precision * Recall / (Precision + Recall)
- **Accuracy**: (TP + TN) / Total

### 7.2 Gate指標

- **error_capture_recall**: Stage2 handoffに含まれるphishingの割合
- **handoff_precision**: handoff候補中の実際のphishing率

### 7.3 コスト関数

```
Total Cost = FN_cost * FN + FP_cost * FP + Handoff_cost * Handoff_count
```

## 8. vLLM依存

- 実行前にvLLMが起動している必要がある
- `config.json` の `llm.base_url` で接続先を指定
- 並列版 (`evaluate_e2e_parallel.py`) はvLLMの自動起動/停止に対応

## 9. 並列版との関係

| 項目 | evaluate_e2e.py | evaluate_e2e_parallel.py |
|------|----------------|--------------------------|
| Worker数 | 1 | 1-3 (可変) |
| vLLM管理 | 手動 | 自動起動/停止 |
| チェックポイント | なし | あり (resume可) |
| ヘルスモニタ | なし | あり |
| 推奨用途 | 小規模テスト (< 1000件) | 大規模評価 (全件) |
