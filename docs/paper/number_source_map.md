# Number Source Map: 論文数値 ↔ データソース対応表

本文・表・図に記載される主要数値と、その正式な出典（CSV/JSONファイル + 列名）の1:1対応表。
更新日: 2026-02-07（paper_outline.md 最終更新版に合わせてマッピング再整備）

すべてのパスは `docs/paper/data/` 配下。

---

## データセット（表1）

| 数値 | 意味 | 出典ファイル | キー/列名 |
|------|------|-------------|----------|
| 532,117 | certificates テーブル総数 | tables/table1_dataset.csv | Source: certificates |
| 222,984 | jpcert テーブル総数 | tables/table1_dataset.csv | Source: jpcert_phishing_urls |
| 94,295 | phishtank テーブル総数 | tables/table1_dataset.csv | Source: phishtank_entries |
| 554,801 | trusted テーブル総数 | tables/table1_dataset.csv | Source: trusted_certificates |
| 319,383 | Phishing cert-holding（重複排除前） | tables/table1_dataset.csv | Phishing (cert-holding, pre-dedup) |
| 318,055 | Phishing（パイプライン後） | tables/table1_dataset.csv | Phishing (post-pipeline) |
| 636,110 | 準備データ総数 | tables/table1_dataset.csv | Total (post-pipeline) |
| 508,888 | 訓練データ件数 | tables/table1_dataset.csv | Train |
| 127,222 | テストドメイン総数 | tables/table1_dataset.csv / system_overall_metrics.json | Test / total_domains |
| 42 | 特徴量数 | (コード定数: FEATURE_ORDER) | — |

## 証明書可用性（表2）

| 数値 | 意味 | 出典ファイル | キー/列名 |
|------|------|-------------|----------|
| 196,083 (36.9%) | certificates cert_data保有 | tables/table2_cert_availability.csv | certificates行 |
| 119,439 (53.6%) | jpcert cert_data保有 | tables/table2_cert_availability.csv | jpcert行 |
| 52,808 (56.0%) | phishtank cert_data保有 | tables/table2_cert_availability.csv | phishtank行 |
| 450,545 (81.2%) | trusted cert_data保有 | tables/table2_cert_availability.csv | trusted行 |

## 証明書ステータス分布（表2補足）

| 数値 | 意味 | 出典ファイル | キー/列名 |
|------|------|-------------|----------|
| NOT_FOUND 49.2% | certificates主要failure | tables/table2_cert_status.csv | certificates, NOT_FOUND |
| NOT_HTTPS 18.7% | jpcert HTTP-onlyサイト | tables/table2_cert_status.csv | jpcert, NOT_HTTPS |

## Stage 1 (XGBoost) ルーティング

| 数値 | 意味 | 出典ファイル | キー/列名 |
|------|------|-------------|----------|
| 60,767 (47.8%) | auto_phishing件数 | tables/fig2_stage_transitions.csv | Stage1, auto_phishing |
| 8,464 (6.7%) | auto_benign件数 | tables/fig2_stage_transitions.csv | Stage1, auto_benign |
| 57,991 (45.6%) | handoff_to_stage2 | tables/fig2_stage_transitions.csv | Stage1, handoff_to_stage2 |
| 60,765 / 2 | auto_phishing TP/FP | statistics/stage1_metrics.json | routing.auto_phishing.TP/FP |
| 8,461 / 3 | auto_benign TN/FN | statistics/stage1_metrics.json | routing.auto_benign.TN/FN |
| 69,231 (54.4%) | 自動判定合計 | tables/fig2_stage_transitions.csv（計算値） | auto_phishing + auto_benign |

## Stage 2 (LR + Certificate Gate) — 表4

| 数値 | 意味 | 出典ファイル | キー/列名 |
|------|------|-------------|----------|
| 46,039 (36.2%) | drop_to_auto件数 | tables/table4_stage2_effect.csv | decision=drop_to_auto |
| 11,952 (9.4%) | handoff_to_agent件数 | tables/table4_stage2_effect.csv | decision=handoff_to_agent |
| 115,270 | 自動判定合計 | tables/table4_stage2_effect.csv | auto_decided_total |
| 401 | auto-decision errors | tables/table4_stage2_effect.csv | auto_errors |
| 0.348% | auto-decision error rate | tables/table4_stage2_effect.csv | auto_error_rate |
| 32,179 | safe_benign (LR base) | tables/table4_stage2_effect.csv | gate=safe_benign (base) |
| 45,171 | safe_benign_cert (cert強化後) | tables/table4_stage2_effect.csv | gate=safe_benign_cert |
| 12,992 | cert gate追加分 | （計算値: 45,171 - 32,179） | — |
| 45,307 | safe_benign_combined (最終) | tables/table4_stage2_effect.csv | gate=safe_benign_combined |
| 8 | safe_phishing_cert | tables/table4_stage2_effect.csv | gate=safe_phishing_cert |
| 1,718 | high_ml_phish override | tables/table4_stage2_effect.csv | gate=high_ml_phish override |
| 45,641 / 398 | drop TN/FN | tables/table4_stage2_effect.csv | drop_to_auto: y_true_0/y_true_1 |
| 9,507 / 2,445 | handoff y_true_0/y_true_1 | tables/table4_stage2_effect.csv | handoff_to_agent: y_true_0/y_true_1 |

## Stage 3 (LLM + Rule Engine) — 表5

| 数値 | 意味 | 出典ファイル | キー/列名 |
|------|------|-------------|----------|
| 11,952 | Stage3評価総数 | tables/table5_stage3_performance.csv | total_evaluated |
| 1,685 | TP | tables/table5_stage3_performance.csv | TP |
| 529 | FP | tables/table5_stage3_performance.csv | FP |
| 8,978 | TN | tables/table5_stage3_performance.csv | TN |
| 760 | FN | tables/table5_stage3_performance.csv | FN |
| 76.11% | Precision | tables/table5_stage3_performance.csv | Precision |
| 68.92% | Recall | tables/table5_stage3_performance.csv | Recall |
| 72.33% | F1 | tables/table5_stage3_performance.csv | F1 |
| 5.56% | FPR | tables/table5_stage3_performance.csv | FPR |
| 2,011 (16.8%) | ルール発動件数 | tables/table5_stage3_performance.csv | rule_fired_count/rule_fired_rate |
| 9.21s | 平均処理時間 | statistics/stage3_metrics.json | processing_time.mean |

## Stage 3 アブレーション（表6）

| 数値 | 意味 | 出典ファイル | キー/列名 |
|------|------|-------------|----------|
| 87.69% / 55.34% / 67.85% | LLMのみ P/R/F1 | tables/table6_stage3_ablation.csv | LLM only行 |
| 76.11% / 68.92% / 72.33% | LLM+Rules P/R/F1 | tables/table6_stage3_ablation.csv | LLM + Rules行 |
| +13.58pt | Recall改善幅 | （計算値: 68.92 - 55.34） | — |
| -11.58pt | Precision低下幅 | （計算値: 76.11 - 87.69） | — |
| 811 (6.79%) | ルールflip件数 | tables/table6_stage3_ablation.csv | total_flipped/flip_rate_pct |
| 402 / 409 | flip正解/不正解 | tables/table6_stage3_ablation.csv | flip_correct/flip_incorrect |
| 49.57% | flip精度 | tables/table6_stage3_ablation.csv | flip_accuracy_pct |

## システム全体 — 表3（ヘッドライン結果）

| 数値 | 意味 | 出典ファイル | キー/列名 |
|------|------|-------------|----------|
| **Stage1+2のみ（ベースライン）** | | | |
| 98.60% | Baseline F1 | tables/table3_system_performance.csv | Stage1+2 only, F1 |
| 97.73% | Baseline Recall | tables/table3_system_performance.csv | Stage1+2 only, Recall |
| 2.27% | Baseline FNR | tables/table3_system_performance.csv | Stage1+2 only, FNR |
| 0.51% | Baseline FPR | tables/table3_system_performance.csv | Stage1+2 only, FPR |
| 1,444 | Baseline FN | tables/table3_system_performance.csv | Stage1+2 only, FN |
| 322 | Baseline FP | tables/table3_system_performance.csv | Stage1+2 only, FP |
| **Full cascade（提案手法）** | | | |
| 98.67% | System F1 | tables/table3_system_performance.csv / system_overall_metrics.json | Full cascade, F1 / f1 |
| 98.18% | System Recall | tables/table3_system_performance.csv / system_overall_metrics.json | Recall / recall |
| 99.16% | System Precision | system_overall_metrics.json | precision |
| 1.82% | System FNR | system_overall_metrics.json | fnr |
| 0.84% | System FPR | system_overall_metrics.json | fpr |
| 1,158 | System FN | tables/table3_system_performance.csv | Full cascade, FN |
| 532 | System FP | tables/table3_system_performance.csv | Full cascade, FP |
| **改善幅** | | | |
| +0.07pt | F1改善 | （計算値: 98.67 - 98.60） | — |
| +0.45pt | Recall改善 | （計算値: 98.18 - 97.73） | — |
| -286件 | FN削減 | （計算値: 1,444 - 1,158） | — |
| 90.6% | Auto-decision率 | system_overall_metrics.json | auto_decision_rate |
| 9.4% | Stage3投入率 | system_overall_metrics.json | stage3_rate |

## 閾値スイープ（図3）

| 数値 | 意味 | 出典ファイル | キー/列名 |
|------|------|-------------|----------|
| τ=0.4 | 運用点の閾値 | tables/fig3_threshold_sweep.csv | tau=0.4 行 |
| 9.39% | 運用点のStage3 call rate | tables/fig3_threshold_sweep.csv | stage3_rate_pct |
| 401 | 運用点のauto-decision errors | tables/fig3_threshold_sweep.csv | auto_errors |
| 0.3479% | 運用点のauto-decision error rate | tables/fig3_threshold_sweep.csv | auto_error_rate_pct |
| 374–1,447 | errors範囲（τ=0.0〜1.0） | tables/fig3_threshold_sweep.csv | auto_errors min/max |
| 396–427 | errors安定域（τ=0.3〜0.5） | tables/fig3_threshold_sweep.csv | τ=0.3〜0.5行のauto_errors |

## 処理遅延（図4）

| 数値 | 意味 | 出典ファイル | キー/列名 |
|------|------|-------------|----------|
| p50=8.31s | 処理時間中央値 | tables/fig4_processing_time.csv / stage3_metrics.json | percentile=50 / p50 |
| p90=15.27s | 処理時間90分位 | tables/fig4_processing_time.csv / stage3_metrics.json | percentile=90 / p90 |
| p99=28.59s | 処理時間99分位 | tables/fig4_processing_time.csv / stage3_metrics.json | percentile=99 / p99 |
| 11,952 | Stage3処理件数 | tables/fig4_processing_time.csv | worker count合計 |

## 誤り分析（図5）

| 数値 | 意味 | 出典ファイル | キー/列名 |
|------|------|-------------|----------|
| 1,158 | FN合計 | tables/fig5_error_categories.csv | FN Total |
| 532 | FP合計 | tables/fig5_error_categories.csv | FP Total |
| 3 / 395 / 760 | FN Stage別 | tables/fig5_error_categories.csv | FN Stage1/2/3 |
| 2 / 1 / 529 | FP Stage別 | tables/fig5_error_categories.csv | FP Stage1/2/3 |
| 387 / 232 / 141 | Stage3 FNソース別 | tables/fig5_error_categories.csv | # Stage3 FN by source |
| 0.1414 | Stage3 FN MLスコア中央値 | tables/fig5_error_categories.csv | # Stage3 FN ML probability stats: median |

## Stage1 ハイパーパラメータ

| パラメータ | 値 | 出典ファイル |
|-----------|-----|-------------|
| n_estimators | 300 | 02_stage1_stage2/configs/default.yaml |
| max_depth | 8 | 02_stage1_stage2/configs/default.yaml |
| learning_rate | 0.1 | 02_stage1_stage2/configs/default.yaml |
| subsample | 0.8 | 02_stage1_stage2/configs/default.yaml |
| colsample_bytree | 0.8 | 02_stage1_stage2/configs/default.yaml |
| early_stopping_rounds | 20 | 02_stage1_stage2/configs/default.yaml |

## ベースライン比較（付録表A）

| 数値 | 意味 | 出典ファイル |
|------|------|-------------|
| F1=98.58〜98.66% | 全モデルF1範囲 | tables/appendix_baselines.csv |
| XGBoost n=300 | Stage1ハイパラ | 02_stage1_stage2/configs/default.yaml |

---

## データソースファイル一覧

すべて `docs/paper/data/` 配下:

```
tables/
  table1_dataset.csv              - データセット構成（表1）
  table2_cert_availability.csv    - 証明書取得率（表2）
  table2_cert_status.csv          - 証明書ステータス分布（表2補足）
  table3_system_performance.csv   - システム全体性能（表3）
  table4_stage2_effect.csv        - Stage2効果（表4）
  table5_stage3_performance.csv   - Stage3混同行列・ルール発動（表5）
  table6_stage3_ablation.csv      - Stage3アブレーション（表6）
  fig2_stage_transitions.csv      - Stage遷移件数・割合（図2）
  fig3_threshold_sweep.csv        - 閾値スイープ（図3）
  fig4_processing_time.csv        - 処理時間分布（図4）
  fig5_error_categories.csv       - エラーカテゴリ（図5）
  appendix_baselines.csv          - ベースライン比較（付録表A）

statistics/
  system_overall_metrics.json     - システム全体指標
  stage1_metrics.json             - Stage1 routing詳細
  stage2_metrics.json             - Stage2 drop詳細
  stage3_metrics.json             - Stage3処理時間等
  rule_firing_summary.json        - ルール発動サマリ
```

## クラス比率別性能推定（表8）

| 数値 | 算出方法 | 入力データ |
|------|--------|---------|
| TPR=0.9818 | TP/(TP+FN) = 62453/63611 | system_overall_metrics.json |
| FPR=0.00836 | FP/(FP+TN) = 532/63611 | system_overall_metrics.json |
| PPV(p) | TPR*p / (TPR*p + FPR*(1-p)) | ベイズ式による推定 |
| 各比率のPrecision/F1 | 上記式から算出 | tables/class_ratio_analysis.csv |
| Precision≥90%の最小p | p ≥ PPV*·FPR / (TPR·(1-PPV*) + PPV*·FPR) = 0.071 | 逆算式 |

生成スクリプト: `scripts/evaluate_class_ratio.py`

---

## outline数値 → データソース 網羅性チェック

| outline箇所 | 参照数値 | 対応データ | 状態 |
|------------|---------|-----------|------|
| §1.4 知見1 | F1 98.60→98.67, FN 1444→1158 | table3 | ✅ |
| §1.4 知見2 | call rate 9.4%, error rate 0.348% | table4 | ✅ |
| §1.4 知見3 | Recall +13.58pt | table6 | ✅ |
| §3.2 実測 | auto_phishing 60,767等 | fig2_stage_transitions | ✅ |
| §3.3 実測 | gate内訳 32,179/45,171/1,718等 | table4 | ✅ |
| §4.1.1 | cert保有率 36.9%〜81.2% | table2_cert_availability | ✅ |
| §4.1.1 | status分布 NOT_FOUND等 | table2_cert_status | ✅ |
| §4.2 Table3 | baseline vs full cascade | table3 | ✅ |
| §4.2 Table4 | 投入制御数値 | table4 | ✅ |
| §4.2 図3 | τスイープ | fig3_threshold_sweep | ✅ |
| §4.2 図4 | p50/p90/p99 | fig4_processing_time | ✅ |
| §4.3 Table5 | Stage3性能 | table5 | ✅ |
| §4.3 Table6 | アブレーション | table6 | ✅ |
| §4.3 図5 | FN/FP Stage別 | fig5_error_categories | ✅ |
| §5.3 T1 | cert保有率 | table2_cert_availability | ✅ |
| §5.3 T4 | FNソース別 387/232/141 | fig5_error_categories | ✅ |
| §5.3 T5 | τ安定域 396〜427 | fig3_threshold_sweep | ✅ |
| §5.3 T6 | flip 811件, 精度49.57% | table6 | ✅ |
| §5.3 T7 | F1 98.58〜98.66% | appendix_baselines | ✅ |
| §5.3 T8 | p50=8.31s等 | fig4_processing_time | ✅ |
| 付録表A | ベースライン5モデル | appendix_baselines | ✅ |
| §5.2 表8 | 比率別Precision/F1, 逆算p≥0.071 | class_ratio_analysis + ベイズ式 | ✅ |
