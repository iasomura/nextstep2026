# Number Source Map: 論文数値 <-> データソース対応表

本文・表・図に記載される主要数値と、その正式な出典（CSV/JSONファイル + 列名）の1:1対応表。

## データセット

| 数値 | 意味 | 出典ファイル | キー/列名 |
|------|------|-------------|----------|
| 127,222 | テストドメイン総数 | statistics/system_overall_metrics.json | total_domains |
| 508,888 | 訓練データ件数 | tables/table1_dataset.csv | (train row) |
| 636,110 | 準備データ総数 | tables/table1_dataset.csv | (total row) |
| 42 | 特徴量数 | (コード定数: FEATURE_ORDER) | - |

## Stage 1 (XGBoost)

| 数値 | 意味 | 出典ファイル | キー/列名 |
|------|------|-------------|----------|
| 60,767 (47.8%) | auto_phishing件数 | tables/fig2_stage_transitions.csv | Stage1, auto_phishing |
| 8,464 (6.7%) | auto_benign件数 | tables/fig2_stage_transitions.csv | Stage1, auto_benign |
| 57,991 (45.6%) | handoff_to_stage2 | tables/fig2_stage_transitions.csv | Stage1, handoff_to_stage2 |
| 60,765 / 2 | auto_phishing TP/FP | statistics/stage1_metrics.json | routing.auto_phishing.TP/FP |
| 8,461 / 3 | auto_benign TN/FN | statistics/stage1_metrics.json | routing.auto_benign.TN/FN |

## Stage 2 (LR + Certificate Gate)

| 数値 | 意味 | 出典ファイル | キー/列名 |
|------|------|-------------|----------|
| 46,039 (36.2%) | drop_to_auto件数 | tables/fig2_stage_transitions.csv | Stage2, drop_to_auto |
| 11,952 (9.4%) | handoff_to_agent件数 | tables/fig2_stage_transitions.csv | Stage2, handoff_to_agent (Stage3) |
| 45,641 / 398 | drop TN/FN | statistics/stage2_metrics.json | drop_to_auto_detail.y_true_0/y_true_1 |

## Stage 3 (LLM + Rule Engine)

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

## システム全体 (Full Cascade)

| 数値 | 意味 | 出典ファイル | キー/列名 |
|------|------|-------------|----------|
| 62,453 | System TP | tables/table3_system_performance.csv | Full cascade, TP |
| 532 | System FP | tables/table3_system_performance.csv | Full cascade, FP |
| 63,079 | System TN | tables/table3_system_performance.csv | Full cascade, TN |
| 1,158 | System FN | tables/table3_system_performance.csv | Full cascade, FN |
| 99.16% | System Precision | statistics/system_overall_metrics.json | precision |
| 98.18% | System Recall | statistics/system_overall_metrics.json | recall |
| 98.67% | System F1 | statistics/system_overall_metrics.json | f1 |
| 0.84% | System FPR | statistics/system_overall_metrics.json | fpr |
| 1.82% | System FNR | statistics/system_overall_metrics.json | fnr |
| 90.6% | Auto-decision率 | statistics/system_overall_metrics.json | auto_decision_rate |
| 9.4% | Stage3投入率 | statistics/system_overall_metrics.json | stage3_rate |

## 閾値スイープ（図3）

| 数値 | 意味 | 出典ファイル | キー/列名 |
|------|------|-------------|----------|
| τ=0.4 | 運用点の閾値 | tables/fig3_threshold_sweep.csv | tau=0.4 行 |
| 9.39% | 運用点のStage3 call rate | tables/fig3_threshold_sweep.csv | stage3_rate_pct |
| 401 | 運用点のauto-decision errors | tables/fig3_threshold_sweep.csv | auto_errors |
| 0.3479% | 運用点のauto-decision error rate | tables/fig3_threshold_sweep.csv | auto_error_rate_pct |
| 374–1,447 | auto-decision errors範囲（τ=0.0〜1.0） | tables/fig3_threshold_sweep.csv | auto_errors |

## Stage1 ハイパーパラメータ

| パラメータ | 値 | 出典ファイル |
|-----------|-----|-------------|
| n_estimators | 300 | 02_stage1_stage2/configs/default.yaml |
| max_depth | 8 | 02_stage1_stage2/configs/default.yaml |
| learning_rate | 0.1 | 02_stage1_stage2/configs/default.yaml |
| subsample | 0.8 | 02_stage1_stage2/configs/default.yaml |
| colsample_bytree | 0.8 | 02_stage1_stage2/configs/default.yaml |
| early_stopping_rounds | 20 | 02_stage1_stage2/configs/default.yaml |

## 処理遅延（図4）

| 数値 | 意味 | 出典ファイル | キー/列名 |
|------|------|-------------|----------|
| p50=8.31s | 処理時間中央値 | tables/fig4_processing_time.csv | percentile=50 |
| p90=15.27s | 処理時間90分位 | tables/fig4_processing_time.csv | percentile=90 |
| p99=28.59s | 処理時間99分位 | tables/fig4_processing_time.csv | percentile=99 |
| 11,952 | Stage3処理件数 | tables/fig4_processing_time.csv | worker count合計 |

## 誤り分析（図5）

| 数値 | 意味 | 出典ファイル | キー/列名 |
|------|------|-------------|----------|
| 1,158 | FN合計 | tables/fig5_error_categories.csv | FN Total |
| 532 | FP合計 | tables/fig5_error_categories.csv | FP Total |
| 3 / 395 / 760 | FN Stage別 | tables/fig5_error_categories.csv | FN Stage1/2/3 |
| 2 / 1 / 529 | FP Stage別 | tables/fig5_error_categories.csv | FP Stage1/2/3 |

## ベースライン比較（付録表A）

| 数値 | 意味 | 出典ファイル |
|------|------|-------------|
| F1=98.58〜98.66% | 全モデルF1範囲 | tables/appendix_baselines.csv |
| XGBoost n=300 | Stage1ハイパラ | 02_stage1_stage2/configs/default.yaml |

## データソースファイル一覧

すべて `docs/paper/data/` 配下:

```
tables/
  fig2_stage_transitions.csv      - Stage遷移件数・割合
  table1_dataset.csv              - データセット構成
  table2_cert_availability.csv    - 証明書取得率
  table2_cert_status.csv          - 証明書ステータス分布
  table3_system_performance.csv   - システム全体性能
  table4_stage2_effect.csv        - Stage2効果（with/without比較）
  table5_stage3_performance.csv   - Stage3混同行列・ルール発動
  table6_stage3_ablation.csv      - Stage3アブレーション
  fig3_threshold_sweep.csv        - 閾値スイープ
  fig4_processing_time.csv        - 処理時間分布
  fig5_error_categories.csv       - エラーカテゴリ

statistics/
  system_overall_metrics.json     - システム全体指標
  stage1_metrics.json             - Stage1 routing詳細
  stage2_metrics.json             - Stage2 drop詳細
  stage3_metrics.json             - Stage3処理時間等
  rule_firing_summary.json        - ルール発動サマリ
```
