# Figure Map: 論文図番号 ↔ ファイル ↔ データソース対応表

更新日: 2026-02-07（P0-2: 最終採用品のみに整理）

## 最終採用図（5点）

| 論文図番号 | ファイル名 | 内容 | データソース | 生成方法 |
|-----------|-----------|------|------------|---------|
| 図1 | fig01_architecture.png | 3段カスケード全体アーキテクチャ | fig2_stage_transitions.csv, table5_stage3_performance.csv, system_overall_metrics.json, stage1_metrics.json, stage2_metrics.json | generate_paper_figures.py (fig01) |
| 図2 | fig02_transitions.png | Stage遷移の件数推移 | fig2_stage_transitions.csv, table5_stage3_performance.csv, stage1_metrics.json, stage2_metrics.json | generate_paper_figures.py (fig06) |
| 図3 | fig03_threshold_sweep.png | 閾値スイープ（call rate vs 自動判定誤り） | fig3_threshold_sweep.csv | generate_paper_figures.py (fig08) |
| 図4 | fig04_latency.png (.pdf) | Stage 3 処理遅延CDF（p50/p90/p99） | fig4_processing_time.csv | generate_new_figures.py |
| 図5 | fig05_error_breakdown.png (.pdf) | 誤り分析（残存FNと増加FPのStage別分布） | fig5_error_categories.csv | generate_new_figures.py |

## データソースのパス

すべて `docs/paper/data/` 配下:

- `tables/fig2_stage_transitions.csv` - Stage遷移件数
- `tables/fig3_threshold_sweep.csv` - 閾値スイープデータ
- `tables/fig4_processing_time.csv` - 処理時間分布
- `tables/fig5_error_categories.csv` - エラーカテゴリ
- `tables/table5_stage3_performance.csv` - Stage3混同行列
- `statistics/system_overall_metrics.json` - システム全体指標
- `statistics/stage1_metrics.json` - Stage1 routing詳細
- `statistics/stage2_metrics.json` - Stage2 drop詳細

## 落選図

`_unused/` に隔離済み（8点）:
- fig01_s3.1_cascade_architecture.png (→ fig01_architecture.png にリネーム)
- fig02_s4.2_learning_curve.png
- fig03_s4.2_feature_importance.png
- fig04_s4.4.3_fn_ml_score_dist.png
- fig05_s3.4_agent_flow.png
- fig06_s4.5.1_processing_flow.png (→ fig02_transitions.png にリネーム)
- fig07_s4.4.2_detection_pattern.png
- fig08_s4.2_threshold_sweep.png (→ fig03_threshold_sweep.png にリネーム)

旧図（数値修正前）は `_legacy/` に隔離済み。
