# Figure Map: 図 <-> ファイル <-> データソース対応表

| 論文図番号 | ファイル名 | データソース | 生成方法 |
|-----------|-----------|------------|---------|
| Fig.1 | fig01_s3.1_cascade_architecture.png | fig2_stage_transitions.csv, table5_stage3_performance.csv, system_overall_metrics.json, stage1_metrics.json, stage2_metrics.json | generate_paper_figures.py |
| Fig.2 | fig02_s4.2_learning_curve.png | XGBoost model + train_data.pkl (sklearn learning_curve) | generate_paper_figures.py |
| Fig.3 | fig03_s4.2_feature_importance.png | XGBoost model (feature_importances_) | generate_paper_figures.py |
| Fig.4 | fig04_s4.4.3_fn_ml_score_dist.png | XGBoost model + test_data.pkl | generate_paper_figures.py |
| Fig.5 | fig05_s3.4_agent_flow.png | eval_df CSV (concrete case extraction) | generate_paper_figures.py |
| Fig.6 | fig06_s4.5.1_processing_flow.png | fig2_stage_transitions.csv, table5_stage3_performance.csv, stage1_metrics.json, stage2_metrics.json | generate_paper_figures.py |
| Fig.7 | fig07_s4.4.2_detection_pattern.png | stage3_detection_advantage.md (hardcoded pattern counts) | generate_paper_figures.py |
| Fig.8 (論文 図3) | fig08_s4.2_threshold_sweep.png | fig3_threshold_sweep.csv | generate_paper_figures.py |

## 論文図番号 ↔ スクリプト図番号の対応

論文の図番号（§図表計画）とスクリプトの生成番号は1:1対応ではない。
論文に掲載する図の選定は paper_outline.md の図表計画を参照。

| 論文 図番号 | スクリプト番号 | 内容 |
|------------|-------------|------|
| 図1 | Fig.1 (fig01) | カスケードアーキテクチャ |
| 図2 | Fig.6 (fig06) | Stage遷移の件数推移 |
| 図3 | **Fig.8 (fig08)** | 閾値スイープ（call rate vs auto-decision errors） |
| 図4 | Fig.4 (fig04) | Stage3遅延/FN分布 |
| 図5 | Fig.7 (fig07) | 誤り分析（検知パターン） |

## データソースのパス

- `docs/paper/data/tables/fig2_stage_transitions.csv` - Stage遷移件数
- `docs/paper/data/tables/fig3_threshold_sweep.csv` - 閾値スイープデータ
- `docs/paper/data/tables/table3_system_performance.csv` - システム全体性能
- `docs/paper/data/tables/table5_stage3_performance.csv` - Stage3混同行列
- `docs/paper/data/statistics/system_overall_metrics.json` - システム全体指標
- `docs/paper/data/statistics/stage1_metrics.json` - Stage1 routing詳細
- `docs/paper/data/statistics/stage2_metrics.json` - Stage2 drop詳細

## 注意事項

- Fig.1, Fig.6 は 2026-02-07 に CSV/JSON 駆動に移行済み（旧ハードコード値を除去）
- Fig.2〜Fig.5 はモデル/評価データから動的生成（CSV駆動ではないがデータ依存）
- Fig.7 はパターン分析の固定値（stage3_detection_advantage.md 由来）
- Fig.8 は 2026-02-07 に新規作成（TODO-8: Fig3主張の整合性修正）
- 旧図は `_legacy/` に隔離済み
