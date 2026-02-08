# docs/ ディレクトリ構成

更新日: 2026-02-08

## フォルダ構成

```
docs/
├── paper/          論文執筆関連 (NEW)
├── specs/          仕様書 (15ファイル)
├── analysis/       分析レポート (6ファイル)
├── sakusen/        計画・戦略 (8ファイル)
├── reference/      リファレンス (5ファイル)
├── research/       リサーチ・日次記録 (21ファイル)
├── reports/        進捗報告書
├── mtg/            打ち合わせ記録
└── chatgpt/        ChatGPT関連メモ (3ファイル)
```

---

## paper/ - 論文執筆関連

```
paper/
├── paper_outline.md          論文骨子（検証済み数値リファレンス付き）
├── number_source_map.md      数値出典対応表
├── STYLE_GUIDE.md            スタイルガイド
├── data/                     論文用データ出力先
│   ├── tables/               表データ (CSV)
│   └── statistics/           統計メトリクス (JSON)
├── images/                   生成済み図 (5 PNG + FIGURE_MAP.md)
│   └── _unused/              旧版・不使用図
├── mori/                     森先生の参考文献PDF (journals/, conferences/)
├── notes/                    作業メモ
│   ├── READING_NOTES_for_outline_update.md  森研論文の読書メモ
│   └── review_notes.md                     レビュー指摘事項と対応状況
├── prompts/                  AI用プロンプト
│   ├── mori_professor_prompt.md             森教授ペルソナプロンプト
│   └── prompt_for_external_ai.md            外部AIレビュー用プロンプト
└── tasks/                    タスク管理
    ├── TODO.md                              未着手作業リスト
    ├── TODO_execution_prompts.md            実行プロンプト集
    ├── 20260207-DONE.md                     完了タスクログ
    └── 20260207-DONE_prompts.md             完了プロンプトログ
```

| ファイル | 内容 |
|---------|------|
| `paper_outline.md` | **論文骨子（メイン）** RQ2つ、評価章との1対1対応、検証済み数値リファレンス |
| `number_source_map.md` | 全主要数値の出典（CSV/JSON）対応表 |
| `STYLE_GUIDE.md` | 論文記述のスタイルガイド |

---

## specs/ - 仕様書

| ファイル | 内容 |
|---------|------|
| `stage3_ai_agent_spec.md` | AI Agent仕様 |
| `parallel_evaluation_spec.md` | 並列評価仕様 |
| `rules_modularization_spec.md` | ルールモジュール化仕様 |
| `stage1_stage2_feature_spec.md` | Stage1/2特徴量仕様 |
| `stage2_certificate_rules_spec.md` | 証明書ルール仕様 |
| `stage3_certificate_enhancement_spec.md` | 証明書強化仕様 |
| `low_signal_phishing_detection_spec.md` | 低シグナル検出仕様 |
| `evaluate_e2e_spec.md` | E2E評価仕様 |
| `pipeline_execution_order.md` | パイプライン実行順序 |
| `vt_batch_investigation_spec.md` | VirusTotal調査仕様 |
| `data_specification_v1.md` | データ仕様v1 |
| `data_specification_draft.md` | データ仕様ドラフト |
| `system_specification.md` | システム仕様 |
| `02_spec.md` | 初期仕様 |
| `98_notebooks_specification.md` | ノートブック仕様 |

---

## analysis/ - 分析レポート

| ファイル | 内容 |
|---------|------|
| `01_baseline_analysis.md` | ベースライン分析（統合版） |
| `02_improvement_analysis.md` | **改善効果分析 (メイン)** |
| `03_certificate_analysis.md` | 証明書特徴量分析 |
| `04_stage3_certificate_analysis.md` | Stage3証明書分析レポート |
| `05_feature_candidates.md` | 特徴量候補メモ |
| `fnfp_analysis_20260201.md` | **全件評価FN/FP詳細分析 (NEW)** |

---

## sakusen/ - 計画・戦略

| ファイル | 内容 |
|---------|------|
| `02_phase0.md` | Phase0計画 |
| `02_phase1_results.md` | Phase1結果 |
| `02_phase1.5_results.md` | Phase1.5結果 |
| `02_phase1.6_results.md` | Phase1.6結果 |
| `02_phase1_brand_issue.md` | ブランド問題 |
| `02_phase2_plan.md` | Phase2計画 |
| `csv_extension_plan.md` | CSV拡張計画 |
| `implementation_plan.md` | 実装計画 |

---

## reference/ - リファレンス

| ファイル | 内容 |
|---------|------|
| `data_pipeline_guide.md` | **データパイプラインガイド (NEW)** |
| `program_inventory.md` | プログラム一覧 |
| `stage3_evaluation_guide.md` | 評価ガイド |
| `access_patterns.md` | アクセスパターン |
| `data_io_consistency.md` | データI/O整合性 |
| `data_cleaning_log.md` | データクリーニングログ |

---

## research/ - リサーチ・日次記録

| ファイル | 内容 |
|---------|------|
| `02_pipeline_overview.md` | パイプライン概要 |
| `03_phishing_agent_overview.md` | Agent概要 |
| `dataset_overview.md` | データセット概要 |
| `related_work.md` | 関連研究 |
| `stage3_knowledge_expansion_rationale.md` | 知識拡張根拠 |
| `20260110.md` ... `20260201.md` | 日次リサーチノート |

---

## reports/ - 進捗報告書

| ファイル | 内容 |
|---------|------|
| `202602_progress_report_draft.md` | **2026年2月 進捗報告書** |

---

## 主要ドキュメント

### 論文骨子（最重要）

**`docs/paper/paper_outline.md`**

- CSS論文「3段カスケード型フィッシング検出における投入制御とルール統合の効果分析」
- RQ2つ、評価章と1対1対応、検証済み数値リファレンス付き

### 改善効果分析

**`docs/analysis/02_improvement_analysis.md`**

- FP/FN分析、問題メカニズム、改善推奨事項
- チューニング知見 (Appendix A)
- 検出不能FN分析 (Appendix B)

### AI Agent仕様

**`docs/specs/stage3_ai_agent_spec.md`**

- Stage3 AI Agentの設計仕様

### ルールモジュール仕様

**`docs/specs/rules_modularization_spec.md`**

- ルールベース検出のモジュール化仕様

### 並列評価仕様

**`docs/specs/parallel_evaluation_spec.md`**

- 3GPU並列評価システムの仕様

### データパイプラインガイド

**`docs/reference/data_pipeline_guide.md`**

- Notebook（01〜05）の実行順序とデータフロー
- artifacts ディレクトリ構造
- 主要CSVカラムの説明

---

## その他のファイル

| ファイル | 内容 |
|---------|------|
| `00_overview.txt` | プロジェクト概要 |
| `CSS2025.pdf` | CSS2025論文 |
| `postgresql_schema.sql` | DBスキーマ |
