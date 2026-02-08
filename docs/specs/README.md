# 仕様書の読み方ガイド

更新日: 2026-02-08

## このディレクトリについて

3段カスケード型フィッシング検出システムの仕様書群。
システムを理解・構築するために必要な情報がここに集約されている。

## 読む順序

初めてシステムを理解する場合、以下の順序で読む。

### Level 1: 全体像を掴む

| 順序 | ファイル | 所要時間 | 何がわかるか |
|------|---------|---------|-------------|
| **1** | `system_specification.md` | 20分 | 3段カスケードの全体像、42特徴量、閾値設計、データソース |
| **2** | `data_specification_v1.md` | 10分 | Stage間を流れるデータの正確な構造（列定義、型、ファイル形式） |

### Level 2: Stage3（最も複雑なコンポーネント）を理解する

| 順序 | ファイル | 所要時間 | 何がわかるか |
|------|---------|---------|-------------|
| **3** | `stage3_ai_agent_spec.md` | 30分 | LangGraph状態機械、ツール仕様、Structured Output、Phase6ポリシー |
| **4** | `rules_modularization_spec.md` | 15分 | 27ルールモジュールの詳細（ML Guard, Cert Gate, Policy等） |

### Level 3: 評価・運用方法を理解する

| 順序 | ファイル | 所要時間 | 何がわかるか |
|------|---------|---------|-------------|
| **5** | `evaluate_e2e_spec.md` | 10分 | 単一GPU評価スクリプトの仕様（入出力、メトリクス） |
| **6** | `parallel_evaluation_spec.md` | 20分 | 3GPU並列評価の設計（ワーカー、チェックポイント、リカバリ） |
| **7** | `pipeline_execution_order.md` | 10分 | 全パイプラインの実行順序とvLLM管理 |

### Level 4: 補助ツール・実験記録

| 順序 | ファイル | 所要時間 | 何がわかるか |
|------|---------|---------|-------------|
| **8** | `vt_batch_investigation_spec.md` | 5分 | VirusTotalによるラベル品質検証 |
| **9** | `llm_domain_features_spec.md` | 5分 | 試みて断念した実験の記録（frozen） |

---

## カバー範囲マトリクス

各仕様書がシステムのどの部分を対象としているかの一覧。

| 仕様書 | Stage1 | Stage2 | Stage3 | 評価 | データ | 運用 |
|--------|--------|--------|--------|------|--------|------|
| `system_specification` | ◎ | ◎ | ○ | − | ○ | − |
| `data_specification_v1` | ○ | ○ | − | ○ | ◎ | − |
| `stage3_ai_agent_spec` | − | − | ◎ | − | − | − |
| `rules_modularization_spec` | − | − | ◎ | − | − | − |
| `evaluate_e2e_spec` | − | − | − | ◎ | ○ | − |
| `parallel_evaluation_spec` | − | − | − | ◎ | ○ | ○ |
| `pipeline_execution_order` | ○ | ○ | ○ | ○ | − | ◎ |
| `vt_batch_investigation_spec` | − | − | − | ○ | − | − |
| `llm_domain_features_spec` | − | − | − | − | − | − |

◎ = 主題として詳述 / ○ = 関連情報あり / − = 対象外

---

## ファイル一覧（アルファベット順）

| ファイル | 更新日 | ステータス | 概要 |
|---------|-------|----------|------|
| `data_specification_v1.md` | 2026-01-20 | 完了 | データ構造定義（cert_full_info_map, df_stage1, 出力ファイル） |
| `evaluate_e2e_spec.md` | 2026-01-31 | 現行 | 単一GPU E2E評価スクリプト仕様 |
| `llm_domain_features_spec.md` | 2026-02-03 | **frozen** | LLMドメイン特徴量抽出（試行→断念の記録） |
| `parallel_evaluation_spec.md` | 2026-01-31 | 現行 | 3GPU並列評価の設計・運用仕様 |
| `pipeline_execution_order.md` | 2026-02-08 | 現行 | パイプライン実行順序、vLLM管理、artifacts構造 |
| `rules_modularization_spec.md` | 2026-02-04 | 現行 | ルールモジュール化仕様（27ルール、RuleEngine） |
| `stage3_ai_agent_spec.md` | 2026-02-04 | 現行 | Stage3 AI Agent詳細仕様（LangGraph, Phase6） |
| `system_specification.md` | 2026-02-08 | 現行 | **システム全体仕様（最初に読むべき文書）** |
| `vt_batch_investigation_spec.md` | 2026-01-24 | 現行 | VirusTotal一括調査スクリプト仕様 |
| `archived/` | − | アーカイブ | 役目を終えた仕様7件 |

---

## 注意事項

- 権威的な性能値は `system_specification.md` §12 を参照（F1=98.67%, n=127,222）
- ルール数は `rules_modularization_spec.md` が権威的（全ルールの定義と閾値を管理）
- 評価は必ず `bash scripts/run_eval_3gpu.sh` で実行（直接のpython実行は禁止）
- 仕様書で不明点がある場合、ソースコード（`02_main.py`, `phishing_agent/`）が最終的な正とする
