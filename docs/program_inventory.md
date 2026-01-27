# プログラム・スクリプト一覧

本プロジェクトのプログラムとスクリプトの一覧。3段階パイプライン（Stage1: ML分類、Stage2: Gate/ルール、Stage3: AI Agent）を中心に構成されている。

---

## 1. パイプライン実行

### メインスクリプト

| ファイル | 概要 |
|----------|------|
| `02_main.py` | Stage1/Stage2統合パイプライン。PostgreSQLからデータ読込、XGBoost学習、Route1閾値判定、Stage2ゲート処理、handoff候補出力 |
| `scripts/run_full_pipeline.sh` | パイプライン全体のオーケストレーション。01→02→03→04→evaluate_e2eを順次実行。vLLMの自動起動/停止対応。`--no-e2e`, `--no-vllm` フラグあり |
| `run_id_registry.py` | RUN_ID管理。artifacts配下のディレクトリ管理とパス解決 |
| `_compat/paths.py` | パス互換レイヤー。compat_base_dirs (raw, data, models, results, handoff, logs, traces) の解決 |

### 設定ファイル

| ファイル | 概要 |
|----------|------|
| `config.json` | マスタ設定。LLM(vLLM Qwen3), DB(PostgreSQL), 分析設定, ブランドキーワード, モデルハイパーパラメータ, TLD分析, バッチサイズ |
| `02_stage1_stage2/configs/default.yaml` | Stage1/Stage2詳細設定。XGBoostパラメータ, Route1閾値, Stage2ゲーティング, DB接続 |
| `scripts/parallel_config.yaml` | 並列評価設定。Worker定義(local/external/remote), vLLM設定, ヘルスチェック, リトライポリシー |

---

## 2. Stage1 (XGBoost ML分類)

### コアモジュール

| ファイル | 概要 |
|----------|------|
| `02_stage1_stage2/src/features.py` | 特徴量エンジニアリング。ドメイン特徴(40+)・SSL/TLS証明書特徴の抽出。エントロピー計算、LE R3検出、拡張証明書分析(CN一致, SAN分析, 鍵強度正規化)。FEATURE_ORDERで正規順序定義 |
| `02_stage1_stage2/src/__init__.py` | パッケージ初期化 |

### 関連スクリプト

| ファイル | 概要 |
|----------|------|
| `scripts/tune_xgboost.py` | XGBoostハイパーパラメータチューニング (Optuna使用) |
| `scripts/search_lr_features.py` | ロジスティック回帰の特徴量重要度検索 |
| `scripts/search_new_features.py` | 新規特徴量の探索・評価 |

---

## 3. Stage2 (Gate/LR + Certificate Rules)

### コアモジュール

| ファイル | 概要 |
|----------|------|
| `02_main.py` 内 `run_stage2_gate()` | **現行Stage2実装**。LRベースのp_error予測 + 証明書ルール + TLDルール。Scenario 5-8の複合フィルタリング |

### 将来実装 (未統合)

| ファイル | 概要 |
|----------|------|
| `future/stage2_v2/stage2_decider_v2.py` | 新設計Stage2。XGBoostベースのp2(フィッシング確率)予測。Wilson boundによる統計的閾値選択 |

### 関連分析

| ファイル | 概要 |
|----------|------|
| `scripts/analyze_handoff.py` | Stage2 handoff分析。振り分け精度・特性評価 |
| `docs/analysis/stage2_independent_eval/evaluate_stage2_rules.py` | Stage2ルールの独立評価 |

---

## 4. Stage3 (AI Agent / LangGraph)

### LangGraphコア

| ファイル | 概要 |
|----------|------|
| `phishing_agent/langgraph_module.py` | LangGraphベースAgent。ツール選択→実行→集約のグラフ構造。LLMConfig, StructuredOutput (ToolSelectionSO, FinalAssessmentSO)。Qwen3-4B SO解析+フォールバック対応 |
| `phishing_agent/phase6_wiring.py` | Phase6最終判定ノード。既存LangGraph agentへのモンキーパッチ。Phase6ポリシー(R1-R6ルール)適用、SOフォールバック、決定論的フォールバック |
| `phishing_agent/llm_final_decision.py` | Phase6 v1.6.3ポリシーエンジン。6つの判定ルール(R1-R6)、post-LLMフリップゲート、ML Paradox検出、strong evidence評価、dangerous TLD分析 |

### 基盤モジュール

| ファイル | 概要 |
|----------|------|
| `phishing_agent/__init__.py` | パッケージ管理。Phase1-3統合API、相対/絶対インポートフォールバック |
| `phishing_agent/agent_foundations.py` | Phase1基盤。データ構造(PhishingAssessment, AgentState, ToolSelectionResult)、例外階層、リスクレベル定義 |
| `phishing_agent/foundations.py` | 拡張基盤。バリデーション、データマージ、正規化データソース管理 |
| `phishing_agent/precheck_module.py` | Phase2前処理。ML分類カテゴリ判定、TLD分析、ドメイン長評価、クイックリスクスコアリング。ツール選択ゲート用ヒント生成 |
| `phishing_agent/tools_module.py` | ツール統合インタフェース。safe_tool_wrapperによるエラーハンドリング |
| `phishing_agent/batch.py` | バッチ処理ユーティリティ |

### ツール (phishing_agent/tools/)

| ファイル | 概要 |
|----------|------|
| `tools/brand_impersonation_check.py` | ブランド偽装検出。ルールベース+LLMブランド検出、Phase2ヒント統合、タイポスクワッティング(編集距離2)、部分文字列一致、日本語ブランド対応(jibunbank, aiful等) |
| `tools/certificate_analysis.py` | 証明書分析。SSL/TLS詳細検査、cert-domain一致、自己署名/DV検出、発行者チェーン分析、鍵強度、SCT/OCSP/CRL検証 |
| `tools/contextual_risk_assessment.py` | コンテキストリスク評価。dangerous TLD検出、ホモグラフ(IDN)検出、ランダムパターン検出、短ドメイン分析、whoisデータ統合 |
| `tools/short_domain_analysis.py` | 短ドメイン分析。2-4文字パターン分析、エントロピー評価、ブランド混同検出、正規短ドメイン判定 |
| `tools/legitimate_domains.py` | 正規ドメインDB。許可リスト(既知の正規ドメイン、ブランド、主要プラットフォーム)。FP削減用ベースライン |
| `tools/__init__.py` | ツールパッケージ初期化 |

---

## 5. 評価スクリプト

### E2E評価

| ファイル | 概要 |
|----------|------|
| `scripts/evaluate_e2e.py` | パイプライン全体評価。Stage1→Stage2→Agent→最終判定。PostgreSQLからデータ読込、TP/FP/FN評価、コスト重み付け対応。出力: `artifacts/{RUN_ID}/results/stage2_validation/` |
| `scripts/evaluate_e2e_parallel.py` | 並列評価。マルチGPU/マルチWorker分散評価。`--add-gpu`, `--resume`, `--n-sample`, `--check-gpus`, `--dry-run` 対応 |

### 並列評価モジュール (scripts/parallel/)

| ファイル | 概要 |
|----------|------|
| `parallel/__init__.py` | パッケージ初期化 |
| `parallel/config.py` | 設定管理。ParallelConfig/WorkerConfig/VLLMConfig等のdataclass。YAML読込・検証 |
| `parallel/orchestrator.py` | オーケストレーター。vLLMクラスタ管理、Worker起動・監視、チェックポイント、結果マージ |
| `parallel/worker.py` | Workerプロセス。個別GPU/ノードでの評価実行。per-worker config.json生成、タイムアウト・pause/resume対応 |
| `parallel/vllm_manager.py` | vLLMインスタンス管理。Local(PID管理)/External(ポートフォワード)/Remote(SSH+tmux)の3タイプ。VLLMCluster抽象 |
| `parallel/checkpoint.py` | チェックポイント管理。WALスタイルCSV追記、fcntlファイルロック、アトミック書込、Worker進捗追跡 |
| `parallel/health_monitor.py` | ヘルスモニタリング。バックグラウンドスレッドで定期チェック、障害コールバック、自動リカバリ |
| `parallel/gpu_checker.py` | GPU検出。ローカル/リモートGPU可用性チェック(nvidia-smi XML)、リソース割当確認 |
| `parallel/ssh_manager.py` | SSH/tmux管理。リモートvLLMライフサイクル管理(SSH接続、ポートフォワード、tmuxセッション) |

### 結果分析

| ファイル | 概要 |
|----------|------|
| `scripts/analyze_evaluation_results.py` | 評価結果の包括分析。混同行列、カテゴリ別分析、FN/FPパターン |
| `scripts/analyze_auto_phishing.py` | 自動検出phishingサンプル分析 |
| `scripts/analyze_safe_benign.py` | 安全なbenignサンプルのパターン分析 |
| `scripts/analyze_featureless_phishing.py` | 特徴量が少ないphishingサンプル分析 |
| `scripts/analyze_phishing_characteristics.py` | phishingドメインの特性分析 |
| `scripts/analyze_scenario5_fn.py` | FNシナリオ分析 |

---

## 6. データメンテナンス

### VirusTotal調査

| ファイル | 概要 |
|----------|------|
| `scripts/virustotal_check.py` | VirusTotal API連携。ドメインレピュテーション確認 |
| `scripts/vt_batch_investigation.py` | バッチVirusTotal調査。並列APIキー対応、チェックポイント付きリジューム、レートリミット制御 |

### SQLスクリプト (データクリーニング)

| ファイル | 概要 |
|----------|------|
| `scripts/data_cleaning.sql` | 初期データクリーニング |
| `scripts/data_cleaning_phishing.sql` | phishingデータクリーニング |
| `scripts/data_cleaning_complete.sql` | 完了版クリーニング |
| `scripts/data_cleaning_final.sql` | 最終版クリーニング |
| `scripts/data_cleaning_stage3.sql` | Stage3 VT調査に基づくラベルエラー削除 (46ドメイン) |

### SQLスクリプト (調査・確認)

| ファイル | 概要 |
|----------|------|
| `scripts/check_domains.sql` | ドメイン状態確認 |
| `scripts/check_domains_detailed.sql` | 詳細ドメイン確認 |
| `scripts/check_domains_status.sql` | ドメインステータス確認 |
| `scripts/check_domain_status.sql` | 個別ドメインステータス |
| `scripts/check_all_domains.sql` | 全ドメイン確認 |
| `scripts/delete_certificates.sql` | 証明書データ削除 |

---

## 7. インフラ・vLLM管理

| ファイル | 概要 |
|----------|------|
| `scripts/vllm.sh` | vLLMサーバ制御。start/stop/status/restart。Qwen3-4B-Thinking-2507-GPTQ-Int8、PIDベース管理、ログファイル管理 |
| `scripts/vllm_manager.py` | vLLMライフサイクル管理 (Python版)。起動・停止・ヘルスチェック |

---

## 8. テスト・デバッグ

| ファイル | 概要 |
|----------|------|
| `scripts/test_ai_agent_sample.py` | AI Agentサンプル実行テスト |
| `scripts/test_ai_agent_high_risk_tld.py` | 高リスクTLDでのAgent動作テスト |
| `scripts/test_low_signal_phishing_gate.py` | Low-signalフィッシングゲートテスト |
| `scripts/debug_policy_trace.py` | Phase6ポリシートレースデバッグ |
| `scripts/quick_test_policy.py` | Phase6ポリシークイックテスト |
| `scripts/quick_test_new_tlds.py` | 新TLD対応テスト |
| `test_integration.py` | パイプライン統合テスト |
| `test_regression.py` | 回帰テスト |
| `test_stage3_cert_integration.py` | Stage3証明書統合テスト |

### 外部API検証

| ファイル | 概要 |
|----------|------|
| `scripts/check_gsb_playwright.py` | Google Safe Browsing API検証 (Playwright) |
| `scripts/check_gsb_selenium.py` | Google Safe Browsing API検証 (Selenium) |
| `scripts/check_phishtank.py` | PhishTank API検証 |
| `scripts/check_urlscan.py` | URLScan API検証 |

---

## 9. アーキテクチャ概要

```
┌─────────────────────────────────────────────────────────────┐
│                    入力: ドメイン + 証明書                      │
└───────────────────────────┬─────────────────────────────────┘
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  Stage1 (XGBoost)                                           │
│  02_main.py + 02_stage1_stage2/src/features.py              │
│  → auto_phishing / auto_benign / handoff_to_agent           │
└───────────────────────────┬─────────────────────────────────┘
                            ▼ handoff_to_agent
┌─────────────────────────────────────────────────────────────┐
│  Stage2 (Gate/LR + Certificate Rules)                       │
│  02_main.py 内 run_stage2_gate()                            │
│  → benign確定(却下) / handoff候補(通過)                       │
└───────────────────────────┬─────────────────────────────────┘
                            ▼ handoff候補
┌─────────────────────────────────────────────────────────────┐
│  Stage3 (AI Agent)                                          │
│  phishing_agent/langgraph_module.py                         │
│  + phase6_wiring.py + llm_final_decision.py                 │
│  ツール: brand / certificate / contextual_risk / short_domain│
│  → phishing / benign (最終判定)                              │
└─────────────────────────────────────────────────────────────┘
```

### 技術スタック

| 領域 | 技術 |
|------|------|
| ML | XGBoost, Logistic Regression, scikit-learn |
| LLM | vLLM (Qwen3-4B-Thinking-2507-GPTQ-Int8), LangChain, LangGraph |
| 構造化出力 | Pydantic, vLLM Structured Output |
| データ | PostgreSQL (phishtank_entries, jpcert_phishing_urls, trusted_certificates) |
| 分散処理 | multiprocessing, チェックポイントリカバリ, マルチGPU |
| 設定 | YAML + JSON, 環境変数 |
| 外部API | VirusTotal, Google Safe Browsing, PhishTank, URLScan |

---

## 10. ディレクトリ構成

```
nextstep/
├── 02_main.py                    # Stage1/Stage2メインパイプライン
├── run_id_registry.py            # RUN_ID管理
├── config.json                   # マスタ設定
├── _compat/                      # パス互換レイヤー
│   └── paths.py
├── 02_stage1_stage2/             # Stage1/Stage2モジュール
│   ├── configs/default.yaml
│   └── src/features.py           # 特徴量エンジニアリング
├── phishing_agent/               # Stage3 AI Agentモジュール
│   ├── langgraph_module.py       # LangGraphコア
│   ├── phase6_wiring.py          # Phase6接続
│   ├── llm_final_decision.py     # 最終判定ポリシー
│   ├── precheck_module.py        # 前処理ヒント
│   ├── agent_foundations.py      # データ構造
│   ├── foundations.py            # 拡張基盤
│   ├── tools_module.py           # ツール統合
│   ├── batch.py                  # バッチ処理
│   ├── rules/                    # ルールエンジン (モジュール化)
│   └── tools/                    # 個別ツール
│       ├── brand_impersonation_check.py
│       ├── certificate_analysis.py
│       ├── contextual_risk_assessment.py
│       ├── short_domain_analysis.py
│       └── legitimate_domains.py
├── future/                       # 将来実装予定
│   └── stage2_v2/                # 新設計Stage2 (未統合)
├── scripts/                      # 評価・メンテナンス
│   ├── run_full_pipeline.sh      # パイプライン実行
│   ├── vllm.sh                   # vLLM管理
│   ├── evaluate_e2e.py           # E2E評価
│   ├── evaluate_e2e_parallel.py  # 並列E2E評価
│   ├── vt_batch_investigation.py # VT調査
│   ├── parallel/                 # 並列評価モジュール
│   │   ├── orchestrator.py
│   │   ├── worker.py
│   │   ├── vllm_manager.py
│   │   ├── config.py
│   │   ├── checkpoint.py
│   │   ├── health_monitor.py
│   │   ├── gpu_checker.py
│   │   └── ssh_manager.py
│   ├── analyze_*.py              # 各種分析
│   ├── test_*.py                 # テスト
│   ├── check_*.py                # 外部API検証
│   └── *.sql                     # DB操作
├── artifacts/{RUN_ID}/           # 実行成果物
│   ├── raw/                      # 生データ
│   ├── processed/                # 処理済みデータ
│   ├── models/                   # 学習済みモデル
│   ├── results/                  # 結果
│   ├── handoff/                  # handoffデータ
│   ├── logs/                     # ログ
│   └── traces/                   # トレース
└── docs/                         # ドキュメント
```
