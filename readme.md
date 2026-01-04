# Hybrid Phishing Detection Agent

本リポジトリは，論文
「機械学習とAIエージェントを組み合わせたハイブリッド型フィッシングサイト検出システム」
で提案した **二段階ハイブリッド方式** のうち，主に **第二層（LLM エージェント側）** の実装と評価用ノートブックをまとめたものです。

---

## システムの目的

* 第一層の XGBoost モデルで大量のドメインを高速にスクリーニングしつつ
* **「ML の判定確信度が低い領域（特に p < 0.2）」に潜むフィッシングサイト** を
  第二層の LLM ベース AI エージェントで補足することで，

  * 偽陰性率を 6.58% → 1.04% に削減すること
  * かつ，各判定に対する根拠（ブランド偽装／証明書／ドメイン構造／文脈統合）を明示し，
    **説明可能な分析ログ** を残すこと
    を目的としています。

本リポジトリは，このうち

* **第一層：XGBoost モデルの学習・評価（Notebook）**
* **第二層：LLM エージェント（`phishing_agent` パッケージ）**
* 評価用ノートブック（偽陰性 4,215 件への適用実験）

を再現できるコードと設定群を含みます。

---

## システム概要

### 全体アーキテクチャ

論文と同様，システム全体は以下の二層構成です：

1. **第一層：XGBoost による高速スクリーニング**

   * URL / ドメイン構造，TLS 証明書，ブランド特徴量などを入力とする XGBoost モデル。
   * 約 64 万件のサンプルで学習し，精度 95.70%，FNR 6.58%。
   * ここで **フィッシング確率 `p < 0.5`**（特に `p < 0.2`）のサンプルを「要精査」として第二層に渡します。

2. **第二層：LLM エージェント（LangGraph + LangChain）**

   * 入力：`domain`, 第一層の `ml_probability`，および外部データ（ブランド辞書，証明書メタ情報，TLD 統計など）。
   * **処理フロー（Phase 1–6）**：

     1. **Phase 1 – 基礎型・例外定義 (`agent_foundations.py`)**

        * Tool 選択結果 `ToolSelectionResult`，最終判定 `PhishingAssessment`，LangGraph 状態 `AgentState` などの Pydantic スキーマ，
          および `clip_confidence`, `get_risk_level`, `convert_to_phase2_format` などの共通ヘルパを定義。
     2. **Phase 2 – 事前チェック (`precheck_module.py`)**

        * TLD 区分（dangerous / legitimate / neutral），ブランド検出有無，ドメイン長カテゴリ，
          TLD 統計によるリスク重み，high-risk キーワードなどから
          `quick_risk`, `ml_paradox` を含む `precheck_hints` を生成。
     3. **Phase 3 – 各種ツール (`tools_module.py` + `tools/`)**

        * すべてのツールは `safe_tool_wrapper` でラップされ，
          例外時にも `{success: False, _fallback: ...}` に丸め込まれる設計。
        * **ブランド偽装検知 (`tools/brand_impersonation_check.py`)**

          * ルールベース（編集距離・サブストリング等）＋ LLM によるブランドなりすまし検出。
          * `legitimate_domains.py` のホワイトリストで公式ドメインを判定し，必要に応じてリスクを減衰。
        * **証明書分析 (`tools/certificate_analysis.py`)**

          * `cert_full_info_map` から対象ドメインの証明書メタを抽出し，
            `free_ca`, `no_org`, `no_cert`, `no_san`, `self_signed` 等の Issue と `risk_score` を算出。
        * **短いドメイン分析 (`tools/short_domain_analysis.py`)**

          * 登録ドメイン長，危険 TLD，
            シャノンエントロピー＋母音・数字比率によるランダム度推定，
            フィッシング TLD 統計からの重み付けを行い，構造的リスクを評価。
        * **文脈的リスク評価 (`tools/contextual_risk_assessment.py`)**

          * 各ツールの `risk_score` 平均，high-risk ワード，known_domains，
            そして「ML 確率が極端に低いのに非 ML シグナルが強い」`ml_paradox` を統合し，
            最終的な `risk_score` と Issue の一覧を生成。
     4. **Phase 4 – LangGraph 状態管理 (`langgraph_module.py`)**

        * `LangGraphPhishingAgent` が
          `precheck → tool_selection → fanout(tool_execution) → aggregate → (contextual?) → final_decision`
          の StateGraph を構築。LangGraph が無い環境では同等の逐次処理にフォールバック。
        * Step1 (tool_selection) / Step3 (final_decision) は Structured Output LLM を想定しつつ，
          LLM 未接続環境では ML スコアに基づくルールベースに自動フォールバック。
     5. **Phase 5 – Structured Output 接続（Tool 選択・最終判定）**

        * `langchain_openai.ChatOpenAI.with_structured_output` を用いて
          `ToolSelectionSO` / `FinalAssessmentSO` を取得するフック実装。
        * ML 確率に応じて

          * `p < 0.5` では 3 ツール（brand, cert, domain）
          * `p ≥ 0.5` では 2 ツール
            を選択するポリシーを LLM 出力に対して強制。
     6. **Phase 6 – ポリシーベース最終判定 (`llm_final_decision.py` + `phase6_wiring.py`)**

        * LLM に `PhishingAssessmentSO` スキーマで Structured Output を返させた上で，
          `ml_probability`, 各ツールの Issue, contextual risk をもとに

          * `contextual.risk_score ≥ 0.5` なら必ず `is_phishing=True`
          * 「free_ca + no_org + very_low ML」等の R1/R2/R3 ポリシーで安全側に補正
          * 設計意図を `decision_trace` として `graph_state` に保存
            する最終ポリシーを適用。
        * `phase6_wiring.py` で `LangGraphPhishingAgent._final_decision_node` に対して
          非破壊モンキーパッチを適用し，Phase 6 の判定を差し替えます。

---

## リポジトリ構成（ざっくり）

### Notebook 群

* `01_data_preparation_fixed_patched_nocert_full.ipynb`

  * 元データからの特徴量抽出・前処理（ドメイン構造 / 証明書 / ブランド特徴量）。
* `02_xgboost_training_evaluation_fixed_v2_vllm_strict_patched_v3.ipynb`

  * 第一層 XGBoost モデルの学習・評価（Learning Curve, AUC, Feature Importance など）。
* `03_ai_agent_analysis_part*.ipynb`

  * AI エージェント設計・分析の実験ノート。現在は Python モジュール（`phishing_agent/`）に集約済み。
* `04-1_config_and_data_preparation_RUNREG_joblibFIX.ipynb`

  * RUN_ID ごとの artifacts ディレクトリ（特徴量・モデル・判定結果）を整理するための設定・前処理。
* `04-2_statistical_analysis_COMPAT_PATCHED.ipynb`

  * TLD ごとのフィッシング統計など，Phase 2/3/4 から参照するオフライン統計を生成。
* `04-3_llm_tools_setup.ipynb`（**現在は未使用／履歴のみ**）

  * 旧 LLM 接続テスト・ツール挙動確認用。現在は `tools/` 以下の Python 実装に置き換え。
* `04-4_agent_implementation.ipynb`（**未使用／履歴のみ**）

  * 旧 LangGraph エージェントの試作・トレース確認用。現行コードは `langgraph_module.py`。
* `04-5_evaluation_execution.ipynb`（**未使用／履歴のみ**）

  * 旧評価実行ノート。現在は下記 99/100 系に統合。
* `99-random100_clean_test_with_debug.ipynb`

  * 代表 100 件程度のテストセットに対し，エージェント内部状態（`graph_state`）を詳細に確認するためのデバッグ用ノート。
* `100-full_eval_from_artifacts_debug_v2.ipynb`

  * RUN_ID ごとに保存された artifacts を読み込み，
    偽陰性 4,215 件などの全件に対して第二層エージェントを適用する評価ノート（現在も利用）。

### Python パッケージ

* `_compat/paths.py`

  * `RUN_ID` 付き `artifacts/{RUN_ID}/...` ディレクトリ構造の解決，
    `config.json` / `config.yaml` のロードなどを一元的に扱う互換レイヤ。
* `phishing_agent/agent_foundations.py` — Phase 1
* `phishing_agent/precheck_module.py` — Phase 2（事前チェック + ツール推奨）
* `phishing_agent/tools_module.py` — Phase 3（ツールラッパ・`safe_tool_wrapper`）
* `phishing_agent/tools/` — 各種ツール本体（brand / cert / domain / contextual / whitelist）
* `phishing_agent/langgraph_module.py` — Phase 4 + Phase 5（StateGraph + SO 接続）
* `phishing_agent/llm_final_decision.py` — Phase 6 最終判定ポリシー & Structured Output
* `phishing_agent/phase6_wiring.py` — Phase 6 を `LangGraphPhishingAgent` に配線するユーティリティ
* `phishing_agent/batch.py`

  * Phase 1 ベースの簡易バッチ API スタブ（基礎動作確認用）。
* `phishing_agent/__init__.py`

  * Phase1〜3 のエクスポートと，`RUN_ID` 指定で Phase 4 エージェントを構築するヘルパ（`_resolve_05_resources` など）。

---

## 典型的な利用フロー（第二層）

※ 論文実験で用いた流れのイメージです。実データや RUN_ID の扱いは環境依存です。

1. **第一層で偽陰性候補を抽出**

   * `02_xgboost_*.ipynb` で学習済みモデルを用いて全ドメインを推論し，
     `ml_probability < 0.5`（特に `< 0.2`）のサンプルを抽出。
   * これらと証明書・TLD 統計などを `artifacts/{RUN_ID}/handoff/` 以下に保存。

2. **外部データのロード**

   * `phishing_agent.__init__` の `_resolve_05_resources(run_id=...)` が
     brand_keywords, dangerous/legitimate_tlds, phishing_tld_stats, known_domains, cert_full_info_map など
     Phase 2/3 で必要となる外部データを読み込む。

3. **エージェントの生成**

   * Phase 4 までで良い場合：
     `LangGraphPhishingAgent(strict_mode=False, external_data=external_data)` を直接生成。
   * Phase 6 まで使う場合：
     `phase6_wiring.wire_phase6()` を一度呼び出し，
     `make_agent_for_test()` などで Phase 6 対応エージェントを生成。

4. **評価実行**

   * `agent.evaluate(domain, ml_probability, external_data=external_data)` を呼ぶと，
     上記 Phase1〜6 を通った結果が **Phase 2 形式の辞書**（`ai_is_phishing`, `ai_confidence`, `ai_risk_level`, `tools_used`, `graph_state` etc.）として返る。
   * `99-*/100-*` ノートブックはこの API を使って少数サンプル／全件評価を行い，
     偽陰性削減効果や decision_trace の可視化に利用しています。

---

## 依存ライブラリ・設定（概要）

コードから読み取れる主な依存は以下の通りです：

* Python 3.9 互換（型表記は `Optional[...]` ベース）
* 第三者ライブラリ

  * `tldextract` — ETLD+1 抽出 （Phase 2/3）
  * `pydantic` v2 — Structured Output スキーマ・バリデーション
  * `langgraph` — StateGraph による状態管理（あれば使用、無ければ順次処理にフォールバック）
  * `langchain-openai`, `langchain-core` — Structured Output LLM（Phase 5, 6）
  * `langchain-community` — `VLLMOpenAI` による vLLM 接続（brand LLM 検出）
* LLM 設定

  * `config.json` などに

    ```json
    {
      "llm": {
        "enabled": true,
        "base_url": "...",   // vLLM / OpenAI 互換エンドポイント
        "model": "Qwen/Qwen3-14B-FP8",
        "api_key": "..."
      }
    }
    ```

    のような `llm` セクションを置き，
    `langgraph_module.load_llm_config()` や `phase6_wiring` が参照します。

---

## 論文との対応関係（ざっくり）

* **論文 §3.2：第一層 XGBoost** → `01_*`, `02_*` Notebook 群，および artifacts 生成処理。
* **論文 §3.3：第二層 LLM エージェント** → `phishing_agent/` 以下の Phase 1–6 実装。
* **論文 §4.2：偽陰性 4,215 件に対する評価** → `100-full_eval_from_artifacts_debug_v2.ipynb` を中心とした評価コード。

---


