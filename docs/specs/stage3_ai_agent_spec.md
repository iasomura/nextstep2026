# Stage3 AI Agent 仕様書

**バージョン**: v1.6.3
**更新日**: 2026-01-24
**対象モジュール**: `phishing_agent/`

---

## 1. 概要

Stage3はLangGraphベースのAI Agentで、Stage2からhandoffされた不確実なドメインに対して最終的なフィッシング判定を行う。4つの分析ツールとPhase6ポリシーエンジンを組み合わせ、LLM (Qwen3-4B-Thinking) による構造化出力で判定を生成する。

## 2. アーキテクチャ

```
入力: ドメイン + 証明書データ + ML確率 + Stage1/2コンテキスト
       │
       ▼
┌─────────────────┐
│  Precheck Node  │  precheck_module.py
│  (Phase2)       │  → MLカテゴリ、TLD分析、ヒント生成
└────────┬────────┘
         ▼
┌─────────────────┐
│ Tool Selection  │  langgraph_module.py (SO: ToolSelectionSO)
│  (Phase4)       │  → LLMがツール選択
└────────┬────────┘
         ▼
┌─────────────────┐
│  Tool Execution │  tools_module.py + tools/*.py
│  (Phase3)       │  → 選択されたツールを実行
└────────┬────────┘
         ▼
┌─────────────────┐
│   Aggregation   │  langgraph_module.py
│                 │  → ツール結果の集約
└────────┬────────┘
         ▼
┌─────────────────┐
│ Final Decision  │  langgraph_module.py (SO: FinalAssessmentSO)
│  + Phase6 Policy│  phase6_wiring.py + llm_final_decision.py
│  (R1-R6, Gates) │  → 最終判定 + ポリシー補正
└────────┬────────┘
         ▼
出力: PhishingAssessment (is_phishing, confidence, risk_level, risk_factors)
```

## 3. LangGraphモジュール (langgraph_module.py)

### 3.1 バージョン
- `v1.3.4-phase4-toolexec-fix-2025-11-08`

### 3.2 StateGraph構成

| ノード | 役割 |
|--------|------|
| `precheck` | Phase2前処理。MLカテゴリ判定、TLD/ドメイン長ヒント生成 |
| `tool_selection` | LLMによるツール選択 (StructuredOutput) |
| `fanout` | 選択ツールの並列実行 |
| `aggregate` | ツール結果の集約 |
| `contextual_check` | 条件付きcontextual_risk_assessment追加実行 |
| `final_decision` | LLMによる最終判定 (StructuredOutput) + Phase6ポリシー |

### 3.3 Structured Output スキーマ

#### ToolSelectionSO
```python
class ToolSelectionSO(BaseModel):
    selected_tools: List[str]  # 実行するツール名リスト
    reasoning: str             # 選択理由
```

#### FinalAssessmentSO
```python
class FinalAssessmentSO(BaseModel):
    is_phishing: bool      # フィッシング判定
    confidence: float      # 信頼度 (0.0-1.0)
    risk_level: str        # "critical"/"high"/"medium"/"low"
    risk_factors: List[str]  # リスク要因リスト
    reasoning: str         # 判定理由
```

### 3.4 LLM設定

| パラメータ | 値 |
|-----------|-----|
| モデル | Qwen3-4B-Thinking-2507-GPTQ-Int8 |
| サーバ | vLLM (localhost:8000) |
| 最大トークン | 8192 (max_model_len) |
| 同時リクエスト | 8 (max_num_seqs) |
| GPU利用率 | 0.5 (gpu_memory_utilization) |

### 3.5 Qwen3対応
- `<think>...</think>` タグの自動除去
- SO解析失敗時のJSON抽出フォールバック
- 決定論的フォールバック (LLM完全失敗時)

## 4. Phase6 ポリシーエンジン (llm_final_decision.py)

### 4.1 バージョン
- `v1.6.3-fn-rescue`

### 4.2 判定ルール (R1-R6)

| ルール | 条件 | 判定 |
|--------|------|------|
| R1 | contextual >= 0.5 + strong_evidence | → Phishing |
| R2 | brand_detected + (free_ca \| no_org) + contextual >= 0.35 | → Phishing |
| R3 | contextual >= 0.4 + strong_evidence + (free_ca \| no_org) | → Phishing |
| R4 | ML < 0.5 + (free_ca, no_org) + contextual >= threshold | → Phishing |
| R5 | ML < 0.5 + dangerous_tld + no_org + contextual >= 0.33 | → Phishing |
| R6 | ML Paradox + dangerous_tld + (free_ca \| no_org) + ctx >= 0.35 | → Phishing |

### 4.3 Strong Evidence定義

以下のいずれかが存在する場合:
- `brand_impersonation` (ブランド偽装検出)
- `dangerous_tld` (domain_issues または ctx_issues)
- `idn_homograph` (ホモグラフ攻撃)
- `random_pattern` + (short/very_short/dangerous_tld/idn_homograph)
- `self_signed` (自己署名証明書)

### 4.4 Post-LLM Flip Gate

| ゲート | 条件 | 効果 |
|--------|------|------|
| POST_LLM_FLIP_GATE | ML < 0.25 & non-dangerous TLD | LLM phishing反転をブロック (FP防止) |
| LOW_ML_GUARD | ML < 0.25 & free_ca/no_orgのみ | Phishing反転を抑制 |
| P1 Gate | non-dangerous TLD + ML < 0.30 | low_signal_phishing_gateを無効化 |
| P4 Gate | 中危険TLD + 短期証明書 + 低SAN + ML < 0.05 | FN救済 |

### 4.5 graph_state出力フィールド

| フィールド | 型 | 内容 |
|-----------|-----|------|
| `phase6_policy_version` | str | ポリシーバージョン |
| `phase6_rules_fired` | List[str] | 発火ルール一覧 |
| `phase6_gate` | Dict | ゲート発動情報 |
| `decision_trace` | Dict | 判定トレース詳細 |

## 5. ツール仕様

### 5.1 brand_impersonation_check

**目的**: ドメイン名に含まれるブランド偽装の検出

| 検出手法 | 説明 |
|----------|------|
| 完全一致 | ドメインにブランド名が含まれる |
| 編集距離2 | タイポスクワッティング (例: go0gle) |
| 部分文字列 | ブランド名の部分一致 |
| Fuzzy TLD除外 | TLD部分のfuzzy matchを除外 |
| 日本語ブランド | jibunbank, aiful, rakuten等 |
| JPCERT連携 | JPCERTフィードからのブランド抽出 |

**出力**: `brand_detected`, `matched_brand`, `match_type`, `confidence`

### 5.2 certificate_analysis

**目的**: SSL/TLS証明書の詳細分析

| 分析項目 | 説明 |
|----------|------|
| cert-domain一致 | CN/SANとドメインの一致確認 |
| 発行者分析 | Let's Encrypt, 自己署名, OV/EV判定 |
| 有効期間 | 短期(< 90日)/長期判定 |
| 鍵強度 | RSA 2048以上, ECDSA対応 |
| 拡張 | SCT, OCSP, CRL Distribution Points |
| SAN分析 | SAN数、DNS/IP比率 |

**出力**: `risk_score`, `findings`, `cert_type`, `is_free_ca`, `has_organization`

### 5.3 contextual_risk_assessment

**目的**: ドメインのコンテキスト情報に基づくリスク評価

| 分析項目 | 説明 |
|----------|------|
| Dangerous TLD | .top, .xyz, .cn, .ru等の危険TLD |
| ホモグラフ (IDN) | Punycode/Unicode混同検出 |
| ランダムパターン | ランダム文字列ドメイン |
| ドメイン長 | 異常に長い/短いドメイン |
| 数字比率 | 数字が多いドメイン |

**出力**: `contextual_score` (0.0-1.0), `domain_issues`, `ctx_issues`

### 5.4 short_domain_analysis

**目的**: 短いドメイン(2-4文字)の分析

| 分析項目 | 説明 |
|----------|------|
| エントロピー | 文字のランダム性 |
| ブランド混同 | 短縮形でのブランド偽装 |
| 正規短ドメイン | 既知の正規短ドメイン判定 |

**出力**: `is_suspicious`, `findings`, `legitimate_match`

## 6. Precheck Module (precheck_module.py)

### 6.1 MLカテゴリ分類

| カテゴリ | ML確率範囲 | 説明 |
|----------|-----------|------|
| high_confidence_phish | >= 0.85 | 高確信フィッシング |
| likely_phish | 0.5-0.85 | フィッシング寄り |
| uncertain | 0.2-0.5 | 不確実 |
| likely_benign | < 0.2 | ベニン寄り |

### 6.2 ヒント生成

- TLD危険度評価
- ドメイン長分類 (very_short/short/normal/long)
- ML Paradox検出 (ML低スコアだがリスク特徴あり)
- ツール選択推奨

## 7. Phase6 Wiring (phase6_wiring.py)

### 7.1 目的
既存のLangGraph agentに対する非破壊的なモンキーパッチ。`final_decision` ノードの出力にPhase6ポリシーを適用する。

### 7.2 処理フロー
1. LLMのFinalAssessmentSOを取得
2. Phase6ポリシールール(R1-R6)を評価
3. Post-LLMゲートを適用
4. 決定トレースをgraph_stateに埋込
5. 最終PhishingAssessmentを返却

### 7.3 SOフォールバック
- JSON抽出フォールバック (正規表現)
- 決定論的フォールバック (ルールベースのみ)

## 8. 入出力仕様

### 8.1 入力

| フィールド | 型 | 説明 |
|-----------|-----|------|
| `domain` | str | 評価対象ドメイン |
| `cert_data` | dict | 証明書情報 (optional) |
| `ml_probability` | float | Stage1 ML確率 |
| `prediction_proba` | float | Stage2予測確率 |
| `source` | str | データソース |

### 8.2 出力

| フィールド | 型 | 説明 |
|-----------|-----|------|
| `ai_is_phishing` | bool | フィッシング判定 |
| `ai_confidence` | float | 信頼度 (0.0-1.0) |
| `ai_risk_level` | str | リスクレベル |
| `ai_risk_factors` | str | リスク要因 (JSON) |
| `processing_time` | float | 処理時間 (秒) |
| `phase6_policy_version` | str | ポリシーバージョン |
| `phase6_rules_fired` | str | 発火ルール |

## 9. 依存関係

```
langgraph_module.py
├── agent_foundations.py    (Phase1: データ構造)
├── precheck_module.py     (Phase2: 前処理)
├── tools_module.py        (Phase3: ツール統合)
│   ├── tools/brand_impersonation_check.py
│   ├── tools/certificate_analysis.py
│   ├── tools/contextual_risk_assessment.py
│   └── tools/short_domain_analysis.py
├── phase6_wiring.py       (Phase6: ポリシー接続)
└── llm_final_decision.py  (Phase6: ポリシーエンジン)
```

## 10. 性能指標 (128,002ドメイン評価)

| 指標 | Stage3単体 | パイプライン全体 |
|------|-----------|----------------|
| Precision | 91.6% | 99.68% |
| Recall | 60.0% | 97.08% |
| F1 Score | 72.5% | 98.36% |
| 処理速度 | ~8.5件/分/GPU | — |
