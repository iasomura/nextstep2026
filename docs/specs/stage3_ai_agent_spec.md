# Stage3 AI Agent 仕様書

**バージョン**: v1.7.1
**更新日**: 2026-02-04
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

#### PhishingAssessment (agent_foundations.py)
```python
class PhishingAssessment(BaseModel):
    is_phishing: bool
    confidence: float = Field(ge=0.0, le=1.0)
    risk_level: str
    detected_brands: List[str] = []
    risk_factors: List[str] = []
    reasoning: str = Field(min_length=20, max_length=2500)  # 2026-02-04改訂
```

**SOエラー対策 (2026-02-04)**:
- `reasoning.max_length`: 1000 → 2500 に拡大
- 背景: 平均reasoning長が1,263文字で、旧制限1000でValidationError発生
- 効果: SOエラー率 23.4% → 0.0%

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
- `v1.7.1-prompt-recall` (2026-02-04更新)

### 4.2 変更履歴

| 日付 | バージョン | 変更内容 |
|------|-----------|----------|
| 2026-02-04 | v1.7.1-prompt-recall | プロンプト改善（Recall向上） |
| 2026-02-03 | v1.7.0-rule-modules | ルールモジュール統合 |
| 2026-01-28 | v1.6.5 | ブランド非依存フィッシング検出強化 |

### 4.3 LLMプロンプト判定ルール (2026-02-04改訂)

| ルール | 条件 | 判定 |
|--------|------|------|
| 1 | random_pattern + corroborating_signal | → Phishing |
| 2 | dangerous_tld + free_ca + no_org | → **MUST Phishing** |
| 3 | ML単独では判定しない | non-ML risk_factors必須 |
| 4 | baseline_risk >= 0.55 | → **MUST Phishing** |
| 4b | baseline_risk >= 0.40 + strong_signal | → Phishing |
| 5 | risk_score < 0.40 | 他シグナルで判定 |
| 6 | benign判定時のstrong risk signal | → mitigated_risk_factors必須 |
| 8 | DV/Let's Encrypt | 緩和要因として扱わない |
| 9 | ml < 0.15 + legitimate TLD | 保守的判定 |
| 10 | **ML >= 0.5 + free_ca_no_org** | → **STRONG Phishing** (新規) |
| 11 | **short_random_combo + dangerous_tld + free_ca** | → high risk (新規) |

**注**: ルール4のbaseline_riskは `max(contextual, cert, domain, brand)`

### 4.4 判定ルール (R1-R6) - ポリシー補正

| ルール | 条件 | 判定 |
|--------|------|------|
| R1 | contextual >= 0.5 + strong_evidence | → Phishing |
| R2 | brand_detected + (free_ca \| no_org) + contextual >= 0.35 | → Phishing |
| R3 | contextual >= 0.4 + strong_evidence + (free_ca \| no_org) | → Phishing |
| R4 | ML < 0.5 + (free_ca, no_org) + contextual >= threshold | → Phishing |
| R5 | ML < 0.5 + dangerous_tld + no_org + contextual >= 0.33 | → Phishing |
| R6 | ML Paradox + dangerous_tld + (free_ca \| no_org) + ctx >= 0.35 | → Phishing |

### 4.5 Strong Evidence定義

以下のいずれかが存在する場合:
- `brand_impersonation` (ブランド偽装検出)
- `dangerous_tld` (domain_issues または ctx_issues)
- `idn_homograph` (ホモグラフ攻撃)
- `random_pattern` + (short/very_short/dangerous_tld/idn_homograph)
- `self_signed` (自己署名証明書)

### 4.6 Post-LLM Flip Gate

| ゲート | 条件 | 効果 |
|--------|------|------|
| POST_LLM_FLIP_GATE | ML < 0.25 & non-dangerous TLD | LLM phishing反転をブロック (FP防止) |
| LOW_ML_GUARD | ML < 0.25 & free_ca/no_orgのみ | Phishing反転を抑制 |
| P1 Gate | non-dangerous TLD + ML < 0.30 | low_signal_phishing_gateを無効化 |
| P4 Gate | 中危険TLD + 短期証明書 + 低SAN + ML < 0.05 | FN救済 |

### 4.7 graph_state出力フィールド

| フィールド | 型 | 内容 |
|-----------|-----|------|
| `phase6_policy_version` | str | ポリシーバージョン |
| `phase6_rules_fired` | List[str] | 発火ルール一覧 |
| `phase6_gate` | Dict | ゲート発動情報 |
| `decision_trace` | Dict | 判定トレース詳細 |

## 5. ツール仕様

### 5.0 共通出力フォーマット

全ツールは以下の共通フォーマットで出力する:

```python
{
    "domain": str,              # 分析対象ドメイン
    "detected_issues": List[str],  # 検出された問題フラグ
    "risk_score": float,        # リスクスコア (0.0-1.0)
    "details": Dict[str, Any],  # ツール固有の詳細情報
    "reasoning": str,           # 人間可読な判定理由 (一部ツール)
}
```

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
| CRITICAL_BRAND_KEYWORDS | 高リスクブランド110キーワード |
| LLM補完検出 | ルールで未検出時のLLM補完 |

**detected_issues例**:
- `brand_detected`, `brand_exact_match`, `brand_substring`, `brand_compound`
- `brand_fuzzy`, `brand_fuzzy2`, `brand_typosquat`, `brand_tld_mismatch`
- `brand_llm`, `brand_llm_confirmed`, `brand_suspected`, `brand_llm_candidate`
- `critical_brand`, `critical_brand_dangerous_tld`, `ml_paradox_brand`

**details構造**:
```python
{
    "detected_brands": List[str],    # 検出されたブランド名
    "match_type": str,               # "exact"/"substring"/"compound"/"fuzzy"/"none"
    "rule_hits": List[str],          # マッチしたルール
    "whitelist": Dict,               # ホワイトリスト情報
    "used_llm": bool,                # LLMを使用したか
    "llm_confidence": float,         # LLM信頼度
    "llm_reasoning": str,            # LLM判定理由
    "brand_detected": bool,          # ブランド検出フラグ
    "brand_suspected": bool,         # ブランド疑惑フラグ
    "has_critical_brand": bool,      # クリティカルブランドフラグ
    "issue_flags": List[str],        # 全検出フラグ
    "precheck": {
        "ml_probability": float,
        "ml_category": str,
        "tld_category": str,
        "domain_length_category": str,
        "quick_risk": float,
        "ml_paradox_flag_from_precheck": bool,
    },
}
```

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

**detected_issues例**:
- `free_ca`, `self_signed`, `short_validity`, `no_org`
- `low_san_count`, `expired`, `weak_key`, `domain_mismatch`

**details構造**:
```python
{
    "validation_level": str,     # "DV"/"OV"/"EV"/"self-signed"
    "is_free_ca": bool,          # 無料CA (Let's Encrypt等)
    "has_org": bool,             # 組織情報あり
    "issuer": str,               # 発行者名
    "validity_days": int,        # 有効期間日数
    "san_count": int,            # SAN数
    "key_type": str,             # "RSA"/"ECDSA"
    "key_bits": int,             # 鍵長
    "not_before": str,           # 有効開始日
    "not_after": str,            # 有効終了日
}
```

### 5.3 contextual_risk_assessment

**目的**: ドメインのコンテキスト情報に基づくリスク評価（他ツール結果を集約）

| 分析項目 | 説明 |
|----------|------|
| Dangerous TLD | .top, .xyz, .cn, .ru等の危険TLD |
| ホモグラフ (IDN) | Punycode/Unicode混同検出 |
| ランダムパターン | ランダム文字列ドメイン |
| ドメイン長 | 異常に長い/短いドメイン |
| 数字比率 | 数字が多いドメイン |
| 多言語リスクワード | connexion, verificar等 |
| 危険TLD重み強化 | 他シグナルとの組み合わせ増幅 |

**detected_issues例**:
- `dangerous_tld`, `medium_danger_tld`, `idn_homograph`
- `random_pattern`, `short`, `very_short`, `high_digit_ratio`
- `dangerous_tld_combo`, `dangerous_tld_random`, `multilingual_risk`

**details構造**:
```python
{
    "ml_probability": float,         # ML確率
    "ml_category": str,              # "high_confidence_phish"/"likely_phish"/"uncertain"/"likely_benign"
    "total_issues_count": int,       # 検出issues総数
    "combined_risk_score": float,    # 全ツール平均リスク
    "tool_average_risk": float,      # combined_risk_scoreと同値 (互換用)
    "is_ml_paradox": bool,           # ML Paradox検出 (強パラドックスのみ)
    "all_detected_issues": List[str],# 全ツールからの集約issues
    "high_risk_hits": int,           # 高リスクワードヒット数
    "known_domain": {                # 既知ドメイン情報
        "is_known_seen": bool,
        "is_known_legit": bool,
        "label": str,
        "mitigation": float,
        "legit_info": Dict,
    },
    "consistency_boost": float,      # 一貫性ブースト値
    "score_components": Dict,        # スコア内訳
    "paradox": {                     # Paradox詳細
        "risk_signal_count": int,
        "is_paradox_strong": bool,
        "is_paradox_weak": bool,
        # 効果測定用 (2026-01-31追加)
        "excluded_signals": List[str],   # 除外されたシグナル名
        "would_have_triggered": bool,    # 除外がなければ発火していたか
    },
}
```

### 5.4 short_domain_analysis

**目的**: ドメイン構造の詳細分析（短ドメインに限らず全般）

| 分析項目 | 説明 |
|----------|------|
| エントロピー | 文字のランダム性 (Shannon entropy) |
| 子音クラスター | 3文字以上の連続子音検出 |
| レアバイグラム | 英語で稀な文字組み合わせ |
| ドメイン長分類 | very_short/short/normal/long |
| 数字/母音比率 | ランダム性指標 |

**detected_issues例**:
- `short`, `very_short`, `random_pattern`
- `consonant_cluster_random`, `rare_bigram_random`
- `high_entropy`, `low_vowel_ratio`

**details構造**:
```python
{
    "domain_length": int,            # ドメイン長
    "domain_length_category": str,   # "very_short"/"short"/"normal"/"long"
    "entropy": float,                # Shannon entropy
    "vowel_ratio": float,            # 母音比率
    "digit_ratio": float,            # 数字比率
    "consonant_cluster_count": int,  # 子音クラスター数
    "rare_bigram_ratio": float,      # レアバイグラム比率
    "is_random": bool,               # ランダムパターン判定
}

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

#### 8.2.1 基本フィールド

| フィールド | 型 | 説明 |
|-----------|-----|------|
| `ai_is_phishing` | bool | フィッシング判定 |
| `ai_confidence` | float | 信頼度 (0.0-1.0) |
| `ai_risk_level` | str | リスクレベル |
| `reasoning` | str | 判定理由 (50文字以上) |
| `risk_factors` | List[str] | リスク要因リスト |
| `detected_brands` | List[str] | 検出ブランドリスト |
| `processing_time` | float | 処理時間 (秒) |
| `phase6_policy_version` | str | ポリシーバージョン |
| `phase6_rules_fired` | List[str] | 発火ルール |

#### 8.2.2 トレースフィールド

FP/FN分析用の詳細トレースフィールドは `langgraph_module.py` の `evaluate()` 出力に含まれる。
評価システムでの保存仕様は **parallel_evaluation_spec.md セクション10.1** を参照。

主要トレースフィールド:
- `trace_precheck_*`: Precheckステージの情報
- `trace_brand/cert/domain/ctx_risk_score`: 各ツールのリスクスコア
- `trace_ctx_issues_json`: 検出された問題点
- `graph_state_slim_json`: 完全なグラフ状態 (デバッグ用)
- `tool_*_output`: 各ツールの完全な出力

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

## 10. 性能指標 (127,222ドメイン評価、2026-02-07 SO再評価後)

| 指標 | Stage3単体 (n=11,952) | パイプライン全体 |
|------|-----------|----------------|
| Precision | 76.11% | 99.16% |
| Recall | 68.92% | 98.18% |
| F1 Score | 72.33% | 98.67% |
| 処理速度 (p50) | 8.31秒/件 | — |

---

## 変更履歴

| バージョン | 日付 | 変更内容 |
|-----------|------|---------|
| v1.6.3 | 2026-01-24 | Phase6ポリシー追加 |
| v1.6.4 | 2026-01-28 | 出力仕様更新: トレースフィールド追加、parallel_evaluation_specへの参照追加 |
| v1.6.5 | 2026-01-28 | Section 5 ツール仕様を実装に合わせて全面更新。共通出力フォーマット追加、detected_issues/details構造を文書化 |
