# 低シグナルフィッシング検出強化仕様書

## ステータス: ドラフト

## 1. 背景・課題

### 1.1 低シグナルフィッシングとは

Stage1（XGBoost）のMLモデルが捉える特徴量（シグナル）が少なく、低リスクと誤判定されるフィッシングサイト。

### 1.2 Handoff分析結果（2026-01-12）

Stage2からStage3へのHandoff 4,386件のうち、**176件**が低シグナルフィッシングと特定された。

| 特徴 | 値 |
|------|-----|
| TLD | .comが多い（57%） |
| 証明書有効期間 | **90日以下が97.7%** |
| SAN数 | 平均**4.3** |
| MLスコア | 平均0.05〜0.15 |
| ソース | JPCERT主体（53%） |

### 1.3 サンプルドメイン

```
ml=0.040 | .in     | playstationgames.in    → ブランド検出可能
ml=0.056 | .com    | pepzop.com             → ブランド検出困難
ml=0.061 | .com    | techwillow.com         → ブランド検出困難
ml=0.064 | .online | amzawszone.online      → ブランド検出可能（LLM）
```

### 1.4 現状の検出能力

| 検出手段 | カバー範囲 | 限界 |
|----------|-----------|------|
| brand_impersonation_check | ブランド含むケース | ブランドなしは検出不可 |
| certificate_analysis | 短期証明書検出 | 単独では弱いシグナル |
| contextual_risk_assessment | 複合シグナル検出 | 低シグナルフィッシング専用ロジックなし |

---

## 2. 提案: 低シグナルフィッシング検出ゲート

### 2.1 概要

証明書特徴量とブランド検出を組み合わせた新しい検出ロジックを追加。

### 2.2 検出条件

#### Gate P1: ブランド偽装 + 短期証明書

```
条件:
  - brand_detected = true（ルールベースまたはLLM）
  - cert_validity_days <= 90
  - ml_probability < 0.30

効果:
  - is_phishing = true に強制
  - risk_level = "medium-high" 以上
```

**根拠**:
- 正規サイトがブランド名を含む場合、通常は長期証明書（90日超）を使用
- 低シグナルフィッシングの97.7%が短期証明書

#### Gate P2: ブランド疑い + 複合証明書リスク

```
条件:
  - brand_suspected = true（LLM候補）
  - cert_validity_days <= 90
  - cert_san_count <= 5
  - ml_probability < 0.25

効果:
  - is_phishing = true に強制
  - risk_level = "medium" 以上
```

**根拠**:
- LLMで疑わしいと判定されたケースに証明書リスクを組み合わせ
- 低シグナルフィッシングは低SAN数（平均4.3）

#### Gate P3: 高リスクTLD + 短期証明書 + 低ML

```
条件:
  - tld_category = "dangerous" または tld in [特定リスト]
  - cert_validity_days <= 90
  - cert_san_count <= 3
  - ml_probability < 0.20
  - benign_indicators が空

効果:
  - contextual_risk_score に +0.15 ボーナス
  - low_signal_phishing_risk フラグを追加
```

**根拠**:
- ブランドがなくても危険TLD + 証明書特徴で疑いを高める
- benign_indicatorsがあれば適用しない（FP防止）

---

## 3. 実装案

### 3.1 案A: llm_final_decision.py に新ゲート追加（推奨）

```python
def _apply_low_signal_phishing_gate(
    asmt: PhishingAssessment,
    tool_summary: Dict[str, Any],
    *,
    ml_probability: Optional[float] = None,
    precheck: Optional[Dict[str, Any]] = None,
    trace: Optional[List[Dict[str, Any]]] = None,
) -> PhishingAssessment:
    """
    低シグナルフィッシング検出ゲート。

    Gate P1: ブランド検出 + 短期証明書 + 低ML → PHISHING強制
    Gate P2: ブランド疑い + 短期証明書 + 低SAN + 低ML → PHISHING強制
    """
```

**長所**:
- Stage2/Stage3の証明書ゲートと一貫したアーキテクチャ
- 既存のBenign Cert Gate (B1-B4)と対称的な設計
- トレース出力で判定根拠が明確

**短所**:
- ポリシーゲートが増える

### 3.2 案B: contextual_risk_assessment.py を強化

```python
# 4-3c. Low-Signal Phishing Detection（強化版）
if brand_detected and cert_short_term and ml_p < 0.30:
    score = max(score, 0.55)
    issues.append("low_signal_phishing_brand_cert")
```

**長所**:
- 既存の低シグナルフィッシング検出ロジックを拡張
- contextualスコアとして自然に統合

**短所**:
- ブランド検出の詳細情報へのアクセスが間接的

### 3.3 案C: brand_impersonation_check.py に証明書情報を渡す

```python
def brand_impersonation_check(
    domain: str,
    brand_keywords: List[str],
    precheck_hints: Optional[Dict[str, Any]] = None,
    cert_info: Optional[Dict[str, Any]] = None,  # 追加
    ...
)
```

**長所**:
- ブランド検出と証明書の相関を直接計算

**短所**:
- ツールの責務が広がりすぎる
- 引数の互換性に注意が必要

---

## 4. 推奨: 案A（llm_final_decision.py に新ゲート追加）

### 4.1 理由

1. **一貫性**: 既存のBenign Cert Gate (B1-B4)と対称的
2. **トレーサビリティ**: gate_traceに記録され、デバッグしやすい
3. **分離**: 各ツールの責務を変えずに済む
4. **調整容易**: 閾値の調整が一箇所で可能

### 4.2 実装場所

`phishing_agent/llm_final_decision.py`:
- `_apply_benign_cert_gate()` の後に `_apply_low_signal_phishing_gate()` を呼び出し

### 4.3 新しいゲート定義

| ゲート | 条件 | 効果 |
|--------|------|------|
| Gate P1 | brand_detected + cert≤90日 + ml<0.30 | → PHISHING強制 |
| Gate P2 | brand_suspected + cert≤90日 + san≤5 + ml<0.25 | → PHISHING強制 |
| Gate P3 | dangerous_tld + cert≤90日 + san≤3 + ml<0.20 + no_benign | → risk_level bump |

---

## 5. 期待効果

### 5.1 検出率向上

| ケース | 現状 | 改善後 |
|--------|------|--------|
| ブランド偽装 + 短期証明書 | 一部検出 | **確実に検出** |
| LLM候補 + 証明書リスク | 見逃し可能性 | **検出強化** |
| 危険TLD + 証明書リスク | 弱い検出 | **リスク上昇** |

### 5.2 定量的目標

- 低シグナルフィッシング176件中、**80%以上**を検出
- FP増加を**1%以下**に抑制

---

## 6. リスク・考慮事項

### 6.1 FPリスク

| リスク | 対策 |
|--------|------|
| 正規サイトが短期証明書を使用 | benign_indicatorsチェックで除外 |
| LLMの誤検出 | brand_suspectedには追加条件（san≤5）を要求 |
| 新興サービスの誤検出 | ml閾値を保守的に設定（<0.30） |

### 6.2 実装リスク

| リスク | 対策 |
|--------|------|
| ゲートの順序依存 | Benign Gate → Phishing Gateの順で適用 |
| 証明書情報の欠損 | 証明書なしの場合はゲートをスキップ |

---

## 7. テスト計画

### 7.1 ユニットテスト

```python
# Gate P1: ブランド + 短期証明書
def test_gate_p1_brand_short_cert():
    tool_summary = {
        "brand": {"issues": ["brand_detected"]},
        "cert": {"details": {"valid_days": 60, "san_count": 3}},
    }
    # ml_probability=0.15 → PHISHING強制

# Gate P2: ブランド疑い + 複合リスク
def test_gate_p2_suspected_compound():
    tool_summary = {
        "brand": {"issues": ["brand_suspected"]},
        "cert": {"details": {"valid_days": 80, "san_count": 4}},
    }
    # ml_probability=0.20 → PHISHING強制

# FP防止: benign_indicatorsがある場合はスキップ
def test_gate_skip_with_benign_indicators():
    tool_summary = {
        "brand": {"issues": ["brand_detected"]},
        "cert": {"details": {"valid_days": 60, "benign_indicators": ["has_crl_dp"]}},
    }
    # → ゲートをスキップ
```

### 7.2 統合テスト

- 低シグナルフィッシング176件のサンプルでバックテスト
- 正規サイト（FP Risk 124件）での誤検知チェック

---

## 8. 実装ステップ

1. [ ] `llm_final_decision.py` に `_apply_low_signal_phishing_gate()` 追加
2. [ ] Gate P1（ブランド + 短期証明書）実装
3. [ ] Gate P2（ブランド疑い + 複合リスク）実装
4. [ ] Gate P3（危険TLD + 証明書リスク）実装
5. [ ] ユニットテスト追加
6. [ ] バックテストで精度検証
7. [ ] 研究日誌に結果記録

---

## 9. 関連ドキュメント

- `docs/specs/stage3_certificate_enhancement_spec.md` - Benign Cert Gate仕様
- `docs/research/20260112.md` - Handoff分析結果
- `phishing_agent/tools/brand_impersonation_check.py` - ブランド偽装検出実装
