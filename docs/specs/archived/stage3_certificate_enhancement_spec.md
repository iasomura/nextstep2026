# Stage3 証明書特徴量強化仕様書

**作成日**: 2026-01-12
**バージョン**: 1.1
**ステータス**: ドラフト（Handoff分析反映済み）

---

## 1. 概要

### 1.1 目的

Stage2で有効性が確認された証明書特徴量をStage3（AI Agent）にも統合し、以下を実現する：

1. **正規サイトの誤検知（FP）削減**: 証明書の正規性シグナルを活用
2. **フィッシングの検出精度向上**: 証明書の異常パターンをポリシールールに反映
3. **Stage2/Stage3の判定一貫性**: 同じ証明書特徴量を両Stageで活用

### 1.2 背景

2026-01-12のStage2実装で以下の証明書特徴量の識別力が確認された：

| 特徴量 | 正規サイト | フィッシング | 識別力 |
|--------|-----------|-------------|--------|
| CRL Distribution Points | 81.7% | 1.6% | **80.1%** |
| ワイルドカード証明書 | 55.1% | 1.5% | **53.6%** |
| OV/EV証明書 | 6.6% | 0.1% | 6.5% |
| 有効期間180日超 | 27.0% | 1.0% | 26.0% |

しかし、Stage3ではこれらが十分に活用されていない。

### 1.3 Stage3 Handoffデータ分析

Stage3に送信される4,386件のHandoffデータを分析した結果、以下のケース分類が判明した：

| カテゴリ | 件数 | 説明 | Stage3の役割 |
|----------|------|------|-------------|
| **低シグナルフィッシング** | 176 | 低ML(<0.3) + 実Phishing | 検知必須 |
| **FP Risk** | 124 | 高ML(≥0.7) + 実Benign | 誤検知防止 |
| 正常Phishing | 1,616 | 高ML + 実Phishing | 容易に判定可 |
| 正常Benign | 1,867 | 低ML + 実Benign | 容易に判定可 |

#### 用語定義

- **低シグナルフィッシング (Low-Signal Phishing)**: MLモデルが低リスクと判定するが、実際はフィッシングであるケース。MLが捉える特徴量（シグナル）が少なく、ドメイン名や証明書の表面的特徴ではフィッシングと判別しにくい。
- **FP Risk（誤検知リスク）**: MLモデルが高リスクと判定するが、実際は正規サイトであるケース。github.com等の有名サイトが含まれる。

#### 証明書特徴による識別可能性

| カテゴリ | SAN数平均 | 90日以下証明書 |
|----------|-----------|---------------|
| 低シグナルフィッシング | **4.3** | 97.7% |
| FP Risk | **13.2** | 92.7% |
| 正常Phishing | 9.2 | 92.8% |
| 正常Benign | 3.6 | 96.8% |

**重要な発見**: SAN数が低シグナルフィッシングとFP Riskの識別に有効。SAN数が多い（≥10）場合は正規サイトの可能性が高い。

---

## 2. 現状分析

### 2.1 Stage3アーキテクチャ

```
START
  ↓
[precheck] - ドメイン特徴抽出、TLDカテゴリ、ブランドヒント
  ↓
[tool_selection] - LLMがツール選択
  ↓
[tool_execution] - brand/cert/domain分析を並列実行
  ↓
[contextual_check] - シグナル統合、低シグナルフィッシング検出
  ↓
[final_decision] - LLM評価 + Phase6ポリシールール + ゲート
  ↓
END
```

### 2.2 現在の証明書機能の問題点

#### A. certificate_analysis.py

現在の`detected_issues`:
```python
detected_issues = [
    "no_cert",       # 証明書なし
    "self_signed",   # 自己署名
    "free_ca",       # Let's Encrypt等
    "no_org",        # DV証明書（Organization無し）
    "no_san",        # SANなし
    "short_term",    # 有効期間90日未満
    "many_san",      # SAN数10以上
    "wildcard",      # ワイルドカード（※リスク扱い）
]
```

**問題点**:
1. `wildcard` がリスク扱い（実際は正規寄り）
2. CRL Distribution Points 未検出
3. OV/EV証明書 未検出
4. 長期有効期間（180日超）未検出

#### B. llm_final_decision.py（R1-R6ルール）

現在のルールは `free_ca & no_org` の組み合わせのみを使用：

| ルール | 条件 | 証明書条件 |
|--------|------|-----------|
| R1 | ml < 0.20 + ctx >= 0.28-0.34 | free_ca & no_org |
| R2 | ml < 0.30 + ctx >= 0.34 | free_ca OR short |
| R3 | ml < 0.40 + ctx >= 0.36 | no_org |
| R4 | ml < 0.50 + ctx >= 0.33-0.35 | free_ca & no_org |
| R5 | ml < 0.50 + dangerous_tld | no_org |
| R6 | ml < 0.30 + dangerous_tld | free_ca & no_org |

**問題点**:
- 正規サイトを示す証明書シグナル（CRL、OV/EV、ワイルドカード）が未使用
- 長期有効期間がルールに反映されていない

---

## 3. 提案: 証明書特徴量強化

### 3.1 新規検出項目の追加

`certificate_analysis.py` に以下を追加：

```python
# === 新規: 正規性シグナル（Benign Indicators） ===
benign_indicators = []

# 1. CRL Distribution Points（正規81.7%が保有）
if cert_info.get('has_crl_dp', False):
    benign_indicators.append("has_crl_dp")

# 2. OV/EV証明書（Subject Organization有り）
if cert_info.get('has_org', False):
    benign_indicators.append("ov_ev_cert")

# 3. ワイルドカード証明書（正規55.1%が使用）
# ※ 既存のwildcard検出を移動、リスクから正規へ
if cert_info.get('is_wildcard', False):
    benign_indicators.append("wildcard_cert")
    # detected_issuesから削除

# 4. 長期有効期間（180日超）
validity_days = cert_info.get('validity_days', 0)
if validity_days > 180:
    benign_indicators.append("long_validity")

# 5. 多数のSAN（10以上 = 正規サイトの可能性高）
# Handoff分析: FP Riskケースは平均SAN 13.2、Evasive Phishingは4.3
san_count = cert_info.get('san_count', 0)
if san_count >= 10:
    benign_indicators.append("high_san_count")
```

### 3.2 リスクスコア計算の修正

```python
def calculate_cert_risk_score(detected_issues, benign_indicators, is_dangerous_tld):
    """証明書リスクスコア計算（改訂版）"""

    base_score = 0.0

    # リスク加算
    if "self_signed" in detected_issues:
        base_score += 0.40
    if "free_ca" in detected_issues and "no_org" in detected_issues:
        base_score += 0.20
    if "short_term" in detected_issues:
        base_score += 0.10
    if "many_san" in detected_issues:
        base_score += 0.05

    # === 新規: 正規性シグナルによる減算 ===
    benign_reduction = 0.0

    if "has_crl_dp" in benign_indicators:
        benign_reduction += 0.15  # 最大効果
    if "ov_ev_cert" in benign_indicators:
        benign_reduction += 0.20  # OV/EVは強い正規シグナル
    if "wildcard_cert" in benign_indicators and not is_dangerous_tld:
        benign_reduction += 0.10  # 危険TLD以外
    if "long_validity" in benign_indicators:
        benign_reduction += 0.08
    if "high_san_count" in benign_indicators:
        benign_reduction += 0.12  # SAN≥10は正規寄り

    # 最終スコア（0.0-1.0）
    final_score = max(0.0, min(1.0, base_score - benign_reduction))

    return final_score
```

### 3.3 ポリシールール拡張

`llm_final_decision.py` に以下のゲートを追加：

```python
# === 新規: Benign Certificate Gate ===
# 強い正規性シグナルがある場合、フィッシング判定を抑制

def _apply_benign_cert_gate(asmt, ml, cert_info, ctx_score):
    """証明書の正規性シグナルに基づくゲート"""

    benign_indicators = cert_info.get('benign_indicators', [])

    # Gate B1: OV/EV証明書
    # OV/EV証明書は発行に組織確認が必要 → フィッシングではまず使われない
    if "ov_ev_cert" in benign_indicators:
        if asmt.is_phishing and ctx_score < 0.50:
            logger.info("Gate B1: OV/EV cert → forcing BENIGN")
            return PhishingAssessment(
                is_phishing=False,
                confidence=0.85,
                risk_factors=["ov_ev_cert_protected"],
                mitigated_risk_factors=asmt.risk_factors,
            )

    # Gate B2: CRL + 低リスク
    # CRL配布ポイントを持つ証明書は正規CAの厳格な発行プロセスを経ている
    if "has_crl_dp" in benign_indicators and ml < 0.30:
        if asmt.is_phishing and ctx_score < 0.45:
            logger.info("Gate B2: CRL + low_ml → forcing BENIGN")
            return PhishingAssessment(
                is_phishing=False,
                confidence=0.80,
                risk_factors=["crl_protected"],
                mitigated_risk_factors=asmt.risk_factors,
            )

    # Gate B3: ワイルドカード + 非危険TLD
    # ワイルドカード証明書は正規運用（CDN、サブドメイン多数）で使用
    if "wildcard_cert" in benign_indicators:
        tld_category = cert_info.get('tld_category', 'unknown')
        if tld_category != 'dangerous':
            if asmt.is_phishing and ctx_score < 0.40:
                logger.info("Gate B3: Wildcard + non-dangerous TLD → forcing BENIGN")
                return PhishingAssessment(
                    is_phishing=False,
                    confidence=0.75,
                    risk_factors=["wildcard_protected"],
                    mitigated_risk_factors=asmt.risk_factors,
                )

    # Gate B4: 多数のSAN + 非危険TLD
    # SAN数が多い証明書は正規の大規模サービス（CDN、SaaS）で使用
    # Handoff分析: FP Riskケースは平均SAN 13.2、低シグナルフィッシングは4.3
    if "high_san_count" in benign_indicators:
        tld_category = cert_info.get('tld_category', 'unknown')
        if tld_category != 'dangerous':
            if asmt.is_phishing and ctx_score < 0.45:
                logger.info("Gate B4: High SAN count + non-dangerous TLD → forcing BENIGN")
                return PhishingAssessment(
                    is_phishing=False,
                    confidence=0.75,
                    risk_factors=["high_san_protected"],
                    mitigated_risk_factors=asmt.risk_factors,
                )

    return asmt  # 変更なし
```

### 3.4 precheck_hintsの拡張

`precheck_module.py` に証明書サマリを追加：

```python
def generate_precheck_hints(domain, ml_probability, cert_info, ...):
    """precheckヒント生成（証明書情報拡張版）"""

    hints = {
        # 既存フィールド...

        # === 新規: 証明書サマリ ===
        "cert_summary": {
            "has_crl_dp": cert_info.get('has_crl_dp', False),
            "is_ov_ev": cert_info.get('has_org', False),
            "is_wildcard": cert_info.get('is_wildcard', False),
            "validity_days": cert_info.get('validity_days', 0),
            "is_long_validity": cert_info.get('validity_days', 0) > 180,
            "san_count": cert_info.get('san_count', 0),
            "is_high_san": cert_info.get('san_count', 0) >= 10,
            "benign_score": _calc_benign_score(cert_info),
        },
    }

    return hints

def _calc_benign_score(cert_info):
    """証明書の正規性スコア（0.0-1.0）"""
    score = 0.0
    if cert_info.get('has_crl_dp', False):
        score += 0.30
    if cert_info.get('has_org', False):
        score += 0.35
    if cert_info.get('is_wildcard', False):
        score += 0.10
    if cert_info.get('validity_days', 0) > 180:
        score += 0.10
    if cert_info.get('san_count', 0) >= 10:
        score += 0.15  # 高SAN数は正規寄り
    return min(1.0, score)
```

### 3.5 低シグナルフィッシング検出強化

Handoff分析から判明した**低シグナルフィッシング (Low-Signal Phishing)**を検出するための追加ロジック：

```python
def detect_low_signal_phishing(domain, ml, cert_info, tool_results):
    """低シグナルフィッシング検出用シグナル"""

    signals = []

    # 低シグナルフィッシングの特徴（Handoff分析より）:
    # - 低ML確率（<0.3）
    # - .comドメイン多い（57%）
    # - 短期有効証明書（90日以下が97.7%）
    # - 低SAN数（平均4.3）
    # - 正規ビジネス風のドメイン名

    # 1. 短期有効証明書（90日以下）
    if cert_info.get('validity_days', 0) <= 90:
        signals.append("short_validity_cert")

    # 2. 低SAN数（5以下）
    if cert_info.get('san_count', 0) <= 5:
        signals.append("low_san_count")

    # 3. ブランド偽装の兆候
    brand_result = tool_results.get('brand_impersonation', {})
    if brand_result.get('brand_detected', False):
        signals.append("brand_impersonation")

    # 4. コンテンツリスク
    content_result = tool_results.get('contextual_risk', {})
    if content_result.get('has_login_form', False):
        signals.append("login_form_detected")
    if content_result.get('credential_harvesting_indicators', False):
        signals.append("credential_harvesting")

    # 判定ロジック
    # 低MLだが複数のリスクシグナルがある場合、フィッシングの可能性高
    if ml < 0.30 and len(signals) >= 2:
        return {
            "is_low_signal_phishing": True,
            "signals": signals,
            "recommendation": "PHISHING",
            "confidence": 0.70 + 0.05 * len(signals),
        }

    return {"is_low_signal_phishing": False, "signals": signals}
```

---

## 4. 実装計画

### 4.1 変更ファイル

| ファイル | 変更内容 | 優先度 |
|----------|----------|--------|
| `phishing_agent/tools/certificate_analysis.py` | benign_indicators追加、SAN分析強化 | 最高 |
| `phishing_agent/llm_final_decision.py` | Gate B1-B4追加、低シグナル検出 | 高 |
| `phishing_agent/precheck_module.py` | cert_summary追加 | 中 |
| `phishing_agent/contextual_risk_assessment.py` | benign_indicators統合 | 中 |

### 4.2 段階的導入

| Phase | 内容 | リスク |
|-------|------|--------|
| Phase 1 | certificate_analysis.pyにbenign_indicators追加 | 低 |
| Phase 2 | Gate B1（OV/EV）追加 | 低 |
| Phase 3 | Gate B2（CRL）追加 | 低 |
| Phase 4 | Gate B3（ワイルドカード）追加 | 中 |
| Phase 5 | Gate B4（高SAN数）追加 | 低 |
| Phase 6 | 低シグナルフィッシング検出ロジック追加 | 中 |
| Phase 7 | precheck_hints拡張 | 低 |

---

## 5. 期待効果

### 5.1 FP削減

| シナリオ | 現状 | 改善後 |
|----------|------|--------|
| OV/EV証明書の正規サイト | FPリスクあり | Gate B1で保護 |
| CRL保有の正規サイト | FPリスクあり | Gate B2で保護 |
| CDN/大規模サイト（ワイルドカード） | FPリスクあり | Gate B3で保護 |

### 5.2 Stage2/Stage3の一貫性

| 特徴量 | Stage2 | Stage3（改善後） |
|--------|--------|-----------------|
| CRL | Safe BENIGN | Gate B2で保護 |
| OV/EV | Safe BENIGN | Gate B1で保護 |
| ワイルドカード | Safe BENIGN（非危険TLD） | Gate B3で保護 |
| 長期有効期間 | Safe BENIGN | benign_score加算 |

---

## 6. テスト計画

### 6.1 単体テスト

| テスト項目 | 内容 |
|-----------|------|
| benign_indicators検出 | CRL、OV/EV、ワイルドカード、長期有効期間の正常検出 |
| Gate B1-B3 | 各ゲートの発火条件と非発火条件 |
| スコア計算 | benign_score計算の正確性 |

### 6.2 統合テスト

| テスト項目 | 期待結果 |
|-----------|----------|
| OV/EV証明書サイト | is_phishing=False |
| CRL保有 + 低ml | is_phishing=False |
| ワイルドカード + .com | is_phishing=False |
| ワイルドカード + .tk | ゲート不発火（危険TLD） |

### 6.3 回帰テスト

既存のテストケース（210件 低シグナルフィッシングテスト等）で性能劣化がないことを確認。

---

## 7. リスクと対策

| リスク | 影響 | 対策 |
|--------|------|------|
| FN増加（フィッシング見逃し） | 危険 | ゲートにctx_score閾値を設定 |
| OV/EV詐称 | 中 | OV/EVは発行コストが高く、詐称は稀 |
| CRL偽装 | 低 | CRL配布ポイントはCA署名で保護 |

---

## 8. 関連ドキュメント

- Stage2証明書ルール仕様: `docs/specs/stage2_certificate_rules_spec.md`
- 証明書分析レポート: `docs/analysis/certificate_analysis_report.md`
- 研究日誌: `docs/research/20260112.md`
- Phase6ポリシー実装: `phishing_agent/llm_final_decision.py`

---

## 変更履歴

| 日付 | バージョン | 変更内容 |
|------|-----------|----------|
| 2026-01-12 | 1.0 | 初版作成 |
| 2026-01-12 | 1.1 | Handoff分析結果を反映、SAN数ルール追加、用語統一（低シグナルフィッシング/FP Risk） |
