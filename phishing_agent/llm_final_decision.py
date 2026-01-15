# -*- coding: utf-8 -*-
"""
llm_final_decision.py (Phase6 v1.4.7-dvguard4)
-------------------------------------------
変更履歴:
  - 2025-12-14: R4/R5 を追加（ML<0.5 帯の FN 改善）
      - R4: ML<0.5 かつ {free_ca,no_org} かつ contextual>=しきい値 → phishing
           * legitimate TLD & normal/long は少しだけ厳しめのしきい値
      - R5: ML<0.5 かつ dangerous_tld & no_org かつ contextual>=0.33 → phishing

  - 2025-12-15: R4(multiple_risk_factors) のしきい値を 0.34→0.33 に微調整（追加FN 4件を狙う）
  - 2025-12-15: R4 の legitimate TLD ガードを微調整（FN 端の救済）
      - legitimate TLD & normal/long でも ctx_issues に multiple_risk_factors がある場合は r4_threshold=0.33 を許容
  - 2025-12-16: graph_state に phase6_policy_version を必ず stamp（LLM/SO 失敗時も追跡可能に）

  - 2026-01-02: FP 低減のため、contextual>=0.5 の hard forcing を緩和し、
                「strong evidence（brand/dangerous_tld/idn_homograph/random/self_signed 等）」
                がある場合のみ phishing へ強制するよう変更。
                併せて free_ca/no_org(DV相当) を単独で決定要因にしないように
                R1/R2/R3/R4 を tighten。
                事後分析を容易にするため、発火した Phase6 ルール一覧を
                graph_state['phase6_rules_fired'] に保存。

  - 2026-01-02: v1.4.5-dvguard2b
      - Low-ML guard: ml<0.25 かつ {free_ca,no_org} だけで Phishing へ反転させない（dangerous_tld / brand は例外）
      - System Prompt: 'valid certificate' を安全・緩和理由として使うことを禁止（DV/Let's Encrypt は中立〜リスク）

  - 2026-01-03: v1.4.6-dvguard3
      - Post-LLM Flip Gate: ml<0.25 & non-dangerous TLD の LLM phishing 反転をブロック（FP止血）
      - System Prompt: 低ML帯の反転制約を明示（ポリシーゲートと整合）
      - graph_state: phase6_gate にゲート発動情報を stamp（後解析を容易に）


  - 2026-01-03: v1.4.7-dvguard4
      - Strong-evidence refinement: dv_suspicious_combo を単独で "strong" 扱いしない。
        random_pattern も単独では強証拠にせず、{short/very_short/dangerous_tld/idn_homograph 等} との複合でのみ強証拠扱い。
      - Post-Policy Gate: domain_issues が random_pattern のみ & brand無し の場合は、
        追加反転（Benign→Phishing）をブロックして FP を抑制（例: cryptpad.org のような誤反転）。

  - 2026-01-11: v1.4.8-mlparadox-tld
      - 全体: ctx_issues (contextual_risk_assessment) の dangerous_tld もチェックするよう統一。
        precheck/short_domain_analysis/contextual_risk_assessment の TLD リストが異なるため、
        どのツールが検出しても正しく処理されるように修正。
      - _has_strong_evidence: ctx_issues に dangerous_tld があれば強証拠として扱う。
      - LOW_ML_GUARD: ctx_issues の dangerous_tld もチェック。
      - R5: any_dangerous_tld (domain_issues | ctx_issues) を使用。
      - R6 (新規): ML Paradox + dangerous_tld + free_ca/no_org + ctx>=0.35 → Phishing。
      - POST_LLM_FLIP_GATE: ctx_issues の dangerous_tld もチェックしてゲート通過を許可。
      - dv_suspicious_combo: combined_issues (domain | ctx) の dangerous_tld もチェック。

既存方針:
  - no_org 単体で True になり得る経路は持たない（複合条件のみ）
  - decision_trace を graph_state に埋め込み、risk_factors に policyタグを追記
  - 既存の I/F / Strict モード / SO 必須の契約は維持
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple, Optional
import json

try:
    # Phase1 型/例外
    from .agent_foundations import (
        PhishingAssessment, StructuredOutputError, get_risk_level, clip_confidence
    )
except Exception:
    from agent_foundations import (
        PhishingAssessment, StructuredOutputError, get_risk_level, clip_confidence
    )


# ------------------------- phase6 meta -------------------------
PHASE6_POLICY_VERSION = "v1.6.0-fp-reduction-tuning"

# ------------------------- TLD classification (2026-01-14) -------------------------
# 高危険TLD: フィッシングに特に多用され、正規利用が少ないTLD
HIGH_DANGER_TLDS = frozenset([
    'tk', 'ml', 'ga', 'cf', 'gq',  # 無料TLD（フィッシング頻出）
    'icu', 'cfd', 'sbs', 'rest', 'cyou',  # フィッシング特化
    'pw', 'buzz', 'lat',  # 高フィッシング率
])

# 中危険TLD: フィッシングにも使われるが、正規ECサイト等でも使用されるTLD
MEDIUM_DANGER_TLDS = frozenset([
    'top', 'shop', 'xyz', 'cc', 'online', 'site', 'website',
    'club', 'vip', 'asia', 'one', 'link', 'click', 'live',
    'cn', 'tokyo', 'dev', 'me', 'pe', 'ar', 'cl', 'mw', 'ci',
])
# ------------------------- small utils -------------------------
def _json_dumps(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))

def _rs(tr: Dict[str, Any], key: str) -> float:
    try:
        v = (tr.get(key) or {}).get("risk_score", 0.0)
        return float(v or 0.0)
    except Exception:
        return 0.0

def _summarize_tool_signals(tool_results: Dict[str, Any]) -> Dict[str, Any]:
    tr = tool_results or {}
    out = {
        "brand": {
            "risk_score": _rs(tr, "brand"),
            "issues": list((tr.get("brand") or {}).get("detected_issues", []) or []),
            "brands": list(((tr.get("brand") or {}).get("details", {}) or {}).get("detected_brands", []) or []),
        },
        "cert": {
            "risk_score": _rs(tr, "cert"),
            "issues": list((tr.get("cert") or {}).get("detected_issues", []) or []),
            "details": dict((tr.get("cert") or {}).get("details", {}) or {}),
        },
        "domain": {
            "risk_score": _rs(tr, "domain"),
            "issues": list((tr.get("domain") or {}).get("detected_issues", []) or []),
            "details": dict((tr.get("domain") or {}).get("details", {}) or {}),
        },
        "contextual": {
            "risk_score": max(_rs(tr, "contextual_risk_assessment"), _rs(tr, "contextual")),
            "issues": list((tr.get("contextual_risk_assessment") or tr.get("contextual") or {}).get("detected_issues", []) or []),
        },
    }
    out["baseline_risk"] = max(out["contextual"]["risk_score"], out["brand"]["risk_score"], out["cert"]["risk_score"], out["domain"]["risk_score"])
    return out


# ---------------------- benign certificate gate (2026-01-12) ---------------------
def _apply_benign_cert_gate(
    asmt: PhishingAssessment,
    tool_summary: Dict[str, Any],
    *,
    ml_probability: Optional[float] = None,
    precheck: Optional[Dict[str, Any]] = None,
    trace: Optional[List[Dict[str, Any]]] = None,
) -> PhishingAssessment:
    """
    証明書の正規性シグナル（benign_indicators）に基づくゲート。
    Stage2で有効性が確認された証明書特徴量をStage3でも活用し、FPを削減。

    Gate B1: OV/EV証明書 + ctx < 0.50 → BENIGN強制
    Gate B2: CRL保有 + ml < 0.30 + ctx < 0.45 → BENIGN強制
    Gate B3: ワイルドカード + 非危険TLD + ctx < 0.40 → BENIGN強制
    Gate B4: 高SAN数 + 非危険TLD + ctx < 0.45 → BENIGN強制
    """
    tr = trace if isinstance(trace, list) else []
    ip = bool(getattr(asmt, "is_phishing", False))

    # Benignなら何もしない
    if not ip:
        return asmt

    tsum = tool_summary or {}
    cert_data = tsum.get("cert") or {}
    cert_details = cert_data.get("details") or {}

    # benign_indicators を取得（certificate_analysis.py で追加されたフィールド）
    benign_indicators = set(cert_details.get("benign_indicators", []) or [])
    if not benign_indicators:
        # 後方互換: benign_indicators がない場合は個別フラグをチェック
        if cert_details.get("has_org") or cert_details.get("has_ov_ev_like_identity"):
            benign_indicators.add("ov_ev_cert")
        if cert_details.get("has_crl_dp"):
            benign_indicators.add("has_crl_dp")
        if cert_details.get("is_wildcard") and not cert_details.get("is_dangerous_tld"):
            benign_indicators.add("wildcard_cert")
        if cert_details.get("is_long_validity"):
            benign_indicators.add("long_validity")
        if cert_details.get("is_high_san") and not cert_details.get("is_dangerous_tld"):
            benign_indicators.add("high_san_count")

    if not benign_indicators:
        return asmt

    ml = float(ml_probability or 0.0)
    pre = dict(precheck or {})
    tld_cat = pre.get("tld_category", "unknown")

    ctx = tsum.get("contextual") or {}
    ctx_score = float(ctx.get("risk_score", 0.0) or 0.0)

    # 強いリスクシグナルがある場合はゲートを適用しない
    # (brand_detected, self_signed, idn_homograph など)
    cert_issues = set(cert_data.get("issues", []) or [])
    brand_data = tsum.get("brand") or {}
    brand_detected = ("brand_detected" in set(brand_data.get("issues", []) or []))
    domain_issues = set((tsum.get("domain") or {}).get("issues", []) or [])

    # 強いリスクシグナルがあればゲートをスキップ
    strong_risk_signals = {
        "self_signed", "brand_detected", "idn_homograph",
        "high_entropy", "very_high_entropy", "random_with_high_tld_stat",
    }
    if (cert_issues | domain_issues) & strong_risk_signals:
        tr.append({
            "rule": "BENIGN_CERT_GATE_SKIP",
            "reason": "strong_risk_signals_present",
            "signals": list((cert_issues | domain_issues) & strong_risk_signals),
        })
        return asmt
    if brand_detected:
        tr.append({"rule": "BENIGN_CERT_GATE_SKIP", "reason": "brand_detected"})
        return asmt

    # 危険TLDの場合もゲートをスキップ（ワイルドカード/高SANのbenign効果を無効化）
    is_dangerous_tld = (tld_cat == "dangerous") or cert_details.get("is_dangerous_tld", False)

    c = clip_confidence(getattr(asmt, "confidence", 0.0))
    rl = getattr(asmt, "risk_level", "low") or "low"
    rf = list(getattr(asmt, "risk_factors", []) or [])
    reasoning = str(getattr(asmt, "reasoning", "") or "")

    gate_fired = None

    # Gate B1: OV/EV証明書
    # OV/EV証明書は発行に組織確認が必要 → フィッシングではまず使われない
    if "ov_ev_cert" in benign_indicators and ctx_score < 0.50:
        gate_fired = "B1_OV_EV"
        tr.append({
            "rule": "BENIGN_CERT_GATE_B1",
            "action": "force_benign",
            "indicator": "ov_ev_cert",
            "ctx_score": round(ctx_score, 4),
            "threshold": 0.50,
        })

    # Gate B2: CRL + 低リスク
    # CRL配布ポイントを持つ証明書は正規CAの厳格な発行プロセスを経ている
    elif "has_crl_dp" in benign_indicators and ml < 0.30 and ctx_score < 0.45:
        gate_fired = "B2_CRL"
        tr.append({
            "rule": "BENIGN_CERT_GATE_B2",
            "action": "force_benign",
            "indicator": "has_crl_dp",
            "ml": round(ml, 4),
            "ctx_score": round(ctx_score, 4),
            "thresholds": {"ml": 0.30, "ctx": 0.45},
        })

    # Gate B3: ワイルドカード + 非危険TLD
    # ワイルドカード証明書は正規運用（CDN、サブドメイン多数）で使用
    elif "wildcard_cert" in benign_indicators and not is_dangerous_tld and ctx_score < 0.40:
        gate_fired = "B3_WILDCARD"
        tr.append({
            "rule": "BENIGN_CERT_GATE_B3",
            "action": "force_benign",
            "indicator": "wildcard_cert",
            "tld_category": tld_cat,
            "ctx_score": round(ctx_score, 4),
            "threshold": 0.40,
        })

    # Gate B4: 多数のSAN + 非危険TLD
    # SAN数が多い証明書は正規の大規模サービス（CDN、SaaS）で使用
    # Handoff分析: FP Riskケースは平均SAN 13.2、低シグナルフィッシングは4.3
    elif "high_san_count" in benign_indicators and not is_dangerous_tld and ctx_score < 0.45:
        gate_fired = "B4_HIGH_SAN"
        tr.append({
            "rule": "BENIGN_CERT_GATE_B4",
            "action": "force_benign",
            "indicator": "high_san_count",
            "san_count": cert_details.get("san_count", 0),
            "tld_category": tld_cat,
            "ctx_score": round(ctx_score, 4),
            "threshold": 0.45,
        })

    # ゲートが発火した場合、BENIGNに強制
    if gate_fired:
        rf.append(f"benign_cert_gate:{gate_fired}")
        reasoning += f" | Benign Cert Gate {gate_fired}: protected by certificate indicators"

        return PhishingAssessment(
            is_phishing=False,
            confidence=max(0.75, c * 0.8),  # 高めの confidence で benign
            risk_level="low",
            detected_brands=list(getattr(asmt, "detected_brands", []) or []),
            risk_factors=rf,
            reasoning=reasoning,
        )

    return asmt


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
    Stage2で見逃されやすい低MLフィッシングを検出する。

    Gate P1: ブランド検出 + 短期証明書 + 低ML → PHISHING強制
    Gate P2: ブランド疑い + 短期証明書 + 低SAN + 低ML → PHISHING強制
    Gate P3: 危険TLD + 短期証明書 + 低SAN + 低ML + benign無し → risk bump
    """
    tr = trace if isinstance(trace, list) else []
    ip = bool(getattr(asmt, "is_phishing", False))

    # 既にPhishingなら何もしない
    if ip:
        return asmt

    tsum = tool_summary or {}
    pre = dict(precheck or {})
    ml = float(ml_probability or 0.0)

    # --- ブランド情報の取得 ---
    brand_data = tsum.get("brand") or {}
    brand_issues = set(brand_data.get("issues", []) or [])
    brand_details = brand_data.get("details") or {}

    brand_detected = "brand_detected" in brand_issues
    brand_suspected = "brand_suspected" in brand_issues or brand_details.get("brand_suspected", False)

    # --- 証明書情報の取得 ---
    cert_data = tsum.get("cert") or {}
    cert_details = cert_data.get("details") or {}
    cert_issues = set(cert_data.get("issues", []) or [])

    valid_days = int(cert_details.get("valid_days", 0) or 0)
    san_count = int(cert_details.get("san_count", 0) or 0)
    benign_indicators = set(cert_details.get("benign_indicators", []) or [])

    # 証明書情報がない場合はスキップ
    if valid_days <= 0:
        return asmt

    # --- TLD情報の取得 ---
    tld_cat = pre.get("tld_category", "unknown")
    domain_issues = set((tsum.get("domain") or {}).get("issues", []) or [])
    ctx_issues = set((tsum.get("contextual") or {}).get("issues", []) or [])

    is_dangerous_tld = (
        tld_cat == "dangerous"
        or "dangerous_tld" in domain_issues
        or "dangerous_tld" in ctx_issues
        or cert_details.get("is_dangerous_tld", False)
    )

    # --- benign_indicatorsがある場合はゲートをスキップ（FP防止） ---
    # ただしGate P1（強いブランド検出）は例外
    has_strong_benign = bool(benign_indicators & {"ov_ev_cert", "has_crl_dp"})

    c = clip_confidence(getattr(asmt, "confidence", 0.0))
    rl = getattr(asmt, "risk_level", "low") or "low"
    rf = list(getattr(asmt, "risk_factors", []) or [])
    reasoning = str(getattr(asmt, "reasoning", "") or "")

    gate_fired = None

    # Gate P1: ブランド検出 + 短期証明書（90日以下） + 低ML（<0.30）
    # 正規サイトがブランド名を含む場合、通常は長期証明書を使用
    # 低シグナルフィッシングの97.7%が短期証明書
    if (
        brand_detected
        and valid_days <= 90
        and ml < 0.30
        and not has_strong_benign  # OV/EV or CRL保有なら除外
    ):
        gate_fired = "P1_BRAND_SHORT_CERT"
        tr.append({
            "rule": "LOW_SIGNAL_PHISHING_GATE_P1",
            "action": "force_phishing",
            "brand_detected": True,
            "valid_days": valid_days,
            "ml": round(ml, 4),
            "thresholds": {"valid_days": 90, "ml": 0.30},
        })

    # Gate P2: ブランド疑い + 短期証明書 + 低SAN + 低ML
    # LLMで疑わしいと判定されたケースに証明書リスクを組み合わせ
    elif (
        brand_suspected
        and not brand_detected  # P1で処理済みでない
        and valid_days <= 90
        and san_count <= 5
        and ml < 0.25
        and not benign_indicators  # benign indicatorsがあればスキップ
    ):
        gate_fired = "P2_SUSPECTED_COMPOUND"
        tr.append({
            "rule": "LOW_SIGNAL_PHISHING_GATE_P2",
            "action": "force_phishing",
            "brand_suspected": True,
            "valid_days": valid_days,
            "san_count": san_count,
            "ml": round(ml, 4),
            "thresholds": {"valid_days": 90, "san_count": 5, "ml": 0.25},
        })

    # Gate P3: 危険TLD + 短期証明書 + 低SAN + 低ML + benign無し
    # ブランドがなくても危険TLD + 証明書特徴で疑いを高める
    elif (
        is_dangerous_tld
        and valid_days <= 90
        and san_count <= 3
        and ml < 0.20
        and not benign_indicators
    ):
        gate_fired = "P3_DANGEROUS_TLD_CERT"
        # P3はPHISHINGに強制せず、risk_levelをbumpするのみ
        tr.append({
            "rule": "LOW_SIGNAL_PHISHING_GATE_P3",
            "action": "risk_bump",
            "is_dangerous_tld": True,
            "valid_days": valid_days,
            "san_count": san_count,
            "ml": round(ml, 4),
            "thresholds": {"valid_days": 90, "san_count": 3, "ml": 0.20},
        })
        # P3はis_phishingを変えずにrisk_levelだけ上げる
        rl = _priority_bump(rl, "medium")
        rf.append(f"low_signal_phishing_gate:{gate_fired}")
        reasoning += f" | Low Signal Phishing Gate {gate_fired}: dangerous TLD + short cert + low SAN"

        return PhishingAssessment(
            is_phishing=False,  # P3はBenignのまま
            confidence=c,
            risk_level=rl,
            detected_brands=list(getattr(asmt, "detected_brands", []) or []),
            risk_factors=rf,
            reasoning=reasoning,
        )

    # P1またはP2が発火した場合、PHISHINGに強制
    if gate_fired and gate_fired.startswith("P1") or gate_fired and gate_fired.startswith("P2"):
        rf.append(f"low_signal_phishing_gate:{gate_fired}")
        reasoning += f" | Low Signal Phishing Gate {gate_fired}: brand + short cert indicates phishing"

        return PhishingAssessment(
            is_phishing=True,
            confidence=max(0.70, c),
            risk_level=_priority_bump(rl, "medium-high"),
            detected_brands=list(getattr(asmt, "detected_brands", []) or []),
            risk_factors=rf,
            reasoning=reasoning,
        )

    return asmt


def _priority_bump(current: str, minimum: str) -> str:
    order = ["low","medium","medium-high","high","critical"]
    try:
        return order[max(order.index(current or "low"), order.index(minimum or "low"))]
    except Exception:
        return minimum or current or "medium"

# ---------------------- policy adjustments ---------------------
def _apply_policy_adjustments(
    asmt: PhishingAssessment,
    tool_summary: Dict[str, Any],
    *,
    ml_probability: Optional[float] = None,
    precheck: Optional[Dict[str, Any]] = None,
    trace: Optional[List[Dict[str, Any]]] = None,
) -> PhishingAssessment:
    """
    仕様整合の最終補正 + Phase6ポリシールール（R1/R2/R3/R4/R5）。

    - ハード: contextual.risk_score >= 0.5 → True（維持）
    - ブランド×証明書の強連携は維持（brand_detected & {no_org, free_ca, no_cert}）
    - 旧: no_org 単体 → True の分岐は **持たない**

    追加（2025-12-14）:
      - R4: ML<0.5 かつ {free_ca,no_org} かつ contextual>=しきい値 → phishing
      - R5: ML<0.5 かつ dangerous_tld & no_org かつ contextual>=0.33 → phishing
    """
    tr = trace if isinstance(trace, list) else []
    c = clip_confidence(getattr(asmt, "confidence", 0.0))
    rl = getattr(asmt, "risk_level", "low") or "low"
    ip = bool(getattr(asmt, "is_phishing", False))
    reasoning_text = str(getattr(asmt, "reasoning", "") or "")

    # 低レベル補正
    if ip and rl == "low":
        rl = "medium"; tr.append({"rule":"low_to_min_medium","why":"is_phishing=True & level=low"})

    # ---- extract signals ----
    tsum = tool_summary or {}
    b_issues = set((tsum.get("brand") or {}).get("issues", []) or [])
    b_names  = set((tsum.get("brand") or {}).get("brands", []) or [])
    brand_detected = ("brand_detected" in b_issues) or bool(b_names)

    cert_issues = set((tsum.get("cert") or {}).get("issues", []) or [])
    domain_issues = set((tsum.get("domain") or {}).get("issues", []) or [])
    ctx = (tsum.get("contextual") or {})
    ctx_score = float(ctx.get("risk_score", 0.0) or 0.0)
    ctx_issues = set(ctx.get("issues", []) or [])

    ml = float(ml_probability or 0.0)
    pre = dict(precheck or {})
    tld_cat = pre.get("tld_category")
    dom_len = pre.get("domain_length_category")

    # ---- brand × cert （維持） ----
    if brand_detected and ({"no_cert","no_org","free_ca"} & cert_issues):
        ip = True
        c = max(c, 0.70)
        rl = _priority_bump(rl, "high")
        tr.append({"rule":"brand_cert_high","ip":True,"c_min":0.70})

    # ---- contextual thresholds (FP-safe) ----
    # NOTE(2026-01-02): ctx>=0.5 を無条件で phishing にすると、DV相当(=free_ca/no_org)
    # や軽いドメイン特徴だけで 0.5 を超えた benign を大量に誤検知しやすい。
    #   - ctx>=0.65 は hard trigger
    #   - 0.50<=ctx<0.65 は "strong evidence" がある場合のみ trigger
    HARD_CTX = 0.65
    SOFT_CTX = 0.50

    _strong_domain = {
        "dangerous_tld",
        "idn_homograph",
        "high_entropy",
        "very_high_entropy",
        "short_random_combo",
        "random_with_high_tld_stat",
        "very_short_dangerous_combo",
        "deep_chain_with_risky_tld",
    }
    _strong_cert = {
        "self_signed",
        "dv_multi_risk_combo",
    }
    _strong_ctx = {
        "ml_paradox",
        "ml_paradox_medium",
    }

    def _has_strong_evidence() -> bool:
        # Brand is always strong (but brand tool itself should aim for high precision).
        if brand_detected:
            return True

        # Domain strong evidence (excluding random_pattern-only which is too noisy).
        if domain_issues & _strong_domain:
            return True

        # 2026-01-11: contextual_risk_assessment が dangerous_tld を検出した場合も強証拠
        # (short_domain_analysis のTLDリストとは異なるTLDを検出している場合がある)
        if "dangerous_tld" in ctx_issues:
            return True

        # random_pattern becomes "strong" only when combined with other domain red flags.
        # (random_pattern-only は誤検知が多い: cryptpad.org など)
        if "random_pattern" in domain_issues:
            if domain_issues & {
                "short",
                "very_short",
                "dangerous_tld",
                "idn_homograph",
                "high_entropy",
                "very_high_entropy",
                "short_random_combo",
                "very_short_dangerous_combo",
                "deep_chain_with_risky_tld",
                "random_with_high_tld_stat",
            }:
                return True

        # Cert strong evidence (rare; DV/NoOrg alone is NOT strong).
        if cert_issues & _strong_cert:
            return True

        # Context strong evidence: paradox flags are meaningful; dv_suspicious_combo alone is not.
        if ctx_issues & _strong_ctx:
            return True

        # dv_suspicious_combo は単体では弱いが、ドメイン側の強シグナルと組み合わせると強証拠として扱う
        # 2026-01-11: ctx_issues の dangerous_tld もチェック
        combined_issues = domain_issues | ctx_issues
        if ("dv_suspicious_combo" in ctx_issues) and (combined_issues & {
            "dangerous_tld",
            "short",
            "very_short",
            "idn_homograph",
            "high_entropy",
            "very_high_entropy",
            "short_random_combo",
            "very_short_dangerous_combo",
            "deep_chain_with_risky_tld",
        }):
            return True

        return False

    strong_evidence = _has_strong_evidence()

    # hard trigger
    if ctx_score >= HARD_CTX:
        if not ip:
            tr.append({"rule":"hard_ctx_ge_0.65","ip":True,"ctx":ctx_score})
        ip = True
        rl = _priority_bump(rl, "high")
        c = max(c, ctx_score, HARD_CTX)

    # soft trigger (requires strong evidence)
    elif (ctx_score >= SOFT_CTX) and strong_evidence:
        if not ip:
            tr.append({"rule":"ctx_ge_0.50_with_strong_evidence","ip":True,"ctx":ctx_score})
        ip = True
        rl = _priority_bump(rl, "medium-high")
        c = max(c, ctx_score, SOFT_CTX)

    else:
        # ---- Phase6 tightened rules (R1/R2/R3/R4/R5/R6) ----
        # Low-ML guard (2026-01-02):
        # - ml が強く安全（<0.25）と出ているとき、DV系証明書（free_ca+no_org）だけで
        #   Phishing に反転させると FP が急増する（stage2_handoff で顕著）。
        # - dangerous_tld や brand など「独立した強い根拠」が無い限り、R1/R2/R4 系の反転は抑止する。
        # - 2026-01-11: ctx_issues の dangerous_tld もチェック (contextual_risk_assessment が検出)
        # - 2026-01-11: cert_issues と ctx_issues を統合してチェック (free_ca/no_org は両方に出る可能性)
        any_dangerous_tld = ("dangerous_tld" in domain_issues) or ("dangerous_tld" in ctx_issues)
        all_cert_ctx_issues = cert_issues | ctx_issues  # 証明書関連の issue を統合
        has_dv_issues = ("free_ca" in all_cert_ctx_issues) and ("no_org" in all_cert_ctx_issues)
        low_ml_guard = (
            (ml < 0.25)
            and has_dv_issues
            and (not any_dangerous_tld)
            and (not brand_detected)
        )
        if low_ml_guard:
            tr.append({
                "rule": "LOW_ML_GUARD",
                "note": "skip DV-only overrides when ml<0.25 (unless dangerous_tld/brand)",
                "ml": round(ml, 4),
                "ctx_score": round(ctx_score, 4),
                "tld_category": tld_cat,
                "domain_length_category": dom_len,
            })

        # guard: legitimate TLD & long/normal length → R1 しきい値を引き上げ
        r1_th = 0.28
        if (tld_cat == "legitimate") and (dom_len in ("normal","long")) and (not any_dangerous_tld):
            r1_th = 0.34
            tr.append({"note":"legit_tld_guard","r1_threshold":r1_th})

        # R1: very_low-ML + free_ca & no_org + 中強度ctx
        # NOTE(2026-01-02): DV相当(free_ca/no_org)だけで True にしない。必ず strong evidence を要求。
        # NOTE(2026-01-11): cert_issues | ctx_issues を使用
        if (ml < 0.20) and has_dv_issues and (ctx_score >= r1_th) and strong_evidence and (not low_ml_guard):
            ip = True
            rl = _priority_bump(rl, "medium-high")
            c = max(c, ctx_score, 0.55)
            tr.append({"rule":"R1","ml":ml,"ctx":ctx_score,"req":["ml<0.2","free_ca&no_org","ctx>=%.2f"%r1_th]})

        # R2: low-ML + no_org + (free_ca or short) + ctx>=0.34
        # NOTE(2026-01-02): short/no_org/free_ca は benign でも頻出 → strong evidence を要求。
        # NOTE(2026-01-11): cert_issues | ctx_issues を使用
        elif (ml < 0.30) and ("no_org" in all_cert_ctx_issues) and (("free_ca" in all_cert_ctx_issues) or (("short" in domain_issues) or ("very_short" in domain_issues))) and (ctx_score >= 0.34) and strong_evidence:
            ip = True
            rl = _priority_bump(rl, "medium-high")
            c = max(c, ctx_score, 0.55)
            tr.append({"rule":"R2","ml":ml,"ctx":ctx_score})

        # R3: <0.40 + short + no_org + ctx>=0.36
        # NOTE(2026-01-02): short/no_org は単独では弱い → strong evidence を要求。
        # NOTE(2026-01-11): cert_issues | ctx_issues を使用
        elif (ml < 0.40) and ("no_org" in all_cert_ctx_issues) and (("short" in domain_issues) or ("very_short" in domain_issues)) and (ctx_score >= 0.36) and strong_evidence:
            ip = True
            rl = _priority_bump(rl, "medium-high")
            c = max(c, ctx_score, 0.55)
            tr.append({"rule":"R3","ml":ml,"ctx":ctx_score})

        # R4: <0.50 + free_ca & no_org + ctx>=th
        # - 目的: ML が 0.30〜0.50 帯に張り付く FN を救済
        # - 副作用: Let's Encrypt + no_org が一般サイトでも多いので、
        #           legitimate TLD かつ normal/long は少しだけ厳しめにする。
        # - 2025-12-15: 500件検証で「ctx=0.34〜0.35 & multiple_risk_factors」のFNがまとまって発生したため、
        #              legitimate TLD & normal/long でも multiple_risk_factors がある場合は 0.33 を許容。
        # NOTE(2026-01-11): cert_issues | ctx_issues を使用
        elif (ml < 0.50) and has_dv_issues and strong_evidence:
            r4_th = 0.34
            if (tld_cat == "legitimate") and (dom_len in ("normal", "long")) and (not any_dangerous_tld):
                # default guard
                r4_th = 0.35
                # relax if contextual already sees multiple supporting risk factors
                if "multiple_risk_factors" in ctx_issues:
                    r4_th = 0.33
                    tr.append({"note":"legit_tld_guard_r4_relaxed_mrf","r4_threshold":r4_th})
                else:
                    tr.append({"note":"legit_tld_guard_r4","r4_threshold":r4_th})
            if ctx_score >= r4_th:
                ip = True
                rl = _priority_bump(rl, "medium-high")
                c = max(c, ctx_score, 0.55)
                tr.append({"rule":"R4","ml":ml,"ctx":ctx_score,"th":r4_th})

        # R5: <0.50 + dangerous_tld + no_org + ctx>=0.33
        # - free_ca が無くても「危険TLD × DVっぽい（no_org）」は強めに扱う
        # - 2026-01-11: ctx_issues の dangerous_tld および no_org もチェック
        elif (ml < 0.50) and any_dangerous_tld and ("no_org" in all_cert_ctx_issues) and (ctx_score >= 0.33):
            ip = True
            rl = _priority_bump(rl, "medium-high")
            c = max(c, ctx_score, 0.55)
            tr.append({"rule":"R5","ml":ml,"ctx":ctx_score,"dangerous_tld_source":"domain_or_ctx"})

        # R6: ML Paradox + dangerous_tld + medium risk (2026-01-11)
        # - Stage1が安全(ml<0.3)だがStage2/contextualがリスクを検出(ctx>=0.35)
        # - dangerous_tld + free_ca/no_org の組み合わせで Phishing 判定
        elif (ml < 0.30) and any_dangerous_tld and has_dv_issues and (ctx_score >= 0.35):
            ip = True
            rl = _priority_bump(rl, "medium-high")
            c = max(c, ctx_score, 0.55)
            tr.append({"rule":"R6_ML_PARADOX_TLD","ml":ml,"ctx":ctx_score})

    # ---- Over-mitigation guard (FN-safe, updated 2026-01-14) ----
    # NOTE(2026-01-02): When ML is already in the phishing range (>=0.50),
    # do NOT flip to benign unless the domain is strongly allowlisted.
    # NOTE(2026-01-14): FP削減のため、以下の条件を緩和:
    #   - ml >= 0.60 に閾値を引き上げ（0.50-0.60帯のFPを削減）
    #   - 証明書のbenign indicatorsがある場合は強制しない
    #   - 非危険TLDで contextual score < 0.45 の場合は強制しない
    is_allowlisted = False
    try:
        dom_details = dict((tsum.get("domain") or {}).get("details", {}) or {})
        lc = dict(dom_details.get("legitimate_check", {}) or {})
        is_allowlisted = bool(lc.get("is_legitimate")) and float(lc.get("confidence", 0.0) or 0.0) >= 0.95
    except Exception:
        is_allowlisted = False

    # 証明書のbenign indicatorsをチェック
    cert_benign_indicators = set()
    try:
        cert_details = (tsum.get("cert") or {}).get("details", {}) or {}
        cert_benign_indicators = set(cert_details.get("benign_indicators", []) or [])
    except Exception:
        pass
    has_strong_benign_cert = bool(cert_benign_indicators & {"ov_ev_cert", "has_crl_dp"})

    # TLD suffix を取得（POST_LLM_FLIP_GATE と共通）
    try:
        tld_suffix_for_ml_guard = pre.get("etld1", {}).get("suffix", "") or ""
        tld_suffix_for_ml_guard = tld_suffix_for_ml_guard.lower().strip(".")
    except Exception:
        tld_suffix_for_ml_guard = ""

    is_non_dangerous_tld = (
        tld_suffix_for_ml_guard not in HIGH_DANGER_TLDS
        and tld_suffix_for_ml_guard not in MEDIUM_DANGER_TLDS
        and tld_cat != "dangerous"
    )

    # 強制PHISHINGの条件（2026-01-15再調整）
    # NOTE: 0.60に引き上げたことで0.50-0.60帯のフィッシングが見逃された
    # → 0.50に戻しつつ、証明書benign indicatorsのみで緩和
    ML_FORCE_PHISHING_TH = 0.50  # 0.60 → 0.50 に戻す
    should_force_phishing = (
        (ml >= ML_FORCE_PHISHING_TH)
        and (not ip)
        and (not is_allowlisted)
        and (not has_strong_benign_cert)  # OV/EV/CRL証明書は除外
    )
    # 非危険TLDで contextual score が非常に低い場合のみスキップ
    if should_force_phishing and is_non_dangerous_tld and ctx_score < 0.30:
        should_force_phishing = False
        tr.append({
            "rule": "ml_ge_0.50_skipped",
            "reason": "non_dangerous_tld_very_low_ctx",
            "ml": round(ml, 4),
            "ctx_score": round(ctx_score, 4),
            "tld_suffix": tld_suffix_for_ml_guard,
        })

    if should_force_phishing:
        ip = True
        rl = _priority_bump(rl, "medium-high")
        c = max(c, ml, 0.55)
        tr.append({"rule":"ml_ge_0.50_no_mitigation","ml":ml,"allowlisted":False,"has_strong_benign_cert":has_strong_benign_cert})

    # Post-LLM Flip Gate (2026-01-03, updated 2026-01-14):
    # - LLM が is_phishing=true を返しても、ML が低い場合は弱い根拠での反転を抑止する。
    # - 2026-01-14: TLDを「高危険」「中危険」に分類し、中危険TLDでもFPを削減できるよう改善
    #   - 高危険TLD (tk, ml, ga, cf, gq等): ゲートをバイパス（従来通り）
    #   - 中危険TLD (top, shop, xyz等): ml < 0.20 の場合のみブロック
    #   - 非危険TLD: ml < 0.35 の場合ブロック（閾値引き上げ）

    # TLD suffix を取得
    try:
        tld_suffix = pre.get("etld1", {}).get("suffix", "") or ""
        tld_suffix = tld_suffix.lower().strip(".")
    except Exception:
        tld_suffix = ""

    # TLD危険度を判定
    is_high_danger_tld = (tld_suffix in HIGH_DANGER_TLDS)
    is_medium_danger_tld = (tld_suffix in MEDIUM_DANGER_TLDS)
    has_dangerous_tld_signal = (
        ("dangerous_tld" in domain_issues)
        or ("dangerous_tld" in ctx_issues)
        or (tld_cat == "dangerous")
    )

    # 閾値の決定（TLD危険度に応じて）
    # NOTE(2026-01-15): 3000件評価の結果を受けて閾値を再調整
    #   - 高危険TLD: ゲート無効化（フィッシング検出を最優先）
    #   - 中危険TLD: 0.04（バランス重視）
    #   - 非危険TLD: 0.15（Recall重視、FP削減は控えめに）
    # 前回の問題: 非危険TLD 0.25 が厳しすぎて .com フィッシングを見逃し
    if is_high_danger_tld:
        LOW_ML_FLIP_GATE_TH = 0.0  # 高危険TLDはゲート無効化
    elif is_medium_danger_tld:
        LOW_ML_FLIP_GATE_TH = 0.04  # 中危険TLDはバランス重視
    else:
        LOW_ML_FLIP_GATE_TH = 0.15  # 非危険TLDはRecall重視

    # ゲート適用判定
    should_block = ip and (ml < LOW_ML_FLIP_GATE_TH)
    # 高危険TLDの場合は従来通りの判定（has_dangerous_tld_signal でバイパス）
    if is_high_danger_tld and has_dangerous_tld_signal:
        should_block = False

    if should_block:
        ip = False
        # 反転ブロック時は「安全」だが警戒は残す（confidence を過大にしない）
        c = max(min(c, 0.70), 0.55)
        rl = "medium"
        try:
            reasoning_text = (reasoning_text + f" | Phase6 gate: blocked low-ML flip (ml={ml:.3f} < {LOW_ML_FLIP_GATE_TH}, tld={tld_suffix}, danger_level={'high' if is_high_danger_tld else 'medium' if is_medium_danger_tld else 'low'})")
        except Exception:
            pass
        tr.append({
            "rule": "POST_LLM_FLIP_GATE",
            "action": "block_low_ml_llm_phishing",
            "ml": round(ml, 4),
            "tld_category": tld_cat,
            "tld_suffix": tld_suffix,
            "tld_danger_level": "high" if is_high_danger_tld else "medium" if is_medium_danger_tld else "low",
            "has_dangerous_tld_signal": has_dangerous_tld_signal,
            "threshold": LOW_ML_FLIP_GATE_TH,
        })

    # ------------------------------------------------------------------
    # Post-Policy flip gate (dvguard4):
    # - domain_issues が random_pattern のみ の場合は、誤反転（FP）が多い。
    #   brand が無い限り、Benign→Phishing の追加反転をブロックする。
    #   (例: cryptpad.org など)
    # ------------------------------------------------------------------
    if ip:
        try:
            _domain_issues_list = list(domain_issues or [])
            _random_only = ("random_pattern" in _domain_issues_list) and (len(_domain_issues_list) == 1)
        except Exception:
            _random_only = False
        if _random_only and (not brand_detected) and (tld_cat in {"legitimate", "neutral", "unknown", ""}):
            ip = False
            c = min(c, 0.35)
            rl = "low"
            try:
                reasoning_text = (reasoning_text + " | Phase6 gate: blocked random_pattern-only flip (dvguard4)")
            except Exception:
                pass
            tr.append({
                "rule": "POST_RANDOM_PATTERN_ONLY_GATE",
                "action": "block_random_pattern_only_flip",
                "ml": round(ml, 4),
                "tld_category": tld_cat,
                "domain_issues": _domain_issues_list,
            })

    # final clip + external risk level
    c = clip_confidence(c)
    try:
        rl_calc = get_risk_level(confidence=c, is_phishing=ip)  # Phase1 I/F
    except TypeError:
        rl_calc = get_risk_level(c)  # fallback
    rl = _priority_bump(rl, rl_calc)

    # risk_factors に policyタグを足しておく（デバッグ用）
    rf = list(getattr(asmt, "risk_factors", []) or [])
    for t in tr:
        if "rule" in t:
            rf.append(f"policy:{t['rule']}")
    asmt = PhishingAssessment(
        is_phishing=ip,
        confidence=c,
        risk_level=rl,
        detected_brands=list(getattr(asmt, "detected_brands", []) or []),
        risk_factors=rf,
        reasoning=reasoning_text,
    )
    return asmt

# -------------------------- public API --------------------------

from enum import Enum
from pydantic import Field, field_validator

class ReasoningCategory(str, Enum):
    """最終判定の主な理由カテゴリ（事後分析用）"""
    SAFE_OFFICIAL_BRAND = "safe_official_brand"       # 正規ブランド公式サイト
    SAFE_GENERIC_CONTENT = "safe_generic_content"     # 一般的な個人・中小企業サイト（フィッシング要素なし）
    SAFE_PARKED_DOMAIN = "safe_parked_domain"         # ドメインパーキング（脅威なし）
    PHISHING_IMPERSONATION = "phishing_impersonation" # ブランドなりすまし
    PHISHING_CREDENTIALS = "phishing_credentials"     # 資格情報（ログイン情報）詐取
    SUSPICIOUS_DGA_DOMAIN = "suspicious_dga_domain"   # DGA と思われるランダムドメイン
    SUSPICIOUS_TLD_COMBO = "suspicious_tld_combo"     # 危険TLD × 無料証明書 × コンテンツ薄
    MALWARE_DISTRIBUTION = "malware_distribution"     # マルウェア配布の疑い

class PhishingAssessmentSO(PhishingAssessment):
    """Phase6 Structured Output schema (PhishingAssessment 拡張版)

    - primary_category: 最終判定に至った主な理由カテゴリ（ReasoningCategory）
    - mitigated_risk_factors: 「認識しているが無視したリスク要因」
      例: dangerous_tld は検知したが、正規ブランド公式サイトなので安全とみなした場合など
    """
    primary_category: ReasoningCategory = Field(
        default=ReasoningCategory.SAFE_GENERIC_CONTENT,
        description="最終判定に至った最も主要な理由カテゴリ",
    )
    mitigated_risk_factors: list[str] = Field(
        default_factory=list,
        description=(
            "リスク要因として検知したが、文脈から『安全・許容範囲』と判断して"
            "最終判定では採用しなかった要素。"
        ),
    )

    @field_validator("mitigated_risk_factors")
    @classmethod
    def _normalize_mitigated(cls, v: list[str]) -> list[str]:
        out: list[str] = []
        seen: set[str] = set()
        for item in v or []:
            s = (item or "").strip()
            if not s:
                continue
            if s not in seen:
                seen.add(s)
                out.append(s)
        return out


def final_decision(
    llm,
    domain: str,
    ml_probability: float,
    tool_results: dict[str, object],
    graph_state: dict[str, object],
    strict_mode: bool = False,
) -> PhishingAssessment:
    """Phase6 最終判定（SO必須）

    - LangChain の with_structured_output で PhishingAssessmentSO を取得
    - ML/ツール結果/事前チェックの矛盾を _apply_policy_adjustments で補正
    - mitigated_risk_factors を risk_factors にタグとして埋め込み
    - decision_trace と LLM の思考過程を graph_state に保存
    """
    # 0) Traceability: Phase6 policy version stamp
    #    - 解析CSV側で phase6_policy_version を確実に参照できるように、
    #      LLM 呼び出し前に graph_state へ書き込む（Strict/SO失敗でも残る）。
    try:
        if isinstance(graph_state, dict):
            graph_state.setdefault("phase6_policy_version", PHASE6_POLICY_VERSION)
    except Exception:
        pass

    # 1) シグナル集約
    tsum = _summarize_tool_signals(tool_results or {})

    ml = float(ml_probability or 0.0)
    if   ml < 0.2: ml_category = "very_low"
    elif ml < 0.4: ml_category = "low"
    elif ml < 0.6: ml_category = "medium"
    elif ml < 0.8: ml_category = "high"
    else:          ml_category = "very_high"

    ctx_score = float((tsum.get("contextual") or {}).get("risk_score", 0.0) or 0.0)
    ml_paradox = (ml < 0.3 and ctx_score >= 0.5)

    pre: dict[str, object] = {}
    if isinstance(graph_state, dict):
        pre = dict(graph_state.get("precheck_hints", {}) or {})

    # 2) LLM へのプロンプト構築
    system_text = (
        "You are an expert AI analyst specializing in cybersecurity and phishing detection.\n"
        "Using the given ML score and the outputs of the analysis tools, decide whether this domain is phishing or not.\n"
        "\n"
        "You MUST output ONLY JSON that conforms to the Pydantic schema PhishingAssessmentSO:\n"
        "- is_phishing: bool\n"
        "- confidence: float between 0.0 and 1.0 (use a smaller value when you are uncertain)\n"
        "- risk_level: one of ['low','medium','medium-high','high','critical']\n"
        "- detected_brands: list of detected brand names (empty if none)\n"
        "- risk_factors: risk factors that you treat as ACTIVE evidence for the final decision\n"
        "    (for example: dangerous_tld, free_ca, no_org, ml_paradox, etc.)\n"
        "- primary_category: choose exactly one value from ReasoningCategory\n"
        "- mitigated_risk_factors: risk factors that you detected but decided to treat as\n"
        "    safe/acceptable in the final decision\n"
        "- reasoning: at least 50 characters explaining why you chose the value of is_phishing\n"
        "    and why you decided that the mitigated_risk_factors can be ignored in the final\n"
        "    decision.\n"
        "\n"
        "Important rules:\n"
        "1. Domains that look like random strings (high entropy / very few vowels) can be risky,\n"
        "   but do NOT treat a single weak heuristic like random_pattern alone as sufficient\n"
        "   for is_phishing=true. Require corroborating signals (e.g., short+random, dangerous_tld,\n"
        "   brand impersonation, idn_homograph, etc.).\n"
        "2. The absence of brand elements does NOT automatically mean the site is safe. When a\n"
        "   dangerous TLD (.icu, .xyz, .top, etc.) is combined with free_ca and no_org, treat\n"
        "   this as a strong risk signal even without any brand element.\n"
        "3. Do NOT set is_phishing=true based on ml_probability alone. If you decide phishing, include at least one\n"
        "   non-ML risk_factors that appear in tool_signals.*.issues.\n"
        "4. When contextual_risk_assessment.risk_score >= 0.65, you MUST set is_phishing=true.\n"
        "   When 0.50 <= contextual_risk_assessment.risk_score < 0.65, set is_phishing=true ONLY if\n"
        "   there is at least one strong non-ML signal (e.g., brand_detected, dangerous_tld, idn_homograph,\n"
        "   random_pattern/high_entropy, self_signed, dv_multi_risk_combo, dv_suspicious_combo, ml_paradox).\n"
        "5. contextual_risk_assessment.risk_score < 0.50 does NOT imply the site is safe. It only means it is not an automatic trigger.\n"
        "6. If you decide is_phishing=false even though there are strong risk signals such as\n"
        "   dangerous_tld, free_ca, no_org, or ml_paradox, you MUST put those signals into\n"
        "   mitigated_risk_factors (not risk_factors) and clearly explain in reasoning why the\n"
        "   site is still considered safe.\n"
        "7. For both risk_factors and mitigated_risk_factors, prefer to use the short\n"
        "   identifiers that appear in tool_signals.*.issues (for example: dangerous_tld,\n"
        "   free_ca, brand_detected, high_entropy, etc.).\n"
        "8. A \"valid\" SSL certificate (especially DV / Let\'s Encrypt) is NOT a mitigating factor.\n"
        "   Phishing sites commonly use valid DV certificates. Do NOT cite \"valid certificate\" as a reason for safety or mitigation.\n"
        "   Treat DV/Let\'s Encrypt as neutral-to-risk unless there is strong identity evidence (e.g., OV/EV with org).\n"
        "9. When ml_probability < 0.25 and precheck_summary.tld_category is not 'dangerous', be VERY conservative about setting is_phishing=true.\n"
        "   Only set is_phishing=true if there is clear independent evidence (e.g., strong brand impersonation).\n"
        "   Otherwise set is_phishing=false and place any detected risk signals into mitigated_risk_factors.\n"
    )

    user_payload = {
        "domain": domain,
        "ml_probability": ml,
        "ml_category": ml_category,
        "ml_paradox_hint": ml_paradox,
        "tool_signals": tsum,
        "precheck_summary": {
            "tld_category": pre.get("tld_category"),
            "quick_risk": pre.get("quick_risk"),
            "potential_brands": pre.get("potential_brands", []),
            "ml_paradox_hint": pre.get("ml_paradox", False),
        },
        "policy": {
            "use_contextual_as_primary": True,
            "brand_plus_cert_elevate": True,
        },
    }

    messages = [
        {"role": "system", "content": system_text},
        {"role": "user", "content": _json_dumps(user_payload)},
    ]

    trace: list[dict[str, object]] = []
    trace.append({
        "phase6_version": PHASE6_POLICY_VERSION,
        "ml": ml,
        "ml_category": ml_category,
        "ctx_score": ctx_score,
        "ml_paradox": ml_paradox,
    })

    # 3) Structured Output 呼び出し
    if not hasattr(llm, "with_structured_output"):
        # LLM 側が SO 非対応の場合は即座に例外（StrictMode の扱いは呼び出し側）
        raise StructuredOutputError(
            "LLM does not support with_structured_output",
            domain=domain,
            ml_probability=ml,
            step="final_decision",
        )

    try:
        chain = llm.with_structured_output(PhishingAssessmentSO)
        asmt_so: PhishingAssessmentSO = chain.invoke(messages)
        trace.append({
            "step": "llm_raw_output",
            "assessment": asmt_so.model_dump(),
        })

        # 4) ポリシー補正（R1/R2/R3/R4/R5 を適用）
        asmt2 = _apply_policy_adjustments(
            asmt_so,
            tsum,
            ml_probability=ml,
            precheck=pre,
            trace=trace,
        )

        # 5) mitigated_risk_factors を risk_factors にタグとして反映
        mitigated = list(getattr(asmt_so, "mitigated_risk_factors", []) or [])
        if mitigated:
            rf = list(getattr(asmt2, "risk_factors", []) or [])
            for f in mitigated:
                tag = f"mitigated:{f}"
                if tag not in rf:
                    rf.append(tag)
            asmt2 = PhishingAssessment(
                is_phishing=asmt2.is_phishing,
                confidence=asmt2.confidence,
                risk_level=asmt2.risk_level,
                detected_brands=list(asmt2.detected_brands or []),
                risk_factors=rf,
                reasoning=asmt2.reasoning,
            )

        # 5b) Benign Certificate Gate (2026-01-12)
        # 証明書の正規性シグナルに基づいてFPを防止
        asmt2 = _apply_benign_cert_gate(
            asmt2,
            tsum,
            ml_probability=ml,
            precheck=pre,
            trace=trace,
        )

        # 5c) Low Signal Phishing Gate (2026-01-12)
        # 低シグナルフィッシング（ブランド偽装 + 短期証明書）を検出
        asmt2 = _apply_low_signal_phishing_gate(
            asmt2,
            tsum,
            ml_probability=ml,
            precheck=pre,
            trace=trace,
        )

        # 6) graph_state へのトレース保存
        try:
            if isinstance(graph_state, dict):
                graph_state["phase6_policy_version"] = PHASE6_POLICY_VERSION

                # 事後分析用: 発火した policy rule をフラットに保存（CSV展開を楽にする）
                rules_fired: list[str] = []
                for t in trace:
                    if isinstance(t, dict) and t.get("rule"):
                        r = str(t.get("rule"))
                        if r not in rules_fired:
                            rules_fired.append(r)
                graph_state["phase6_rules_fired"] = rules_fired

                # Post-LLM gate info stamp (CSV-friendly)
                try:
                    gate = None
                    for t in trace:
                        if isinstance(t, dict) and t.get("rule") == "POST_LLM_FLIP_GATE":
                            gate = dict(t)
                            break
                    if gate:
                        graph_state["phase6_gate"] = gate
                except Exception:
                    pass

                # Benign Certificate Gate info stamp (2026-01-12)
                try:
                    benign_gate = None
                    for t in trace:
                        if isinstance(t, dict) and str(t.get("rule", "")).startswith("BENIGN_CERT_GATE_B"):
                            benign_gate = dict(t)
                            break
                    if benign_gate:
                        graph_state["benign_cert_gate"] = benign_gate
                except Exception:
                    pass

                # Low Signal Phishing Gate info stamp (2026-01-12)
                try:
                    low_signal_gate = None
                    for t in trace:
                        if isinstance(t, dict) and str(t.get("rule", "")).startswith("LOW_SIGNAL_PHISHING_GATE"):
                            low_signal_gate = dict(t)
                            break
                    if low_signal_gate:
                        graph_state["low_signal_phishing_gate"] = low_signal_gate
                except Exception:
                    pass

                dt = list(graph_state.get("decision_trace", []) or [])
                dt.append({
                    "phase6_version": PHASE6_POLICY_VERSION,
                    "domain": domain,
                    "ml": ml,
                    "ml_category": ml_category,
                    "ctx_score": ctx_score,
                    "tool_summary": tsum,
                    "ml_paradox": ml_paradox,
                    "llm_primary_category": str(getattr(asmt_so, "primary_category", "")),
                    "llm_mitigated_risk_factors": mitigated,
                    "llm_risk_factors": list(getattr(asmt_so, "risk_factors", []) or []),
                    "policy_rules_fired": rules_fired,
                    "policy_trace": trace,
                })
                graph_state["decision_trace"] = dt
        except Exception:
            # トレース保存はベストエフォート
            pass

        return asmt2

    except Exception as e:
        # 7) SO失敗時の扱い
        if strict_mode:
            # Strict=True の場合はそのまま例外を投げる
            raise StructuredOutputError(
                f"Phase6 final_decision SO failed: {e}",
                domain=domain,
                ml_probability=ml,
                step="final_decision",
                original_error=str(e),
            )

        # Strict=False: 安全側フォールバック（既存仕様と互換）
        try:
            if isinstance(graph_state, dict):
                locs = list(graph_state.get("fallback_locations", []) or [])
                locs.append("final_decision")
                graph_state["fallback_locations"] = locs
        except Exception:
            pass

        return PhishingAssessment(
            is_phishing=False,
            confidence=0.0,
            risk_level="low",
            detected_brands=[],
            risk_factors=[],
            reasoning="Structured Output not available; safe fallback (Phase6).",
        )

