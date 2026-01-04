# phishing_agent/tools/contextual_risk_assessment.py
from __future__ import annotations
# ---------------------------------------------------------------------
# Change history
# - 2026-01-02: Added score_components (score breakdown) for log export.
#              Refined ML paradox logic to avoid treating only {free_ca,no_org}
#              as an automatic strong paradox (FP reduction).
#              Expanded low-ML safety cap to p<0.2 with dangerous_tld guard.
# - 2026-01-02: Reworked multiple_risk_factors bonus to be category-based
#              (brand/cert/domain) instead of raw issue-count. This prevents
#              DV-like certificate signals (free_ca/no_org) alone from
#              artificially inflating the contextual score and causing FP.
# ---------------------------------------------------------------------
from typing import Any, Dict, List, Optional

from ..tools_module import safe_tool_wrapper, _ET, _tokenize_domain_labels

# Legitimate-domain helper (best effort).
# NOTE: known_domains passed from external data is sometimes a large "seen set".
# We must NOT treat it as a whitelist. Mitigation should apply only when the
# domain is strongly verified as legitimate (strict allowlist).
try:
    from .legitimate_domains import is_legitimate_domain  # type: ignore
except Exception:  # pragma: no cover
    is_legitimate_domain = None  # type: ignore


# ---------------------------------------------------------------------
# Thresholds & Weights (tuning-friendly configuration)
# ---------------------------------------------------------------------
# ML probability category boundaries
ML_VERY_LOW: float = 0.20
ML_LOW: float = 0.35       # up to 0.35 is treated as "low"
ML_MEDIUM: float = 0.50
ML_HIGH: float = 0.80

# ML Paradox detection thresholds
PARADOX_STRONG_MAX_ML: float = 0.20
PARADOX_WEAK_MAX_ML: float = 0.30
PARADOX_STRONG_MIN_SIGNALS: int = 2
PARADOX_WEAK_MIN_SIGNALS: int = 1
BASE_SCORE_STRONG_PARADOX: float = 0.80  # strong paradox → treat ML as 0.8
BASE_SCORE_WEAK_PARADOX: float = 0.60    # weak paradox → treat ML as 0.6

# Additional condition for strong paradox when signals are very dense
PARADOX_STRONG_ALT_MIN_SIGNALS: int = 3  # for p <= ML_LOW & many signals

# Core weights for ML & tool scores (ML + tools ≒ 0.80)
WEIGHT_ML: float = 0.45
WEIGHT_TOOLS: float = 0.35

# Bonus when multiple non-ML factors are present
# NOTE(2026-01-02): Reduced slightly and changed the trigger condition to
# category-based (see section 4-2). This reduces FP caused by over-counting
# weak/non-independent signals.
BONUS_MULTIPLE_FACTORS: float = 0.12

# High-risk words bonus
HIGH_RISK_WORD_BASE: float = 0.12
HIGH_RISK_WORD_STEP: float = 0.04
HIGH_RISK_WORD_MAX: float = 0.28

# Known domain mitigation (slightly weaker than old logic)
KNOWN_DOMAIN_MITIGATION_LOW: float = 0.08   # applied when score < 0.7
KNOWN_DOMAIN_MITIGATION_HIGH: float = 0.04  # applied when score >= 0.7
KNOWN_DOMAIN_MITIGATION_SWITCH: float = 0.70

# Consistency bonus when tools agree & issues are rich
CONSISTENCY_THRESHOLD_TOOL_RISK: float = 0.40
CONSISTENCY_THRESHOLD_ISSUES: int = 3
CONSISTENCY_BONUS: float = 0.10

# Risk signal helper thresholds
RISK_SIGNAL_MIN_TOOL_RISK: float = 0.30  # avg_tool_risk >= 0.3 → one signal

# Tags treated as strong non‑ML signals (certificate / domain / brand)
# NOTE(2026-01-02): free_ca/no_org は「弱い身元情報」(DV相当)であり、
#                   それ単体で Paradox(ML≪0だが非MLが強い) を強判定すると
#                   Let's Encrypt 等の一般サイトでFPが増えやすい。
#                   Paradox 用のシグナルには *より強い* タグのみを使う。
STRONG_NON_ML_TAGS: tuple = (
    "dangerous_tld",
    "brand_detected",
    "wildcard",
    "self_signed",
)

# ただし free_ca/no_org 自体は risk 要因としては引き続き有効（スコア寄与は残す）。
WEAK_IDENTITY_TAGS: tuple = (
    "free_ca",
    "no_org",
)

# Multiple factors threshold
MULTIPLE_FACTORS_MIN_ISSUES: int = 2


def _count_high_risk_hits(tokens: List[str], high_risk_words: Optional[List[str]]) -> int:
    """high_risk_words に含まれるトークンがいくつあるか数えるヘルパー."""
    if not high_risk_words:
        return 0
    hr = {w.strip().lower() for w in high_risk_words if w and str(w).strip()}
    return sum(1 for t in tokens if t in hr)


@safe_tool_wrapper("contextual_risk_assessment")
def contextual_risk_assessment(
    domain: str,
    ml_probability: float = 0.0,
    tool_results: Optional[Dict[str, Any]] = None,
    high_risk_words: Optional[List[str]] = None,
    known_domains: Optional[Dict[str, Any]] = None,
    **kwargs: Any,
) -> Dict[str, Any]:
    """
    文脈的リスク評価ツール（Contextual Risk Assessment）

    - 第1層 ML（XGBoost）の確率と、brand/cert/domain の 3 つのツール結果を統合
    - 「ML パラドックス」（ML は非常に低いが非 ML シグナルが強いケース）を検出し、
      ML ベーススコアを 2 段階で底上げ（強/弱パラドックス）
    - known_domains（既知正規ドメイン）については、最終スコアから緩やかに減点
    """
    et = _ET(domain)
    p = float(ml_probability or 0.0)

    # ------------------------------------------------------------------
    # 0. ML カテゴリ判定（定数に基づく）
    # ------------------------------------------------------------------
    if p < ML_VERY_LOW:
        ml_category = "very_low"
    elif p < ML_LOW:
        ml_category = "low"
    elif p < ML_MEDIUM:
        ml_category = "medium"
    elif p < ML_HIGH:
        ml_category = "high"
    else:
        ml_category = "very_high"

    # ------------------------------------------------------------------
    # 1. ツール結果の集計（brand / cert / domain など）
    # ------------------------------------------------------------------
    results = tool_results or {}
    uniq_issues: List[str] = []
    s, c = 0.0, 0

    for res in results.values():
        if not isinstance(res, dict):
            continue

        # 対応形式:
        # - {"success": True, "data": {...}}
        # - {...} （data 本体のみ）
        data = res.get("data") if "data" in res else res
        if not isinstance(data, dict):
            continue

        # 明示的な失敗 or フォールバックはスコアから除外
        if res.get("success") is False or data.get("_fallback"):
            continue

        issues = data.get("detected_issues", []) or []
        uniq_issues.extend(issues)

        s += float(data.get("risk_score", 0.0) or 0.0)
        c += 1

    # ツールで検出された issue をユニーク化
    uniq_issues = list(dict.fromkeys(uniq_issues))
    issue_set = set(uniq_issues)
    avg_tool_risk: float = (s / c) if c else 0.0

    # --------------------------------------------------------------
    # 1b. Per-tool extraction (for category-based scoring/logging)
    # --------------------------------------------------------------
    def _extract_tool_data(name: str) -> Dict[str, Any]:
        """Return tool 'data' dict in a tolerant way.

        tool_results can be either:
          - {"success": True, "data": {...}}
          - {...} (data-only)
        """
        raw = results.get(name) or {}
        if not isinstance(raw, dict):
            return {}
        data = raw.get("data") if "data" in raw else raw
        if not isinstance(data, dict):
            return {}
        # explicit failure / fallback → ignore
        if raw.get("success") is False or data.get("_fallback"):
            return {}
        return data

    brand_data = _extract_tool_data("brand_impersonation_check")
    cert_data  = _extract_tool_data("certificate_analysis")
    dom_data   = _extract_tool_data("short_domain_analysis")

    brand_risk = float(brand_data.get("risk_score", 0.0) or 0.0)
    cert_risk  = float(cert_data.get("risk_score", 0.0) or 0.0)
    dom_risk   = float(dom_data.get("risk_score", 0.0) or 0.0)

    brand_issues = set(brand_data.get("detected_issues", []) or [])
    cert_issues  = set(cert_data.get("detected_issues", []) or [])
    dom_issues   = set(dom_data.get("detected_issues", []) or [])

    # ------------------------------------------------------------------
    # 2. 高リスク単語ヒット数 / 既知ドメイン判定
    # ------------------------------------------------------------------
    tokens = _tokenize_domain_labels(et)
    hr_hits = _count_high_risk_hits(tokens, high_risk_words)

    # "known_domains" is external-data dependent. In some runs it behaves like a
    # seen-set (contains almost everything), which would incorrectly apply
    # mitigation to phishing domains. We therefore separate:
    #   - is_known_seen : membership in the external dict
    #   - is_known_legit: *strict* legitimate allowlist check
    is_known_seen = False
    known_label: Any = None
    rd = getattr(et, "registered_domain", None)
    if isinstance(known_domains, dict) and rd in known_domains:
        is_known_seen = True
        known_label = known_domains.get(rd)

    is_known_legit = False
    legit_info: Optional[Dict[str, Any]] = None
    try:
        if callable(is_legitimate_domain) and rd:
            legit_info = is_legitimate_domain(str(rd))
            # strict allowlist only
            is_known_legit = bool(legit_info.get("is_legitimate")) and float(legit_info.get("confidence", 0.0) or 0.0) >= 0.98
    except Exception:
        is_known_legit = False

    issues: List[str] = []
    score: float = 0.0
    mitigation: float = 0.0
    consistency_boost: float = 0.0

    # ------------------------------------------------------------------
    # 3. ML パラドックス判定（定数化）
    #
    # risk_signal_count = 0〜3:
    #   1) avg_tool_risk >= RISK_SIGNAL_MIN_TOOL_RISK
    #   2) hr_hits > 0
    #   3) STRONG_NON_ML_TAGS のいずれかが含まれる
    #
    # 強パラドックス:
    #   (p <= PARADOX_STRONG_MAX_ML & signals >= PARADOX_STRONG_MIN_SIGNALS)
    #   or (p <= ML_LOW & signals >= PARADOX_STRONG_ALT_MIN_SIGNALS)
    #
    # 弱パラドックス:
    #   not strong & (p <= PARADOX_WEAK_MAX_ML & signals >= PARADOX_WEAK_MIN_SIGNALS)
    #
    # NOTE(2026-01-02): 以前は p<=PARADOX_STRONG_MAX_ML & {free_ca,no_org} で
    # 「常に強パラドックス」だったが、Let's Encrypt 等の一般サイトでも頻出なため
    # FP を誘発しやすい。現在は “追加の強シグナルがある場合のみ” strong に昇格。
    # ------------------------------------------------------------------
    risk_signal_count = 0
    if avg_tool_risk >= RISK_SIGNAL_MIN_TOOL_RISK:
        risk_signal_count += 1
    if hr_hits > 0:
        risk_signal_count += 1
    # NOTE: STRONG_NON_ML_TAGS には free_ca/no_org を含めない（FP低減）
    if any(tag in issue_set for tag in STRONG_NON_ML_TAGS):
        risk_signal_count += 1

    is_paradox_strong = False
    is_paradox_weak = False

    # 強パラドックス条件（2 パターン）
    if (
        (p <= PARADOX_STRONG_MAX_ML and risk_signal_count >= PARADOX_STRONG_MIN_SIGNALS)
        or (p <= ML_LOW and risk_signal_count >= PARADOX_STRONG_ALT_MIN_SIGNALS)
    ):
        is_paradox_strong = True

    # 弱パラドックス条件
    if (not is_paradox_strong) and (
        p <= PARADOX_WEAK_MAX_ML and risk_signal_count >= PARADOX_WEAK_MIN_SIGNALS
    ):
        is_paradox_weak = True

    # very low ML かつ free_ca + no_org:
    #   以前は「常に強パラドックス扱い」だったが、Let's Encrypt + No Org は
    #   *一般サイトでも頻出* のため FP を誘発しやすい。
    #   → 追加の強い非MLシグナルがある場合にのみ strong に昇格する。
    if p <= PARADOX_STRONG_MAX_ML and {"free_ca", "no_org"}.issubset(issue_set):
        _needs_extra = {
            "dangerous_tld",
            "brand_detected",
            "random_pattern",
            "high_entropy",
            "short_random_combo",
            "random_with_high_tld_stat",
            "idn_homograph",
        }
        if issue_set & _needs_extra:
            is_paradox_strong = True
            is_paradox_weak = False

    # ML 由来ベーススコアの決定
    if is_paradox_strong:
        issues.append("ml_paradox")
        base_from_ml = BASE_SCORE_STRONG_PARADOX
    elif is_paradox_weak:
        issues.append("ml_paradox_medium")
        base_from_ml = BASE_SCORE_WEAK_PARADOX
    else:
        base_from_ml = p

    # ------------------------------------------------------------------
    # 4. スコア計算（ML + ツール平均 + 各種ボーナス/減点）
    # ------------------------------------------------------------------
    # (ログ/チューニング向け) スコア内訳を残す
    score_components: Dict[str, Any] = {
        "ml_probability": p,
        "ml_category": ml_category,
        "base_from_ml": base_from_ml,
        "avg_tool_risk": avg_tool_risk,
        "weight_ml": WEIGHT_ML,
        "weight_tools": WEIGHT_TOOLS,
        "ml_contrib": round(base_from_ml * WEIGHT_ML, 4),
        "tools_contrib": round(avg_tool_risk * WEIGHT_TOOLS, 4),
        "bonus_multiple_factors": 0.0,
        "multi_factor_categories": [],
        "multi_factor_count": 0,
        "bonus_high_risk_words": 0.0,
        "dv_suspicious_combo": False,
        "known_domain_mitigation": 0.0,
        "consistency_boost": 0.0,
        "low_ml_safety_cap_applied": False,
        "low_ml_safety_cap_before": None,
        "low_ml_safety_cap_after": None,
        "final_score": None,
    }

    # 4-1. ML / ツールからの寄与
    score += base_from_ml * WEIGHT_ML
    score += avg_tool_risk * WEIGHT_TOOLS

    # 4-2. 複数要因ボーナス（カテゴリベース）
    # NOTE(2026-01-02):
    #   以前は「検出 issue 数」で判定していたため、free_ca/no_org/no_san/short_term などの
    #   “弱い/非独立” な証明書由来シグナルだけでボーナスが乗り、FP を誘発しやすかった。
    #   → brand/cert/domain の *複数カテゴリ* から意味のあるシグナルが出ている場合のみ bonus。
    _domain_strong = {
        "dangerous_tld",
        "idn_homograph",
        "random_pattern",
        "high_entropy",
        "very_high_entropy",
        "short_random_combo",
        "random_with_high_tld_stat",
        "very_short_dangerous_combo",
        "deep_chain_with_risky_tld",
    }
    _cert_strong = {
        "self_signed",
        "dv_multi_risk_combo",
        # NOTE: dv_weak_identity/free_ca_no_org は benign でも多いため
        # multi-factor の「強い独立シグナル」としては扱わない。
    }

    brand_signal = ("brand_detected" in brand_issues) or (brand_risk >= 0.40)
    domain_signal = (dom_risk >= 0.40) or bool(dom_issues & _domain_strong)
    cert_signal = (cert_risk >= 0.65) or bool(cert_issues & _cert_strong)

    _cats: List[str] = []
    if brand_signal:
        _cats.append("brand")
    if domain_signal:
        _cats.append("domain")
    if cert_signal:
        _cats.append("cert")

    score_components["multi_factor_categories"] = _cats
    score_components["multi_factor_count"] = len(_cats)

    if len(_cats) >= 2:
        issues.append("multiple_risk_factors")
        score += BONUS_MULTIPLE_FACTORS
        score_components["bonus_multiple_factors"] = BONUS_MULTIPLE_FACTORS

    # 4-3. 高リスク単語ボーナス
    if hr_hits > 0:
        issues.append("high_risk_words")
        _hr_bonus = min(
            HIGH_RISK_WORD_MAX,
            HIGH_RISK_WORD_BASE + HIGH_RISK_WORD_STEP * (hr_hits - 1),
        )
        score += _hr_bonus
        score_components["bonus_high_risk_words"] = round(float(_hr_bonus), 4)

    # 4-3b. "DV weak identity" + suspicious domain combo boost
    # This targets the common FN pattern: brand absent, cert looks DV-ish (free_ca/no_org)
    # and the domain has strong structural signals (dangerous_tld / random / entropy).
    if (
        ("free_ca_no_org" in issue_set or ("free_ca" in issue_set and "no_org" in issue_set))
        and (
            "dangerous_tld" in issue_set
            or "random_pattern" in issue_set
            or "high_entropy" in issue_set
            or "short_random_combo" in issue_set
            or "random_with_high_tld_stat" in issue_set
        )
    ):
        issues.append("dv_suspicious_combo")
        score = max(score, 0.42)
        score_components["dv_suspicious_combo"] = True

    # 4-4. 既知ドメイン緩和（減点）
    # NOTE: apply mitigation ONLY for strict legitimate allowlist matches.
    if is_known_legit:
        mitigation = (
            KNOWN_DOMAIN_MITIGATION_LOW
            if score < KNOWN_DOMAIN_MITIGATION_SWITCH
            else KNOWN_DOMAIN_MITIGATION_HIGH
        )
        score = max(0.0, score - mitigation)
        issues.append("known_domain")
        score_components["known_domain_mitigation"] = round(float(mitigation), 4)

    # 4-5. ツール整合性ボーナス
    if avg_tool_risk >= CONSISTENCY_THRESHOLD_TOOL_RISK and len(uniq_issues) >= CONSISTENCY_THRESHOLD_ISSUES:
        consistency_boost = CONSISTENCY_BONUS
        score = min(1.0, score + consistency_boost)
        issues.append("consistency")
        score_components["consistency_boost"] = round(float(consistency_boost), 4)

    # 4-6. 最終クリップ
    score = min(1.0, score)

    # ------------------------------------------------------------------
    # 5.x  低MLセーフティキャップ:
    #   - ML が極端に低い (p < 0.2)
    #   - brand ツールはほぼ無反応 (risk < 0.5)
    #   - high_risk_words のヒットもない
    #   - 強い証明書・ドメイン問題もない（no_cert / dangerous_tld / random_pattern だけ等）
    #   - 既知で「明確に怪しい」ドメインラベルでもない
    #   → contextual の score が 0.49 を超えないようにクリップする
    # ------------------------------------------------------------------
    try:
        tr = tool_results or {}

        # brand_risk（data ラッパ対応）
        b_raw = tr.get("brand_impersonation_check") or {}
        b_data = b_raw.get("data") if isinstance(b_raw, dict) and "data" in b_raw else b_raw
        brand_risk = float((b_data or {}).get("risk_score", 0.0) or 0.0)

        # cert / domain issues（data ラッパ対応）
        c_raw = tr.get("certificate_analysis") or {}
        c_data = c_raw.get("data") if isinstance(c_raw, dict) and "data" in c_raw else c_raw
        cert_issues = set(((c_data or {}).get("detected_issues", []) or []))

        d_raw = tr.get("short_domain_analysis") or {}
        d_data = d_raw.get("data") if isinstance(d_raw, dict) and "data" in d_raw else d_raw
        dom_issues = set(((d_data or {}).get("detected_issues", []) or []))

        # 「本当にヤバい」系フラグ（必要に応じて拡張）
        strong_cert_flags = {"mismatched_name", "expired", "revoked", "invalid_chain"}
        strong_dom_flags = {"idn_homograph", "very_short", "extreme_random_pattern"}

        has_strong_cert = bool(cert_issues & strong_cert_flags)
        has_strong_dom = bool(dom_issues & strong_dom_flags)

        # known_domain ラベルから「明確に怪しい」ものだけ除外対象にする
        label_str: Optional[str] = None
        if isinstance(known_label, str):
            label_str = known_label
        is_known_suspicious = bool(is_known_seen and label_str in {"phishing", "phishing_like", "block"})

        if (
            p < 0.20
            and hr_hits == 0
            and brand_risk < 0.5
            and not has_strong_cert
            and not has_strong_dom
            and not is_known_suspicious
        ):
            # Guard: dangerous_tld は強シグナルのため cap 対象外
            if "dangerous_tld" not in dom_issues and score > 0.49:
                score_components["low_ml_safety_cap_applied"] = True
                score_components["low_ml_safety_cap_before"] = round(float(score), 4)
                score = 0.49
                score_components["low_ml_safety_cap_after"] = 0.49
                if "low_ml_safety_cap" not in issues:
                    issues.append("low_ml_safety_cap")
    except Exception:
        # ここで落ちても元のスコアをそのまま返す
        pass

    # ------------------------------------------------------------------
    # 5. Reasoning / details（既存キーは保持）
    # ------------------------------------------------------------------
    reasoning_bits: List[str] = [
        f"ML={p:.2f}({ml_category})",
        f"ツール平均={avg_tool_risk:.2f}",
    ]
    if hr_hits:
        reasoning_bits.append(f"高リスク語ヒット={hr_hits}")
    if is_known_seen and rd:
        reasoning_bits.append(f"既知(外部)={rd}({known_label})")
    if is_known_legit and rd:
        reasoning_bits.append("正規allowlist一致")
    if is_paradox_strong or is_paradox_weak:
        reasoning_bits.append("ML Paradox")
    if "multiple_risk_factors" in issues:
        reasoning_bits.append(f"要因数={len(uniq_issues)}")
    if "consistency" in issues:
        reasoning_bits.append("整合性")
    if "low_ml_safety_cap" in issues:
        reasoning_bits.append("低MLセーフティキャップ適用")

    # finalize score breakdown for logging
    try:
        score_components["final_score"] = round(float(score), 4)
    except Exception:
        score_components["final_score"] = None

    return {
        "tool_name": "contextual_risk_assessment",
        "detected_issues": issues,
        "risk_score": score,
        "details": {
            "ml_probability": p,
            "ml_category": ml_category,
            "total_issues_count": len(uniq_issues),
            # 既存コードとの互換用
            "combined_risk_score": round(avg_tool_risk, 2),
            "tool_average_risk": round(avg_tool_risk, 2),
            "is_ml_paradox": is_paradox_strong,  # 互換のため「強パラドックスのみ」True
            "all_detected_issues": uniq_issues,
            "high_risk_hits": hr_hits,
            "known_domain": {
                "is_known_seen": is_known_seen,
                "is_known_legit": is_known_legit,
                "label": known_label,
                "mitigation": mitigation,
                "legit_info": legit_info or {},
            },
            "consistency_boost": round(consistency_boost, 2),
            "score_components": score_components,
            # 追加の内部情報（将来のチューニング用）
            "paradox": {
                "risk_signal_count": risk_signal_count,
                "is_paradox_strong": is_paradox_strong,
                "is_paradox_weak": is_paradox_weak,
            },
        },
        "reasoning": " / ".join(reasoning_bits),
    }
