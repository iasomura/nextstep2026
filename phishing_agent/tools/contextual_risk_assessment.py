# phishing_agent/tools/contextual_risk_assessment.py
from __future__ import annotations
from typing import Any, Dict, List, Optional

from ..tools_module import safe_tool_wrapper, _ET, _tokenize_domain_labels


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
BONUS_MULTIPLE_FACTORS: float = 0.15

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
STRONG_NON_ML_TAGS: tuple = (
    "free_ca",
    "no_org",
    "dangerous_tld",
    "brand_detected",
    "wildcard",
    "self_signed",
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

    # ------------------------------------------------------------------
    # 2. 高リスク単語ヒット数 / 既知ドメイン判定
    # ------------------------------------------------------------------
    tokens = _tokenize_domain_labels(et)
    hr_hits = _count_high_risk_hits(tokens, high_risk_words)

    is_known = False
    known_label: Any = None
    rd = getattr(et, "registered_domain", None)
    if isinstance(known_domains, dict) and rd in known_domains:
        is_known = True
        known_label = known_domains.get(rd)

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
    #   or (p <= ML_LOW & signals >= 3)
    #
    # 弱パラドックス:
    #   not strong & (p <= PARADOX_WEAK_MAX_ML & signals >= PARADOX_WEAK_MIN_SIGNALS)
    #
    # さらに、p <= PARADOX_STRONG_MAX_ML かつ {free_ca, no_org} が両方あれば
    # 常に強パラドックス扱い（弱パラドックスは解除）
    # ------------------------------------------------------------------
    risk_signal_count = 0
    if avg_tool_risk >= RISK_SIGNAL_MIN_TOOL_RISK:
        risk_signal_count += 1
    if hr_hits > 0:
        risk_signal_count += 1
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

    # very low ML かつ free_ca + no_org の組み合わせは常に強パラドックス扱い
    if p <= PARADOX_STRONG_MAX_ML and {"free_ca", "no_org"}.issubset(issue_set):
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
    # 4-1. ML / ツールからの寄与
    score += base_from_ml * WEIGHT_ML
    score += avg_tool_risk * WEIGHT_TOOLS

    # 4-2. 複数要因ボーナス
    if len(uniq_issues) >= MULTIPLE_FACTORS_MIN_ISSUES:
        issues.append("multiple_risk_factors")
        score += BONUS_MULTIPLE_FACTORS

    # 4-3. 高リスク単語ボーナス
    if hr_hits > 0:
        issues.append("high_risk_words")
        score += min(
            HIGH_RISK_WORD_MAX,
            HIGH_RISK_WORD_BASE + HIGH_RISK_WORD_STEP * (hr_hits - 1),
        )

    # 4-4. 既知ドメイン緩和（減点）
    if is_known:
        mitigation = (
            KNOWN_DOMAIN_MITIGATION_LOW
            if score < KNOWN_DOMAIN_MITIGATION_SWITCH
            else KNOWN_DOMAIN_MITIGATION_HIGH
        )
        score = max(0.0, score - mitigation)
        issues.append("known_domain")

    # 4-5. ツール整合性ボーナス
    if avg_tool_risk >= CONSISTENCY_THRESHOLD_TOOL_RISK and len(uniq_issues) >= CONSISTENCY_THRESHOLD_ISSUES:
        consistency_boost = CONSISTENCY_BONUS
        score = min(1.0, score + consistency_boost)
        issues.append("consistency")

    # 4-6. 最終クリップ
    score = min(1.0, score)

    # ------------------------------------------------------------------
    # 5. Reasoning / details（既存キーは保持）
    # ------------------------------------------------------------------
    reasoning_bits: List[str] = [
        f"ML={p:.2f}({ml_category})",
        f"ツール平均={avg_tool_risk:.2f}",
    ]
    if hr_hits:
        reasoning_bits.append(f"高リスク語ヒット={hr_hits}")
    if is_known and rd:
        reasoning_bits.append(f"既知ドメイン={rd}({known_label})")
    if is_paradox_strong or is_paradox_weak:
        reasoning_bits.append("ML Paradox")
    if "multiple_risk_factors" in issues:
        reasoning_bits.append(f"要因数={len(uniq_issues)}")
    if "consistency" in issues:
        reasoning_bits.append("整合性")

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
                "is_known": is_known,
                "label": known_label,
                "mitigation": mitigation,
            },
            "consistency_boost": round(consistency_boost, 2),
            # 追加の内部情報（将来のチューニング用）
            "paradox": {
                "risk_signal_count": risk_signal_count,
                "is_paradox_strong": is_paradox_strong,
                "is_paradox_weak": is_paradox_weak,
            },
        },
        "reasoning": " / ".join(reasoning_bits),
    }
