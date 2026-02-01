# -*- coding: utf-8 -*-
"""
phishing_agent.rules.result_applier
-----------------------------------
Apply RuleEngine results to PhishingAssessment.

Converts EngineResult into modifications to a PhishingAssessment,
including trace logging for debugging and analysis.

変更履歴:
    - 2026-01-31: 初版作成（ルールモジュール移行計画 Step 1.2）
"""

from typing import Any, Dict, List, Optional

try:
    from ..agent_foundations import PhishingAssessment, clip_confidence
except ImportError:
    from phishing_agent.agent_foundations import PhishingAssessment, clip_confidence

from .engine import EngineResult


# Risk level priority ordering
RISK_LEVEL_ORDER = ["low", "medium", "medium-high", "high", "critical"]

# TLD danger classifications for POST_LLM_FLIP_GATE
# Must match llm_final_decision.py exactly
HIGH_DANGER_TLDS = frozenset({
    "tk", "ml", "ga", "cf", "gq",  # 無料TLD（フィッシング頻出）
    "icu", "cfd", "sbs", "rest", "cyou",  # フィッシング特化
    "pw", "buzz", "lat",  # 高フィッシング率
})

MEDIUM_DANGER_TLDS = frozenset({
    "top", "shop", "xyz", "cc", "online", "site", "website",
    "club", "vip", "asia", "one", "link", "click", "live",
    "cn", "tokyo", "dev", "me", "pe", "ar", "cl", "mw", "ci",
})

# POST_LLM_FLIP_GATE thresholds
LOW_ML_FLIP_GATE_HIGH_DANGER = 0.0    # 高危険TLDは通過
LOW_ML_FLIP_GATE_MEDIUM_DANGER = 0.04  # 中危険TLD
LOW_ML_FLIP_GATE_NON_DANGER = 0.30     # 非危険TLD

# CTX thresholds for bypass
HARD_CTX = 0.65
SOFT_CTX = 0.50


def _priority_bump(current: str, minimum: str) -> str:
    """Bump risk level to at least the minimum.

    Args:
        current: Current risk level
        minimum: Minimum required risk level

    Returns:
        Higher of the two risk levels
    """
    try:
        current_idx = RISK_LEVEL_ORDER.index(current or "low")
        minimum_idx = RISK_LEVEL_ORDER.index(minimum or "low")
        return RISK_LEVEL_ORDER[max(current_idx, minimum_idx)]
    except (ValueError, IndexError):
        return minimum or current or "medium"


class ResultApplier:
    """Apply EngineResult to PhishingAssessment.

    Takes the aggregated results from RuleEngine evaluation and applies
    them to a PhishingAssessment, handling:
    - force_phishing / force_benign flags
    - confidence floor/ceiling adjustments
    - risk level bumps
    - trace logging

    Example:
        engine_result = rule_engine.evaluate(ctx)
        trace = []
        final_assessment = ResultApplier.apply(
            original=llm_assessment,
            engine_result=engine_result,
            trace=trace,
        )
    """

    @staticmethod
    def apply(
        original: PhishingAssessment,
        engine_result: EngineResult,
        trace: Optional[List[Dict[str, Any]]] = None,
    ) -> PhishingAssessment:
        """Apply engine result to assessment.

        Args:
            original: Original PhishingAssessment from LLM
            engine_result: Result from RuleEngine.evaluate()
            trace: Optional trace list for debugging (modified in-place)

        Returns:
            Modified PhishingAssessment with rules applied
        """
        tr = trace if isinstance(trace, list) else []

        # Extract original values
        is_phishing = bool(getattr(original, "is_phishing", False))
        confidence = float(getattr(original, "confidence", 0.0))
        risk_level = str(getattr(original, "risk_level", "low") or "low")
        risk_factors = list(getattr(original, "risk_factors", []) or [])
        detected_brands = list(getattr(original, "detected_brands", []) or [])
        reasoning = str(getattr(original, "reasoning", "") or "")

        # Track if any changes were made
        changes_made = []

        # --- Apply force_phishing with POST_LLM_FLIP_GATE check ---
        if engine_result.force_phishing is True:
            # Check if POST_LLM_FLIP_GATE should block this
            should_apply_force = True
            gate_blocked = False

            if not is_phishing:  # Original LLM was benign
                gate_blocked, gate_reason = ResultApplier._check_post_llm_flip_gate(
                    engine_result, original
                )
                if gate_blocked:
                    should_apply_force = False
                    tr.append({
                        "rule": "POST_LLM_FLIP_GATE",
                        "action": "block_force_phishing",
                        "reason": gate_reason,
                        "ml": engine_result.ml_probability,
                        "ctx": engine_result.ctx_score,
                        "tld": engine_result.tld,
                    })
                    changes_made.append("post_llm_flip_gate_blocked")

            if should_apply_force:
                if not is_phishing:
                    is_phishing = True
                    changes_made.append("force_phishing")
                    # Log which rules triggered the force
                    for rule_result in engine_result.rule_results:
                        if rule_result.triggered and rule_result.force_phishing:
                            tr.append({
                                "rule": rule_result.rule_name,
                                "action": "force_phishing",
                                "reasoning": rule_result.reasoning,
                                "details": rule_result.details,
                            })
                            risk_factors.append(f"rule:{rule_result.rule_name}")

        # --- Apply force_benign (only if force_phishing is not set) ---
        elif engine_result.force_benign is True:
            if is_phishing:
                is_phishing = False
                changes_made.append("force_benign")
                # Log which rules triggered the force
                for rule_result in engine_result.rule_results:
                    if rule_result.triggered and rule_result.force_benign:
                        tr.append({
                            "rule": rule_result.rule_name,
                            "action": "force_benign",
                            "reasoning": rule_result.reasoning,
                            "details": rule_result.details,
                        })
                        risk_factors.append(f"mitigated:{rule_result.rule_name}")

        # --- Apply confidence_floor ---
        if engine_result.confidence_floor is not None:
            if confidence < engine_result.confidence_floor:
                old_conf = confidence
                confidence = engine_result.confidence_floor
                changes_made.append(f"confidence_floor:{old_conf:.3f}->{confidence:.3f}")
                tr.append({
                    "adjustment": "confidence_floor",
                    "old": old_conf,
                    "new": confidence,
                    "triggered_by": engine_result.triggered_rules,
                })

        # --- Apply confidence_ceiling ---
        if engine_result.confidence_ceiling is not None:
            if confidence > engine_result.confidence_ceiling:
                old_conf = confidence
                confidence = engine_result.confidence_ceiling
                changes_made.append(f"confidence_ceiling:{old_conf:.3f}->{confidence:.3f}")
                tr.append({
                    "adjustment": "confidence_ceiling",
                    "old": old_conf,
                    "new": confidence,
                    "triggered_by": engine_result.triggered_rules,
                })

        # --- Apply risk_level_bump ---
        if engine_result.highest_risk_bump:
            new_risk = _priority_bump(risk_level, engine_result.highest_risk_bump)
            if new_risk != risk_level:
                old_risk = risk_level
                risk_level = new_risk
                changes_made.append(f"risk_bump:{old_risk}->{risk_level}")
                tr.append({
                    "adjustment": "risk_level_bump",
                    "old": old_risk,
                    "new": risk_level,
                    "triggered_by": engine_result.triggered_rules,
                })

        # --- Ensure phishing has at least medium risk ---
        if is_phishing and risk_level == "low":
            risk_level = "medium"
            changes_made.append("phishing_risk_floor")
            tr.append({
                "rule": "phishing_risk_floor",
                "action": "bump_to_medium",
                "reason": "is_phishing=True requires at least medium risk",
            })

        # --- Add detected issues to risk_factors ---
        for issue in engine_result.detected_issues:
            if issue not in risk_factors:
                risk_factors.append(issue)

        # --- Update reasoning if changes were made ---
        if changes_made and engine_result.reasoning:
            reasoning = reasoning + " | Rules: " + engine_result.reasoning

        # --- Clip confidence ---
        confidence = clip_confidence(confidence)

        # --- Summary trace entry ---
        if engine_result.triggered_rules:
            tr.append({
                "summary": "rule_engine_applied",
                "triggered_rules": engine_result.triggered_rules,
                "skipped_rules": engine_result.skipped_rules,
                "changes_made": changes_made,
                "final_is_phishing": is_phishing,
                "final_risk_level": risk_level,
                "final_confidence": round(confidence, 4),
                "execution_time_ms": round(engine_result.execution_time_ms, 2),
            })

        # --- Build result ---
        return PhishingAssessment(
            is_phishing=is_phishing,
            confidence=confidence,
            risk_level=risk_level,
            detected_brands=detected_brands,
            risk_factors=risk_factors,
            reasoning=reasoning,
        )

    @staticmethod
    def _check_post_llm_flip_gate(
        engine_result: EngineResult,
        original: PhishingAssessment,
    ) -> tuple:
        """Check if POST_LLM_FLIP_GATE should block force_phishing.

        This gate blocks low-ML phishing decisions from policy rules when
        the original LLM assessment was benign.

        Args:
            engine_result: Result from RuleEngine.evaluate()
            original: Original PhishingAssessment from LLM

        Returns:
            Tuple of (should_block: bool, reason: str)

        変更履歴:
            - 2026-01-31: 初版作成（inline版POST_LLM_FLIP_GATEと同等の動作）
        """
        ml = engine_result.ml_probability or 0.0
        ctx_score = engine_result.ctx_score or 0.0
        tld = (engine_result.tld or "").lower().strip(".")
        brand_detected = engine_result.brand_detected
        has_dangerous_signal = engine_result.has_dangerous_tld_signal

        # Determine TLD danger level and threshold
        is_high_danger = tld in HIGH_DANGER_TLDS
        is_medium_danger = tld in MEDIUM_DANGER_TLDS

        if is_high_danger:
            threshold = LOW_ML_FLIP_GATE_HIGH_DANGER
            # 高危険TLDはdangerous_tld シグナルがあれば通過
            if has_dangerous_signal:
                return (False, "high_danger_tld_pass")
        elif is_medium_danger:
            threshold = LOW_ML_FLIP_GATE_MEDIUM_DANGER
        else:
            threshold = LOW_ML_FLIP_GATE_NON_DANGER

        # Check if ML exceeds threshold
        if ml >= threshold:
            return (False, f"ml_above_threshold:{ml:.3f}>={threshold}")

        # Bypass conditions

        # 1. Hard CTX trigger (ctx >= 0.65)
        if ctx_score >= HARD_CTX:
            return (False, f"hard_ctx_bypass:{ctx_score:.3f}>={HARD_CTX}")

        # 2. Brand detected
        if brand_detected:
            return (False, "brand_bypass")

        # 3. Random pattern combo with soft ctx (simplified check)
        # In inline version, this checks specific domain_issues patterns
        # For now, we rely on ctx_score >= SOFT_CTX as a simpler proxy
        # (Additional issue_set checks could be added if needed)

        # Block the force_phishing
        danger_level = "high" if is_high_danger else "medium" if is_medium_danger else "low"
        return (
            True,
            f"low_ml_flip_gate:ml={ml:.3f}<{threshold},tld_danger={danger_level}"
        )

    @staticmethod
    def apply_with_min_score(
        original: PhishingAssessment,
        engine_result: EngineResult,
        trace: Optional[List[Dict[str, Any]]] = None,
    ) -> PhishingAssessment:
        """Apply engine result with min_score adjustment.

        This variant also applies the min_score from rule results,
        which can be used to set a minimum phishing probability threshold.

        Args:
            original: Original PhishingAssessment from LLM
            engine_result: Result from RuleEngine.evaluate()
            trace: Optional trace list for debugging

        Returns:
            Modified PhishingAssessment with rules applied
        """
        # First apply standard rules
        result = ResultApplier.apply(original, engine_result, trace)

        # Then apply min_score if set
        if engine_result.min_score is not None:
            confidence = float(getattr(result, "confidence", 0.0))
            if confidence < engine_result.min_score:
                # Update confidence
                new_result = PhishingAssessment(
                    is_phishing=result.is_phishing,
                    confidence=max(confidence, engine_result.min_score),
                    risk_level=result.risk_level,
                    detected_brands=list(result.detected_brands or []),
                    risk_factors=list(result.risk_factors or []),
                    reasoning=result.reasoning,
                )
                if trace is not None:
                    trace.append({
                        "adjustment": "min_score",
                        "old": confidence,
                        "new": engine_result.min_score,
                        "triggered_by": engine_result.triggered_rules,
                    })
                return new_result

        return result
