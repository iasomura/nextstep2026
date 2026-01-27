# -*- coding: utf-8 -*-
"""
phishing_agent.rules.integration
--------------------------------
Integration helpers for using the rules module with llm_final_decision.py.

This module provides helper functions to:
- Build RuleContext from tool results
- Apply EngineResult to PhishingAssessment
- Integrate with existing Phase6 logic

変更履歴:
    - 2026-01-28: 初版作成
"""

from typing import Any, Dict, Optional, Set, List
from dataclasses import dataclass
import logging

from .detectors.base import RuleContext, RuleResult
from .engine import RuleEngine, EngineResult, create_default_engine
from .metrics import MetricsCollector

logger = logging.getLogger(__name__)


def build_rule_context(
    domain: str,
    *,
    ml_probability: float = 0.0,
    tool_results: Optional[Dict[str, Any]] = None,
    precheck: Optional[Dict[str, Any]] = None,
    llm_is_phishing: Optional[bool] = None,
    llm_confidence: float = 0.0,
    llm_risk_level: str = "low",
) -> RuleContext:
    """Build a RuleContext from tool results.

    Args:
        domain: Domain being analyzed
        ml_probability: ML model probability
        tool_results: Dictionary of tool results
        precheck: Precheck results
        llm_is_phishing: LLM judgment result
        llm_confidence: LLM confidence
        llm_risk_level: LLM risk level

    Returns:
        RuleContext populated with all available data

    変更履歴:
        - 2026-01-28: 初版作成
    """
    tr = tool_results or {}
    pre = precheck or {}

    # Extract issue sets from each tool
    brand_data = tr.get("brand") or {}
    brand_issues = set(brand_data.get("detected_issues", []) or [])
    brand_details = brand_data.get("details", {}) or {}

    cert_data = tr.get("cert") or {}
    cert_issues = set(cert_data.get("detected_issues", []) or [])
    cert_details = cert_data.get("details", {}) or {}

    domain_data = tr.get("domain") or {}
    domain_issues = set(domain_data.get("detected_issues", []) or [])
    domain_details = domain_data.get("details", {}) or {}

    ctx_data = tr.get("contextual_risk_assessment") or tr.get("contextual") or {}
    ctx_issues = set(ctx_data.get("detected_issues", []) or [])
    ctx_score = float(ctx_data.get("risk_score", 0.0) or 0.0)

    # Combine all issues
    all_issues = brand_issues | cert_issues | domain_issues

    # Extract tool risks
    tool_risks = {}
    for key in ["brand", "cert", "domain", "contextual_risk_assessment", "contextual"]:
        if key in tr and tr[key]:
            try:
                risk = float((tr[key] or {}).get("risk_score", 0.0) or 0.0)
                tool_risks[key] = risk
            except (TypeError, ValueError):
                pass

    # Extract benign indicators from cert details
    benign_indicators = set(cert_details.get("benign_indicators", []) or [])

    # Backward compatibility: build benign_indicators from individual flags
    if not benign_indicators:
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

    # Extract TLD info
    etld1 = pre.get("etld1", {}) or {}
    tld = etld1.get("suffix", "") or ""
    registered_domain = etld1.get("registered_domain", "") or ""

    # Check if known legitimate
    is_known_legitimate = False
    try:
        lc = domain_details.get("legitimate_check", {}) or {}
        is_known_legitimate = bool(lc.get("is_legitimate")) and float(lc.get("confidence", 0.0) or 0.0) >= 0.85
    except Exception:
        pass

    return RuleContext(
        domain=domain,
        ml_probability=ml_probability,
        issue_set=all_issues,
        tool_risks=tool_risks,
        cert_details=cert_details,
        brand_details=brand_details,
        domain_details=domain_details,
        is_known_legitimate=is_known_legitimate,
        tld=tld,
        registered_domain=registered_domain,
        # Phase6 fields
        ctx_score=ctx_score,
        ctx_issues=ctx_issues,
        precheck=pre,
        benign_indicators=benign_indicators,
        llm_is_phishing=llm_is_phishing,
        llm_confidence=llm_confidence,
        llm_risk_level=llm_risk_level,
    )


@dataclass
class IntegrationResult:
    """Result of rule integration.

    Attributes:
        engine_result: Full EngineResult from rule evaluation
        should_override_phishing: True if rules mandate is_phishing=True
        should_override_benign: True if rules mandate is_phishing=False
        risk_level_bump: Recommended risk level bump
        confidence_floor: Minimum confidence to enforce
        confidence_ceiling: Maximum confidence to enforce
        triggered_rule_tags: Issue tags from triggered rules
        trace: List of rule trace entries for debugging
    """
    engine_result: EngineResult
    should_override_phishing: bool = False
    should_override_benign: bool = False
    risk_level_bump: Optional[str] = None
    confidence_floor: Optional[float] = None
    confidence_ceiling: Optional[float] = None
    triggered_rule_tags: Set[str] = None
    trace: List[Dict[str, Any]] = None

    def __post_init__(self):
        if self.triggered_rule_tags is None:
            self.triggered_rule_tags = set()
        if self.trace is None:
            self.trace = []


# Module-level engine instance (lazy initialization)
_default_engine: Optional[RuleEngine] = None
_metrics_collector: Optional[MetricsCollector] = None


def get_default_engine() -> RuleEngine:
    """Get or create the default rule engine.

    Returns:
        Singleton RuleEngine instance

    変更履歴:
        - 2026-01-28: 初版作成
    """
    global _default_engine, _metrics_collector
    if _default_engine is None:
        _default_engine = create_default_engine(metrics_collector=_metrics_collector)
        logger.info(f"Created default RuleEngine with {len(_default_engine)} rules")
    return _default_engine


def set_metrics_collector(collector: MetricsCollector) -> None:
    """Set the metrics collector for the default engine.

    Must be called before get_default_engine() is called.

    Args:
        collector: MetricsCollector instance

    変更履歴:
        - 2026-01-28: 初版作成
    """
    global _metrics_collector, _default_engine
    _metrics_collector = collector
    # Reset engine so it gets recreated with the new collector
    _default_engine = None


def reset_default_engine() -> None:
    """Reset the default engine (for testing).

    変更履歴:
        - 2026-01-28: 初版作成
    """
    global _default_engine
    _default_engine = None


def evaluate_rules(
    domain: str,
    *,
    ml_probability: float = 0.0,
    tool_results: Optional[Dict[str, Any]] = None,
    precheck: Optional[Dict[str, Any]] = None,
    llm_is_phishing: Optional[bool] = None,
    llm_confidence: float = 0.0,
    llm_risk_level: str = "low",
    engine: Optional[RuleEngine] = None,
) -> IntegrationResult:
    """Evaluate all rules and return integration result.

    This is the main entry point for using the rules module from
    llm_final_decision.py.

    Args:
        domain: Domain being analyzed
        ml_probability: ML model probability
        tool_results: Dictionary of tool results
        precheck: Precheck results
        llm_is_phishing: LLM judgment result (for post-LLM gates)
        llm_confidence: LLM confidence
        llm_risk_level: LLM risk level
        engine: Optional custom RuleEngine (uses default if None)

    Returns:
        IntegrationResult with rule evaluation results

    Usage:
        from phishing_agent.rules.integration import evaluate_rules

        result = evaluate_rules(
            domain="example.com",
            ml_probability=0.25,
            tool_results=tool_results,
            precheck=precheck,
            llm_is_phishing=asmt.is_phishing,
            llm_confidence=asmt.confidence,
            llm_risk_level=asmt.risk_level,
        )

        if result.should_override_phishing:
            asmt.is_phishing = True
        elif result.should_override_benign:
            asmt.is_phishing = False

    変更履歴:
        - 2026-01-28: 初版作成
    """
    # Build context
    ctx = build_rule_context(
        domain=domain,
        ml_probability=ml_probability,
        tool_results=tool_results,
        precheck=precheck,
        llm_is_phishing=llm_is_phishing,
        llm_confidence=llm_confidence,
        llm_risk_level=llm_risk_level,
    )

    # Evaluate rules
    eng = engine or get_default_engine()
    engine_result = eng.evaluate(ctx)

    # Build trace entries
    trace = []
    for rr in engine_result.rule_results:
        if rr.triggered:
            trace.append({
                "rule": rr.rule_name,
                "issue_tag": rr.issue_tag,
                "force_phishing": rr.force_phishing,
                "force_benign": rr.force_benign,
                "risk_level_bump": rr.risk_level_bump,
                "confidence_floor": rr.confidence_floor,
                "reasoning": rr.reasoning,
                "details": rr.details,
            })

    return IntegrationResult(
        engine_result=engine_result,
        should_override_phishing=engine_result.force_phishing is True,
        should_override_benign=(
            engine_result.force_benign is True
            and engine_result.force_phishing is not True
        ),
        risk_level_bump=engine_result.highest_risk_bump,
        confidence_floor=engine_result.confidence_floor,
        confidence_ceiling=engine_result.confidence_ceiling,
        triggered_rule_tags=engine_result.detected_issues,
        trace=trace,
    )


def finalize_evaluation(
    eval_id: str,
    predicted_phishing: bool,
    actual_phishing: Optional[bool] = None,
    engine: Optional[RuleEngine] = None,
) -> None:
    """Finalize an evaluation with prediction and ground truth.

    Args:
        eval_id: Evaluation ID from IntegrationResult.engine_result.eval_id
        predicted_phishing: Final phishing prediction
        actual_phishing: Ground truth label (if known)
        engine: Optional custom RuleEngine

    変更履歴:
        - 2026-01-28: 初版作成
    """
    eng = engine or get_default_engine()
    eng.finalize_evaluation(eval_id, predicted_phishing, actual_phishing)
