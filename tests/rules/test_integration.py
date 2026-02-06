# -*- coding: utf-8 -*-
"""
tests.rules.test_integration
-----------------------------
Integration tests for rule engine and context builder.

変更履歴:
    - 2026-01-31: 初版作成
"""

import pytest
from phishing_agent.rules.context_builder import RuleContextBuilder
from phishing_agent.rules.engine import (
    RuleEngine,
    create_phase6_engine,
    create_default_engine,
)
from phishing_agent.rules.result_applier import ResultApplier
from phishing_agent.agent_foundations import PhishingAssessment


class TestEngineIntegration:
    """Integration tests for rule engine."""

    def test_phase6_engine_creation(self):
        """Test that phase6 engine can be created."""
        engine = create_phase6_engine()
        assert len(engine) > 0

        rules = engine.list_rules()
        rule_names = [r["name"] for r in rules]

        # Check that key rules exist
        assert "hard_ctx_trigger" in rule_names
        assert "soft_ctx_trigger" in rule_names
        assert "gov_edu_benign_gate" in rule_names
        assert "benign_cert_gate_b1" in rule_names
        assert "policy_r1" in rule_names
        assert "very_high_ml_override" in rule_names

    def test_engine_evaluate_phished(self):
        """Test engine evaluation with phasing."""
        engine = create_phase6_engine()

        # Create a context that should trigger hard_ctx_trigger
        tool_summary = {
            "brand": {"risk_score": 0.0, "issues": [], "brands": []},
            "cert": {"risk_score": 0.5, "issues": ["free_ca", "no_org"], "details": {}},
            "domain": {"risk_score": 0.6, "issues": ["dangerous_tld"], "details": {}},
            "contextual": {"risk_score": 0.70, "issues": ["dv_suspicious_combo"]},
        }
        precheck = {
            "etld1": {"suffix": "tk", "registered_domain": "test.tk"},
            "tld_category": "dangerous",
        }
        llm_assessment = PhishingAssessment(
            is_phishing=False,  # LLM said benign
            confidence=0.60,
            risk_level="medium",
            detected_brands=[],
            risk_factors=[],
            reasoning="No brand detected in domain analysis, appears benign.",
        )

        ctx = RuleContextBuilder.build(
            domain="test.tk",
            ml_probability=0.05,
            tool_summary=tool_summary,
            precheck=precheck,
            llm_assessment=llm_assessment,
        )

        result = engine.evaluate_phased(ctx)

        # Hard ctx trigger should fire (ctx=0.70 >= 0.65)
        assert result.force_phishing is True
        assert "hard_ctx_trigger" in result.triggered_rules

    def test_gov_edu_protection(self):
        """Test government/education domain protection."""
        engine = create_phase6_engine()

        tool_summary = {
            "brand": {"risk_score": 0.0, "issues": [], "brands": []},
            "cert": {"risk_score": 0.3, "issues": ["free_ca"], "details": {}},
            "domain": {"risk_score": 0.4, "issues": ["random_pattern"], "details": {}},
            "contextual": {"risk_score": 0.45, "issues": []},
        }
        precheck = {
            "etld1": {"suffix": "gov.in", "registered_domain": "sscsr.gov.in"},
            "tld_category": "legitimate",
        }
        llm_assessment = PhishingAssessment(
            is_phishing=True,  # LLM incorrectly flagged as phishing
            confidence=0.65,
            risk_level="medium-high",
            detected_brands=[],
            risk_factors=["random_pattern"],
            reasoning="Random pattern detected",
        )

        ctx = RuleContextBuilder.build(
            domain="sscsr.gov.in",
            ml_probability=0.10,
            tool_summary=tool_summary,
            precheck=precheck,
            llm_assessment=llm_assessment,
        )

        result = engine.evaluate_phased(ctx)

        # Gov/edu gate should fire and protect the domain
        assert result.force_benign is True
        assert "gov_edu_benign_gate" in result.triggered_rules


class TestResultApplierIntegration:
    """Integration tests for result applier."""

    def test_apply_force_phishing(self):
        """Test applying force_phishing result."""
        engine = create_phase6_engine()

        tool_summary = {
            "brand": {"risk_score": 0.8, "issues": ["brand_detected"], "brands": ["paypal"]},
            "cert": {"risk_score": 0.5, "issues": ["free_ca", "no_org"], "details": {}},
            "domain": {"risk_score": 0.4, "issues": [], "details": {}},
            "contextual": {"risk_score": 0.55, "issues": []},
        }
        precheck = {
            "etld1": {"suffix": "com", "registered_domain": "paypal-secure.com"},
            "tld_category": "legitimate",
        }
        original = PhishingAssessment(
            is_phishing=False,
            confidence=0.50,
            risk_level="medium",
            detected_brands=["paypal"],
            risk_factors=[],
            reasoning="Brand detected but unsure",
        )

        ctx = RuleContextBuilder.build(
            domain="paypal-secure.com",
            ml_probability=0.30,
            tool_summary=tool_summary,
            precheck=precheck,
            llm_assessment=original,
        )

        engine_result = engine.evaluate_phased(ctx)
        trace = []
        final = ResultApplier.apply(original, engine_result, trace)

        # brand_cert_high should fire
        if engine_result.force_phishing:
            assert final.is_phishing is True
            assert final.risk_level in {"high", "critical"}

    def test_apply_force_benign(self):
        """Test applying force_benign result."""
        engine = create_phase6_engine()

        tool_summary = {
            "brand": {"risk_score": 0.0, "issues": [], "brands": []},
            "cert": {
                "risk_score": 0.1,
                "issues": [],
                "details": {"benign_indicators": ["ov_ev_cert"]},
            },
            "domain": {"risk_score": 0.2, "issues": [], "details": {}},
            "contextual": {"risk_score": 0.35, "issues": []},
        }
        precheck = {
            "etld1": {"suffix": "com", "registered_domain": "example.com"},
            "tld_category": "legitimate",
        }
        original = PhishingAssessment(
            is_phishing=True,  # LLM incorrectly flagged
            confidence=0.60,
            risk_level="medium",
            detected_brands=[],
            risk_factors=[],
            reasoning="Some concern detected during analysis.",
        )

        ctx = RuleContextBuilder.build(
            domain="example.com",
            ml_probability=0.15,
            tool_summary=tool_summary,
            precheck=precheck,
            llm_assessment=original,
        )

        engine_result = engine.evaluate_phased(ctx)
        trace = []
        final = ResultApplier.apply(original, engine_result, trace)

        # benign_cert_gate_b1 should fire (OV/EV cert)
        if engine_result.force_benign:
            assert final.is_phishing is False
            # risk_level is preserved from original (medium), ResultApplier only bumps up, not down
            assert final.risk_level == "medium"


class TestFullPipeline:
    """Full pipeline integration tests."""

    def test_high_ml_override(self):
        """Test high ML override scenario."""
        engine = create_phase6_engine()

        tool_summary = {
            "brand": {"risk_score": 0.0, "issues": [], "brands": []},
            "cert": {"risk_score": 0.4, "issues": ["free_ca"], "details": {}},
            "domain": {"risk_score": 0.5, "issues": ["random_pattern", "short"], "details": {}},
            "contextual": {"risk_score": 0.45, "issues": []},
        }
        precheck = {
            "etld1": {"suffix": "com", "registered_domain": "xyz123.com"},
            "tld_category": "legitimate",
        }
        original = PhishingAssessment(
            is_phishing=False,  # LLM said benign
            confidence=0.55,
            risk_level="low",
            detected_brands=[],
            risk_factors=[],
            reasoning="No significant risk factors detected during analysis.",
        )

        ctx = RuleContextBuilder.build(
            domain="xyz123.com",
            ml_probability=0.90,  # Very high ML
            tool_summary=tool_summary,
            precheck=precheck,
            llm_assessment=original,
        )

        engine_result = engine.evaluate_phased(ctx)
        trace = []
        final = ResultApplier.apply(original, engine_result, trace)

        # very_high_ml_override should fire
        assert final.is_phishing is True
        assert "very_high_ml_override" in engine_result.triggered_rules

    def test_ultra_low_ml_block(self):
        """Test ultra low ML block scenario."""
        engine = create_phase6_engine()

        tool_summary = {
            "brand": {"risk_score": 0.0, "issues": [], "brands": []},
            "cert": {"risk_score": 0.2, "issues": [], "details": {}},
            "domain": {"risk_score": 0.3, "issues": [], "details": {}},
            "contextual": {"risk_score": 0.35, "issues": []},
        }
        precheck = {
            "etld1": {"suffix": "org", "registered_domain": "example.org"},
            "tld_category": "legitimate",
        }
        original = PhishingAssessment(
            is_phishing=True,  # LLM incorrectly flagged
            confidence=0.55,
            risk_level="medium",
            detected_brands=[],
            risk_factors=["some_issue"],
            reasoning="Suspicious patterns detected in domain.",
        )

        ctx = RuleContextBuilder.build(
            domain="example.org",
            ml_probability=0.02,  # Ultra low ML
            tool_summary=tool_summary,
            precheck=precheck,
            llm_assessment=original,
        )

        engine_result = engine.evaluate_phased(ctx)
        trace = []
        final = ResultApplier.apply(original, engine_result, trace)

        # ultra_low_ml_block should fire
        assert final.is_phishing is False
        assert "ultra_low_ml_block" in engine_result.triggered_rules
