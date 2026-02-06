# -*- coding: utf-8 -*-
"""
tests.rules.test_cert_gate
---------------------------
Unit tests for Certificate gate rules.

変更履歴:
    - 2026-01-31: 初版作成
"""

import pytest
from phishing_agent.rules.detectors.base import RuleContext
from phishing_agent.rules.detectors.cert_gate import (
    BenignCertGateB1Rule,
    BenignCertGateB2Rule,
    BenignCertGateB3Rule,
    BenignCertGateB4Rule,
    create_cert_gate_rules,
)


class TestBenignCertGateB1Rule:
    """BenignCertGateB1Rule (OV/EV) tests."""

    def test_trigger_on_ov_ev_cert(self):
        """Test trigger on OV/EV certificate with low ctx."""
        ctx = RuleContext(
            domain="example.com",
            ml_probability=0.10,
            ctx_score=0.35,
            benign_indicators={"ov_ev_cert"},
            llm_is_phishing=True,
        )
        rule = BenignCertGateB1Rule()
        result = rule.evaluate(ctx)

        assert result.triggered is True
        assert result.force_benign is True
        assert "ov_ev_cert" in result.details.get("indicator", "")

    def test_no_trigger_when_already_benign(self):
        """Test no trigger when already benign."""
        ctx = RuleContext(
            domain="example.com",
            ml_probability=0.10,
            ctx_score=0.35,
            benign_indicators={"ov_ev_cert"},
            llm_is_phishing=False,
        )
        rule = BenignCertGateB1Rule()
        result = rule.evaluate(ctx)

        assert result.triggered is False

    def test_no_trigger_on_high_ctx(self):
        """Test no trigger when ctx >= 0.50."""
        ctx = RuleContext(
            domain="example.com",
            ml_probability=0.10,
            ctx_score=0.55,
            benign_indicators={"ov_ev_cert"},
            llm_is_phishing=True,
        )
        rule = BenignCertGateB1Rule()
        result = rule.evaluate(ctx)

        assert result.triggered is False

    def test_no_trigger_without_ov_ev(self):
        """Test no trigger without OV/EV indicator."""
        ctx = RuleContext(
            domain="example.com",
            ml_probability=0.10,
            ctx_score=0.35,
            benign_indicators={"has_crl_dp"},  # Not OV/EV
            llm_is_phishing=True,
        )
        rule = BenignCertGateB1Rule()
        result = rule.evaluate(ctx)

        assert result.triggered is False

    def test_skip_on_brand_detected(self):
        """Test skip when brand is detected."""
        ctx = RuleContext(
            domain="example.com",
            ml_probability=0.10,
            ctx_score=0.35,
            benign_indicators={"ov_ev_cert"},
            brand_details={"detected_brands": ["paypal"]},
            llm_is_phishing=True,
        )
        rule = BenignCertGateB1Rule()
        result = rule.evaluate(ctx)

        assert result.triggered is False
        assert "strong_risk_signals" in result.details.get("skip_reason", "")


class TestBenignCertGateB2Rule:
    """BenignCertGateB2Rule (CRL) tests."""

    def test_trigger_on_crl_cert(self):
        """Test trigger on CRL certificate with low ml and ctx."""
        ctx = RuleContext(
            domain="example.com",
            ml_probability=0.20,
            ctx_score=0.40,
            benign_indicators={"has_crl_dp"},
            llm_is_phishing=True,
        )
        rule = BenignCertGateB2Rule()
        result = rule.evaluate(ctx)

        assert result.triggered is True
        assert result.force_benign is True

    def test_no_trigger_on_high_ml(self):
        """Test no trigger when ml >= 0.30."""
        ctx = RuleContext(
            domain="example.com",
            ml_probability=0.35,
            ctx_score=0.40,
            benign_indicators={"has_crl_dp"},
            llm_is_phishing=True,
        )
        rule = BenignCertGateB2Rule()
        result = rule.evaluate(ctx)

        assert result.triggered is False

    def test_no_trigger_on_high_ctx(self):
        """Test no trigger when ctx >= 0.45."""
        ctx = RuleContext(
            domain="example.com",
            ml_probability=0.20,
            ctx_score=0.50,
            benign_indicators={"has_crl_dp"},
            llm_is_phishing=True,
        )
        rule = BenignCertGateB2Rule()
        result = rule.evaluate(ctx)

        assert result.triggered is False


class TestBenignCertGateB3Rule:
    """BenignCertGateB3Rule (Wildcard) tests."""

    def test_trigger_on_wildcard_cert(self):
        """Test trigger on wildcard certificate with non-dangerous TLD."""
        ctx = RuleContext(
            domain="example.com",
            ml_probability=0.10,
            ctx_score=0.35,
            benign_indicators={"wildcard_cert"},
            llm_is_phishing=True,
            tld="com",
        )
        rule = BenignCertGateB3Rule()
        result = rule.evaluate(ctx)

        assert result.triggered is True
        assert result.force_benign is True

    def test_no_trigger_on_dangerous_tld(self):
        """Test no trigger on dangerous TLD."""
        ctx = RuleContext(
            domain="example.tk",
            ml_probability=0.10,
            ctx_score=0.35,
            benign_indicators={"wildcard_cert"},
            llm_is_phishing=True,
            tld="tk",
        )
        rule = BenignCertGateB3Rule()
        result = rule.evaluate(ctx)

        assert result.triggered is False
        assert "dangerous_tld" in result.details.get("skip_reason", "")


class TestBenignCertGateB4Rule:
    """BenignCertGateB4Rule (High SAN) tests."""

    def test_trigger_on_high_san(self):
        """Test trigger on high SAN count certificate."""
        ctx = RuleContext(
            domain="example.com",
            ml_probability=0.10,
            ctx_score=0.40,
            benign_indicators={"high_san_count"},
            cert_details={"san_count": 15},
            llm_is_phishing=True,
            tld="com",
        )
        rule = BenignCertGateB4Rule()
        result = rule.evaluate(ctx)

        assert result.triggered is True
        assert result.force_benign is True

    def test_no_trigger_on_dangerous_tld(self):
        """Test no trigger on dangerous TLD."""
        ctx = RuleContext(
            domain="example.top",
            ml_probability=0.10,
            ctx_score=0.40,
            benign_indicators={"high_san_count"},
            cert_details={"san_count": 15},
            llm_is_phishing=True,
            tld="top",
        )
        rule = BenignCertGateB4Rule()
        result = rule.evaluate(ctx)

        assert result.triggered is False


class TestCreateCertGateRules:
    """Test create_cert_gate_rules factory."""

    def test_creates_all_rules(self):
        """Test that factory creates all expected rules."""
        rules = create_cert_gate_rules()

        assert len(rules) == 4
        names = [r.name for r in rules]
        assert "benign_cert_gate_b1" in names
        assert "benign_cert_gate_b2" in names
        assert "benign_cert_gate_b3" in names
        assert "benign_cert_gate_b4" in names
