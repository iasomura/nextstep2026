# -*- coding: utf-8 -*-
"""
tests.rules.test_brand_cert
---------------------------
Unit tests for brand + certificate rules.

変更履歴:
    - 2026-01-31: 初版作成
"""

import pytest
from phishing_agent.rules.detectors.base import RuleContext
from phishing_agent.rules.detectors.brand_cert import (
    BrandCertHighRule,
    BenignCertGateSkipRule,
    create_brand_cert_rules,
)


class TestBrandCertHighRule:
    """BrandCertHighRule tests."""

    def test_trigger_on_brand_with_no_org(self):
        """Test trigger on brand + no_org certificate."""
        ctx = RuleContext(
            domain="paypal-secure.com",
            ml_probability=0.30,
            ctx_score=0.55,
            issue_set={"no_org"},
            brand_details={"detected_brands": ["paypal"]},
            llm_is_phishing=False,
        )
        rule = BrandCertHighRule()
        result = rule.evaluate(ctx)

        assert result.triggered is True
        assert result.force_phishing is True
        assert result.confidence_floor == 0.70
        assert "brand_cert_high" in result.issue_tag

    def test_trigger_on_brand_with_free_ca(self):
        """Test trigger on brand + free_ca certificate."""
        ctx = RuleContext(
            domain="amazon-login.com",
            ml_probability=0.30,
            ctx_score=0.55,
            issue_set={"free_ca"},
            brand_details={"detected_brands": ["amazon"]},
            llm_is_phishing=False,
        )
        rule = BrandCertHighRule()
        result = rule.evaluate(ctx)

        assert result.triggered is True
        assert result.force_phishing is True

    def test_trigger_on_brand_with_no_cert(self):
        """Test trigger on brand + no_cert."""
        ctx = RuleContext(
            domain="microsoft-verify.com",
            ml_probability=0.30,
            ctx_score=0.55,
            ctx_issues={"no_cert"},
            brand_details={"detected_brands": ["microsoft"]},
            llm_is_phishing=False,
        )
        rule = BrandCertHighRule()
        result = rule.evaluate(ctx)

        assert result.triggered is True
        assert result.force_phishing is True

    def test_no_trigger_without_brand(self):
        """Test no trigger without brand detection."""
        ctx = RuleContext(
            domain="example.com",
            ml_probability=0.30,
            ctx_score=0.55,
            issue_set={"no_org", "free_ca"},
            brand_details={"detected_brands": []},
            llm_is_phishing=False,
        )
        rule = BrandCertHighRule()
        result = rule.evaluate(ctx)

        assert result.triggered is False

    def test_no_trigger_without_low_quality_cert(self):
        """Test no trigger without low quality certificate."""
        ctx = RuleContext(
            domain="paypal-secure.com",
            ml_probability=0.30,
            ctx_score=0.55,
            issue_set=set(),  # No low quality cert issues
            brand_details={"detected_brands": ["paypal"]},
            llm_is_phishing=False,
        )
        rule = BrandCertHighRule()
        result = rule.evaluate(ctx)

        assert result.triggered is False

    def test_trigger_with_cert_details_issues(self):
        """Test trigger with cert_details issues."""
        ctx = RuleContext(
            domain="google-login.com",
            ml_probability=0.30,
            ctx_score=0.55,
            issue_set=set(),
            cert_details={"issues": ["free_ca", "short_validity"]},
            brand_details={"detected_brands": ["google"]},
            llm_is_phishing=False,
        )
        rule = BrandCertHighRule()
        result = rule.evaluate(ctx)

        assert result.triggered is True


class TestBenignCertGateSkipRule:
    """BenignCertGateSkipRule tests."""

    def test_trigger_on_brand_detected(self):
        """Test trigger when brand is detected."""
        ctx = RuleContext(
            domain="paypal-secure.com",
            ml_probability=0.30,
            ctx_score=0.45,
            brand_details={"detected_brands": ["paypal"]},
            llm_is_phishing=True,
        )
        rule = BenignCertGateSkipRule()
        result = rule.evaluate(ctx)

        assert result.triggered is True
        assert result.details.get("skip_reason") == "brand_detected"

    def test_trigger_on_self_signed(self):
        """Test trigger when self_signed is in issues."""
        ctx = RuleContext(
            domain="example.com",
            ml_probability=0.30,
            ctx_score=0.45,
            issue_set={"self_signed"},
            brand_details={"detected_brands": []},
            llm_is_phishing=True,
        )
        rule = BenignCertGateSkipRule()
        result = rule.evaluate(ctx)

        assert result.triggered is True
        assert "strong_risk_signals" in result.details.get("skip_reason")

    def test_trigger_on_idn_homograph(self):
        """Test trigger when idn_homograph is in issues."""
        ctx = RuleContext(
            domain="xn--pple-43d.com",  # Unicode domain
            ml_probability=0.30,
            ctx_score=0.45,
            issue_set={"idn_homograph"},
            brand_details={"detected_brands": []},
            llm_is_phishing=True,
        )
        rule = BenignCertGateSkipRule()
        result = rule.evaluate(ctx)

        assert result.triggered is True
        assert "idn_homograph" in result.details.get("signals", [])

    def test_trigger_on_high_entropy(self):
        """Test trigger when high_entropy is in issues."""
        ctx = RuleContext(
            domain="xyzabc123.com",
            ml_probability=0.30,
            ctx_score=0.45,
            issue_set={"high_entropy"},
            brand_details={"detected_brands": []},
            llm_is_phishing=True,
        )
        rule = BenignCertGateSkipRule()
        result = rule.evaluate(ctx)

        assert result.triggered is True

    def test_no_trigger_without_strong_signals(self):
        """Test no trigger without brand or strong signals."""
        ctx = RuleContext(
            domain="example.com",
            ml_probability=0.30,
            ctx_score=0.45,
            issue_set={"random_pattern"},  # Not a strong signal
            brand_details={"detected_brands": []},
            llm_is_phishing=True,
        )
        rule = BenignCertGateSkipRule()
        result = rule.evaluate(ctx)

        assert result.triggered is False


class TestCreateBrandCertRules:
    """Test create_brand_cert_rules factory."""

    def test_creates_all_rules(self):
        """Test that factory creates all expected rules."""
        rules = create_brand_cert_rules()

        assert len(rules) == 2
        names = [r.name for r in rules]
        assert "brand_cert_high" in names
        assert "benign_cert_gate_skip" in names

    def test_respects_enabled_flag(self):
        """Test that factory respects enabled flag."""
        rules = create_brand_cert_rules(enabled=False)

        for rule in rules:
            assert rule.enabled is False
