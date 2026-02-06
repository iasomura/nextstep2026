# -*- coding: utf-8 -*-
"""
tests.rules.test_ml_guard
-------------------------
Unit tests for ML guard rules.

変更履歴:
    - 2026-01-31: 初版作成
"""

import pytest
from phishing_agent.rules.detectors.base import RuleContext
from phishing_agent.rules.detectors.ml_guard import (
    VeryHighMLOverrideRule,
    HighMLOverrideRule,
    HighMLCtxRescueRule,
    UltraLowMLBlockRule,
    PostLLMFlipGateRule,
    create_ml_guard_rules,
)


class TestVeryHighMLOverrideRule:
    """VeryHighMLOverrideRule tests."""

    def test_trigger_on_very_high_ml(self):
        """Test trigger when ML >= 0.85."""
        ctx = RuleContext(
            domain="example.com",
            ml_probability=0.90,
            ctx_score=0.30,
            llm_is_phishing=False,
            llm_risk_level="low",
            tld="com",
        )
        rule = VeryHighMLOverrideRule()
        result = rule.evaluate(ctx)

        assert result.triggered is True
        assert result.force_phishing is True
        assert result.confidence_floor == 0.80
        assert "very_high_ml_override" in result.issue_tag

    def test_no_trigger_when_already_phishing(self):
        """Test no trigger when already phishing."""
        ctx = RuleContext(
            domain="example.com",
            ml_probability=0.90,
            ctx_score=0.30,
            llm_is_phishing=True,
            llm_risk_level="high",
            tld="com",
        )
        rule = VeryHighMLOverrideRule()
        result = rule.evaluate(ctx)

        assert result.triggered is False

    def test_no_trigger_on_low_ml(self):
        """Test no trigger when ML < 0.85."""
        ctx = RuleContext(
            domain="example.com",
            ml_probability=0.70,
            ctx_score=0.30,
            llm_is_phishing=False,
            llm_risk_level="low",
            tld="com",
        )
        rule = VeryHighMLOverrideRule()
        result = rule.evaluate(ctx)

        assert result.triggered is False

    def test_no_trigger_on_gov_domain(self):
        """Test no trigger on government domain."""
        ctx = RuleContext(
            domain="example.gov.in",
            ml_probability=0.90,
            ctx_score=0.30,
            llm_is_phishing=False,
            llm_risk_level="low",
            tld="gov.in",
            registered_domain="example.gov.in",
        )
        rule = VeryHighMLOverrideRule()
        result = rule.evaluate(ctx)

        assert result.triggered is False

    def test_no_trigger_on_edu_domain(self):
        """Test no trigger on education domain."""
        ctx = RuleContext(
            domain="university.edu",
            ml_probability=0.90,
            ctx_score=0.30,
            llm_is_phishing=False,
            llm_risk_level="low",
            tld="edu",
            registered_domain="university.edu",
        )
        rule = VeryHighMLOverrideRule()
        result = rule.evaluate(ctx)

        assert result.triggered is False

    def test_no_trigger_on_allowlist(self):
        """Test no trigger when on allowlist."""
        ctx = RuleContext(
            domain="example.com",
            ml_probability=0.90,
            ctx_score=0.30,
            llm_is_phishing=False,
            llm_risk_level="low",
            tld="com",
            is_known_legitimate=True,
        )
        rule = VeryHighMLOverrideRule()
        result = rule.evaluate(ctx)

        assert result.triggered is False


class TestHighMLOverrideRule:
    """HighMLOverrideRule tests."""

    def test_trigger_with_random_signal(self):
        """Test trigger when ML >= 0.40 with random signal."""
        ctx = RuleContext(
            domain="xyz123.com",
            ml_probability=0.50,
            ctx_score=0.35,
            issue_set={"random_pattern"},
            llm_is_phishing=False,
            llm_risk_level="low",
            tld="com",
        )
        rule = HighMLOverrideRule()
        result = rule.evaluate(ctx)

        assert result.triggered is True
        assert result.force_phishing is True
        assert result.confidence_floor == 0.65

    def test_trigger_with_dangerous_tld(self):
        """Test trigger when ML >= 0.40 with dangerous TLD."""
        ctx = RuleContext(
            domain="example.tk",
            ml_probability=0.50,
            ctx_score=0.35,
            issue_set={"dangerous_tld"},
            llm_is_phishing=False,
            llm_risk_level="low",
            tld="tk",
        )
        rule = HighMLOverrideRule()
        result = rule.evaluate(ctx)

        assert result.triggered is True

    def test_no_trigger_without_signals(self):
        """Test no trigger without random/dangerous signals."""
        ctx = RuleContext(
            domain="example.com",
            ml_probability=0.50,
            ctx_score=0.35,
            issue_set=set(),
            llm_is_phishing=False,
            llm_risk_level="low",
            tld="com",
        )
        rule = HighMLOverrideRule()
        result = rule.evaluate(ctx)

        assert result.triggered is False

    def test_no_trigger_on_ml_below_threshold(self):
        """Test no trigger when ML < 0.40."""
        ctx = RuleContext(
            domain="xyz123.com",
            ml_probability=0.30,
            ctx_score=0.35,
            issue_set={"random_pattern"},
            llm_is_phishing=False,
            llm_risk_level="low",
            tld="com",
        )
        rule = HighMLOverrideRule()
        result = rule.evaluate(ctx)

        assert result.triggered is False

    def test_no_trigger_on_very_high_ml(self):
        """Test no trigger when ML >= 0.85 (handled by VeryHighMLOverrideRule)."""
        ctx = RuleContext(
            domain="xyz123.com",
            ml_probability=0.90,
            ctx_score=0.35,
            issue_set={"random_pattern"},
            llm_is_phishing=False,
            llm_risk_level="low",
            tld="com",
        )
        rule = HighMLOverrideRule()
        result = rule.evaluate(ctx)

        assert result.triggered is False


class TestHighMLCtxRescueRule:
    """HighMLCtxRescueRule tests."""

    def test_trigger_on_ml_ctx_combo(self):
        """Test trigger when ML >= 0.35 and Ctx in [0.40, 0.50)."""
        ctx = RuleContext(
            domain="example.com",
            ml_probability=0.40,
            ctx_score=0.45,
            llm_is_phishing=False,
            llm_risk_level="low",
            tld="com",
        )
        rule = HighMLCtxRescueRule()
        result = rule.evaluate(ctx)

        assert result.triggered is True
        assert result.force_phishing is True
        assert "high_ml_ctx_rescue" in result.issue_tag

    def test_no_trigger_when_ctx_too_high(self):
        """Test no trigger when Ctx >= 0.50."""
        ctx = RuleContext(
            domain="example.com",
            ml_probability=0.40,
            ctx_score=0.55,
            llm_is_phishing=False,
            llm_risk_level="low",
            tld="com",
        )
        rule = HighMLCtxRescueRule()
        result = rule.evaluate(ctx)

        assert result.triggered is False

    def test_no_trigger_when_ctx_too_low(self):
        """Test no trigger when Ctx < 0.40."""
        ctx = RuleContext(
            domain="example.com",
            ml_probability=0.40,
            ctx_score=0.35,
            llm_is_phishing=False,
            llm_risk_level="low",
            tld="com",
        )
        rule = HighMLCtxRescueRule()
        result = rule.evaluate(ctx)

        assert result.triggered is False

    def test_no_trigger_when_ml_too_low(self):
        """Test no trigger when ML < 0.35."""
        ctx = RuleContext(
            domain="example.com",
            ml_probability=0.30,
            ctx_score=0.45,
            llm_is_phishing=False,
            llm_risk_level="low",
            tld="com",
        )
        rule = HighMLCtxRescueRule()
        result = rule.evaluate(ctx)

        assert result.triggered is False

    def test_no_trigger_on_gov_domain(self):
        """Test no trigger on government domain."""
        ctx = RuleContext(
            domain="example.gov.uk",
            ml_probability=0.40,
            ctx_score=0.45,
            llm_is_phishing=False,
            llm_risk_level="low",
            tld="gov.uk",
            registered_domain="example.gov.uk",
        )
        rule = HighMLCtxRescueRule()
        result = rule.evaluate(ctx)

        assert result.triggered is False


class TestUltraLowMLBlockRule:
    """UltraLowMLBlockRule tests."""

    def test_trigger_on_ultra_low_ml(self):
        """Test trigger when ML < 0.05, no brand, no dangerous TLD."""
        ctx = RuleContext(
            domain="example.com",
            ml_probability=0.02,
            ctx_score=0.35,
            llm_is_phishing=True,
            tld="com",
            brand_details={"detected_brands": []},
        )
        rule = UltraLowMLBlockRule()
        result = rule.evaluate(ctx)

        assert result.triggered is True
        assert result.force_benign is True
        assert "ultra_low_ml_block" in result.issue_tag

    def test_no_trigger_when_benign(self):
        """Test no trigger when already benign."""
        ctx = RuleContext(
            domain="example.com",
            ml_probability=0.02,
            ctx_score=0.35,
            llm_is_phishing=False,
            tld="com",
        )
        rule = UltraLowMLBlockRule()
        result = rule.evaluate(ctx)

        assert result.triggered is False

    def test_no_trigger_on_brand_detected(self):
        """Test no trigger when brand is detected."""
        ctx = RuleContext(
            domain="paypal-login.com",
            ml_probability=0.02,
            ctx_score=0.35,
            llm_is_phishing=True,
            tld="com",
            brand_details={"detected_brands": ["paypal"]},
        )
        rule = UltraLowMLBlockRule()
        result = rule.evaluate(ctx)

        assert result.triggered is False

    def test_no_trigger_on_dangerous_tld(self):
        """Test no trigger on dangerous TLD."""
        ctx = RuleContext(
            domain="example.tk",
            ml_probability=0.02,
            ctx_score=0.35,
            llm_is_phishing=True,
            tld="tk",
            issue_set={"dangerous_tld"},
            brand_details={"detected_brands": []},
        )
        rule = UltraLowMLBlockRule()
        result = rule.evaluate(ctx)

        assert result.triggered is False


class TestPostLLMFlipGateRule:
    """PostLLMFlipGateRule tests."""

    def test_trigger_on_low_ml_non_dangerous_tld(self):
        """Test trigger when ML < 0.30 on non-dangerous TLD."""
        ctx = RuleContext(
            domain="example.com",
            ml_probability=0.15,
            ctx_score=0.35,
            llm_is_phishing=True,
            tld="com",
        )
        rule = PostLLMFlipGateRule()
        result = rule.evaluate(ctx)

        assert result.triggered is True
        assert result.force_benign is True
        assert "post_llm_flip_gate" in result.issue_tag

    def test_no_trigger_on_high_ctx(self):
        """Test bypass when ctx >= 0.65."""
        ctx = RuleContext(
            domain="example.com",
            ml_probability=0.15,
            ctx_score=0.70,
            llm_is_phishing=True,
            tld="com",
        )
        rule = PostLLMFlipGateRule()
        result = rule.evaluate(ctx)

        assert result.triggered is False

    def test_no_trigger_on_brand_detected(self):
        """Test bypass when brand is detected."""
        ctx = RuleContext(
            domain="paypal-login.com",
            ml_probability=0.15,
            ctx_score=0.35,
            llm_is_phishing=True,
            tld="com",
            brand_details={"detected_brands": ["paypal"]},
        )
        rule = PostLLMFlipGateRule()
        result = rule.evaluate(ctx)

        assert result.triggered is False

    def test_no_trigger_on_medium_danger_tld_low_ml(self):
        """Test gate behavior on medium danger TLD (threshold 0.04)."""
        ctx = RuleContext(
            domain="example.online",
            ml_probability=0.02,  # Below 0.04
            ctx_score=0.35,
            llm_is_phishing=True,
            tld="online",  # Medium danger
        )
        rule = PostLLMFlipGateRule()
        result = rule.evaluate(ctx)

        assert result.triggered is True

    def test_bypass_on_random_pattern_with_soft_ctx(self):
        """Test bypass on random_pattern + short with ctx >= 0.50."""
        ctx = RuleContext(
            domain="xyz123.com",
            ml_probability=0.15,
            ctx_score=0.55,
            issue_set={"random_pattern", "short"},
            llm_is_phishing=True,
            tld="com",
            registered_domain="xyz123.com",
        )
        rule = PostLLMFlipGateRule()
        result = rule.evaluate(ctx)

        assert result.triggered is False  # Bypassed

    def test_no_bypass_on_gov_domain_with_random(self):
        """Test no bypass on gov domain even with random pattern."""
        ctx = RuleContext(
            domain="sscsr.gov.in",
            ml_probability=0.15,
            ctx_score=0.55,
            issue_set={"random_pattern", "short"},
            llm_is_phishing=True,
            tld="gov.in",
            registered_domain="sscsr.gov.in",
        )
        rule = PostLLMFlipGateRule()
        result = rule.evaluate(ctx)

        # On gov domain, random pattern bypass should not work
        assert result.triggered is True  # Gate applies


class TestCreateMLGuardRules:
    """Test create_ml_guard_rules factory."""

    def test_creates_all_rules(self):
        """Test that factory creates all expected rules."""
        rules = create_ml_guard_rules()

        assert len(rules) == 5
        names = [r.name for r in rules]
        assert "very_high_ml_override" in names
        assert "high_ml_override" in names
        assert "high_ml_ctx_rescue" in names
        assert "ultra_low_ml_block" in names
        assert "post_llm_flip_gate" in names

    def test_respects_enabled_flag(self):
        """Test that factory respects enabled flag."""
        rules = create_ml_guard_rules(enabled=False)

        for rule in rules:
            assert rule.enabled is False
