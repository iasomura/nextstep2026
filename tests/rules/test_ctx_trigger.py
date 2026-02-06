# -*- coding: utf-8 -*-
"""
tests.rules.test_ctx_trigger
-----------------------------
Unit tests for CTX trigger rules.

変更履歴:
    - 2026-01-31: 初版作成
"""

import pytest
from phishing_agent.rules.detectors.base import RuleContext
from phishing_agent.rules.detectors.ctx_trigger import (
    HardCtxTriggerRule,
    SoftCtxTriggerRule,
    create_ctx_trigger_rules,
)


class TestHardCtxTriggerRule:
    """HardCtxTriggerRule tests."""

    def test_trigger_on_high_ctx(self):
        """Test trigger when ctx >= 0.65."""
        ctx = RuleContext(
            domain="example.com",
            ml_probability=0.10,
            ctx_score=0.70,
            llm_is_phishing=False,
        )
        rule = HardCtxTriggerRule()
        result = rule.evaluate(ctx)

        assert result.triggered is True
        assert result.force_phishing is True
        assert result.confidence_floor == 0.70
        assert "hard_ctx_trigger" in result.issue_tag

    def test_no_trigger_when_already_phishing(self):
        """Test no trigger when already phishing."""
        ctx = RuleContext(
            domain="example.com",
            ml_probability=0.10,
            ctx_score=0.70,
            llm_is_phishing=True,
        )
        rule = HardCtxTriggerRule()
        result = rule.evaluate(ctx)

        assert result.triggered is False

    def test_no_trigger_when_ctx_below_threshold(self):
        """Test no trigger when ctx < 0.65."""
        ctx = RuleContext(
            domain="example.com",
            ml_probability=0.10,
            ctx_score=0.50,
            llm_is_phishing=False,
        )
        rule = HardCtxTriggerRule()
        result = rule.evaluate(ctx)

        assert result.triggered is False

    def test_custom_threshold(self):
        """Test with custom threshold."""
        ctx = RuleContext(
            domain="example.com",
            ml_probability=0.10,
            ctx_score=0.55,
            llm_is_phishing=False,
        )
        rule = HardCtxTriggerRule(ctx_threshold=0.50)
        result = rule.evaluate(ctx)

        assert result.triggered is True


class TestSoftCtxTriggerRule:
    """SoftCtxTriggerRule tests."""

    def test_trigger_with_strong_evidence(self):
        """Test trigger when ctx >= 0.50 with strong evidence."""
        ctx = RuleContext(
            domain="example.com",
            ml_probability=0.10,
            ctx_score=0.55,
            issue_set={"dangerous_tld", "short"},
            llm_is_phishing=False,
        )
        rule = SoftCtxTriggerRule()
        result = rule.evaluate(ctx)

        assert result.triggered is True
        assert result.force_phishing is True
        assert result.confidence_floor == 0.60

    def test_trigger_with_brand_detected(self):
        """Test trigger when brand is detected."""
        ctx = RuleContext(
            domain="example.com",
            ml_probability=0.10,
            ctx_score=0.55,
            issue_set=set(),
            brand_details={"detected_brands": ["paypal"]},
            llm_is_phishing=False,
        )
        rule = SoftCtxTriggerRule()
        result = rule.evaluate(ctx)

        assert result.triggered is True

    def test_no_trigger_without_strong_evidence(self):
        """Test no trigger without strong evidence."""
        ctx = RuleContext(
            domain="example.com",
            ml_probability=0.10,
            ctx_score=0.55,
            issue_set=set(),  # No strong evidence
            llm_is_phishing=False,
        )
        rule = SoftCtxTriggerRule()
        result = rule.evaluate(ctx)

        assert result.triggered is False

    def test_no_trigger_when_ctx_too_high(self):
        """Test no trigger when ctx >= 0.65 (handled by hard trigger)."""
        ctx = RuleContext(
            domain="example.com",
            ml_probability=0.10,
            ctx_score=0.70,
            issue_set={"dangerous_tld"},
            llm_is_phishing=False,
        )
        rule = SoftCtxTriggerRule()
        result = rule.evaluate(ctx)

        assert result.triggered is False  # Should be handled by HardCtxTriggerRule

    def test_no_trigger_when_ctx_too_low(self):
        """Test no trigger when ctx < 0.50."""
        ctx = RuleContext(
            domain="example.com",
            ml_probability=0.10,
            ctx_score=0.45,
            issue_set={"dangerous_tld"},
            llm_is_phishing=False,
        )
        rule = SoftCtxTriggerRule()
        result = rule.evaluate(ctx)

        assert result.triggered is False

    def test_trigger_with_random_pattern_combo(self):
        """Test trigger with random_pattern + short combo."""
        ctx = RuleContext(
            domain="abc123.com",
            ml_probability=0.10,
            ctx_score=0.55,
            issue_set={"random_pattern", "short"},
            llm_is_phishing=False,
            tld="com",
            registered_domain="abc123.com",
        )
        rule = SoftCtxTriggerRule()
        result = rule.evaluate(ctx)

        assert result.triggered is True

    def test_no_trigger_on_gov_domain_with_random(self):
        """Test no trigger on gov domain even with random pattern."""
        ctx = RuleContext(
            domain="sscsr.gov.in",
            ml_probability=0.10,
            ctx_score=0.55,
            issue_set={"random_pattern"},
            llm_is_phishing=False,
            tld="gov.in",
            registered_domain="sscsr.gov.in",
        )
        rule = SoftCtxTriggerRule()
        result = rule.evaluate(ctx)

        # random_pattern alone on gov domain should not trigger
        # because _is_gov_edu_tld returns True
        assert result.triggered is False


class TestCreateCtxTriggerRules:
    """Test create_ctx_trigger_rules factory."""

    def test_creates_all_rules(self):
        """Test that factory creates all expected rules."""
        rules = create_ctx_trigger_rules()

        assert len(rules) == 2
        names = [r.name for r in rules]
        assert "hard_ctx_trigger" in names
        assert "soft_ctx_trigger" in names

    def test_respects_enabled_flag(self):
        """Test that factory respects enabled flag."""
        rules = create_ctx_trigger_rules(enabled=False)

        for rule in rules:
            assert rule.enabled is False
