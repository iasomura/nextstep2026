# -*- coding: utf-8 -*-
"""
tests.rules.test_post_gates
---------------------------
Unit tests for post-processing gate rules.

変更履歴:
    - 2026-01-31: 初版作成
"""

import pytest
from phishing_agent.rules.detectors.base import RuleContext
from phishing_agent.rules.detectors.post_gates import (
    PostRandomPatternOnlyGateRule,
    MlNoMitigationGateRule,
    LowToMinMediumRule,
    create_post_gate_rules,
)


class TestPostRandomPatternOnlyGateRule:
    """PostRandomPatternOnlyGateRule tests."""

    def test_trigger_on_random_pattern_only_legit_tld(self):
        """Test trigger when only random_pattern on legitimate TLD."""
        ctx = RuleContext(
            domain="cryptpad.org",
            ml_probability=0.15,
            ctx_score=0.35,
            issue_set={"random_pattern"},
            llm_is_phishing=True,
            tld="org",
        )
        rule = PostRandomPatternOnlyGateRule()
        result = rule.evaluate(ctx)

        assert result.triggered is True
        assert result.force_benign is True
        assert result.confidence_ceiling == 0.35
        assert "post_random_pattern_only_gate" in result.issue_tag

    def test_trigger_with_short_signal(self):
        """Test trigger when random_pattern + short (non-risky combo)."""
        ctx = RuleContext(
            domain="xyz.com",
            ml_probability=0.15,
            ctx_score=0.35,
            issue_set={"random_pattern", "short"},  # short is non-risky
            llm_is_phishing=True,
            tld="com",
        )
        rule = PostRandomPatternOnlyGateRule()
        result = rule.evaluate(ctx)

        assert result.triggered is True

    def test_no_trigger_when_benign(self):
        """Test no trigger when already benign."""
        ctx = RuleContext(
            domain="cryptpad.org",
            ml_probability=0.15,
            ctx_score=0.35,
            issue_set={"random_pattern"},
            llm_is_phishing=False,
            tld="org",
        )
        rule = PostRandomPatternOnlyGateRule()
        result = rule.evaluate(ctx)

        assert result.triggered is False

    def test_no_trigger_on_brand_detected(self):
        """Test no trigger when brand is detected."""
        ctx = RuleContext(
            domain="paypal-xyz.com",
            ml_probability=0.15,
            ctx_score=0.35,
            issue_set={"random_pattern"},
            brand_details={"detected_brands": ["paypal"]},
            llm_is_phishing=True,
            tld="com",
        )
        rule = PostRandomPatternOnlyGateRule()
        result = rule.evaluate(ctx)

        assert result.triggered is False

    def test_no_trigger_on_dangerous_tld(self):
        """Test no trigger on dangerous TLD."""
        ctx = RuleContext(
            domain="example.tk",
            ml_probability=0.15,
            ctx_score=0.35,
            issue_set={"random_pattern", "dangerous_tld"},
            llm_is_phishing=True,
            tld="tk",
        )
        rule = PostRandomPatternOnlyGateRule()
        result = rule.evaluate(ctx)

        assert result.triggered is False

    def test_no_trigger_with_multiple_risky_issues(self):
        """Test no trigger with multiple risky issues."""
        ctx = RuleContext(
            domain="example.com",
            ml_probability=0.15,
            ctx_score=0.35,
            issue_set={"random_pattern", "idn_homograph"},  # Additional risky issue
            llm_is_phishing=True,
            tld="com",
        )
        rule = PostRandomPatternOnlyGateRule()
        result = rule.evaluate(ctx)

        assert result.triggered is False

    def test_no_trigger_with_high_entropy_in_ctx(self):
        """Test no trigger when high_entropy is in ctx_issues."""
        ctx = RuleContext(
            domain="example.com",
            ml_probability=0.15,
            ctx_score=0.35,
            issue_set={"random_pattern"},
            ctx_issues={"high_entropy"},
            llm_is_phishing=True,
            tld="com",
        )
        rule = PostRandomPatternOnlyGateRule()
        result = rule.evaluate(ctx)

        assert result.triggered is False


class TestMlNoMitigationGateRule:
    """MlNoMitigationGateRule tests."""

    def test_trigger_on_high_ml_no_mitigation(self):
        """Test trigger when ML >= 0.50 with no mitigation."""
        ctx = RuleContext(
            domain="example.com",
            ml_probability=0.55,
            ctx_score=0.40,
            llm_is_phishing=False,
            tld="com",
            is_known_legitimate=False,
            benign_indicators=set(),
        )
        rule = MlNoMitigationGateRule()
        result = rule.evaluate(ctx)

        assert result.triggered is True
        assert result.force_phishing is True
        assert result.confidence_floor == 0.55
        assert "ml_no_mitigation_gate" in result.issue_tag

    def test_no_trigger_when_already_phishing(self):
        """Test no trigger when already phishing."""
        ctx = RuleContext(
            domain="example.com",
            ml_probability=0.55,
            ctx_score=0.40,
            llm_is_phishing=True,
            tld="com",
        )
        rule = MlNoMitigationGateRule()
        result = rule.evaluate(ctx)

        assert result.triggered is False

    def test_no_trigger_on_low_ml(self):
        """Test no trigger when ML < 0.50."""
        ctx = RuleContext(
            domain="example.com",
            ml_probability=0.40,
            ctx_score=0.40,
            llm_is_phishing=False,
            tld="com",
        )
        rule = MlNoMitigationGateRule()
        result = rule.evaluate(ctx)

        assert result.triggered is False

    def test_no_trigger_on_allowlist(self):
        """Test no trigger when on allowlist."""
        ctx = RuleContext(
            domain="example.com",
            ml_probability=0.55,
            ctx_score=0.40,
            llm_is_phishing=False,
            tld="com",
            is_known_legitimate=True,
        )
        rule = MlNoMitigationGateRule()
        result = rule.evaluate(ctx)

        assert result.triggered is False

    def test_no_trigger_with_benign_cert(self):
        """Test no trigger when benign cert indicator present (ML < 0.70)."""
        ctx = RuleContext(
            domain="example.com",
            ml_probability=0.55,  # < 0.70
            ctx_score=0.40,
            llm_is_phishing=False,
            tld="com",
            benign_indicators={"ov_ev_cert"},
        )
        rule = MlNoMitigationGateRule()
        result = rule.evaluate(ctx)

        assert result.triggered is False

    def test_trigger_with_benign_cert_high_ml(self):
        """Test trigger when benign cert but ML >= 0.70."""
        ctx = RuleContext(
            domain="example.com",
            ml_probability=0.75,  # >= 0.70
            ctx_score=0.40,
            llm_is_phishing=False,
            tld="com",
            benign_indicators={"ov_ev_cert"},
        )
        rule = MlNoMitigationGateRule()
        result = rule.evaluate(ctx)

        assert result.triggered is True

    def test_skip_on_non_dangerous_tld_low_ctx(self):
        """Test skip on non-dangerous TLD with ctx < 0.30."""
        ctx = RuleContext(
            domain="example.com",
            ml_probability=0.55,
            ctx_score=0.25,  # < 0.30
            llm_is_phishing=False,
            tld="com",  # Non-dangerous
        )
        rule = MlNoMitigationGateRule()
        result = rule.evaluate(ctx)

        assert result.triggered is False
        assert "skip_reason" in result.details


class TestLowToMinMediumRule:
    """LowToMinMediumRule tests."""

    def test_trigger_on_phishing_low_risk(self):
        """Test trigger when phishing with low risk level."""
        ctx = RuleContext(
            domain="example.com",
            ml_probability=0.30,
            ctx_score=0.40,
            llm_is_phishing=True,
            llm_risk_level="low",
        )
        rule = LowToMinMediumRule()
        result = rule.evaluate(ctx)

        assert result.triggered is True
        assert result.risk_level_bump == "medium"
        assert "low_to_min_medium" in result.issue_tag

    def test_no_trigger_when_benign(self):
        """Test no trigger when benign."""
        ctx = RuleContext(
            domain="example.com",
            ml_probability=0.30,
            ctx_score=0.40,
            llm_is_phishing=False,
            llm_risk_level="low",
        )
        rule = LowToMinMediumRule()
        result = rule.evaluate(ctx)

        assert result.triggered is False

    def test_no_trigger_on_medium_risk(self):
        """Test no trigger when already medium risk."""
        ctx = RuleContext(
            domain="example.com",
            ml_probability=0.30,
            ctx_score=0.40,
            llm_is_phishing=True,
            llm_risk_level="medium",
        )
        rule = LowToMinMediumRule()
        result = rule.evaluate(ctx)

        assert result.triggered is False

    def test_no_trigger_on_high_risk(self):
        """Test no trigger when already high risk."""
        ctx = RuleContext(
            domain="example.com",
            ml_probability=0.30,
            ctx_score=0.40,
            llm_is_phishing=True,
            llm_risk_level="high",
        )
        rule = LowToMinMediumRule()
        result = rule.evaluate(ctx)

        assert result.triggered is False


class TestCreatePostGateRules:
    """Test create_post_gate_rules factory."""

    def test_creates_all_rules(self):
        """Test that factory creates all expected rules."""
        rules = create_post_gate_rules()

        assert len(rules) == 3
        names = [r.name for r in rules]
        assert "post_random_pattern_only_gate" in names
        assert "ml_no_mitigation_gate" in names
        assert "low_to_min_medium" in names

    def test_respects_enabled_flag(self):
        """Test that factory respects enabled flag."""
        rules = create_post_gate_rules(enabled=False)

        for rule in rules:
            assert rule.enabled is False
