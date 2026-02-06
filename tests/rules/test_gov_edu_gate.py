# -*- coding: utf-8 -*-
"""
tests.rules.test_gov_edu_gate
-----------------------------
Unit tests for government/education gate rules.

変更履歴:
    - 2026-01-31: 初版作成
"""

import pytest
from phishing_agent.rules.detectors.base import RuleContext
from phishing_agent.rules.detectors.gov_edu_gate import (
    GovEduBenignGateRule,
    create_gov_edu_gate_rules,
)


class TestGovEduBenignGateRule:
    """GovEduBenignGateRule tests."""

    def test_trigger_on_gov_domain(self):
        """Test trigger on .gov domain."""
        ctx = RuleContext(
            domain="example.gov",
            ml_probability=0.15,
            ctx_score=0.40,
            llm_is_phishing=True,
            tld="gov",
            registered_domain="example.gov",
        )
        rule = GovEduBenignGateRule()
        result = rule.evaluate(ctx)

        assert result.triggered is True
        assert result.force_benign is True
        assert "gov_edu_benign_gate" in result.issue_tag

    def test_trigger_on_gov_in_domain(self):
        """Test trigger on .gov.in domain."""
        ctx = RuleContext(
            domain="sscsr.gov.in",
            ml_probability=0.15,
            ctx_score=0.45,
            llm_is_phishing=True,
            tld="gov.in",
            registered_domain="sscsr.gov.in",
        )
        rule = GovEduBenignGateRule()
        result = rule.evaluate(ctx)

        assert result.triggered is True
        assert result.force_benign is True

    def test_trigger_on_edu_domain(self):
        """Test trigger on .edu domain."""
        ctx = RuleContext(
            domain="university.edu",
            ml_probability=0.15,
            ctx_score=0.40,
            llm_is_phishing=True,
            tld="edu",
            registered_domain="university.edu",
        )
        rule = GovEduBenignGateRule()
        result = rule.evaluate(ctx)

        assert result.triggered is True
        assert result.force_benign is True

    def test_trigger_on_mil_domain(self):
        """Test trigger on .mil domain."""
        ctx = RuleContext(
            domain="base.mil",
            ml_probability=0.15,
            ctx_score=0.40,
            llm_is_phishing=True,
            tld="mil",
            registered_domain="base.mil",
        )
        rule = GovEduBenignGateRule()
        result = rule.evaluate(ctx)

        assert result.triggered is True
        assert result.force_benign is True

    def test_trigger_on_ac_uk_domain(self):
        """Test trigger on .ac.uk domain."""
        ctx = RuleContext(
            domain="oxford.ac.uk",
            ml_probability=0.15,
            ctx_score=0.40,
            llm_is_phishing=True,
            tld="ac.uk",
            registered_domain="oxford.ac.uk",
        )
        rule = GovEduBenignGateRule()
        result = rule.evaluate(ctx)

        assert result.triggered is True

    def test_trigger_on_go_jp_domain(self):
        """Test trigger on .go.jp domain."""
        ctx = RuleContext(
            domain="ministry.go.jp",
            ml_probability=0.15,
            ctx_score=0.40,
            llm_is_phishing=True,
            tld="go.jp",
            registered_domain="ministry.go.jp",
        )
        rule = GovEduBenignGateRule()
        result = rule.evaluate(ctx)

        assert result.triggered is True

    def test_trigger_on_gov_wales_domain(self):
        """Test trigger on gov.wales domain (registered domain pattern)."""
        ctx = RuleContext(
            domain="estyn.gov.wales",
            ml_probability=0.15,
            ctx_score=0.45,
            llm_is_phishing=True,
            tld="wales",
            registered_domain="gov.wales",
        )
        rule = GovEduBenignGateRule()
        result = rule.evaluate(ctx)

        assert result.triggered is True

    def test_no_trigger_when_already_benign(self):
        """Test no trigger when already benign."""
        ctx = RuleContext(
            domain="example.gov",
            ml_probability=0.15,
            ctx_score=0.40,
            llm_is_phishing=False,
            tld="gov",
            registered_domain="example.gov",
        )
        rule = GovEduBenignGateRule()
        result = rule.evaluate(ctx)

        assert result.triggered is False

    def test_no_trigger_on_non_gov_domain(self):
        """Test no trigger on non-government domain."""
        ctx = RuleContext(
            domain="example.com",
            ml_probability=0.15,
            ctx_score=0.40,
            llm_is_phishing=True,
            tld="com",
            registered_domain="example.com",
        )
        rule = GovEduBenignGateRule()
        result = rule.evaluate(ctx)

        assert result.triggered is False

    def test_no_trigger_on_brand_detected(self):
        """Test no trigger when brand is detected on gov domain."""
        ctx = RuleContext(
            domain="paypal.gov.fake",
            ml_probability=0.15,
            ctx_score=0.40,
            llm_is_phishing=True,
            tld="gov.fake",
            registered_domain="gov.fake",
            brand_details={"detected_brands": ["paypal"]},
        )
        rule = GovEduBenignGateRule()
        result = rule.evaluate(ctx)

        # Brands should be in skip_reason, not a trigger
        assert result.triggered is False
        assert "skip_reason" in result.details
        assert "brand_detected" in result.details["skip_reason"]


class TestCreateGovEduGateRules:
    """Test create_gov_edu_gate_rules factory."""

    def test_creates_all_rules(self):
        """Test that factory creates all expected rules."""
        rules = create_gov_edu_gate_rules()

        assert len(rules) == 1
        assert rules[0].name == "gov_edu_benign_gate"

    def test_respects_enabled_flag(self):
        """Test that factory respects enabled flag."""
        rules = create_gov_edu_gate_rules(enabled=False)

        for rule in rules:
            assert rule.enabled is False
