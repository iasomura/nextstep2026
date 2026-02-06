# -*- coding: utf-8 -*-
"""
tests.rules.test_context_builder
---------------------------------
Unit tests for RuleContextBuilder.

変更履歴:
    - 2026-01-31: 初版作成
"""

import pytest
from phishing_agent.rules.context_builder import RuleContextBuilder
from phishing_agent.agent_foundations import PhishingAssessment


class TestRuleContextBuilder:
    """RuleContextBuilder tests."""

    def test_build_basic(self):
        """Test basic context building."""
        tool_summary = {
            "brand": {"risk_score": 0.5, "issues": ["brand_detected"], "brands": ["paypal"]},
            "cert": {"risk_score": 0.3, "issues": ["free_ca"], "details": {"valid_days": 90}},
            "domain": {"risk_score": 0.4, "issues": ["short", "random_pattern"], "details": {}},
            "contextual": {"risk_score": 0.55, "issues": ["dv_suspicious_combo"]},
        }
        precheck = {
            "etld1": {"suffix": "com", "registered_domain": "example.com"},
            "tld_category": "legitimate",
        }
        llm_assessment = PhishingAssessment(
            is_phishing=True,
            confidence=0.85,
            risk_level="high",
            detected_brands=["paypal"],
            risk_factors=["brand_detected", "free_ca"],
            reasoning="Brand detected with low quality certificate",
        )

        ctx = RuleContextBuilder.build(
            domain="example.com",
            ml_probability=0.35,
            tool_summary=tool_summary,
            precheck=precheck,
            llm_assessment=llm_assessment,
        )

        # Basic fields
        assert ctx.domain == "example.com"
        assert ctx.ml_probability == 0.35
        assert ctx.tld == "com"
        assert ctx.registered_domain == "example.com"

        # Issue set (domain issues are in issue_set, cert issues merged)
        assert "free_ca" in ctx.issue_set
        assert "short" in ctx.issue_set
        assert "random_pattern" in ctx.issue_set
        assert "dv_suspicious_combo" in ctx.ctx_issues
        # Brand issues are stored in brand_details, not issue_set
        assert "brand_detected" in ctx.brand_details.get("issues", [])

        # Contextual score
        assert ctx.ctx_score == 0.55

        # LLM assessment fields
        assert ctx.llm_is_phishing is True
        assert ctx.llm_confidence == 0.85
        assert ctx.llm_risk_level == "high"

        # Brand details
        assert ctx.brand_details.get("detected_brands") == ["paypal"]

    def test_build_with_benign_indicators(self):
        """Test context building with benign indicators."""
        tool_summary = {
            "brand": {"risk_score": 0.0, "issues": [], "brands": []},
            "cert": {
                "risk_score": 0.1,
                "issues": [],
                "details": {
                    "benign_indicators": ["ov_ev_cert", "has_crl_dp"],
                    "valid_days": 365,
                },
            },
            "domain": {"risk_score": 0.2, "issues": [], "details": {}},
            "contextual": {"risk_score": 0.3, "issues": []},
        }
        precheck = {
            "etld1": {"suffix": "org", "registered_domain": "example.org"},
            "tld_category": "legitimate",
        }

        ctx = RuleContextBuilder.build(
            domain="example.org",
            ml_probability=0.10,
            tool_summary=tool_summary,
            precheck=precheck,
            llm_assessment=None,
        )

        # Benign indicators
        assert "ov_ev_cert" in ctx.benign_indicators
        assert "has_crl_dp" in ctx.benign_indicators

        # LLM assessment is None
        assert ctx.llm_is_phishing is None

    def test_build_with_dangerous_tld(self):
        """Test context building with dangerous TLD."""
        tool_summary = {
            "brand": {"risk_score": 0.0, "issues": [], "brands": []},
            "cert": {"risk_score": 0.5, "issues": ["free_ca", "no_org"], "details": {}},
            "domain": {"risk_score": 0.7, "issues": ["dangerous_tld", "short"], "details": {}},
            "contextual": {"risk_score": 0.6, "issues": ["dangerous_tld"]},
        }
        precheck = {
            "etld1": {"suffix": "tk", "registered_domain": "test.tk"},
            "tld_category": "dangerous",
        }

        ctx = RuleContextBuilder.build(
            domain="test.tk",
            ml_probability=0.05,
            tool_summary=tool_summary,
            precheck=precheck,
            llm_assessment=None,
        )

        # TLD
        assert ctx.tld == "tk"

        # Dangerous TLD in issues
        assert "dangerous_tld" in ctx.issue_set
        assert "dangerous_tld" in ctx.ctx_issues

        # Precheck
        assert ctx.precheck.get("tld_category") == "dangerous"

    def test_build_from_full_state(self):
        """Test context building from full graph state."""
        graph_state = {
            "tool_results": {
                "brand": {
                    "risk_score": 0.0,
                    "detected_issues": [],
                    "details": {"detected_brands": []},
                },
                "cert": {
                    "risk_score": 0.2,
                    "detected_issues": [],
                    "details": {},
                },
                "domain": {
                    "risk_score": 0.3,
                    "detected_issues": ["short"],
                    "details": {},
                },
                "contextual_risk_assessment": {
                    "risk_score": 0.35,
                    "detected_issues": [],
                },
            },
            "precheck": {
                "etld1": {"suffix": "net", "registered_domain": "test.net"},
                "tld_category": "neutral",
            },
            "ml_probability": 0.25,
        }
        llm_assessment = PhishingAssessment(
            is_phishing=False,
            confidence=0.70,
            risk_level="low",
            detected_brands=[],
            risk_factors=[],
            reasoning="No significant risk factors detected",
        )

        ctx = RuleContextBuilder.build_from_full_state(
            domain="test.net",
            graph_state=graph_state,
            llm_assessment=llm_assessment,
        )

        assert ctx.domain == "test.net"
        assert ctx.ml_probability == 0.25
        assert ctx.tld == "net"
        assert ctx.llm_is_phishing is False

    def test_build_with_empty_data(self):
        """Test context building with empty data."""
        ctx = RuleContextBuilder.build(
            domain="empty.com",
            ml_probability=0.0,
            tool_summary={},
            precheck={},
            llm_assessment=None,
        )

        assert ctx.domain == "empty.com"
        assert ctx.ml_probability == 0.0
        assert ctx.tld == ""
        assert ctx.ctx_score == 0.0
        assert len(ctx.issue_set) == 0
        assert ctx.llm_is_phishing is None

    def test_backward_compatibility_benign_indicators(self):
        """Test backward compatibility for benign indicators without the field."""
        tool_summary = {
            "brand": {"risk_score": 0.0, "issues": [], "brands": []},
            "cert": {
                "risk_score": 0.1,
                "issues": [],
                "details": {
                    # No "benign_indicators" field, but has individual flags
                    "has_org": True,
                    "has_crl_dp": True,
                    "is_wildcard": True,
                    "is_dangerous_tld": False,
                },
            },
            "domain": {"risk_score": 0.1, "issues": [], "details": {}},
            "contextual": {"risk_score": 0.2, "issues": []},
        }

        ctx = RuleContextBuilder.build(
            domain="legacy.com",
            ml_probability=0.15,
            tool_summary=tool_summary,
            precheck={},
            llm_assessment=None,
        )

        # Should extract benign indicators from individual flags
        assert "ov_ev_cert" in ctx.benign_indicators
        assert "has_crl_dp" in ctx.benign_indicators
        assert "wildcard_cert" in ctx.benign_indicators
