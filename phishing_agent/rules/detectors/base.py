# -*- coding: utf-8 -*-
"""
phishing_agent.rules.detectors.base
-----------------------------------
Base classes for detection rules.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Set, Dict, List, Optional, Any


@dataclass
class RuleContext:
    """Context for rule evaluation.

    Contains all information needed to evaluate detection rules.

    Attributes:
        domain: The domain being analyzed
        ml_probability: ML model's phishing probability (0.0-1.0)
        issue_set: Set of detected issues from all tools
        tool_risks: Risk scores from each tool {tool_name: score}
        cert_details: Certificate analysis details
        brand_details: Brand impersonation check details
        domain_details: Short domain analysis details
        is_known_legitimate: Whether domain is in known legitimate list
        tld: Top-level domain suffix
        registered_domain: Registered domain part

    Phase6 拡張フィールド:
        ctx_score: Contextual risk assessment のスコア
        ctx_issues: Contextual risk assessment で検出された issues
        precheck: Precheck結果
        benign_indicators: 証明書による benign indicators (ov_ev_cert, has_crl 等)
        llm_is_phishing: LLM判定結果 (Phase6ゲート用)
        llm_confidence: LLM confidence
        llm_risk_level: LLM risk level (low/medium/high)

    変更履歴:
        - 2026-01-27: Phase6対応のためフィールド追加
    """
    domain: str
    ml_probability: float = 0.0
    issue_set: Set[str] = field(default_factory=set)
    tool_risks: Dict[str, float] = field(default_factory=dict)
    cert_details: Dict[str, Any] = field(default_factory=dict)
    brand_details: Dict[str, Any] = field(default_factory=dict)
    domain_details: Dict[str, Any] = field(default_factory=dict)
    is_known_legitimate: bool = False
    tld: str = ""
    registered_domain: str = ""

    # Phase6 拡張フィールド
    ctx_score: float = 0.0
    ctx_issues: Set[str] = field(default_factory=set)
    precheck: Dict[str, Any] = field(default_factory=dict)
    benign_indicators: Set[str] = field(default_factory=set)
    llm_is_phishing: Optional[bool] = None
    llm_confidence: float = 0.0
    llm_risk_level: str = "low"

    @property
    def avg_tool_risk(self) -> float:
        """Calculate average tool risk score."""
        if not self.tool_risks:
            return 0.0
        return sum(self.tool_risks.values()) / len(self.tool_risks)

    def has_issue(self, issue: str) -> bool:
        """Check if a specific issue is present."""
        return issue in self.issue_set

    def has_any_issue(self, issues: Set[str]) -> bool:
        """Check if any of the specified issues are present."""
        return bool(self.issue_set & issues)


@dataclass
class RuleResult:
    """Result of a rule evaluation.

    Attributes:
        triggered: Whether the rule was triggered
        rule_name: Name of the rule that produced this result
        issue_tag: Issue tag to add (if triggered)
        score_adjustment: Score adjustment to apply (additive)
        min_score: Minimum score to enforce (if triggered)
        reasoning: Human-readable explanation
        details: Additional details for debugging
        skipped: Whether the rule was skipped (disabled)

    Phase6 拡張フィールド:
        force_phishing: True ならis_phishingを強制的にTrue
        force_benign: True ならis_phishingを強制的にFalse
        risk_level_bump: risk_levelの引き上げ先 (low/medium/high)
        confidence_floor: 最低confidence (これ以上を保証)
        confidence_ceiling: 最大confidence (これ以下に制限)

    変更履歴:
        - 2026-01-27: Phase6対応のためフィールド追加
    """
    triggered: bool
    rule_name: str = ""
    issue_tag: Optional[str] = None
    score_adjustment: float = 0.0
    min_score: Optional[float] = None
    reasoning: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    skipped: bool = False

    # Phase6 拡張フィールド
    force_phishing: Optional[bool] = None
    force_benign: Optional[bool] = None
    risk_level_bump: Optional[str] = None
    confidence_floor: Optional[float] = None
    confidence_ceiling: Optional[float] = None

    @classmethod
    def not_triggered(cls, rule_name: str = "") -> "RuleResult":
        """Create a not-triggered result."""
        return cls(triggered=False, rule_name=rule_name)

    @classmethod
    def skipped_result(cls, rule_name: str, reason: str = "Rule disabled") -> "RuleResult":
        """Create a skipped result (rule disabled)."""
        return cls(
            triggered=False,
            rule_name=rule_name,
            skipped=True,
            reasoning=reason
        )


class DetectionRule(ABC):
    """Base class for detection rules.

    All detection rules should inherit from this class and implement
    the `name` property and `_evaluate` method.

    The rule can be enabled/disabled via the `enabled` property.
    When disabled, `evaluate()` returns a skipped result without
    calling `_evaluate()`.

    Example:
        class MyRule(DetectionRule):
            @property
            def name(self) -> str:
                return "my_rule"

            def _evaluate(self, ctx: RuleContext) -> RuleResult:
                if some_condition(ctx):
                    return RuleResult(
                        triggered=True,
                        issue_tag="my_issue",
                        min_score=0.5
                    )
                return RuleResult.not_triggered()
    """

    def __init__(self, enabled: bool = True):
        """Initialize the rule.

        Args:
            enabled: Whether the rule is enabled (default: True)
        """
        self._enabled = enabled

    @property
    def enabled(self) -> bool:
        """Whether the rule is enabled."""
        return self._enabled

    @enabled.setter
    def enabled(self, value: bool):
        """Set the enabled state."""
        self._enabled = value

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique name for this rule."""
        pass

    @property
    def description(self) -> str:
        """Human-readable description of this rule."""
        return ""

    @abstractmethod
    def _evaluate(self, ctx: RuleContext) -> RuleResult:
        """Evaluate the rule against the context.

        This method should be implemented by subclasses.
        It is only called when the rule is enabled.

        Args:
            ctx: The rule context

        Returns:
            RuleResult with evaluation outcome
        """
        pass

    def evaluate(self, ctx: RuleContext) -> RuleResult:
        """Evaluate the rule, respecting enabled state.

        If the rule is disabled, returns a skipped result.
        Otherwise, calls _evaluate() and sets the rule_name.

        Args:
            ctx: The rule context

        Returns:
            RuleResult with evaluation outcome
        """
        if not self._enabled:
            return RuleResult.skipped_result(
                self.name,
                f"Rule '{self.name}' is disabled"
            )

        result = self._evaluate(ctx)
        result.rule_name = self.name
        return result

    def __repr__(self) -> str:
        status = "enabled" if self._enabled else "disabled"
        return f"{self.__class__.__name__}(name='{self.name}', {status})"
