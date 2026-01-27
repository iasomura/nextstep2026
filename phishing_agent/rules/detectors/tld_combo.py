# -*- coding: utf-8 -*-
"""
phishing_agent.rules.detectors.tld_combo
----------------------------------------
Dangerous TLD combination detection rules.

Detects risky combinations of dangerous TLDs with other signals
such as random patterns, short domains, or brand detection.
"""

from .base import DetectionRule, RuleContext, RuleResult
from ..config.thresholds import TLDComboConfig
from ..data.tlds import DANGEROUS_TLDS, HIGH_DANGER_TLDS
from ..data.patterns import RANDOM_PATTERN_INDICATORS


class DangerousTLDLowMLRule(DetectionRule):
    """Dangerous TLD with low ML probability.

    Triggers when:
    - TLD is in dangerous TLD list
    - ML probability is in the low range (0.10 <= ML <= 0.15)

    This helps catch phishing domains on dangerous TLDs that ML might
    underestimate.
    """

    def __init__(
        self,
        enabled: bool = True,
        config: TLDComboConfig = TLDComboConfig(),
    ):
        super().__init__(enabled=enabled)
        self._config = config

    @property
    def name(self) -> str:
        return "dangerous_tld_low_ml"

    @property
    def description(self) -> str:
        return (
            f"Dangerous TLD with low ML: "
            f"{self._config.min_ml_for_low_ml_boost} <= ML <= "
            f"{self._config.max_ml_for_low_ml_boost}"
        )

    def _evaluate(self, ctx: RuleContext) -> RuleResult:
        # Check if TLD is dangerous
        tld = ctx.tld.lower().strip(".")
        if tld not in DANGEROUS_TLDS:
            return RuleResult.not_triggered(self.name)

        # Check ML range
        if not (
            self._config.min_ml_for_low_ml_boost
            <= ctx.ml_probability
            <= self._config.max_ml_for_low_ml_boost
        ):
            return RuleResult.not_triggered(self.name)

        # Triggered
        return RuleResult(
            triggered=True,
            rule_name=self.name,
            issue_tag="dangerous_tld_low_ml",
            score_adjustment=self._config.low_ml_boost,
            reasoning=(
                f"Dangerous TLD '.{tld}' with low ML={ctx.ml_probability:.2f}"
            ),
            details={
                "tld": tld,
                "ml_probability": ctx.ml_probability,
                "boost": self._config.low_ml_boost,
            },
        )


class DangerousTLDRandomRule(DetectionRule):
    """Dangerous TLD with random pattern.

    Triggers when:
    - TLD is in dangerous TLD list
    - Domain shows random pattern indicators

    Random strings on dangerous TLDs are highly suspicious.
    """

    def __init__(
        self,
        enabled: bool = True,
        config: TLDComboConfig = TLDComboConfig(),
    ):
        super().__init__(enabled=enabled)
        self._config = config

    @property
    def name(self) -> str:
        return "dangerous_tld_random"

    @property
    def description(self) -> str:
        return "Dangerous TLD with random pattern"

    def _evaluate(self, ctx: RuleContext) -> RuleResult:
        # Check if TLD is dangerous
        tld = ctx.tld.lower().strip(".")
        if tld not in DANGEROUS_TLDS:
            return RuleResult.not_triggered(self.name)

        # Check for random pattern indicators
        random_issues = ctx.issue_set & RANDOM_PATTERN_INDICATORS
        if not random_issues:
            return RuleResult.not_triggered(self.name)

        # Triggered
        return RuleResult(
            triggered=True,
            rule_name=self.name,
            issue_tag="dangerous_tld_random",
            score_adjustment=self._config.random_boost,
            reasoning=(
                f"Dangerous TLD '.{tld}' with random pattern: {random_issues}"
            ),
            details={
                "tld": tld,
                "random_indicators": list(random_issues),
                "boost": self._config.random_boost,
            },
        )


class DangerousTLDBrandRule(DetectionRule):
    """Dangerous TLD with brand detection.

    Triggers when:
    - TLD is in dangerous TLD list
    - Brand impersonation is detected

    Brand impersonation on dangerous TLDs is highly suspicious.
    """

    def __init__(
        self,
        enabled: bool = True,
        config: TLDComboConfig = TLDComboConfig(),
    ):
        super().__init__(enabled=enabled)
        self._config = config

    @property
    def name(self) -> str:
        return "dangerous_tld_brand"

    @property
    def description(self) -> str:
        return "Dangerous TLD with brand detection"

    def _evaluate(self, ctx: RuleContext) -> RuleResult:
        # Check if TLD is dangerous
        tld = ctx.tld.lower().strip(".")
        if tld not in DANGEROUS_TLDS:
            return RuleResult.not_triggered(self.name)

        # Check for brand detection
        if not ctx.has_issue("brand_detected"):
            return RuleResult.not_triggered(self.name)

        # Triggered
        detected_brands = ctx.brand_details.get("detected_brands", [])
        return RuleResult(
            triggered=True,
            rule_name=self.name,
            issue_tag="dangerous_tld_brand",
            score_adjustment=self._config.brand_boost,
            reasoning=(
                f"Dangerous TLD '.{tld}' with brand detection: {detected_brands}"
            ),
            details={
                "tld": tld,
                "detected_brands": detected_brands,
                "boost": self._config.brand_boost,
            },
        )


class HighDangerTLDRule(DetectionRule):
    """High danger TLD detection.

    Triggers when:
    - TLD is in high danger TLD list (>50% phishing rate)

    These TLDs have extremely high phishing rates.
    """

    def __init__(
        self,
        enabled: bool = True,
        min_score: float = 0.35,
    ):
        super().__init__(enabled=enabled)
        self._min_score = min_score

    @property
    def name(self) -> str:
        return "high_danger_tld"

    @property
    def description(self) -> str:
        return "High danger TLD (>50% phishing rate)"

    def _evaluate(self, ctx: RuleContext) -> RuleResult:
        # Check if TLD is high danger
        tld = ctx.tld.lower().strip(".")
        if tld not in HIGH_DANGER_TLDS:
            return RuleResult.not_triggered(self.name)

        # Triggered
        return RuleResult(
            triggered=True,
            rule_name=self.name,
            issue_tag="high_danger_tld",
            min_score=self._min_score,
            reasoning=f"High danger TLD '.{tld}' (>50% phishing rate)",
            details={
                "tld": tld,
                "min_score": self._min_score,
            },
        )


def create_tld_combo_rules(
    config: TLDComboConfig = TLDComboConfig(),
    enabled: bool = True,
) -> list:
    """Create all TLD combination rules.

    Args:
        config: TLD combination configuration
        enabled: Whether rules are enabled by default

    Returns:
        List of TLD combination rules
    """
    return [
        DangerousTLDLowMLRule(enabled=enabled, config=config),
        DangerousTLDRandomRule(enabled=enabled, config=config),
        DangerousTLDBrandRule(enabled=enabled, config=config),
        HighDangerTLDRule(enabled=enabled),
    ]
