# -*- coding: utf-8 -*-
"""
phishing_agent.rules.detectors.low_signal
-----------------------------------------
Low-signal phishing detection rules.

Detects phishing domains with weak signals that individually might not
be suspicious but together indicate phishing:
- Low ML probability (but not zero)
- DV certificate
- Short certificate validity
- Low SAN count
"""

from .base import DetectionRule, RuleContext, RuleResult
from ..config.thresholds import LowSignalConfig


class LowSignalPhishingRule(DetectionRule):
    """Low-signal phishing detection.

    Triggers when multiple weak signals are present:
    - ML probability in low range (0.10 <= ML <= 0.30)
    - DV certificate (weak identity)
    - Short certificate validity (<=90 days)
    - Low SAN count (<=5)

    Each signal contributes to a cumulative score.
    """

    def __init__(
        self,
        enabled: bool = True,
        config: LowSignalConfig = LowSignalConfig(),
    ):
        super().__init__(enabled=enabled)
        self._config = config

    @property
    def name(self) -> str:
        return "low_signal_phishing"

    @property
    def description(self) -> str:
        return (
            f"Low-signal phishing: ML {self._config.min_ml}-{self._config.max_ml} "
            f"with >= {self._config.min_signals} weak signals"
        )

    def _evaluate(self, ctx: RuleContext) -> RuleResult:
        # Check ML range - MUST have some ML indication
        if ctx.ml_probability < self._config.min_ml:
            return RuleResult.not_triggered(self.name)
        if ctx.ml_probability > self._config.max_ml:
            return RuleResult.not_triggered(self.name)

        # Count weak signals
        signals = []
        signal_count = 0

        # Check DV certificate
        if ctx.has_any_issue({"dv_weak_identity", "free_ca", "free_ca_no_org"}):
            signal_count += 1
            signals.append("dv_weak_identity")

        # Check short validity
        cert_details = ctx.cert_details
        valid_days = cert_details.get("validity_days", 365)
        if valid_days <= self._config.max_valid_days:
            signal_count += 1
            signals.append(f"short_validity({valid_days}d)")

        # Check low SAN count
        san_count = cert_details.get("san_count", 10)
        if san_count <= self._config.max_san_count:
            signal_count += 1
            signals.append(f"low_san({san_count})")

        # Check if minimum signals met
        if signal_count < self._config.min_signals:
            return RuleResult.not_triggered(self.name)

        # Calculate score
        score = self._config.base_score + (
            (signal_count - self._config.min_signals)
            * self._config.score_per_signal
        )

        return RuleResult(
            triggered=True,
            rule_name=self.name,
            issue_tag="low_signal_phishing",
            min_score=score,
            reasoning=(
                f"Low-signal phishing: ML={ctx.ml_probability:.2f} with "
                f"{signal_count} signals: {signals}"
            ),
            details={
                "ml_probability": ctx.ml_probability,
                "signal_count": signal_count,
                "signals": signals,
                "score": score,
            },
        )


class DVSuspiciousComboRule(DetectionRule):
    """DV certificate with suspicious combination.

    Triggers when:
    - DV certificate is present
    - ML probability >= min_ml (ensures some ML signal)
    - TLD is dangerous or domain has multiple risk factors

    This catches phishing on DV-only certificates with risky TLDs.
    """

    def __init__(
        self,
        enabled: bool = True,
        min_ml: float = 0.10,
        high_danger_min_score: float = 0.42,
        medium_danger_min_score: float = 0.35,
    ):
        super().__init__(enabled=enabled)
        self._min_ml = min_ml
        self._high_danger_min_score = high_danger_min_score
        self._medium_danger_min_score = medium_danger_min_score

    @property
    def name(self) -> str:
        return "dv_suspicious_combo"

    @property
    def description(self) -> str:
        return f"DV certificate with suspicious combo (ML >= {self._min_ml})"

    def _evaluate(self, ctx: RuleContext) -> RuleResult:
        # Check minimum ML threshold
        if ctx.ml_probability < self._min_ml:
            return RuleResult.not_triggered(self.name)

        # Check for DV certificate
        has_dv = ctx.has_any_issue({
            "dv_weak_identity", "free_ca", "free_ca_no_org", "dv_multi_risk_combo"
        })
        if not has_dv:
            return RuleResult.not_triggered(self.name)

        # Determine TLD danger level
        from ..data.tlds import HIGH_DANGER_TLDS, DANGEROUS_TLDS
        tld = ctx.tld.lower().strip(".")

        if tld in HIGH_DANGER_TLDS:
            return RuleResult(
                triggered=True,
                rule_name=self.name,
                issue_tag="dv_suspicious_combo",
                min_score=self._high_danger_min_score,
                reasoning=(
                    f"DV cert with high danger TLD '.{tld}' "
                    f"(ML={ctx.ml_probability:.2f})"
                ),
                details={
                    "tld": tld,
                    "danger_level": "high",
                    "min_score": self._high_danger_min_score,
                },
            )

        if tld in DANGEROUS_TLDS:
            return RuleResult(
                triggered=True,
                rule_name=self.name,
                issue_tag="dv_suspicious_combo",
                min_score=self._medium_danger_min_score,
                reasoning=(
                    f"DV cert with dangerous TLD '.{tld}' "
                    f"(ML={ctx.ml_probability:.2f})"
                ),
                details={
                    "tld": tld,
                    "danger_level": "medium",
                    "min_score": self._medium_danger_min_score,
                },
            )

        return RuleResult.not_triggered(self.name)


def create_low_signal_rules(
    config: LowSignalConfig = LowSignalConfig(),
    enabled: bool = True,
) -> list:
    """Create all low-signal detection rules.

    Args:
        config: Low-signal detection configuration
        enabled: Whether rules are enabled by default

    Returns:
        List of low-signal detection rules
    """
    return [
        LowSignalPhishingRule(enabled=enabled, config=config),
        DVSuspiciousComboRule(
            enabled=enabled,
            min_ml=config.min_ml,
        ),
    ]
