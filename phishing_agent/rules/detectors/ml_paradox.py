# -*- coding: utf-8 -*-
"""
phishing_agent.rules.detectors.ml_paradox
-----------------------------------------
ML Paradox detection rule.

Detects cases where ML probability is low but structural signals strongly
suggest phishing (e.g., dangerous TLD, random pattern, brand detection).
"""

from typing import Set
from .base import DetectionRule, RuleContext, RuleResult
from ..config.thresholds import ParadoxConfig
from ..data.patterns import STRONG_NON_ML_SIGNALS


class MLParadoxStrongRule(DetectionRule):
    """Strong ML Paradox detection.

    Triggers when:
    - ML probability <= strong_max_ml (default: 0.20)
    - At least strong_min_signals (default: 2) strong non-ML signals present

    This indicates a likely phishing domain that the ML model missed.
    """

    def __init__(
        self,
        enabled: bool = True,
        config: ParadoxConfig = ParadoxConfig(),
        strong_signals: Set[str] = STRONG_NON_ML_SIGNALS,
    ):
        super().__init__(enabled=enabled)
        self._config = config
        self._strong_signals = strong_signals

    @property
    def name(self) -> str:
        return "ml_paradox_strong"

    @property
    def description(self) -> str:
        return (
            f"ML Paradox (Strong): ML <= {self._config.strong_max_ml} with "
            f">= {self._config.strong_min_signals} strong signals"
        )

    def _evaluate(self, ctx: RuleContext) -> RuleResult:
        # Check ML threshold
        if ctx.ml_probability > self._config.strong_max_ml:
            return RuleResult.not_triggered(self.name)

        # Count strong signals
        signal_count = len(ctx.issue_set & self._strong_signals)
        if signal_count < self._config.strong_min_signals:
            return RuleResult.not_triggered(self.name)

        # Triggered - apply strong paradox scoring
        matched_signals = ctx.issue_set & self._strong_signals
        return RuleResult(
            triggered=True,
            rule_name=self.name,
            issue_tag="ml_paradox_strong",
            min_score=self._config.strong_base_score,
            reasoning=(
                f"Strong ML paradox: ML={ctx.ml_probability:.2f} but "
                f"{signal_count} strong signals: {matched_signals}"
            ),
            details={
                "ml_probability": ctx.ml_probability,
                "signal_count": signal_count,
                "matched_signals": list(matched_signals),
            },
        )


class MLParadoxWeakRule(DetectionRule):
    """Weak ML Paradox detection.

    Triggers when:
    - ML probability <= weak_max_ml (default: 0.30)
    - At least weak_min_signals (default: 1) strong non-ML signal present
    - Does not meet strong paradox criteria

    This indicates a possibly suspicious domain that warrants attention.
    """

    def __init__(
        self,
        enabled: bool = True,
        config: ParadoxConfig = ParadoxConfig(),
        strong_signals: Set[str] = STRONG_NON_ML_SIGNALS,
    ):
        super().__init__(enabled=enabled)
        self._config = config
        self._strong_signals = strong_signals

    @property
    def name(self) -> str:
        return "ml_paradox_weak"

    @property
    def description(self) -> str:
        return (
            f"ML Paradox (Weak): ML <= {self._config.weak_max_ml} with "
            f">= {self._config.weak_min_signals} strong signal"
        )

    def _evaluate(self, ctx: RuleContext) -> RuleResult:
        # Check if strong paradox would trigger (skip if so)
        if ctx.ml_probability <= self._config.strong_max_ml:
            signal_count = len(ctx.issue_set & self._strong_signals)
            if signal_count >= self._config.strong_min_signals:
                return RuleResult.not_triggered(self.name)

        # Check weak paradox threshold
        if ctx.ml_probability > self._config.weak_max_ml:
            return RuleResult.not_triggered(self.name)

        # Count strong signals
        signal_count = len(ctx.issue_set & self._strong_signals)
        if signal_count < self._config.weak_min_signals:
            return RuleResult.not_triggered(self.name)

        # Triggered - apply weak paradox scoring
        matched_signals = ctx.issue_set & self._strong_signals
        return RuleResult(
            triggered=True,
            rule_name=self.name,
            issue_tag="ml_paradox_weak",
            min_score=self._config.weak_base_score,
            reasoning=(
                f"Weak ML paradox: ML={ctx.ml_probability:.2f} with "
                f"{signal_count} strong signal(s): {matched_signals}"
            ),
            details={
                "ml_probability": ctx.ml_probability,
                "signal_count": signal_count,
                "matched_signals": list(matched_signals),
            },
        )


def create_ml_paradox_rules(
    config: ParadoxConfig = ParadoxConfig(),
    enabled: bool = True,
) -> list:
    """Create both strong and weak ML paradox rules.

    Args:
        config: Paradox detection configuration
        enabled: Whether rules are enabled by default

    Returns:
        List of [MLParadoxStrongRule, MLParadoxWeakRule]
    """
    return [
        MLParadoxStrongRule(enabled=enabled, config=config),
        MLParadoxWeakRule(enabled=enabled, config=config),
    ]
