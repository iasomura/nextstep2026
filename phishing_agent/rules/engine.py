# -*- coding: utf-8 -*-
"""
phishing_agent.rules.engine
---------------------------
Rule execution engine for phishing detection.

Manages rule loading, execution, and result aggregation.
Supports enable/disable control for individual rules.
Includes metrics collection for rule effectiveness measurement.
"""

from typing import List, Dict, Any, Optional, Set, TYPE_CHECKING
from dataclasses import dataclass, field
import logging
import time

from .detectors.base import DetectionRule, RuleContext, RuleResult
from .config.settings import RulesConfig, RuleSettings

if TYPE_CHECKING:
    from .metrics import MetricsCollector

logger = logging.getLogger(__name__)


@dataclass
class EngineResult:
    """Aggregated result from all rules.

    Attributes:
        eval_id: Evaluation ID for metrics tracking
        domain: Domain that was evaluated
        detected_issues: All issue tags from triggered rules
        total_score_adjustment: Sum of all score adjustments
        min_score: Highest minimum score from any triggered rule
        triggered_rules: Names of rules that triggered
        skipped_rules: Names of rules that were skipped (disabled)
        rule_results: Individual results from each rule
        reasoning: Combined reasoning from all triggered rules
        execution_time_ms: Total execution time in milliseconds

    Phase6 拡張フィールド:
        force_phishing: Trueならis_phishingを強制的にTrue
        force_benign: Trueならis_phishingを強制的にFalse
        highest_risk_bump: 最も高いリスクレベルバンプ
        confidence_floor: 最低confidence (これ以上を保証)
        confidence_ceiling: 最大confidence (これ以下に制限)

    変更履歴:
        - 2026-01-28: Phase6 拡張フィールドを追加
    """
    eval_id: str = ""
    domain: str = ""
    detected_issues: Set[str] = field(default_factory=set)
    total_score_adjustment: float = 0.0
    min_score: Optional[float] = None
    triggered_rules: List[str] = field(default_factory=list)
    skipped_rules: List[str] = field(default_factory=list)
    rule_results: List[RuleResult] = field(default_factory=list)
    reasoning: str = ""
    execution_time_ms: float = 0.0

    # Phase6 拡張フィールド
    force_phishing: Optional[bool] = None
    force_benign: Optional[bool] = None
    highest_risk_bump: Optional[str] = None
    confidence_floor: Optional[float] = None
    confidence_ceiling: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "eval_id": self.eval_id,
            "domain": self.domain,
            "detected_issues": list(self.detected_issues),
            "total_score_adjustment": self.total_score_adjustment,
            "min_score": self.min_score,
            "triggered_rules": self.triggered_rules,
            "skipped_rules": self.skipped_rules,
            "reasoning": self.reasoning,
            "execution_time_ms": self.execution_time_ms,
            # Phase6 拡張
            "force_phishing": self.force_phishing,
            "force_benign": self.force_benign,
            "highest_risk_bump": self.highest_risk_bump,
            "confidence_floor": self.confidence_floor,
            "confidence_ceiling": self.confidence_ceiling,
        }


class RuleEngine:
    """Engine for executing detection rules.

    The engine manages a collection of rules and executes them
    against a RuleContext. Rules can be enabled/disabled either
    individually or via a RulesConfig.

    Supports optional metrics collection for rule effectiveness measurement.

    Example:
        from phishing_agent.rules.metrics import MetricsCollector

        collector = MetricsCollector(log_file="rule_metrics.jsonl")
        engine = RuleEngine(metrics_collector=collector)
        engine.register(MLParadoxRule())

        ctx = RuleContext(domain="example.com", ml_probability=0.15)
        result = engine.evaluate(ctx)

        # After ground truth is known
        collector.finalize_evaluation(result.eval_id, predicted=True, actual=True)
        collector.print_summary()
    """

    def __init__(
        self,
        config: Optional[RulesConfig] = None,
        metrics_collector: Optional["MetricsCollector"] = None,
    ):
        """Initialize the rule engine.

        Args:
            config: Optional rules configuration for enable/disable settings
            metrics_collector: Optional metrics collector for effectiveness tracking
        """
        self._rules: List[DetectionRule] = []
        self._config = config or RulesConfig()
        self._rule_map: Dict[str, DetectionRule] = {}
        self._metrics = metrics_collector

    def register(self, rule: DetectionRule) -> "RuleEngine":
        """Register a rule with the engine.

        Args:
            rule: The detection rule to register

        Returns:
            Self for method chaining
        """
        self._rules.append(rule)
        self._rule_map[rule.name] = rule

        # Apply config settings if available
        self._apply_config_to_rule(rule)

        return self

    def register_all(self, rules: List[DetectionRule]) -> "RuleEngine":
        """Register multiple rules at once.

        Args:
            rules: List of detection rules to register

        Returns:
            Self for method chaining
        """
        for rule in rules:
            self.register(rule)
        return self

    def _apply_config_to_rule(self, rule: DetectionRule) -> None:
        """Apply configuration settings to a rule.

        変更履歴:
            - 2026-01-28: Phase6 ルール (ml_guard, cert_gate, low_signal_gate, policy) を追加
        """
        # Map rule names to config attributes
        # Multiple rule variants can map to the same config setting
        config_mapping = {
            # ML Paradox rules
            "ml_paradox": "ml_paradox",
            "ml_paradox_strong": "ml_paradox",
            "ml_paradox_weak": "ml_paradox",
            # TLD combination rules
            "dangerous_tld_combo": "dangerous_tld_combo",
            "dangerous_tld_low_ml": "dangerous_tld_combo",
            "dangerous_tld_random": "dangerous_tld_combo",
            "dangerous_tld_brand": "dangerous_tld_combo",
            "high_danger_tld": "dangerous_tld_combo",
            # Low-signal rules
            "low_signal_phishing": "low_signal_phishing",
            "dv_suspicious_combo": "dv_suspicious_combo",
            # Random pattern rules
            "random_pattern": "random_pattern_minimum",
            "random_pattern_minimum": "random_pattern_minimum",
            # High risk words
            "high_risk_words": "high_risk_words",
            "high_risk_keywords": "high_risk_words",
            # Other rules
            "multiple_risk_factors": "multiple_risk_factors",
            "known_domain_mitigation": "known_domain_mitigation",
            "old_cert_phishing": "old_cert_phishing",
            "critical_brand_minimum": "critical_brand_minimum",
            "random_crl_override": "random_crl_override",
            # Phase6: ML Guard rules (2026-01-28追加)
            "very_high_ml_override": "ml_paradox",  # ML関連ルールとして同じ設定を使用
            "high_ml_override": "ml_paradox",
            "ultra_low_ml_block": "ml_paradox",
            "post_llm_flip_gate": "ml_paradox",
            # Phase6: Certificate Gate rules (2026-01-28追加)
            "benign_cert_gate_b1": "dv_suspicious_combo",  # 証明書関連として同じ設定を使用
            "benign_cert_gate_b2": "dv_suspicious_combo",
            "benign_cert_gate_b3": "dv_suspicious_combo",
            "benign_cert_gate_b4": "dv_suspicious_combo",
            # Phase6: Low Signal Gate rules (2026-01-28追加)
            "low_signal_phishing_gate_p1": "low_signal_phishing",
            "low_signal_phishing_gate_p2": "low_signal_phishing",
            "low_signal_phishing_gate_p3": "low_signal_phishing",
            "low_signal_phishing_gate_p4": "low_signal_phishing",
            # Phase6: Policy rules (2026-01-28追加)
            "policy_r1": "multiple_risk_factors",
            "policy_r2": "multiple_risk_factors",
            "policy_r3": "multiple_risk_factors",
            "policy_r4": "multiple_risk_factors",
            "policy_r5": "multiple_risk_factors",
            "policy_r6": "multiple_risk_factors",
        }

        config_attr = config_mapping.get(rule.name)
        if config_attr and hasattr(self._config, config_attr):
            settings = getattr(self._config, config_attr)
            if isinstance(settings, RuleSettings):
                rule.enabled = settings.enabled
                if not settings.enabled:
                    logger.debug(
                        f"Rule '{rule.name}' disabled: {settings.disabled_reason}"
                    )

    def get_rule(self, name: str) -> Optional[DetectionRule]:
        """Get a rule by name.

        Args:
            name: The rule name

        Returns:
            The rule if found, None otherwise
        """
        return self._rule_map.get(name)

    def enable_rule(self, name: str) -> bool:
        """Enable a rule by name.

        Args:
            name: The rule name

        Returns:
            True if rule was found and enabled
        """
        rule = self._rule_map.get(name)
        if rule:
            rule.enabled = True
            return True
        return False

    def disable_rule(self, name: str) -> bool:
        """Disable a rule by name.

        Args:
            name: The rule name

        Returns:
            True if rule was found and disabled
        """
        rule = self._rule_map.get(name)
        if rule:
            rule.enabled = False
            return True
        return False

    def set_rule_enabled(self, name: str, enabled: bool) -> bool:
        """Set a rule's enabled state.

        Args:
            name: The rule name
            enabled: Whether to enable the rule

        Returns:
            True if rule was found and updated
        """
        rule = self._rule_map.get(name)
        if rule:
            rule.enabled = enabled
            return True
        return False

    def list_rules(self) -> List[Dict[str, Any]]:
        """List all registered rules and their status.

        Returns:
            List of rule info dictionaries
        """
        return [
            {
                "name": rule.name,
                "enabled": rule.enabled,
                "description": rule.description,
            }
            for rule in self._rules
        ]

    def evaluate(self, ctx: RuleContext) -> EngineResult:
        """Evaluate all rules against the context.

        Args:
            ctx: The rule context containing domain and analysis data

        Returns:
            Aggregated result from all rules

        変更履歴:
            - 2026-01-28: Phase6 拡張フィールドの集約処理を追加
        """
        start_time = time.perf_counter()

        result = EngineResult(domain=ctx.domain)
        reasoning_parts: List[str] = []

        # Start metrics tracking if collector is available
        eval_id = ""
        if self._metrics:
            eval_id = self._metrics.start_evaluation(
                ctx.domain,
                [r.name for r in self._rules]
            )
            result.eval_id = eval_id

        # Phase6: リスクレベルの優先度マップ
        risk_level_priority = {
            "low": 0,
            "medium": 1,
            "medium-high": 2,
            "high": 3,
        }

        for rule in self._rules:
            try:
                rule_result = rule.evaluate(ctx)
                result.rule_results.append(rule_result)

                if rule_result.skipped:
                    result.skipped_rules.append(rule.name)
                    if self._metrics:
                        self._metrics.record_skip(eval_id, rule.name)
                    continue

                if rule_result.triggered:
                    result.triggered_rules.append(rule.name)

                    # Collect issue tag
                    if rule_result.issue_tag:
                        result.detected_issues.add(rule_result.issue_tag)

                    # Accumulate score adjustment
                    result.total_score_adjustment += rule_result.score_adjustment

                    # Track minimum score (take the highest min_score)
                    if rule_result.min_score is not None:
                        if result.min_score is None:
                            result.min_score = rule_result.min_score
                        else:
                            result.min_score = max(
                                result.min_score, rule_result.min_score
                            )

                    # Phase6: force_phishing の集約 (どれか1つでもTrueなら全体をTrue)
                    if rule_result.force_phishing is True:
                        result.force_phishing = True

                    # Phase6: force_benign の集約 (force_phishingが優先)
                    if rule_result.force_benign is True and result.force_phishing is not True:
                        result.force_benign = True

                    # Phase6: リスクレベルバンプの集約 (最も高いものを採用)
                    if rule_result.risk_level_bump:
                        current_priority = risk_level_priority.get(result.highest_risk_bump or "low", 0)
                        new_priority = risk_level_priority.get(rule_result.risk_level_bump, 0)
                        if new_priority > current_priority:
                            result.highest_risk_bump = rule_result.risk_level_bump

                    # Phase6: confidence_floor の集約 (最も高いものを採用)
                    if rule_result.confidence_floor is not None:
                        if result.confidence_floor is None:
                            result.confidence_floor = rule_result.confidence_floor
                        else:
                            result.confidence_floor = max(
                                result.confidence_floor, rule_result.confidence_floor
                            )

                    # Phase6: confidence_ceiling の集約 (最も低いものを採用)
                    if rule_result.confidence_ceiling is not None:
                        if result.confidence_ceiling is None:
                            result.confidence_ceiling = rule_result.confidence_ceiling
                        else:
                            result.confidence_ceiling = min(
                                result.confidence_ceiling, rule_result.confidence_ceiling
                            )

                    # Collect reasoning
                    if rule_result.reasoning:
                        reasoning_parts.append(
                            f"[{rule.name}] {rule_result.reasoning}"
                        )

                    # Record metrics
                    if self._metrics:
                        self._metrics.record_trigger(
                            eval_id,
                            rule.name,
                            score_adjustment=rule_result.score_adjustment,
                            min_score=rule_result.min_score,
                            details=rule_result.details,
                        )
                else:
                    # Record non-trigger for metrics
                    if self._metrics:
                        self._metrics.record_non_trigger(eval_id, rule.name)

            except Exception as e:
                logger.error(f"Error evaluating rule '{rule.name}': {e}")
                continue

        # Combine reasoning
        if reasoning_parts:
            result.reasoning = " | ".join(reasoning_parts)

        # Record execution time
        result.execution_time_ms = (time.perf_counter() - start_time) * 1000

        return result

    def finalize_evaluation(
        self,
        eval_id: str,
        predicted_phishing: bool,
        actual_phishing: Optional[bool] = None,
    ):
        """Finalize an evaluation with prediction and optional ground truth.

        Call this after evaluate() to record the final prediction
        and optionally the ground truth for metrics.

        Args:
            eval_id: Evaluation ID from EngineResult.eval_id
            predicted_phishing: Whether the system predicted phishing
            actual_phishing: Ground truth (if known)
        """
        if self._metrics:
            self._metrics.finalize_evaluation(
                eval_id, predicted_phishing, actual_phishing
            )

    def get_metrics_summary(self) -> Optional[Dict[str, Any]]:
        """Get metrics summary if collector is available."""
        if not self._metrics:
            return None
        return {
            name: m.to_dict()
            for name, m in self._metrics.get_all_metrics().items()
        }

    def print_metrics(self):
        """Print metrics summary if collector is available."""
        if self._metrics:
            self._metrics.print_summary()

    def __len__(self) -> int:
        """Return the number of registered rules."""
        return len(self._rules)

    def __repr__(self) -> str:
        enabled_count = sum(1 for r in self._rules if r.enabled)
        return (
            f"RuleEngine(rules={len(self._rules)}, "
            f"enabled={enabled_count})"
        )


def create_all_rules(enabled: bool = True) -> List[DetectionRule]:
    """Create all detection rules.

    Args:
        enabled: Default enabled state for all rules

    Returns:
        List of all detection rule instances

    変更履歴:
        - 2026-01-28: Phase6 ルールを含む全ルール生成ファクトリ関数を追加
    """
    from .detectors import (
        create_ml_paradox_rules,
        create_tld_combo_rules,
        create_low_signal_rules,
        create_ml_guard_rules,
        create_cert_gate_rules,
        create_low_signal_gate_rules,
        create_policy_rules,
    )

    rules = []
    rules.extend(create_ml_paradox_rules(enabled=enabled))
    rules.extend(create_tld_combo_rules(enabled=enabled))
    rules.extend(create_low_signal_rules(enabled=enabled))
    rules.extend(create_ml_guard_rules(enabled=enabled))
    rules.extend(create_cert_gate_rules(enabled=enabled))
    rules.extend(create_low_signal_gate_rules(enabled=enabled))
    rules.extend(create_policy_rules(enabled=enabled))

    return rules


def create_default_engine(
    config: Optional[RulesConfig] = None,
    metrics_collector: Optional["MetricsCollector"] = None,
) -> RuleEngine:
    """Create a RuleEngine with all default rules registered.

    Args:
        config: Optional rules configuration
        metrics_collector: Optional metrics collector

    Returns:
        RuleEngine with all rules registered

    変更履歴:
        - 2026-01-28: デフォルトエンジン生成関数を追加
    """
    engine = RuleEngine(config=config, metrics_collector=metrics_collector)
    engine.register_all(create_all_rules())
    return engine
