# -*- coding: utf-8 -*-
"""
phishing_agent.rules.metrics
----------------------------
Rule effectiveness metrics and logging.

Tracks per-rule statistics for effectiveness measurement:
- Trigger count (total, TP, FP, TN, FN)
- Score impact distribution
- Execution time

Usage:
    from phishing_agent.rules.metrics import RuleMetrics, MetricsCollector

    collector = MetricsCollector()
    engine = RuleEngine(metrics_collector=collector)

    # After evaluation
    engine.evaluate(ctx)

    # After ground truth is known
    collector.record_outcome("ml_paradox_strong", predicted=True, actual=True)

    # Get statistics
    collector.print_summary()
    collector.to_csv("rule_metrics.csv")
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from collections import defaultdict
import json
import csv
import logging
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class RuleMetrics:
    """Metrics for a single rule.

    Attributes:
        rule_name: Name of the rule
        trigger_count: Total times rule triggered
        true_positive: Triggered and actual phishing
        false_positive: Triggered but actually benign
        true_negative: Not triggered and actually benign
        false_negative: Not triggered but actual phishing
        skip_count: Times rule was skipped (disabled)
        score_adjustments: List of score adjustments when triggered
        min_scores_applied: List of min_score values when applied
        execution_times_ms: Execution times in milliseconds
    """
    rule_name: str
    trigger_count: int = 0
    true_positive: int = 0
    false_positive: int = 0
    true_negative: int = 0
    false_negative: int = 0
    skip_count: int = 0
    score_adjustments: List[float] = field(default_factory=list)
    min_scores_applied: List[float] = field(default_factory=list)
    execution_times_ms: List[float] = field(default_factory=list)

    @property
    def precision(self) -> float:
        """Precision = TP / (TP + FP)"""
        total = self.true_positive + self.false_positive
        return self.true_positive / total if total > 0 else 0.0

    @property
    def recall(self) -> float:
        """Recall = TP / (TP + FN)"""
        total = self.true_positive + self.false_negative
        return self.true_positive / total if total > 0 else 0.0

    @property
    def f1_score(self) -> float:
        """F1 = 2 * (precision * recall) / (precision + recall)"""
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0

    @property
    def trigger_rate(self) -> float:
        """Trigger rate = triggers / (triggers + non-triggers)"""
        total = self.trigger_count + self.true_negative + self.false_negative
        return self.trigger_count / total if total > 0 else 0.0

    @property
    def avg_score_adjustment(self) -> float:
        """Average score adjustment when triggered."""
        if not self.score_adjustments:
            return 0.0
        return sum(self.score_adjustments) / len(self.score_adjustments)

    @property
    def avg_min_score(self) -> float:
        """Average minimum score when applied."""
        if not self.min_scores_applied:
            return 0.0
        return sum(self.min_scores_applied) / len(self.min_scores_applied)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "rule_name": self.rule_name,
            "trigger_count": self.trigger_count,
            "true_positive": self.true_positive,
            "false_positive": self.false_positive,
            "true_negative": self.true_negative,
            "false_negative": self.false_negative,
            "skip_count": self.skip_count,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1_score": round(self.f1_score, 4),
            "trigger_rate": round(self.trigger_rate, 4),
            "avg_score_adjustment": round(self.avg_score_adjustment, 4),
            "avg_min_score": round(self.avg_min_score, 4),
        }


@dataclass
class EvaluationRecord:
    """Record of a single evaluation for later outcome recording.

    Attributes:
        domain: Domain that was evaluated
        timestamp: When evaluation occurred
        triggered_rules: Rules that triggered
        non_triggered_rules: Rules that didn't trigger
        skipped_rules: Rules that were skipped
        predicted_phishing: Whether prediction was phishing
        actual_phishing: Ground truth (None until recorded)
        rule_details: Details from each rule evaluation
    """
    domain: str
    timestamp: datetime
    triggered_rules: List[str]
    non_triggered_rules: List[str]
    skipped_rules: List[str]
    predicted_phishing: bool
    actual_phishing: Optional[bool] = None
    rule_details: Dict[str, Dict[str, Any]] = field(default_factory=dict)


class MetricsCollector:
    """Collects and aggregates rule metrics.

    Thread-safe metrics collection for rule effectiveness measurement.

    Example:
        collector = MetricsCollector(log_file="rule_metrics.jsonl")

        # During evaluation (called by RuleEngine)
        collector.record_trigger("ml_paradox_strong", score_adj=0.0, min_score=0.8)

        # After ground truth is known
        collector.finalize_evaluation(domain, actual_phishing=True)

        # Get summary
        collector.print_summary()
    """

    def __init__(
        self,
        log_file: Optional[str] = None,
        log_level: int = logging.INFO,
    ):
        """Initialize metrics collector.

        Args:
            log_file: Path to JSONL log file (optional)
            log_level: Logging level for rule triggers
        """
        self._metrics: Dict[str, RuleMetrics] = {}
        self._pending_evaluations: Dict[str, EvaluationRecord] = {}
        self._log_file = Path(log_file) if log_file else None
        self._log_level = log_level
        self._evaluation_count = 0

        if self._log_file:
            self._log_file.parent.mkdir(parents=True, exist_ok=True)

    def _get_or_create_metrics(self, rule_name: str) -> RuleMetrics:
        """Get or create metrics for a rule."""
        if rule_name not in self._metrics:
            self._metrics[rule_name] = RuleMetrics(rule_name=rule_name)
        return self._metrics[rule_name]

    def start_evaluation(
        self,
        domain: str,
        rule_names: List[str],
    ) -> str:
        """Start tracking an evaluation.

        Args:
            domain: Domain being evaluated
            rule_names: All rule names being evaluated

        Returns:
            Evaluation ID for later reference
        """
        eval_id = f"{domain}_{self._evaluation_count}"
        self._evaluation_count += 1

        self._pending_evaluations[eval_id] = EvaluationRecord(
            domain=domain,
            timestamp=datetime.now(),
            triggered_rules=[],
            non_triggered_rules=list(rule_names),
            skipped_rules=[],
            predicted_phishing=False,
        )
        return eval_id

    def record_trigger(
        self,
        eval_id: str,
        rule_name: str,
        score_adjustment: float = 0.0,
        min_score: Optional[float] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        """Record a rule trigger.

        Args:
            eval_id: Evaluation ID from start_evaluation
            rule_name: Name of the triggered rule
            score_adjustment: Score adjustment applied
            min_score: Minimum score applied (if any)
            details: Additional details from rule
        """
        metrics = self._get_or_create_metrics(rule_name)
        metrics.trigger_count += 1

        if score_adjustment != 0:
            metrics.score_adjustments.append(score_adjustment)
        if min_score is not None:
            metrics.min_scores_applied.append(min_score)

        # Update pending evaluation
        if eval_id in self._pending_evaluations:
            record = self._pending_evaluations[eval_id]
            record.triggered_rules.append(rule_name)
            if rule_name in record.non_triggered_rules:
                record.non_triggered_rules.remove(rule_name)
            if details:
                record.rule_details[rule_name] = details

        # Log trigger
        logger.log(
            self._log_level,
            f"[RULE_TRIGGER] {rule_name}: adj={score_adjustment:.3f}, "
            f"min={min_score if min_score else 'N/A'}"
        )

    def record_skip(self, eval_id: str, rule_name: str):
        """Record a rule skip (disabled).

        Args:
            eval_id: Evaluation ID
            rule_name: Name of the skipped rule
        """
        metrics = self._get_or_create_metrics(rule_name)
        metrics.skip_count += 1

        if eval_id in self._pending_evaluations:
            record = self._pending_evaluations[eval_id]
            record.skipped_rules.append(rule_name)
            if rule_name in record.non_triggered_rules:
                record.non_triggered_rules.remove(rule_name)

    def record_non_trigger(self, eval_id: str, rule_name: str):
        """Record that a rule did not trigger.

        Args:
            eval_id: Evaluation ID
            rule_name: Name of the non-triggered rule
        """
        # Non-triggers are tracked in pending_evaluations
        # TP/TN/FP/FN will be calculated in finalize_evaluation
        pass

    def finalize_evaluation(
        self,
        eval_id: str,
        predicted_phishing: bool,
        actual_phishing: Optional[bool] = None,
    ):
        """Finalize an evaluation with prediction result.

        Args:
            eval_id: Evaluation ID
            predicted_phishing: Whether the system predicted phishing
            actual_phishing: Ground truth (if known)
        """
        if eval_id not in self._pending_evaluations:
            return

        record = self._pending_evaluations[eval_id]
        record.predicted_phishing = predicted_phishing
        record.actual_phishing = actual_phishing

        # Update TP/FP/TN/FN if ground truth is known
        if actual_phishing is not None:
            self._update_confusion_matrix(record)

        # Log to file
        if self._log_file:
            self._write_log_entry(record)

        # Keep record for potential later ground truth update
        # (In production, might want to clean up old records)

    def update_ground_truth(self, eval_id: str, actual_phishing: bool):
        """Update ground truth for a previous evaluation.

        Args:
            eval_id: Evaluation ID
            actual_phishing: Ground truth label
        """
        if eval_id not in self._pending_evaluations:
            return

        record = self._pending_evaluations[eval_id]
        record.actual_phishing = actual_phishing
        self._update_confusion_matrix(record)

    def _update_confusion_matrix(self, record: EvaluationRecord):
        """Update TP/FP/TN/FN counts based on record."""
        if record.actual_phishing is None:
            return

        actual = record.actual_phishing

        for rule_name in record.triggered_rules:
            metrics = self._get_or_create_metrics(rule_name)
            if actual:
                metrics.true_positive += 1
            else:
                metrics.false_positive += 1

        for rule_name in record.non_triggered_rules:
            metrics = self._get_or_create_metrics(rule_name)
            if actual:
                metrics.false_negative += 1
            else:
                metrics.true_negative += 1

    def _write_log_entry(self, record: EvaluationRecord):
        """Write evaluation record to log file."""
        entry = {
            "timestamp": record.timestamp.isoformat(),
            "domain": record.domain,
            "triggered_rules": record.triggered_rules,
            "skipped_rules": record.skipped_rules,
            "predicted_phishing": record.predicted_phishing,
            "actual_phishing": record.actual_phishing,
            "rule_details": record.rule_details,
        }
        with open(self._log_file, "a") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def get_metrics(self, rule_name: str) -> Optional[RuleMetrics]:
        """Get metrics for a specific rule."""
        return self._metrics.get(rule_name)

    def get_all_metrics(self) -> Dict[str, RuleMetrics]:
        """Get all rule metrics."""
        return self._metrics.copy()

    def print_summary(self):
        """Print summary of all rule metrics."""
        print("\n" + "=" * 80)
        print("RULE EFFECTIVENESS SUMMARY")
        print("=" * 80)

        # Sort by trigger count descending
        sorted_rules = sorted(
            self._metrics.values(),
            key=lambda m: m.trigger_count,
            reverse=True
        )

        print(f"\n{'Rule Name':<30} {'Triggers':>8} {'TP':>6} {'FP':>6} "
              f"{'Prec':>7} {'Recall':>7} {'F1':>7}")
        print("-" * 80)

        for m in sorted_rules:
            print(
                f"{m.rule_name:<30} {m.trigger_count:>8} "
                f"{m.true_positive:>6} {m.false_positive:>6} "
                f"{m.precision:>7.3f} {m.recall:>7.3f} {m.f1_score:>7.3f}"
            )

        print("-" * 80)
        total_triggers = sum(m.trigger_count for m in sorted_rules)
        total_tp = sum(m.true_positive for m in sorted_rules)
        total_fp = sum(m.false_positive for m in sorted_rules)
        print(f"{'TOTAL':<30} {total_triggers:>8} {total_tp:>6} {total_fp:>6}")
        print("=" * 80 + "\n")

    def to_csv(self, path: str):
        """Export metrics to CSV file.

        Args:
            path: Output CSV file path
        """
        fieldnames = [
            "rule_name", "trigger_count", "true_positive", "false_positive",
            "true_negative", "false_negative", "skip_count",
            "precision", "recall", "f1_score", "trigger_rate",
            "avg_score_adjustment", "avg_min_score",
        ]

        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for metrics in self._metrics.values():
                writer.writerow(metrics.to_dict())

        logger.info(f"Metrics exported to {path}")

    def to_json(self, path: str):
        """Export metrics to JSON file.

        Args:
            path: Output JSON file path
        """
        data = {
            "generated_at": datetime.now().isoformat(),
            "evaluation_count": self._evaluation_count,
            "rules": {
                name: m.to_dict()
                for name, m in self._metrics.items()
            }
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        logger.info(f"Metrics exported to {path}")

    def reset(self):
        """Reset all metrics."""
        self._metrics.clear()
        self._pending_evaluations.clear()
        self._evaluation_count = 0
