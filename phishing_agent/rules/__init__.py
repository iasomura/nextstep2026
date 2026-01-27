# -*- coding: utf-8 -*-
"""
phishing_agent.rules
--------------------
Rule-based detection module for phishing analysis.

This module provides:
- Configurable detection rules
- Rule engine for evaluation
- Data definitions (TLDs, brands, patterns)

Usage:
    from phishing_agent.rules import RuleEngine, RuleContext
    from phishing_agent.rules.detectors import MLParadoxRule, TLDComboRule

    engine = RuleEngine()
    engine.add_rule(MLParadoxRule())
    engine.add_rule(TLDComboRule())

    ctx = RuleContext(domain="example.com", ml_probability=0.15, ...)
    score, issues = engine.compute_score(ctx, base_score=0.3)
"""

from .engine import RuleEngine, EngineResult, create_all_rules, create_default_engine
from .detectors.base import RuleContext, RuleResult, DetectionRule
from .config import (
    MLThresholds,
    ParadoxConfig,
    ScoreWeights,
    LowSignalConfig,
    TLDComboConfig,
    DVComboConfig,
    RandomPatternConfig,
    HighRiskWordsConfig,
    RulesConfig,
    RuleSettings,
)
from .metrics import MetricsCollector, RuleMetrics, EvaluationRecord

__all__ = [
    # Engine
    'RuleEngine',
    'EngineResult',
    'create_all_rules',
    'create_default_engine',
    # Base classes
    'RuleContext',
    'RuleResult',
    'DetectionRule',
    # Config - Thresholds
    'MLThresholds',
    'ParadoxConfig',
    'ScoreWeights',
    'LowSignalConfig',
    'TLDComboConfig',
    'DVComboConfig',
    'RandomPatternConfig',
    'HighRiskWordsConfig',
    # Config - Settings
    'RulesConfig',
    'RuleSettings',
    # Metrics
    'MetricsCollector',
    'RuleMetrics',
    'EvaluationRecord',
]
