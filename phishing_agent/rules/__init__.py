# -*- coding: utf-8 -*-
"""
phishing_agent.rules
--------------------
Rule-based detection module for phishing analysis.

This module provides:
- Configurable detection rules
- Rule engine for evaluation
- Data definitions (TLDs, brands, patterns)
- Context builder for pipeline integration
- Result applier for assessment modification

Usage:
    from phishing_agent.rules import RuleEngine, RuleContext
    from phishing_agent.rules.detectors import MLParadoxRule, TLDComboRule

    engine = RuleEngine()
    engine.add_rule(MLParadoxRule())
    engine.add_rule(TLDComboRule())

    ctx = RuleContext(domain="example.com", ml_probability=0.15, ...)
    score, issues = engine.compute_score(ctx, base_score=0.3)

Phase6 Integration (2026-01-31):
    from phishing_agent.rules import RuleContextBuilder, create_phase6_engine, ResultApplier

    # Build context from pipeline data
    ctx = RuleContextBuilder.build(domain, ml, tool_summary, precheck, llm_assessment)

    # Evaluate with Phase6 rules
    engine = create_phase6_engine()
    result = engine.evaluate_phased(ctx)

    # Apply to assessment
    final = ResultApplier.apply(original_assessment, result, trace)

変更履歴:
    - 2026-01-31: Phase6 統合モジュール追加 (context_builder, result_applier, create_phase6_engine)
"""

from .engine import (
    RuleEngine,
    EngineResult,
    RulePhase,
    create_all_rules,
    create_default_engine,
    create_phase6_rules,
    create_phase6_engine,
)
from .detectors.base import RuleContext, RuleResult, DetectionRule
from .context_builder import RuleContextBuilder
from .result_applier import ResultApplier
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
    'RulePhase',
    'create_all_rules',
    'create_default_engine',
    'create_phase6_rules',
    'create_phase6_engine',
    # Base classes
    'RuleContext',
    'RuleResult',
    'DetectionRule',
    # Phase6 Integration (2026-01-31)
    'RuleContextBuilder',
    'ResultApplier',
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
