# -*- coding: utf-8 -*-
"""
phishing_agent.rules.config
---------------------------
Configuration classes for detection rules.
"""

from .thresholds import (
    MLThresholds,
    ParadoxConfig,
    ScoreWeights,
    LowSignalConfig,
    TLDComboConfig,
    DVComboConfig,
    RandomPatternConfig,
    HighRiskWordsConfig,
)
from .settings import RuleSettings, RulesConfig

__all__ = [
    'MLThresholds',
    'ParadoxConfig',
    'ScoreWeights',
    'LowSignalConfig',
    'TLDComboConfig',
    'DVComboConfig',
    'RandomPatternConfig',
    'HighRiskWordsConfig',
    'RuleSettings',
    'RulesConfig',
]
