# -*- coding: utf-8 -*-
"""
phishing_agent.rules.detectors
------------------------------
Detection rule implementations.
"""

from .base import DetectionRule, RuleContext, RuleResult

# ML Paradox rules
from .ml_paradox import (
    MLParadoxStrongRule,
    MLParadoxWeakRule,
    create_ml_paradox_rules,
)

# TLD combination rules
from .tld_combo import (
    DangerousTLDLowMLRule,
    DangerousTLDRandomRule,
    DangerousTLDBrandRule,
    HighDangerTLDRule,
    create_tld_combo_rules,
)

# Low-signal detection rules
from .low_signal import (
    LowSignalPhishingRule,
    DVSuspiciousComboRule,
    create_low_signal_rules,
)

# ML guard rules (2026-01-27追加)
from .ml_guard import (
    VeryHighMLOverrideRule,
    HighMLOverrideRule,
    UltraLowMLBlockRule,
    PostLLMFlipGateRule,
    create_ml_guard_rules,
)

# Certificate gate rules (2026-01-27追加)
from .cert_gate import (
    BenignCertGateB1Rule,
    BenignCertGateB2Rule,
    BenignCertGateB3Rule,
    BenignCertGateB4Rule,
    create_cert_gate_rules,
)

# Low signal phishing gate rules (2026-01-27追加)
from .low_signal_gate import (
    LowSignalPhishingGateP1Rule,
    LowSignalPhishingGateP2Rule,
    LowSignalPhishingGateP3Rule,
    LowSignalPhishingGateP4Rule,
    create_low_signal_gate_rules,
)

# Policy rules (2026-01-27追加)
from .policy import (
    PolicyR1Rule,
    PolicyR2Rule,
    PolicyR3Rule,
    PolicyR4Rule,
    PolicyR5Rule,
    PolicyR6Rule,
    create_policy_rules,
)

__all__ = [
    # Base classes
    'DetectionRule',
    'RuleContext',
    'RuleResult',
    # ML Paradox
    'MLParadoxStrongRule',
    'MLParadoxWeakRule',
    'create_ml_paradox_rules',
    # TLD Combo
    'DangerousTLDLowMLRule',
    'DangerousTLDRandomRule',
    'DangerousTLDBrandRule',
    'HighDangerTLDRule',
    'create_tld_combo_rules',
    # Low-signal
    'LowSignalPhishingRule',
    'DVSuspiciousComboRule',
    'create_low_signal_rules',
    # ML Guard (2026-01-27追加)
    'VeryHighMLOverrideRule',
    'HighMLOverrideRule',
    'UltraLowMLBlockRule',
    'PostLLMFlipGateRule',
    'create_ml_guard_rules',
    # Certificate Gate (2026-01-27追加)
    'BenignCertGateB1Rule',
    'BenignCertGateB2Rule',
    'BenignCertGateB3Rule',
    'BenignCertGateB4Rule',
    'create_cert_gate_rules',
    # Low Signal Gate (2026-01-27追加)
    'LowSignalPhishingGateP1Rule',
    'LowSignalPhishingGateP2Rule',
    'LowSignalPhishingGateP3Rule',
    'LowSignalPhishingGateP4Rule',
    'create_low_signal_gate_rules',
    # Policy Rules (2026-01-27追加)
    'PolicyR1Rule',
    'PolicyR2Rule',
    'PolicyR3Rule',
    'PolicyR4Rule',
    'PolicyR5Rule',
    'PolicyR6Rule',
    'create_policy_rules',
]
