# -*- coding: utf-8 -*-
"""
phishing_agent.rules.data
-------------------------
Data definitions for detection rules.
"""

from .tlds import (
    DANGEROUS_TLDS,
    HIGH_DANGER_TLDS,
    MEDIUM_DANGER_TLDS,  # 2026-01-27追加
    SAFE_TLDS,
    CCTLD_COUNTRIES,
    DANGEROUS_CCTLDS,
)
from .patterns import (
    HIGH_RISK_WORDS,
    MULTILINGUAL_RISK_WORDS,
    RARE_BIGRAMS,
    RANDOM_PATTERN_INDICATORS,
)
from .brands import (
    CRITICAL_BRAND_KEYWORDS,
    BOUNDARY_REQUIRED_BRANDS,
    BRAND_FP_EXCLUSION_WORDS,
)

__all__ = [
    # TLDs
    'DANGEROUS_TLDS',
    'HIGH_DANGER_TLDS',
    'MEDIUM_DANGER_TLDS',  # 2026-01-27追加
    'SAFE_TLDS',
    'CCTLD_COUNTRIES',
    'DANGEROUS_CCTLDS',
    # Patterns
    'HIGH_RISK_WORDS',
    'MULTILINGUAL_RISK_WORDS',
    'RARE_BIGRAMS',
    'RANDOM_PATTERN_INDICATORS',
    # Brands
    'CRITICAL_BRAND_KEYWORDS',
    'BOUNDARY_REQUIRED_BRANDS',
    'BRAND_FP_EXCLUSION_WORDS',
]
