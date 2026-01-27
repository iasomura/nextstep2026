# -*- coding: utf-8 -*-
"""
phishing_agent.rules.config.thresholds
--------------------------------------
Threshold and parameter configurations for detection rules.

All configurations use frozen dataclasses for immutability.
To customize, create a new instance with modified values.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class MLThresholds:
    """ML probability thresholds for categorization.

    Attributes:
        very_low: Below this, ML strongly suggests benign (default: 0.10)
        low: Low probability threshold (default: 0.20)
        medium: Medium probability threshold (default: 0.35)
        high: High probability threshold (default: 0.50)
        very_high: Very high probability threshold (default: 0.80)
    """
    very_low: float = 0.10
    low: float = 0.20
    medium: float = 0.35
    high: float = 0.50
    very_high: float = 0.80


@dataclass(frozen=True)
class ParadoxConfig:
    """ML Paradox detection configuration.

    ML Paradox: When ML probability is low but structural signals suggest phishing.

    Attributes:
        strong_max_ml: Max ML for strong paradox (default: 0.20)
        strong_min_signals: Min signals for strong paradox (default: 2)
        weak_max_ml: Max ML for weak paradox (default: 0.30)
        weak_min_signals: Min signals for weak paradox (default: 1)
        strong_base_score: Base score for strong paradox (default: 0.80)
        weak_base_score: Base score for weak paradox (default: 0.60)
        alt_min_signals: Alternative min signals for ML <= low (default: 3)
    """
    strong_max_ml: float = 0.20
    strong_min_signals: int = 2
    weak_max_ml: float = 0.30
    weak_min_signals: int = 1
    strong_base_score: float = 0.80
    weak_base_score: float = 0.60
    alt_min_signals: int = 3


@dataclass(frozen=True)
class ScoreWeights:
    """Score calculation weights.

    Attributes:
        ml_weight: Weight for ML probability (default: 0.45)
        tools_weight: Weight for tool average risk (default: 0.35)
        multi_factor_bonus: Bonus for multiple risk factors (default: 0.12)
    """
    ml_weight: float = 0.45
    tools_weight: float = 0.35
    multi_factor_bonus: float = 0.12


@dataclass(frozen=True)
class LowSignalConfig:
    """Low-signal phishing detection configuration.

    Detects phishing with weak signals: low ML + DV cert + short validity + low SAN.

    Attributes:
        min_ml: Minimum ML to trigger (default: 0.10)
        max_ml: Maximum ML to trigger (default: 0.30)
        min_signals: Minimum signals required (default: 2)
        base_score: Base score when triggered (default: 0.38)
        score_per_signal: Additional score per signal (default: 0.03)
        max_valid_days: Max certificate validity days (default: 90)
        max_san_count: Max SAN count considered low (default: 5)
    """
    min_ml: float = 0.10
    max_ml: float = 0.30
    min_signals: int = 2
    base_score: float = 0.38
    score_per_signal: float = 0.03
    max_valid_days: int = 90
    max_san_count: int = 5


@dataclass(frozen=True)
class TLDComboConfig:
    """Dangerous TLD combination detection configuration.

    Attributes:
        low_ml_boost: Boost for dangerous TLD + low ML (default: 0.12)
        random_boost: Boost for dangerous TLD + random pattern (default: 0.20)
        short_boost: Boost for dangerous TLD + short domain (default: 0.15)
        brand_boost: Boost for dangerous TLD + brand detection (default: 0.25)
        high_risk_words_boost: Boost for dangerous TLD + risk words (default: 0.28)
        cn_extra_boost: Extra boost for .cn TLD (default: 0.15)
        max_total_boost: Maximum total boost (default: 0.50)
        min_ml_for_low_ml_boost: Min ML for low_ml_boost (default: 0.10)
        max_ml_for_low_ml_boost: Max ML for low_ml_boost (default: 0.15)
    """
    low_ml_boost: float = 0.12
    random_boost: float = 0.20
    short_boost: float = 0.15
    brand_boost: float = 0.25
    high_risk_words_boost: float = 0.28
    cn_extra_boost: float = 0.15
    max_total_boost: float = 0.50
    min_ml_for_low_ml_boost: float = 0.10
    max_ml_for_low_ml_boost: float = 0.15


@dataclass(frozen=True)
class DVComboConfig:
    """DV certificate suspicious combo detection configuration.

    Attributes:
        min_ml: Minimum ML to trigger (default: 0.10)
        high_danger_min_score: Min score for high danger TLDs (default: 0.42)
        medium_danger_min_score: Min score for medium danger TLDs (default: 0.35)
    """
    min_ml: float = 0.10
    high_danger_min_score: float = 0.42
    medium_danger_min_score: float = 0.35


@dataclass(frozen=True)
class RandomPatternConfig:
    """Random pattern detection configuration.

    Attributes:
        min_score_base: Base minimum score (default: 0.45)
        min_score_short: Minimum score for short domains (default: 0.50)
        min_score_dangerous_tld: Minimum score for dangerous TLDs (default: 0.55)
        entropy_threshold: Shannon entropy threshold (default: 4.0)
        entropy_threshold_short: Entropy threshold for short domains (default: 3.5)
        vowel_ratio_threshold: Vowel ratio threshold (default: 0.20)
        vowel_ratio_threshold_dangerous: Vowel ratio for dangerous TLDs (default: 0.15)
        consonant_cluster_min: Min consonant clusters for detection (default: 2)
        rare_bigram_ratio_threshold: Rare bigram ratio threshold (default: 0.15)
    """
    min_score_base: float = 0.45
    min_score_short: float = 0.50
    min_score_dangerous_tld: float = 0.55
    entropy_threshold: float = 4.0
    entropy_threshold_short: float = 3.5
    vowel_ratio_threshold: float = 0.20
    vowel_ratio_threshold_dangerous: float = 0.15
    consonant_cluster_min: int = 2
    rare_bigram_ratio_threshold: float = 0.15


@dataclass(frozen=True)
class HighRiskWordsConfig:
    """High risk words detection configuration.

    Attributes:
        base_bonus: Base bonus for first match (default: 0.18)
        step_bonus: Additional bonus per match (default: 0.06)
        max_bonus: Maximum total bonus (default: 0.38)
    """
    base_bonus: float = 0.18
    step_bonus: float = 0.06
    max_bonus: float = 0.38
