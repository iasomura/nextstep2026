"""
Route1 automatic threshold selection module.

This module implements Wilson score-based threshold selection
for minimizing DEFER while satisfying risk constraints.
"""

import numpy as np
from typing import Tuple, Dict, Any, Optional


def _z_one_sided(alpha: float) -> float:
    """
    Return z-score for one-sided normal quantile.

    Supports common alpha values without requiring SciPy.

    Args:
        alpha: Significance level

    Returns:
        Z-score for one-sided test
    """
    if alpha <= 0:
        return 10.0

    # Common values (precomputed)
    alpha_map = {
        0.10: 1.2815515655446004,
        0.05: 1.6448536269514722,
        0.02: 2.053748910631823,
        0.01: 2.3263478740408408,
        0.005: 2.5758293035489004,
        0.001: 3.090232306167813,
    }

    # Find closest alpha
    for key, value in alpha_map.items():
        if abs(alpha - key) < 1e-9:
            return value

    # Fallback to alpha=0.05
    return 1.6448536269514722


def wilson_upper_bound(
    k: np.ndarray,
    n: np.ndarray,
    alpha: float = 0.05
) -> np.ndarray:
    """
    Wilson score one-sided upper confidence bound for Bernoulli proportion.

    Args:
        k: Number of successes (array)
        n: Number of trials (array)
        alpha: Significance level for one-sided test

    Returns:
        Upper confidence bound for proportion
    """
    k = np.asarray(k, dtype=float)
    n = np.asarray(n, dtype=float)

    # Avoid division by zero
    n_safe = np.maximum(n, 1.0)

    # Sample proportion
    phat = k / n_safe

    # Z-score
    z = _z_one_sided(alpha)
    z2 = z * z

    # Wilson score formula
    denom = 1.0 + z2 / n_safe
    center = (phat + z2 / (2.0 * n_safe)) / denom
    half = (z * np.sqrt(
        (phat * (1.0 - phat) / n_safe) +
        (z2 / (4.0 * n_safe * n_safe))
    )) / denom

    # Upper bound, capped at 1.0
    return np.minimum(1.0, center + half)


class Route1ThresholdSelector:
    """
    Route1 automatic threshold selector using Wilson score.

    Example:
        >>> from src.config import Route1Config
        >>> cfg = Route1Config()
        >>> selector = Route1ThresholdSelector(cfg)
        >>> t_low, t_high, stats = selector.select_thresholds(y_val, p_val)
    """

    def __init__(self, config):
        """
        Initialize threshold selector.

        Args:
            config: Route1Config object from src.config
        """
        self.config = config
        self.t_low = None
        self.t_high = None
        self.selection_meta = None

    def select_thresholds(
        self,
        y_val: np.ndarray,
        p_val: np.ndarray
    ) -> Tuple[float, float, Dict[str, Any]]:
        """
        Select (t_low, t_high) from validation data.

        Minimizes DEFER region while satisfying risk constraints:
        - P(y=1 | p <= t_low) <= risk_max_auto_benign
        - P(y=0 | p >= t_high) <= risk_max_auto_phish

        Args:
            y_val: True labels (0 or 1)
            p_val: Predicted probabilities

        Returns:
            Tuple of (t_low, t_high, stats_dict)
        """
        print("\n" + "="*80)
        print("🎯 Route1 Threshold Selection (Wilson Score)")
        print("="*80)

        y_val = np.asarray(y_val).astype(int)
        p_val = np.asarray(p_val).astype(float)

        print(f"📊 Validation data: {len(y_val):,} samples")
        print(f"   Phish: {(y_val == 1).sum():,} ({(y_val == 1).mean()*100:.1f}%)")
        print(f"   Benign: {(y_val == 0).sum():,} ({(y_val == 0).mean()*100:.1f}%)")

        print(f"\n🔧 Risk constraints:")
        print(f"   risk_max_auto_benign: {self.config.risk_max_auto_benign:.4f}")
        print(f"   risk_max_auto_phish: {self.config.risk_max_auto_phish:.4f}")
        print(f"   min_auto_samples: {self.config.min_auto_samples}")
        print(f"   risk_use_upper: {self.config.risk_use_upper}")
        print(f"   risk_alpha: {self.config.risk_alpha}")

        # Select t_low: maximize coverage with risk <= risk_max_auto_benign
        print("\n🔍 Selecting t_low (auto_benign threshold)...")
        t_low, meta_low = self._select_t_low(y_val, p_val)

        # Select t_high: maximize coverage with risk <= risk_max_auto_phish
        print("\n🔍 Selecting t_high (auto_phish threshold)...")
        t_high, meta_high = self._select_t_high(y_val, p_val)

        # Validation
        if t_low is None or t_high is None:
            raise ValueError(
                "Failed to select thresholds satisfying risk constraints. "
                "Try relaxing risk_max_auto_benign/phish or reducing min_auto_samples."
            )

        if not (0.0 <= t_low < t_high <= 1.0):
            raise ValueError(
                f"Invalid thresholds: t_low={t_low:.6f}, t_high={t_high:.6f}. "
                f"Must satisfy 0 <= t_low < t_high <= 1."
            )

        # Store results
        self.t_low = t_low
        self.t_high = t_high
        self.selection_meta = {
            't_low': float(t_low),
            't_high': float(t_high),
            **meta_low,
            **meta_high,
        }

        # Print summary
        print("\n" + "="*80)
        print("✅ Threshold Selection Complete")
        print("="*80)
        print(f"   t_low:  {t_low:.6f}")
        print(f"   t_high: {t_high:.6f}")
        print(f"   AUTO_BENIGN coverage: {meta_low['n']:,} ({meta_low['coverage']*100:.1f}%)")
        print(f"   AUTO_PHISH coverage:  {meta_high['n']:,} ({meta_high['coverage']*100:.1f}%)")
        print(f"   DEFER: {(1 - meta_low['coverage'] - meta_high['coverage'])*100:.1f}%")
        print("="*80)

        return t_low, t_high, self.selection_meta

    def _select_t_low(
        self,
        y_val: np.ndarray,
        p_val: np.ndarray
    ) -> Tuple[Optional[float], Dict[str, Any]]:
        """
        Select t_low (auto_benign threshold).

        Maximize coverage while keeping P(y=1 | p <= t_low) <= risk_max_auto_benign.
        """
        # Sort by probability (ascending)
        order = np.argsort(p_val)
        p_sorted = p_val[order]
        y_sorted = y_val[order]

        # Cumulative counts
        cum_pos = np.cumsum(y_sorted == 1)  # Number of phish
        idx = np.arange(len(p_sorted))
        size = idx + 1  # Number of samples

        # Risk estimate
        risk_point = cum_pos / np.maximum(size, 1)
        if self.config.risk_use_upper:
            risk = wilson_upper_bound(cum_pos, size, self.config.risk_alpha)
        else:
            risk = risk_point

        # Find valid candidates
        ok = (size >= self.config.min_auto_samples) & (risk <= self.config.risk_max_auto_benign)

        if not np.any(ok):
            return None, {}

        # Select largest coverage satisfying constraints
        i = int(np.max(np.where(ok)[0]))
        t_low = float(p_sorted[i])

        meta = {
            'low_n': int(size[i]),
            'low_k': int(cum_pos[i]),
            'low_risk_point': float(risk_point[i]),
            'low_risk_est': float(risk[i]),
            'n': int(size[i]),
            'coverage': float(size[i] / len(y_val)),
        }

        print(f"   Selected: p <= {t_low:.6f}")
        print(f"   Coverage: {meta['n']:,}/{len(y_val):,} ({meta['coverage']*100:.1f}%)")
        print(f"   Risk: {meta['low_risk_point']:.4f} (point), {meta['low_risk_est']:.4f} (upper bound)")

        return t_low, meta

    def _select_t_high(
        self,
        y_val: np.ndarray,
        p_val: np.ndarray
    ) -> Tuple[Optional[float], Dict[str, Any]]:
        """
        Select t_high (auto_phish threshold).

        Maximize coverage while keeping P(y=0 | p >= t_high) <= risk_max_auto_phish.
        """
        # Sort by probability (descending)
        order = np.argsort(-p_val)
        p_desc = p_val[order]
        y_desc = y_val[order]

        # Cumulative counts
        cum_neg = np.cumsum(y_desc == 0)  # Number of benign
        idx = np.arange(len(p_desc))
        size = idx + 1  # Number of samples

        # Risk estimate
        risk_point = cum_neg / np.maximum(size, 1)
        if self.config.risk_use_upper:
            risk = wilson_upper_bound(cum_neg, size, self.config.risk_alpha)
        else:
            risk = risk_point

        # Find valid candidates
        ok = (size >= self.config.min_auto_samples) & (risk <= self.config.risk_max_auto_phish)

        if not np.any(ok):
            return None, {}

        # Select largest coverage satisfying constraints
        j = int(np.max(np.where(ok)[0]))
        t_high = float(p_desc[j])

        meta = {
            'high_n': int(size[j]),
            'high_k': int(cum_neg[j]),
            'high_risk_point': float(risk_point[j]),
            'high_risk_est': float(risk[j]),
            'n': int(size[j]),
            'coverage': float(size[j] / len(y_val)),
        }

        print(f"   Selected: p >= {t_high:.6f}")
        print(f"   Coverage: {meta['n']:,}/{len(y_val):,} ({meta['coverage']*100:.1f}%)")
        print(f"   Risk: {meta['high_risk_point']:.4f} (point), {meta['high_risk_est']:.4f} (upper bound)")

        return t_high, meta

    def apply_thresholds(
        self,
        p: np.ndarray
    ) -> np.ndarray:
        """
        Apply thresholds to predictions.

        Args:
            p: Predicted probabilities

        Returns:
            Array of decisions: 0=auto_benign, 1=defer, 2=auto_phish
        """
        if self.t_low is None or self.t_high is None:
            raise ValueError("Thresholds not selected yet. Call select_thresholds() first.")

        decisions = np.ones(len(p), dtype=int)  # Default: defer
        decisions[p <= self.t_low] = 0  # auto_benign
        decisions[p >= self.t_high] = 2  # auto_phish

        return decisions

    def get_meta(self) -> Dict[str, Any]:
        """Get threshold selection metadata."""
        if self.selection_meta is None:
            raise ValueError("Thresholds not selected yet. Call select_thresholds() first.")
        return self.selection_meta.copy()


def select_thresholds_auto(
    config,
    y_val: np.ndarray,
    p_val: np.ndarray
) -> Tuple[float, float, Dict[str, Any]]:
    """
    Convenience function for automatic threshold selection.

    Args:
        config: Route1Config object
        y_val: Validation labels
        p_val: Validation probabilities

    Returns:
        Tuple of (t_low, t_high, stats_dict)

    Example:
        >>> from src.config import load_config
        >>> cfg = load_config()
        >>> t_low, t_high, stats = select_thresholds_auto(cfg.route1, y_val, p_val)
    """
    selector = Route1ThresholdSelector(config)
    return selector.select_thresholds(y_val, p_val)
