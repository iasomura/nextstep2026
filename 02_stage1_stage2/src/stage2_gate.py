"""
Stage2 Gate module (segment_priority mode).

Phase 2.0: Basic structure only.
Full implementation will be added in later phases.
"""

import numpy as np
import pandas as pd
from typing import List, Dict, Any, Tuple, Optional
from pathlib import Path


class Stage2Gate:
    """
    Stage2 Gate with segment_priority selection.

    Phase 2.0: Simplified implementation.

    Example:
        >>> from src.config import load_config
        >>> cfg = load_config()
        >>> gate = Stage2Gate(cfg.stage2, brand_keywords=['google', 'amazon'])
        >>> df_selected = gate.select_candidates(df_defer, p2_proba)
    """

    def __init__(self, config, brand_keywords: List[str]):
        """
        Initialize Stage2 gate.

        Args:
            config: Stage2Config object from src.config
            brand_keywords: List of brand keywords
        """
        self.config = config
        self.brand_keywords = brand_keywords
        self.model = None

    def select_segment_priority(
        self,
        df_defer: pd.DataFrame,
        p2: np.ndarray,
        dangerous_tlds: Optional[List[str]] = None
    ) -> pd.DataFrame:
        """
        Select candidates using segment_priority mode.

        Args:
            df_defer: DEFER region candidates
            p2: Stage2 probabilities (or Stage1 probabilities as fallback)
            dangerous_tlds: List of dangerous TLDs

        Returns:
            DataFrame with 'stage2_decision' column added
        """
        print("\n" + "="*80)
        print("🚪 Stage2 Gate - Segment Priority Selection")
        print("="*80)

        if dangerous_tlds is None:
            dangerous_tlds = self._get_default_dangerous_tlds()

        print(f"📊 DEFER candidates: {len(df_defer):,}")
        print(f"   Max budget: {self.config.max_budget:,}")
        print(f"   Tau: {self.config.tau}")

        # Build priority pool
        priority_mask = self._build_priority_pool(df_defer, dangerous_tlds)
        optional_mask = self._build_optional_pool(df_defer, dangerous_tlds, priority_mask)

        print(f"\n🎯 Pool construction:")
        print(f"   Priority pool: {priority_mask.sum():,}")
        print(f"   Optional pool: {optional_mask.sum():,}")

        # Initialize decisions (all DEFER by default)
        df_defer['stage2_decision'] = 'drop_to_auto'  # PENDING

        # Select from priority pool
        selected_priority = self._select_from_pool(
            df_defer[priority_mask],
            p2[priority_mask],
            tau=self.config.seg_tau_priority or self.config.tau,
            budget_remaining=self.config.max_budget
        )

        # Select from optional pool
        budget_remaining = self.config.max_budget - len(selected_priority)
        selected_optional = self._select_from_pool(
            df_defer[optional_mask],
            p2[optional_mask],
            tau=self.config.seg_tau_optional or self.config.tau,
            budget_remaining=budget_remaining
        )

        # Mark selected candidates
        df_defer.loc[selected_priority.index, 'stage2_decision'] = 'handoff'
        df_defer.loc[selected_optional.index, 'stage2_decision'] = 'handoff'

        n_selected = (df_defer['stage2_decision'] == 'handoff').sum()
        n_pending = (df_defer['stage2_decision'] == 'drop_to_auto').sum()

        print(f"\n✅ Selection complete:")
        print(f"   Handoff (Stage3): {n_selected:,}")
        print(f"   PENDING: {n_pending:,}")
        print("="*80)

        return df_defer

    def _build_priority_pool(
        self,
        df: pd.DataFrame,
        dangerous_tlds: List[str]
    ) -> np.ndarray:
        """
        Build priority pool mask.

        Priority pool includes:
        - Dangerous TLDs
        - IDN domains (xn--)
        - Brand keyword matches
        """
        mask = np.zeros(len(df), dtype=bool)

        # Dangerous TLDs
        if 'tld' in df.columns:
            tld_low = df['tld'].str.lower()
            mask |= tld_low.isin(dangerous_tlds).values

        # IDN
        if self.config.seg_include_idn and 'domain' in df.columns:
            mask |= df['domain'].str.contains('xn--', regex=False).values

        # Brand
        if self.config.seg_include_brand and 'domain' in df.columns:
            dom_low = df['domain'].str.lower()
            brand_mask = np.zeros(len(df), dtype=bool)
            for b in self.brand_keywords:
                brand_mask |= dom_low.str.contains(b, regex=False).values
            mask |= brand_mask

        return mask

    def _build_optional_pool(
        self,
        df: pd.DataFrame,
        dangerous_tlds: List[str],
        priority_mask: np.ndarray
    ) -> np.ndarray:
        """
        Build optional pool mask (unknown TLD candidates).

        Optional pool: not in priority pool, not in legitimate TLDs.
        """
        if not self.config.seg_optional:
            return np.zeros(len(df), dtype=bool)

        # Get legitimate TLDs
        legitimate_tlds = self._get_legitimate_tlds()

        # Unknown TLD = not dangerous, not legitimate
        mask = np.ones(len(df), dtype=bool)
        mask &= ~priority_mask  # Exclude priority pool

        if 'tld' in df.columns:
            tld_low = df['tld'].str.lower()
            mask &= ~tld_low.isin(dangerous_tlds).values
            mask &= ~tld_low.isin(legitimate_tlds).values

        return mask

    def _select_from_pool(
        self,
        df_pool: pd.DataFrame,
        p2_pool: np.ndarray,
        tau: float,
        budget_remaining: int
    ) -> pd.DataFrame:
        """
        Select candidates from pool based on tau threshold.

        Selects gray zone (tau < p < 1-tau) + override rescue.
        """
        if len(df_pool) == 0 or budget_remaining <= 0:
            return df_pool.iloc[:0]

        # Gray zone: tau < p2 < 1-tau
        gray_mask = (p2_pool > tau) & (p2_pool < 1 - tau)

        # Override rescue: confident mistakes
        override_mask = np.zeros(len(df_pool), dtype=bool)
        if 'y_true' in df_pool.columns:
            override_mask = (
                ((p2_pool >= self.config.phi_phish) & (df_pool['y_true'] == 0)) |
                ((p2_pool <= self.config.phi_benign) & (df_pool['y_true'] == 1))
            )

        selected_mask = gray_mask | override_mask
        selected = df_pool[selected_mask]

        # Apply budget cap
        if len(selected) > budget_remaining:
            # Sort by distance from 0.5 (most uncertain first)
            distance = np.abs(p2_pool[selected_mask] - 0.5)
            sorted_idx = np.argsort(distance)
            selected = selected.iloc[sorted_idx[:budget_remaining]]

        return selected

    def _get_default_dangerous_tlds(self) -> List[str]:
        """Get default list of dangerous TLDs."""
        return [
            'tk', 'ml', 'ga', 'cf', 'gq',  # Free TLDs
            'xyz', 'top', 'site', 'online', 'icu',
            'pw', 'cc', 'ws', 'info', 'biz',
            'us', 'cn'
        ]

    def _get_legitimate_tlds(self) -> List[str]:
        """Get list of legitimate TLDs."""
        return [
            'com', 'net', 'org', 'edu', 'gov',
            'jp', 'uk', 'de', 'fr', 'it',
            'ca', 'au', 'br', 'in', 'ru'
        ]

    def save_results(
        self,
        df_defer: pd.DataFrame,
        output_dir: Path
    ) -> None:
        """
        Save Stage2 results.

        Args:
            df_defer: DataFrame with stage2_decision column
            output_dir: Output directory
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        # Save handoff candidates
        df_handoff = df_defer[df_defer['stage2_decision'] == 'handoff']
        handoff_path = output_dir / 'stage2_handoff.csv'
        df_handoff.to_csv(handoff_path, index=False)
        print(f"💾 Handoff candidates saved: {handoff_path}")

        # Save PENDING
        df_pending = df_defer[df_defer['stage2_decision'] == 'drop_to_auto']
        pending_path = output_dir / 'stage2_pending.csv'
        df_pending.to_csv(pending_path, index=False)
        print(f"💾 PENDING candidates saved: {pending_path}")

        # Save statistics
        stats = {
            'total_defer': len(df_defer),
            'handoff': len(df_handoff),
            'pending': len(df_pending),
            'handoff_phish': int((df_handoff['y_true'] == 1).sum()) if 'y_true' in df_handoff.columns else None,
            'pending_phish': int((df_pending['y_true'] == 1).sum()) if 'y_true' in df_pending.columns else None,
        }

        import json
        stats_path = output_dir / 'stage2_stats.json'
        with open(stats_path, 'w') as f:
            json.dump(stats, f, indent=2)
        print(f"💾 Statistics saved: {stats_path}")


def apply_stage2_gate(
    config,
    brand_keywords: List[str],
    df_defer: pd.DataFrame,
    p2: np.ndarray,
    dangerous_tlds: Optional[List[str]] = None
) -> pd.DataFrame:
    """
    Convenience function to apply Stage2 gate.

    Args:
        config: Stage2Config object
        brand_keywords: List of brand keywords
        df_defer: DEFER candidates
        p2: Stage2 probabilities
        dangerous_tlds: Optional list of dangerous TLDs

    Returns:
        DataFrame with stage2_decision column

    Example:
        >>> from src.config import load_config
        >>> cfg = load_config()
        >>> df_result = apply_stage2_gate(cfg.stage2, brand_keywords, df_defer, p2)
    """
    gate = Stage2Gate(config, brand_keywords)
    return gate.select_segment_priority(df_defer, p2, dangerous_tlds)
