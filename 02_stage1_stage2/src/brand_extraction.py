"""
Brand keyword extraction module.

Phase 2.0: Simplified version that wraps the existing notebook logic.
Full implementation will be added in later phases.
"""

from typing import List, Dict, Optional
import pandas as pd
import numpy as np


class BrandExtractor:
    """
    Brand keyword extractor (Phase 2.0: Simplified wrapper).

    This class provides a clean interface to the brand extraction logic
    from Cell 16 of the notebook.
    """

    def __init__(self, config):
        """
        Initialize brand extractor.

        Args:
            config: BrandConfig object from src.config
        """
        self.config = config
        self.brand_keywords = []

    def extract_from_globals(self) -> List[str]:
        """
        Extract BRAND_KEYWORDS from global namespace.

        This is a temporary method for Phase 2.0 that assumes
        Cell 16 has already been executed in the notebook environment.

        Returns:
            List of brand keywords
        """
        import builtins

        # Try to get BRAND_KEYWORDS from global namespace
        if hasattr(builtins, 'BRAND_KEYWORDS'):
            keywords = builtins.BRAND_KEYWORDS
        elif 'BRAND_KEYWORDS' in globals():
            keywords = globals()['BRAND_KEYWORDS']
        else:
            raise ValueError(
                "BRAND_KEYWORDS not found in global namespace. "
                "Please run Cell 16 first."
            )

        self.brand_keywords = keywords
        return keywords

    def filter_keywords(self, keywords: List[str]) -> List[str]:
        """
        Apply filtering based on config.

        Args:
            keywords: List of raw brand keywords

        Returns:
            Filtered list of keywords
        """
        filtered = keywords.copy()

        # Length filter
        if self.config.min_length is not None:
            filtered = [k for k in filtered if len(k) >= self.config.min_length]
        if self.config.max_length is not None:
            filtered = [k for k in filtered if len(k) <= self.config.max_length]

        # Blacklist filter
        if self.config.blacklist:
            filtered = [k for k in filtered if k not in self.config.blacklist]

        # Manual additions
        if self.config.manual_additions:
            for kw in self.config.manual_additions:
                if kw not in filtered:
                    filtered.append(kw)

        return filtered

    def validate_with_data(
        self,
        keywords: List[str],
        df_candidates: pd.DataFrame
    ) -> Dict[str, dict]:
        """
        Validate keywords against actual candidate data.

        Args:
            keywords: List of keywords to validate
            df_candidates: DataFrame with 'domain' and 'y_true' columns

        Returns:
            Dict mapping keyword to performance stats
        """
        stats = {}
        dom_low = df_candidates['domain'].str.lower()

        for kw in keywords:
            mask = dom_low.str.contains(kw, regex=False)
            matched = df_candidates[mask]

            if len(matched) > 0:
                n_phish = (matched['y_true'] == 1).sum()
                phish_rate = n_phish / len(matched)

                # Check if keyword meets threshold
                keep = True
                if self.config.phish_rate_threshold is not None:
                    keep = phish_rate >= self.config.phish_rate_threshold

                stats[kw] = {
                    'matches': len(matched),
                    'phish_count': int(n_phish),
                    'phish_rate': float(phish_rate),
                    'keep': keep
                }
            else:
                stats[kw] = {
                    'matches': 0,
                    'phish_count': 0,
                    'phish_rate': 0.0,
                    'keep': False
                }

        return stats

    def print_validation_report(self, stats: Dict[str, dict]) -> None:
        """
        Print validation report.

        Args:
            stats: Validation statistics from validate_with_data()
        """
        print("\n" + "="*80)
        print("Brand Keyword Validation Report")
        print("="*80)

        # Sort by phish_rate descending
        sorted_keywords = sorted(
            stats.items(),
            key=lambda x: (-x[1]['phish_rate'], -x[1]['matches'])
        )

        print(f"\n{'Keyword':<20} {'Matches':>8} {'Phish':>6} {'Rate':>7} {'Keep':>6}")
        print("-"*80)

        for kw, stat in sorted_keywords:
            if stat['matches'] > 0:
                keep_mark = "✅" if stat['keep'] else "❌"
                print(
                    f"{kw:<20} {stat['matches']:>8} {stat['phish_count']:>6} "
                    f"{stat['phish_rate']:>6.1%} {keep_mark:>6}"
                )

        # Summary
        total_keywords = len(stats)
        kept_keywords = sum(1 for s in stats.values() if s['keep'])
        total_matches = sum(s['matches'] for s in stats.values())
        total_phish = sum(s['phish_count'] for s in stats.values())

        print("-"*80)
        print(f"Total keywords: {total_keywords}")
        print(f"Kept keywords: {kept_keywords}")
        print(f"Total matches: {total_matches:,}")
        print(f"Total phish: {total_phish:,}")
        if total_matches > 0:
            print(f"Overall phish rate: {total_phish/total_matches:.1%}")
        print("="*80)


def extract_brand_keywords(config) -> List[str]:
    """
    Convenience function to extract brand keywords.

    Phase 2.0: This is a simplified wrapper that assumes
    BRAND_KEYWORDS already exists in the global namespace.

    Args:
        config: BrandConfig object

    Returns:
        List of brand keywords

    Example:
        >>> from src.config import load_config
        >>> from src.brand_extraction import extract_brand_keywords
        >>> cfg = load_config()
        >>> keywords = extract_brand_keywords(cfg.brand_keywords)
    """
    extractor = BrandExtractor(config)
    return extractor.extract_from_globals()
