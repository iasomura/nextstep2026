# -*- coding: utf-8 -*-
"""
phishing_agent.rules.detectors.low_signal_gate
----------------------------------------------
Low-signal phishing detection gate rules.

These rules detect phishing domains that have low ML scores but exhibit
suspicious certificate and brand patterns.

変更履歴:
    - 2026-01-27: 初版作成 (llm_final_decision.py から移植)
"""

from typing import Set, Optional
from .base import DetectionRule, RuleContext, RuleResult
from ..data.tlds import HIGH_DANGER_TLDS, MEDIUM_DANGER_TLDS


class LowSignalPhishingGateP1Rule(DetectionRule):
    """Low Signal Phishing Gate P1: Brand + Short Certificate.

    ブランド検出 + 短期証明書(≤90日) + 低ML(< 0.30) → PHISHING
    正規サイトがブランド名を含む場合、通常は長期証明書を使用する。

    例外:
    - 非危険TLD + ML < 0.30 の場合はスキップ (Let's Encrypt対策)
    - OV/EV/CRL証明書がある場合はスキップ

    変更履歴:
        - 2026-01-27: llm_final_decision.py から移植
    """

    def __init__(
        self,
        enabled: bool = True,
        valid_days_threshold: int = 90,
        ml_threshold: float = 0.30,
    ):
        super().__init__(enabled=enabled)
        self._valid_days_threshold = valid_days_threshold
        self._ml_threshold = ml_threshold

    @property
    def name(self) -> str:
        return "low_signal_phishing_gate_p1"

    @property
    def description(self) -> str:
        return f"PHISHING detection: Brand + short cert (≤{self._valid_days_threshold}d) + ML < {self._ml_threshold}"

    def _evaluate(self, ctx: RuleContext) -> RuleResult:
        # 既に phishing なら何もしない
        if ctx.llm_is_phishing:
            return RuleResult.not_triggered(self.name)

        # ブランド検出チェック
        brand_detected = bool(ctx.brand_details.get("detected_brands"))
        if not brand_detected:
            return RuleResult.not_triggered(self.name)

        # 証明書情報チェック
        valid_days = ctx.cert_details.get("valid_days", 0) or 0
        if valid_days <= 0 or valid_days > self._valid_days_threshold:
            return RuleResult.not_triggered(self.name)

        # ML threshold チェック
        if ctx.ml_probability >= self._ml_threshold:
            return RuleResult.not_triggered(self.name)

        # TLD危険度チェック
        tld = ctx.tld.lower().strip(".")
        is_high_danger = tld in HIGH_DANGER_TLDS
        is_medium_danger = tld in MEDIUM_DANGER_TLDS
        is_non_danger = not (is_high_danger or is_medium_danger or "dangerous_tld" in ctx.issue_set)

        # 非危険TLD + 低ML の場合はスキップ (Let's Encrypt対策)
        if is_non_danger and ctx.ml_probability < self._ml_threshold:
            return RuleResult(
                triggered=False,
                rule_name=self.name,
                reasoning="Skipped: non-dangerous TLD with low ML",
                details={
                    "skip_reason": "non_danger_tld_low_ml",
                    "tld": tld,
                    "ml_probability": ctx.ml_probability,
                },
            )

        # OV/EV/CRL証明書チェック
        has_strong_benign = bool(ctx.benign_indicators & {"ov_ev_cert", "has_crl_dp"})
        if has_strong_benign:
            return RuleResult(
                triggered=False,
                rule_name=self.name,
                reasoning="Skipped: strong benign certificate indicators",
                details={"skip_reason": "strong_benign_cert"},
            )

        # PHISHING 強制
        return RuleResult(
            triggered=True,
            rule_name=self.name,
            issue_tag="low_signal_phishing_gate_p1",
            force_phishing=True,
            confidence_floor=0.70,
            risk_level_bump="medium-high",
            reasoning=(
                f"Brand detected + short cert ({valid_days}d ≤ {self._valid_days_threshold}d) + "
                f"ML={ctx.ml_probability:.3f} < {self._ml_threshold}"
            ),
            details={
                "brand_detected": True,
                "valid_days": valid_days,
                "ml_probability": ctx.ml_probability,
                "tld": tld,
                "tld_danger": "high" if is_high_danger else "medium" if is_medium_danger else "low",
            },
        )


class LowSignalPhishingGateP2Rule(DetectionRule):
    """Low Signal Phishing Gate P2: Suspected Brand + Certificate Compound.

    ブランド疑い + 短期証明書 + 低SAN(≤5) + 低ML(< 0.25) → PHISHING
    LLMで疑わしいと判定されたケースに証明書リスクを組み合わせる。

    変更履歴:
        - 2026-01-27: llm_final_decision.py から移植
    """

    def __init__(
        self,
        enabled: bool = True,
        valid_days_threshold: int = 90,
        san_threshold: int = 5,
        ml_threshold: float = 0.25,
    ):
        super().__init__(enabled=enabled)
        self._valid_days_threshold = valid_days_threshold
        self._san_threshold = san_threshold
        self._ml_threshold = ml_threshold

    @property
    def name(self) -> str:
        return "low_signal_phishing_gate_p2"

    @property
    def description(self) -> str:
        return f"PHISHING detection: Suspected brand + short cert + low SAN (≤{self._san_threshold}) + ML < {self._ml_threshold}"

    def _evaluate(self, ctx: RuleContext) -> RuleResult:
        # 既に phishing なら何もしない
        if ctx.llm_is_phishing:
            return RuleResult.not_triggered(self.name)

        # ブランド検出済みならP1で処理
        brand_detected = bool(ctx.brand_details.get("detected_brands"))
        if brand_detected:
            return RuleResult.not_triggered(self.name)

        # ブランド疑いチェック
        brand_suspected = ctx.brand_details.get("brand_suspected", False)
        if not brand_suspected:
            return RuleResult.not_triggered(self.name)

        # 証明書情報チェック
        valid_days = ctx.cert_details.get("valid_days", 0) or 0
        san_count = ctx.cert_details.get("san_count", 0) or 0

        if valid_days <= 0 or valid_days > self._valid_days_threshold:
            return RuleResult.not_triggered(self.name)

        if san_count > self._san_threshold:
            return RuleResult.not_triggered(self.name)

        # ML threshold チェック
        if ctx.ml_probability >= self._ml_threshold:
            return RuleResult.not_triggered(self.name)

        # benign indicators チェック
        if ctx.benign_indicators:
            return RuleResult(
                triggered=False,
                rule_name=self.name,
                reasoning="Skipped: benign certificate indicators present",
                details={"skip_reason": "benign_indicators"},
            )

        # PHISHING 強制
        return RuleResult(
            triggered=True,
            rule_name=self.name,
            issue_tag="low_signal_phishing_gate_p2",
            force_phishing=True,
            confidence_floor=0.70,
            risk_level_bump="medium-high",
            reasoning=(
                f"Suspected brand + short cert ({valid_days}d) + low SAN ({san_count}) + "
                f"ML={ctx.ml_probability:.3f} < {self._ml_threshold}"
            ),
            details={
                "brand_suspected": True,
                "valid_days": valid_days,
                "san_count": san_count,
                "ml_probability": ctx.ml_probability,
            },
        )


class LowSignalPhishingGateP3Rule(DetectionRule):
    """Low Signal Phishing Gate P3: Dangerous TLD + Certificate Risk.

    危険TLD + 短期証明書 + 低SAN(≤3) + 低ML(< 0.20) → risk bump
    ブランドがなくても危険TLD + 証明書特徴で疑いを高める。

    注: P3はis_phishingを強制せず、risk_levelをbumpするのみ。

    変更履歴:
        - 2026-01-27: llm_final_decision.py から移植
    """

    def __init__(
        self,
        enabled: bool = True,
        valid_days_threshold: int = 90,
        san_threshold: int = 3,
        ml_threshold: float = 0.20,
    ):
        super().__init__(enabled=enabled)
        self._valid_days_threshold = valid_days_threshold
        self._san_threshold = san_threshold
        self._ml_threshold = ml_threshold

    @property
    def name(self) -> str:
        return "low_signal_phishing_gate_p3"

    @property
    def description(self) -> str:
        return f"Risk bump: Dangerous TLD + short cert + low SAN (≤{self._san_threshold}) + ML < {self._ml_threshold}"

    def _evaluate(self, ctx: RuleContext) -> RuleResult:
        # 既に phishing なら何もしない
        if ctx.llm_is_phishing:
            return RuleResult.not_triggered(self.name)

        # 危険TLDチェック
        tld = ctx.tld.lower().strip(".")
        is_dangerous_tld = (
            tld in HIGH_DANGER_TLDS
            or tld in MEDIUM_DANGER_TLDS
            or "dangerous_tld" in ctx.issue_set
            or "dangerous_tld" in ctx.ctx_issues
        )
        if not is_dangerous_tld:
            return RuleResult.not_triggered(self.name)

        # 証明書情報チェック
        valid_days = ctx.cert_details.get("valid_days", 0) or 0
        san_count = ctx.cert_details.get("san_count", 0) or 0

        if valid_days <= 0 or valid_days > self._valid_days_threshold:
            return RuleResult.not_triggered(self.name)

        if san_count > self._san_threshold:
            return RuleResult.not_triggered(self.name)

        # ML threshold チェック
        if ctx.ml_probability >= self._ml_threshold:
            return RuleResult.not_triggered(self.name)

        # benign indicators チェック
        if ctx.benign_indicators:
            return RuleResult(
                triggered=False,
                rule_name=self.name,
                reasoning="Skipped: benign certificate indicators present",
                details={"skip_reason": "benign_indicators"},
            )

        # Risk bump (not force_phishing)
        return RuleResult(
            triggered=True,
            rule_name=self.name,
            issue_tag="low_signal_phishing_gate_p3",
            force_phishing=False,  # P3はphishing強制しない
            risk_level_bump="medium",
            reasoning=(
                f"Dangerous TLD ({tld}) + short cert ({valid_days}d) + low SAN ({san_count}) + "
                f"ML={ctx.ml_probability:.3f} < {self._ml_threshold}"
            ),
            details={
                "is_dangerous_tld": True,
                "tld": tld,
                "valid_days": valid_days,
                "san_count": san_count,
                "ml_probability": ctx.ml_probability,
            },
        )


class LowSignalPhishingGateP4Rule(DetectionRule):
    """Low Signal Phishing Gate P4: Medium Danger TLD + Very Low ML.

    中危険TLD + 短期証明書 + 低SAN(≤2) + 非常に低いML(< 0.05) → PHISHING
    POST_LLM_FLIP_GATEでブロックされていたケースを救済する。

    変更履歴:
        - 2026-01-27: llm_final_decision.py から移植
    """

    def __init__(
        self,
        enabled: bool = True,
        valid_days_threshold: int = 90,
        san_threshold: int = 2,
        ml_threshold: float = 0.05,
    ):
        super().__init__(enabled=enabled)
        self._valid_days_threshold = valid_days_threshold
        self._san_threshold = san_threshold
        self._ml_threshold = ml_threshold

    @property
    def name(self) -> str:
        return "low_signal_phishing_gate_p4"

    @property
    def description(self) -> str:
        return f"PHISHING detection: Medium danger TLD + short cert + low SAN (≤{self._san_threshold}) + ML < {self._ml_threshold}"

    def _evaluate(self, ctx: RuleContext) -> RuleResult:
        # 既に phishing なら何もしない
        if ctx.llm_is_phishing:
            return RuleResult.not_triggered(self.name)

        # 中危険TLDチェック
        tld = ctx.tld.lower().strip(".")
        is_medium_danger = tld in MEDIUM_DANGER_TLDS
        if not is_medium_danger:
            return RuleResult.not_triggered(self.name)

        # 証明書情報チェック
        valid_days = ctx.cert_details.get("valid_days", 0) or 0
        san_count = ctx.cert_details.get("san_count", 0) or 0

        if valid_days <= 0 or valid_days > self._valid_days_threshold:
            return RuleResult.not_triggered(self.name)

        if san_count > self._san_threshold:
            return RuleResult.not_triggered(self.name)

        # ML threshold チェック (非常に低いML)
        if ctx.ml_probability >= self._ml_threshold:
            return RuleResult.not_triggered(self.name)

        # benign indicators チェック
        if ctx.benign_indicators:
            return RuleResult(
                triggered=False,
                rule_name=self.name,
                reasoning="Skipped: benign certificate indicators present",
                details={"skip_reason": "benign_indicators"},
            )

        # PHISHING 強制
        return RuleResult(
            triggered=True,
            rule_name=self.name,
            issue_tag="low_signal_phishing_gate_p4",
            force_phishing=True,
            confidence_floor=0.65,
            risk_level_bump="medium-high",
            reasoning=(
                f"Medium danger TLD ({tld}) + short cert ({valid_days}d) + low SAN ({san_count}) + "
                f"very low ML={ctx.ml_probability:.3f} < {self._ml_threshold}"
            ),
            details={
                "is_medium_danger_tld": True,
                "tld": tld,
                "valid_days": valid_days,
                "san_count": san_count,
                "ml_probability": ctx.ml_probability,
            },
        )


def create_low_signal_gate_rules(enabled: bool = True) -> list:
    """Create all low signal phishing gate rules.

    Args:
        enabled: Whether rules are enabled by default

    Returns:
        List of low signal gate rule instances
    """
    return [
        LowSignalPhishingGateP1Rule(enabled=enabled),
        LowSignalPhishingGateP2Rule(enabled=enabled),
        LowSignalPhishingGateP3Rule(enabled=enabled),
        LowSignalPhishingGateP4Rule(enabled=enabled),
    ]
