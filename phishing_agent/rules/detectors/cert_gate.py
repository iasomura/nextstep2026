# -*- coding: utf-8 -*-
"""
phishing_agent.rules.detectors.cert_gate
----------------------------------------
Certificate-based benign gate rules.

These rules use certificate quality indicators to identify legitimate domains
and prevent false positives.

変更履歴:
    - 2026-01-27: 初版作成 (llm_final_decision.py から移植)
"""

from typing import Set, Optional
from .base import DetectionRule, RuleContext, RuleResult
from ..data.tlds import HIGH_DANGER_TLDS, MEDIUM_DANGER_TLDS


# 強いリスクシグナル（これらがあると証明書ゲートをスキップ）
STRONG_RISK_SIGNALS: Set[str] = frozenset({
    "self_signed",
    "brand_detected",
    "idn_homograph",
    "high_entropy",
    "very_high_entropy",
    "random_with_high_tld_stat",
})


class BenignCertGateB1Rule(DetectionRule):
    """Benign Certificate Gate B1: OV/EV Certificate.

    OV/EV証明書は発行に組織確認が必要なため、フィッシングではまず使われない。
    OV/EV証明書 + contextual score < 0.50 → BENIGN

    変更履歴:
        - 2026-01-27: llm_final_decision.py から移植
    """

    def __init__(
        self,
        enabled: bool = True,
        ctx_threshold: float = 0.50,
    ):
        super().__init__(enabled=enabled)
        self._ctx_threshold = ctx_threshold

    @property
    def name(self) -> str:
        return "benign_cert_gate_b1"

    @property
    def description(self) -> str:
        return f"BENIGN protection: OV/EV certificate with ctx < {self._ctx_threshold}"

    def _evaluate(self, ctx: RuleContext) -> RuleResult:
        # 既に benign なら何もしない
        if ctx.llm_is_phishing is False:
            return RuleResult.not_triggered(self.name)

        # 強いリスクシグナルがあればスキップ
        if self._has_strong_risk_signals(ctx):
            return RuleResult(
                triggered=False,
                rule_name=self.name,
                reasoning="Skipped: strong risk signals present",
                details={"skip_reason": "strong_risk_signals"},
            )

        # OV/EV証明書チェック
        if "ov_ev_cert" not in ctx.benign_indicators:
            return RuleResult.not_triggered(self.name)

        # ctx threshold チェック
        if ctx.ctx_score >= self._ctx_threshold:
            return RuleResult.not_triggered(self.name)

        # BENIGN 強制
        return RuleResult(
            triggered=True,
            rule_name=self.name,
            issue_tag="benign_cert_gate_b1",
            force_benign=True,
            confidence_floor=0.75,
            risk_level_bump="low",
            reasoning=(
                f"OV/EV certificate detected with ctx={ctx.ctx_score:.3f} < {self._ctx_threshold}"
            ),
            details={
                "indicator": "ov_ev_cert",
                "ctx_score": ctx.ctx_score,
                "threshold": self._ctx_threshold,
            },
        )

    def _has_strong_risk_signals(self, ctx: RuleContext) -> bool:
        """強いリスクシグナルがあるかチェック"""
        all_issues = ctx.issue_set | ctx.ctx_issues
        if all_issues & STRONG_RISK_SIGNALS:
            return True
        # brand_detected は brand_details からもチェック
        if ctx.brand_details.get("detected_brands"):
            return True
        return False


class BenignCertGateB2Rule(DetectionRule):
    """Benign Certificate Gate B2: CRL Distribution Point.

    CRL配布ポイントを持つ証明書は正規CAの厳格な発行プロセスを経ている。
    CRL保有 + ML < 0.30 + ctx < 0.45 → BENIGN

    変更履歴:
        - 2026-01-27: llm_final_decision.py から移植
    """

    def __init__(
        self,
        enabled: bool = True,
        ml_threshold: float = 0.30,
        ctx_threshold: float = 0.45,
    ):
        super().__init__(enabled=enabled)
        self._ml_threshold = ml_threshold
        self._ctx_threshold = ctx_threshold

    @property
    def name(self) -> str:
        return "benign_cert_gate_b2"

    @property
    def description(self) -> str:
        return f"BENIGN protection: CRL cert with ML < {self._ml_threshold} and ctx < {self._ctx_threshold}"

    def _evaluate(self, ctx: RuleContext) -> RuleResult:
        # 既に benign なら何もしない
        if ctx.llm_is_phishing is False:
            return RuleResult.not_triggered(self.name)

        # 強いリスクシグナルがあればスキップ
        if self._has_strong_risk_signals(ctx):
            return RuleResult(
                triggered=False,
                rule_name=self.name,
                reasoning="Skipped: strong risk signals present",
                details={"skip_reason": "strong_risk_signals"},
            )

        # CRL証明書チェック
        if "has_crl_dp" not in ctx.benign_indicators:
            return RuleResult.not_triggered(self.name)

        # ML threshold チェック
        if ctx.ml_probability >= self._ml_threshold:
            return RuleResult.not_triggered(self.name)

        # ctx threshold チェック
        if ctx.ctx_score >= self._ctx_threshold:
            return RuleResult.not_triggered(self.name)

        # BENIGN 強制
        return RuleResult(
            triggered=True,
            rule_name=self.name,
            issue_tag="benign_cert_gate_b2",
            force_benign=True,
            confidence_floor=0.75,
            risk_level_bump="low",
            reasoning=(
                f"CRL certificate with ML={ctx.ml_probability:.3f} < {self._ml_threshold} "
                f"and ctx={ctx.ctx_score:.3f} < {self._ctx_threshold}"
            ),
            details={
                "indicator": "has_crl_dp",
                "ml_probability": ctx.ml_probability,
                "ctx_score": ctx.ctx_score,
                "thresholds": {
                    "ml": self._ml_threshold,
                    "ctx": self._ctx_threshold,
                },
            },
        )

    def _has_strong_risk_signals(self, ctx: RuleContext) -> bool:
        """強いリスクシグナルがあるかチェック"""
        all_issues = ctx.issue_set | ctx.ctx_issues
        if all_issues & STRONG_RISK_SIGNALS:
            return True
        if ctx.brand_details.get("detected_brands"):
            return True
        return False


class BenignCertGateB3Rule(DetectionRule):
    """Benign Certificate Gate B3: Wildcard Certificate.

    ワイルドカード証明書は正規運用（CDN、サブドメイン多数）で使用される。
    ワイルドカード + 非危険TLD + ctx < 0.40 → BENIGN

    変更履歴:
        - 2026-01-27: llm_final_decision.py から移植
    """

    def __init__(
        self,
        enabled: bool = True,
        ctx_threshold: float = 0.40,
    ):
        super().__init__(enabled=enabled)
        self._ctx_threshold = ctx_threshold

    @property
    def name(self) -> str:
        return "benign_cert_gate_b3"

    @property
    def description(self) -> str:
        return f"BENIGN protection: Wildcard cert on non-dangerous TLD with ctx < {self._ctx_threshold}"

    def _evaluate(self, ctx: RuleContext) -> RuleResult:
        # 既に benign なら何もしない
        if ctx.llm_is_phishing is False:
            return RuleResult.not_triggered(self.name)

        # 強いリスクシグナルがあればスキップ
        if self._has_strong_risk_signals(ctx):
            return RuleResult(
                triggered=False,
                rule_name=self.name,
                reasoning="Skipped: strong risk signals present",
                details={"skip_reason": "strong_risk_signals"},
            )

        # ワイルドカード証明書チェック
        if "wildcard_cert" not in ctx.benign_indicators:
            return RuleResult.not_triggered(self.name)

        # 危険TLDチェック
        if self._is_dangerous_tld(ctx):
            return RuleResult(
                triggered=False,
                rule_name=self.name,
                reasoning="Skipped: dangerous TLD",
                details={"skip_reason": "dangerous_tld"},
            )

        # ctx threshold チェック
        if ctx.ctx_score >= self._ctx_threshold:
            return RuleResult.not_triggered(self.name)

        # BENIGN 強制
        return RuleResult(
            triggered=True,
            rule_name=self.name,
            issue_tag="benign_cert_gate_b3",
            force_benign=True,
            confidence_floor=0.75,
            risk_level_bump="low",
            reasoning=(
                f"Wildcard certificate on non-dangerous TLD with ctx={ctx.ctx_score:.3f} < {self._ctx_threshold}"
            ),
            details={
                "indicator": "wildcard_cert",
                "tld": ctx.tld,
                "ctx_score": ctx.ctx_score,
                "threshold": self._ctx_threshold,
            },
        )

    def _has_strong_risk_signals(self, ctx: RuleContext) -> bool:
        """強いリスクシグナルがあるかチェック"""
        all_issues = ctx.issue_set | ctx.ctx_issues
        if all_issues & STRONG_RISK_SIGNALS:
            return True
        if ctx.brand_details.get("detected_brands"):
            return True
        return False

    def _is_dangerous_tld(self, ctx: RuleContext) -> bool:
        """危険TLDかチェック"""
        tld = ctx.tld.lower().strip(".")
        return (
            tld in HIGH_DANGER_TLDS
            or tld in MEDIUM_DANGER_TLDS
            or "dangerous_tld" in ctx.issue_set
            or "dangerous_tld" in ctx.ctx_issues
        )


class BenignCertGateB4Rule(DetectionRule):
    """Benign Certificate Gate B4: High SAN Count.

    SAN数が多い証明書は正規の大規模サービス（CDN、SaaS）で使用される。
    高SAN数(10+) + 非危険TLD + ctx < 0.45 → BENIGN

    変更履歴:
        - 2026-01-27: llm_final_decision.py から移植
    """

    def __init__(
        self,
        enabled: bool = True,
        ctx_threshold: float = 0.45,
    ):
        super().__init__(enabled=enabled)
        self._ctx_threshold = ctx_threshold

    @property
    def name(self) -> str:
        return "benign_cert_gate_b4"

    @property
    def description(self) -> str:
        return f"BENIGN protection: High SAN count on non-dangerous TLD with ctx < {self._ctx_threshold}"

    def _evaluate(self, ctx: RuleContext) -> RuleResult:
        # 既に benign なら何もしない
        if ctx.llm_is_phishing is False:
            return RuleResult.not_triggered(self.name)

        # 強いリスクシグナルがあればスキップ
        if self._has_strong_risk_signals(ctx):
            return RuleResult(
                triggered=False,
                rule_name=self.name,
                reasoning="Skipped: strong risk signals present",
                details={"skip_reason": "strong_risk_signals"},
            )

        # 高SAN数チェック
        if "high_san_count" not in ctx.benign_indicators:
            return RuleResult.not_triggered(self.name)

        # 危険TLDチェック
        if self._is_dangerous_tld(ctx):
            return RuleResult(
                triggered=False,
                rule_name=self.name,
                reasoning="Skipped: dangerous TLD",
                details={"skip_reason": "dangerous_tld"},
            )

        # ctx threshold チェック
        if ctx.ctx_score >= self._ctx_threshold:
            return RuleResult.not_triggered(self.name)

        # SAN数を取得
        san_count = ctx.cert_details.get("san_count", 0)

        # BENIGN 強制
        return RuleResult(
            triggered=True,
            rule_name=self.name,
            issue_tag="benign_cert_gate_b4",
            force_benign=True,
            confidence_floor=0.75,
            risk_level_bump="low",
            reasoning=(
                f"High SAN count ({san_count}) on non-dangerous TLD with ctx={ctx.ctx_score:.3f} < {self._ctx_threshold}"
            ),
            details={
                "indicator": "high_san_count",
                "san_count": san_count,
                "tld": ctx.tld,
                "ctx_score": ctx.ctx_score,
                "threshold": self._ctx_threshold,
            },
        )

    def _has_strong_risk_signals(self, ctx: RuleContext) -> bool:
        """強いリスクシグナルがあるかチェック"""
        all_issues = ctx.issue_set | ctx.ctx_issues
        if all_issues & STRONG_RISK_SIGNALS:
            return True
        if ctx.brand_details.get("detected_brands"):
            return True
        return False

    def _is_dangerous_tld(self, ctx: RuleContext) -> bool:
        """危険TLDかチェック"""
        tld = ctx.tld.lower().strip(".")
        return (
            tld in HIGH_DANGER_TLDS
            or tld in MEDIUM_DANGER_TLDS
            or "dangerous_tld" in ctx.issue_set
            or "dangerous_tld" in ctx.ctx_issues
        )


def create_cert_gate_rules(enabled: bool = True) -> list:
    """Create all certificate gate rules.

    Args:
        enabled: Whether rules are enabled by default

    Returns:
        List of certificate gate rule instances
    """
    return [
        BenignCertGateB1Rule(enabled=enabled),
        BenignCertGateB2Rule(enabled=enabled),
        BenignCertGateB3Rule(enabled=enabled),
        BenignCertGateB4Rule(enabled=enabled),
    ]
