# -*- coding: utf-8 -*-
"""
phishing_agent.rules.detectors.brand_cert
------------------------------------------
Brand + Certificate combination rules.

変更履歴:
    - 2026-01-31: 初版作成（ルールモジュール移行計画 Step 2.3）
"""

from .base import DetectionRule, RuleContext, RuleResult


class BrandCertHighRule(DetectionRule):
    """Brand + Low Quality Certificate Rule.

    ブランド検出 + 低品質証明書（no_cert, no_org, free_ca）の組み合わせは
    フィッシングの強い兆候。

    条件:
    - brand_detected
    - かつ {no_cert, no_org, free_ca} のいずれかがある

    変更履歴:
        - 2026-01-31: 初版作成 (llm_final_decision.py の brand_cert_high から移植)
    """

    def __init__(
        self,
        enabled: bool = True,
        confidence_floor: float = 0.70,
    ):
        super().__init__(enabled=enabled)
        self._confidence_floor = confidence_floor

    @property
    def name(self) -> str:
        return "brand_cert_high"

    @property
    def description(self) -> str:
        return "Force phishing when brand detected with low quality certificate"

    def _evaluate(self, ctx: RuleContext) -> RuleResult:
        # ブランド検出チェック
        brand_detected = bool(ctx.brand_details.get("detected_brands"))
        if not brand_detected:
            return RuleResult.not_triggered(self.name)

        # 低品質証明書チェック
        cert_issues = set(ctx.cert_details.get("issues", []) or [])
        all_issues = ctx.issue_set | ctx.ctx_issues | cert_issues
        low_quality_cert = all_issues & {"no_cert", "no_org", "free_ca"}

        if not low_quality_cert:
            return RuleResult.not_triggered(self.name)

        # phishing 強制
        return RuleResult(
            triggered=True,
            rule_name=self.name,
            issue_tag="brand_cert_high",
            force_phishing=True,
            confidence_floor=self._confidence_floor,
            risk_level_bump="high",
            reasoning=(
                f"Brand + low quality cert: brand detected with {list(low_quality_cert)}"
            ),
            details={
                "brand_detected": True,
                "brands": ctx.brand_details.get("detected_brands"),
                "low_quality_cert_issues": list(low_quality_cert),
            },
        )


class BenignCertGateSkipRule(DetectionRule):
    """Benign Certificate Gate Skip Rule.

    ブランド検出時や強いリスクシグナルがある場合、
    証明書ベースのbenignゲートをスキップするためのマーカールール。

    このルールは単独では判定を行わず、cert_gateルールの前に実行されることで
    スキップ条件を記録する。

    変更履歴:
        - 2026-01-31: 初版作成 (llm_final_decision.py の BENIGN_CERT_GATE_SKIP から移植)
    """

    # 強いリスクシグナル
    STRONG_RISK_SIGNALS = frozenset({
        "self_signed",
        "brand_detected",
        "idn_homograph",
        "high_entropy",
        "very_high_entropy",
        "random_with_high_tld_stat",
    })

    def __init__(self, enabled: bool = True):
        super().__init__(enabled=enabled)

    @property
    def name(self) -> str:
        return "benign_cert_gate_skip"

    @property
    def description(self) -> str:
        return "Mark domains that should skip benign cert gate"

    def _evaluate(self, ctx: RuleContext) -> RuleResult:
        # ブランド検出チェック
        brand_detected = bool(ctx.brand_details.get("detected_brands"))
        if brand_detected:
            return RuleResult(
                triggered=True,
                rule_name=self.name,
                issue_tag="benign_cert_gate_skip",
                reasoning="Skip benign cert gate: brand detected",
                details={
                    "skip_reason": "brand_detected",
                    "brands": ctx.brand_details.get("detected_brands"),
                },
            )

        # 強いリスクシグナルチェック
        cert_issues = set(ctx.cert_details.get("issues", []) or [])
        all_issues = ctx.issue_set | ctx.ctx_issues | cert_issues
        strong_signals = all_issues & self.STRONG_RISK_SIGNALS

        if strong_signals:
            return RuleResult(
                triggered=True,
                rule_name=self.name,
                issue_tag="benign_cert_gate_skip",
                reasoning=f"Skip benign cert gate: strong risk signals {list(strong_signals)}",
                details={
                    "skip_reason": "strong_risk_signals",
                    "signals": list(strong_signals),
                },
            )

        return RuleResult.not_triggered(self.name)


def create_brand_cert_rules(enabled: bool = True) -> list:
    """Create all brand + certificate rules.

    Args:
        enabled: Whether rules are enabled by default

    Returns:
        List of brand + certificate rule instances
    """
    return [
        BrandCertHighRule(enabled=enabled),
        BenignCertGateSkipRule(enabled=enabled),
    ]
