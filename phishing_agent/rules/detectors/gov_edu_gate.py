# -*- coding: utf-8 -*-
"""
phishing_agent.rules.detectors.gov_edu_gate
--------------------------------------------
Government/Education domain protection gate.

変更履歴:
    - 2026-01-31: 初版作成（ルールモジュール移行計画 Step 2.2）
"""

from .base import DetectionRule, RuleContext, RuleResult


def _is_gov_edu_domain(ctx: RuleContext) -> bool:
    """政府/教育ドメインかどうか詳細判定"""
    tld = ctx.tld.lower().strip(".")
    reg_domain = ctx.registered_domain.lower()

    return (
        tld.startswith("gov.")  # gov.in, gov.uk, etc.
        or tld == "gov"
        or tld.startswith("go.")   # go.jp, go.kr, etc.
        or tld.startswith("gob.")  # gob.mx, gob.es, etc.
        or tld.startswith("gouv.") # gouv.fr, etc.
        or ".gov." in tld          # state.gov.xx
        or tld.endswith(".gov")    # xx.gov
        or tld == "mil"            # military
        or tld.startswith("mil.")  # mil.xx
        or tld == "edu"            # education
        or tld.startswith("edu.")  # edu.xx
        or tld.startswith("ac.")   # ac.uk, ac.jp (academic)
        or tld == "int"            # international organizations
        # registered_domain が gov.xx の形式 (例: gov.wales, gov.scot)
        or reg_domain.startswith("gov.")
        or reg_domain == "gov"
    )


class GovEduBenignGateRule(DetectionRule):
    """Government/Education Benign Gate Rule.

    政府/教育ドメインはフィッシングサイトである可能性が極めて低い。
    ブランド偽装がない限り、phishing 判定を benign に変更する。

    例: estyn.gov.wales (ウェールズ教育監察機関)

    除外条件:
    - brand_detected がある場合はゲートを適用しない

    変更履歴:
        - 2026-01-31: 初版作成 (llm_final_decision.py の GOV_EDU_BENIGN_GATE から移植)
    """

    def __init__(
        self,
        enabled: bool = True,
        confidence_floor: float = 0.90,
    ):
        super().__init__(enabled=enabled)
        self._confidence_floor = confidence_floor

    @property
    def name(self) -> str:
        return "gov_edu_benign_gate"

    @property
    def description(self) -> str:
        return "Protect government/education domains from false positive phishing"

    def _evaluate(self, ctx: RuleContext) -> RuleResult:
        # benign なら何もしない
        if not ctx.llm_is_phishing:
            return RuleResult.not_triggered(self.name)

        # 政府/教育ドメインチェック
        if not _is_gov_edu_domain(ctx):
            return RuleResult.not_triggered(self.name)

        # ブランド偽装チェック
        brand_detected = bool(ctx.brand_details.get("detected_brands"))
        if brand_detected:
            return RuleResult(
                triggered=False,
                rule_name=self.name,
                reasoning="Skipped: brand detected on gov/edu domain",
                details={
                    "skip_reason": "brand_detected",
                    "brands": ctx.brand_details.get("detected_brands"),
                },
            )

        # benign 強制
        return RuleResult(
            triggered=True,
            rule_name=self.name,
            issue_tag="gov_edu_benign_gate",
            force_benign=True,
            confidence_floor=self._confidence_floor,
            risk_level_bump="low",
            reasoning=(
                f"Gov/edu domain protection: {ctx.registered_domain or ctx.tld} "
                f"is a trusted government/education domain"
            ),
            details={
                "tld": ctx.tld,
                "registered_domain": ctx.registered_domain,
                "is_gov_edu": True,
            },
        )


def create_gov_edu_gate_rules(enabled: bool = True) -> list:
    """Create all government/education gate rules.

    Args:
        enabled: Whether rules are enabled by default

    Returns:
        List of government/education gate rule instances
    """
    return [
        GovEduBenignGateRule(enabled=enabled),
    ]
