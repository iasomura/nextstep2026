# -*- coding: utf-8 -*-
"""
phishing_agent.rules.detectors.post_gates
------------------------------------------
Post-processing gate rules.

変更履歴:
    - 2026-01-31: 初版作成（ルールモジュール移行計画 Step 2.4）
"""

from typing import Set
from .base import DetectionRule, RuleContext, RuleResult
from ..data.tlds import HIGH_DANGER_TLDS, MEDIUM_DANGER_TLDS


# 正規TLD（ランダムパターンのみでの誤検出を防ぐ）
LEGITIMATE_TLDS: Set[str] = frozenset({
    "com", "org", "net", "edu", "gov", "mil", "int",
    "co", "io", "uk", "de", "fr", "jp", "au", "ca",
})


def _is_gov_edu_tld(ctx: RuleContext) -> bool:
    """政府/教育ドメインかどうか判定"""
    tld = ctx.tld.lower().strip(".")
    reg_domain = ctx.registered_domain.lower()

    return (
        tld.startswith("gov.") or tld == "gov"
        or tld.startswith("go.") or tld.startswith("gob.")
        or tld.startswith("gouv.") or ".gov." in tld
        or tld.endswith(".gov")
        or tld == "mil" or tld.startswith("mil.")
        or tld == "edu" or tld.startswith("edu.")
        or tld.startswith("ac.")
        or reg_domain.startswith("gov.") or reg_domain == "gov"
    )


class PostRandomPatternOnlyGateRule(DetectionRule):
    """Post Random Pattern Only Gate Rule.

    domain_issues が random_pattern のみで、ブランド検出がなく、
    正規TLDの場合は、追加反転（Benign→Phishing）をブロックして
    FPを抑制する。

    例: cryptpad.org のような誤反転を防ぐ

    条件:
    - 現在 phishing 判定
    - domain_issues が random_pattern のみ
    - brand_detected がない
    - TLD が正規TLD（com, org, net, etc.）または政府/教育TLD

    変更履歴:
        - 2026-01-31: 初版作成 (llm_final_decision.py の POST_RANDOM_PATTERN_ONLY_GATE から移植)
    """

    def __init__(
        self,
        enabled: bool = True,
        confidence_ceiling: float = 0.35,
    ):
        super().__init__(enabled=enabled)
        self._confidence_ceiling = confidence_ceiling

    @property
    def name(self) -> str:
        return "post_random_pattern_only_gate"

    @property
    def description(self) -> str:
        return "Block phishing when only random_pattern detected on legitimate TLD"

    def _evaluate(self, ctx: RuleContext) -> RuleResult:
        # benign なら何もしない
        if not ctx.llm_is_phishing:
            return RuleResult.not_triggered(self.name)

        # ブランド検出チェック
        brand_detected = bool(ctx.brand_details.get("detected_brands"))
        if brand_detected:
            return RuleResult.not_triggered(self.name)

        # 危険TLDチェック
        tld = ctx.tld.lower().strip(".")
        is_dangerous = (
            tld in HIGH_DANGER_TLDS
            or tld in MEDIUM_DANGER_TLDS
            or "dangerous_tld" in ctx.issue_set
            or "dangerous_tld" in ctx.ctx_issues
        )
        if is_dangerous:
            return RuleResult.not_triggered(self.name)

        # 正規TLDまたは政府/教育TLDチェック
        is_legit_tld = tld in LEGITIMATE_TLDS or _is_gov_edu_tld(ctx)
        if not is_legit_tld:
            return RuleResult.not_triggered(self.name)

        # domain_issues が random_pattern のみかチェック
        domain_issues = ctx.issue_set.copy()
        # 除外するシグナル（これらは random_pattern と共存しても問題ない）
        non_risky_signals = {
            "short", "very_short",  # 長さだけでは判定しない
        }
        # リスクシグナルのみを抽出
        risky_issues = domain_issues - non_risky_signals

        # random_pattern のみか？
        if risky_issues != {"random_pattern"}:
            return RuleResult.not_triggered(self.name)

        # 他の強いシグナルがないかチェック
        strong_signals = {
            "idn_homograph", "high_entropy", "very_high_entropy",
            "dangerous_tld", "short_random_combo", "random_with_high_tld_stat",
            "self_signed", "no_cert",
        }
        all_issues = ctx.issue_set | ctx.ctx_issues
        if all_issues & strong_signals:
            return RuleResult.not_triggered(self.name)

        # benign 強制
        return RuleResult(
            triggered=True,
            rule_name=self.name,
            issue_tag="post_random_pattern_only_gate",
            force_benign=True,
            confidence_ceiling=self._confidence_ceiling,
            risk_level_bump="medium",
            reasoning=(
                f"Random pattern only gate: {ctx.domain} has only random_pattern "
                f"on legitimate TLD ({tld}), no brand detected"
            ),
            details={
                "tld": tld,
                "domain_issues": list(ctx.issue_set),
                "is_legitimate_tld": True,
            },
        )


class MlNoMitigationGateRule(DetectionRule):
    """ML No Mitigation Gate Rule.

    ML >= 0.50 で、allowlist外、benign証明書がない場合、
    強制的に phishing 判定にする。

    ただし、非危険TLDで ctx < 0.30 の場合はスキップ。

    変更履歴:
        - 2026-01-31: 初版作成 (llm_final_decision.py の ml_ge_0.50_no_mitigation から移植)
    """

    # benign 証明書インジケータ
    BENIGN_CERT_INDICATORS = frozenset({"ov_ev_cert", "has_crl_dp"})

    def __init__(
        self,
        enabled: bool = True,
        ml_threshold: float = 0.50,
        ml_benign_override_threshold: float = 0.70,
        ctx_skip_threshold: float = 0.30,
        confidence_floor: float = 0.55,
    ):
        super().__init__(enabled=enabled)
        self._ml_threshold = ml_threshold
        self._ml_benign_override_threshold = ml_benign_override_threshold
        self._ctx_skip_threshold = ctx_skip_threshold
        self._confidence_floor = confidence_floor

    @property
    def name(self) -> str:
        return "ml_no_mitigation_gate"

    @property
    def description(self) -> str:
        return f"Force phishing when ML >= {self._ml_threshold} with no mitigation"

    def _evaluate(self, ctx: RuleContext) -> RuleResult:
        # 既に phishing なら何もしない
        if ctx.llm_is_phishing:
            return RuleResult.not_triggered(self.name)

        # ML threshold チェック
        if ctx.ml_probability < self._ml_threshold:
            return RuleResult.not_triggered(self.name)

        # allowlist チェック
        if ctx.is_known_legitimate:
            return RuleResult.not_triggered(self.name)

        # benign 証明書チェック（ML < 0.70 の場合のみ有効）
        has_strong_benign_cert = bool(ctx.benign_indicators & self.BENIGN_CERT_INDICATORS)
        if has_strong_benign_cert and ctx.ml_probability < self._ml_benign_override_threshold:
            return RuleResult.not_triggered(self.name)

        # 非危険TLD + 低ctx のスキップ
        tld = ctx.tld.lower().strip(".")
        is_non_dangerous = (
            tld not in HIGH_DANGER_TLDS
            and tld not in MEDIUM_DANGER_TLDS
            and "dangerous_tld" not in ctx.issue_set
            and "dangerous_tld" not in ctx.ctx_issues
        )
        if is_non_dangerous and ctx.ctx_score < self._ctx_skip_threshold:
            return RuleResult(
                triggered=False,
                rule_name=self.name,
                reasoning=f"Skipped: non-dangerous TLD with ctx < {self._ctx_skip_threshold}",
                details={
                    "skip_reason": "non_dangerous_tld_very_low_ctx",
                    "ml_probability": ctx.ml_probability,
                    "ctx_score": ctx.ctx_score,
                },
            )

        # phishing 強制
        return RuleResult(
            triggered=True,
            rule_name=self.name,
            issue_tag="ml_no_mitigation_gate",
            force_phishing=True,
            confidence_floor=self._confidence_floor,
            risk_level_bump="medium-high",
            reasoning=(
                f"ML no mitigation: ML={ctx.ml_probability:.3f} >= {self._ml_threshold}, "
                f"no allowlist, no benign cert"
            ),
            details={
                "ml_probability": ctx.ml_probability,
                "threshold": self._ml_threshold,
                "is_known_legitimate": False,
                "has_strong_benign_cert": has_strong_benign_cert,
            },
        )


class LowToMinMediumRule(DetectionRule):
    """Low to Min Medium Rule.

    phishing 判定で risk_level が "low" の場合、
    最低でも "medium" に引き上げる。

    変更履歴:
        - 2026-01-31: 初版作成 (llm_final_decision.py の low_to_min_medium から移植)
    """

    def __init__(self, enabled: bool = True):
        super().__init__(enabled=enabled)

    @property
    def name(self) -> str:
        return "low_to_min_medium"

    @property
    def description(self) -> str:
        return "Bump risk level from low to medium when phishing"

    def _evaluate(self, ctx: RuleContext) -> RuleResult:
        # benign なら何もしない
        if not ctx.llm_is_phishing:
            return RuleResult.not_triggered(self.name)

        # risk_level が "low" でない場合は何もしない
        if ctx.llm_risk_level != "low":
            return RuleResult.not_triggered(self.name)

        # risk_level を "medium" に引き上げ
        return RuleResult(
            triggered=True,
            rule_name=self.name,
            issue_tag="low_to_min_medium",
            risk_level_bump="medium",
            reasoning="Phishing with low risk level bumped to medium",
            details={
                "original_risk_level": "low",
                "new_risk_level": "medium",
            },
        )


def create_post_gate_rules(enabled: bool = True) -> list:
    """Create all post-processing gate rules.

    Args:
        enabled: Whether rules are enabled by default

    Returns:
        List of post-processing gate rule instances
    """
    return [
        PostRandomPatternOnlyGateRule(enabled=enabled),
        MlNoMitigationGateRule(enabled=enabled),
        LowToMinMediumRule(enabled=enabled),
    ]
