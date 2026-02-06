# -*- coding: utf-8 -*-
"""
phishing_agent.rules.detectors.policy
-------------------------------------
Policy rules for phishing detection.

These rules combine ML probability, contextual score, and certificate
characteristics to make nuanced phishing decisions.

変更履歴:
    - 2026-02-04: FP削減のための閾値調整
        - PolicyR1Rule: ctx_threshold 0.28 → 0.32, ctx_threshold_legit_tld 0.34 → 0.38
        - PolicyR2Rule: ctx_threshold 0.34 → 0.38
        - PolicyR4Rule: ctx_threshold 0.34 → 0.40, ctx_threshold_legit_tld 0.35 → 0.42
    - 2026-01-27: 初版作成 (llm_final_decision.py から移植)
"""

from typing import Set, Optional
from .base import DetectionRule, RuleContext, RuleResult
from ..data.tlds import HIGH_DANGER_TLDS, MEDIUM_DANGER_TLDS


# 強証拠シグナル (ドメイン)
STRONG_DOMAIN_SIGNALS: Set[str] = frozenset({
    "dangerous_tld",
    "idn_homograph",
    "high_entropy",
    "very_high_entropy",
    "short_random_combo",
    "random_with_high_tld_stat",
    "very_short_dangerous_combo",
    "deep_chain_with_risky_tld",
})

# 強証拠シグナル (証明書)
STRONG_CERT_SIGNALS: Set[str] = frozenset({
    "self_signed",
    "dv_multi_risk_combo",
})

# 強証拠シグナル (コンテキスト)
STRONG_CTX_SIGNALS: Set[str] = frozenset({
    "ml_paradox",
    "ml_paradox_medium",
})

# ランダム系シグナル
RANDOM_SIGNALS: Set[str] = frozenset({
    "digit_mixed_random",
    "consonant_cluster_random",
    "rare_bigram_random",
})

# random_pattern との組み合わせで強証拠になるシグナル
RANDOM_COMBO_SIGNALS: Set[str] = frozenset({
    "short",
    "very_short",
    "dangerous_tld",
    "idn_homograph",
    "high_entropy",
    "very_high_entropy",
    "short_random_combo",
    "very_short_dangerous_combo",
    "deep_chain_with_risky_tld",
    "random_with_high_tld_stat",
})

# dv_suspicious_combo との組み合わせで強証拠になるシグナル
DV_COMBO_SIGNALS: Set[str] = frozenset({
    "dangerous_tld",
    "short",
    "very_short",
    "idn_homograph",
    "high_entropy",
    "very_high_entropy",
    "short_random_combo",
    "very_short_dangerous_combo",
    "deep_chain_with_risky_tld",
})


def _has_strong_evidence(ctx: RuleContext) -> bool:
    """強証拠があるかチェック"""
    # Brand は常に強証拠
    if ctx.brand_details.get("detected_brands"):
        return True

    # ドメイン強証拠
    if ctx.issue_set & STRONG_DOMAIN_SIGNALS:
        return True

    # contextual_risk_assessment が dangerous_tld を検出
    if "dangerous_tld" in ctx.ctx_issues:
        return True

    # 政府/教育ドメインチェック (random 系バイパスで除外)
    is_gov_tld = _is_gov_edu_tld(ctx)

    # random_pattern + 他シグナル の組み合わせ
    if "random_pattern" in ctx.issue_set and not is_gov_tld:
        if ctx.issue_set & RANDOM_COMBO_SIGNALS:
            return True

    # ランダム系シグナル単体
    if (ctx.issue_set & RANDOM_SIGNALS) and not is_gov_tld:
        return True

    # 証明書強証拠
    cert_issues = set(ctx.cert_details.get("issues", []) or [])
    if cert_issues & STRONG_CERT_SIGNALS:
        return True

    # コンテキスト強証拠
    if ctx.ctx_issues & STRONG_CTX_SIGNALS:
        return True

    # high_risk_words
    if "high_risk_words" in ctx.ctx_issues:
        return True

    # dv_suspicious_combo + ドメインシグナル
    combined_issues = ctx.issue_set | ctx.ctx_issues
    if "dv_suspicious_combo" in ctx.ctx_issues:
        if combined_issues & DV_COMBO_SIGNALS:
            return True

    return False


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


def _has_dv_issues(ctx: RuleContext) -> bool:
    """DV相当の証明書問題があるか (free_ca & no_org)"""
    all_issues = ctx.issue_set | ctx.ctx_issues
    cert_issues = set(ctx.cert_details.get("issues", []) or [])
    combined = all_issues | cert_issues
    return ("free_ca" in combined) and ("no_org" in combined)


def _has_any_dangerous_tld(ctx: RuleContext) -> bool:
    """危険TLDがあるか"""
    return "dangerous_tld" in ctx.issue_set or "dangerous_tld" in ctx.ctx_issues


class PolicyR1Rule(DetectionRule):
    """Policy R1: Very Low ML + DV + Medium Context + Strong Evidence.

    ML < 0.20 + free_ca & no_org + ctx >= 0.28 + strong_evidence → PHISHING

    変更履歴:
        - 2026-01-27: llm_final_decision.py から移植
    """

    def __init__(
        self,
        enabled: bool = True,
        ml_threshold: float = 0.20,
        ctx_threshold: float = 0.32,  # 2026-02-04: 0.28 → 0.32 (FP削減)
        ctx_threshold_legit_tld: float = 0.38,  # 2026-02-04: 0.34 → 0.38 (FP削減)
    ):
        super().__init__(enabled=enabled)
        self._ml_threshold = ml_threshold
        self._ctx_threshold = ctx_threshold
        self._ctx_threshold_legit_tld = ctx_threshold_legit_tld

    @property
    def name(self) -> str:
        return "policy_r1"

    @property
    def description(self) -> str:
        return f"PHISHING: ML < {self._ml_threshold} + DV cert + ctx >= {self._ctx_threshold} + strong evidence"

    def _evaluate(self, ctx: RuleContext) -> RuleResult:
        # ML threshold チェック
        if ctx.ml_probability >= self._ml_threshold:
            return RuleResult.not_triggered(self.name)

        # DV証明書チェック
        if not _has_dv_issues(ctx):
            return RuleResult.not_triggered(self.name)

        # 強証拠チェック
        if not _has_strong_evidence(ctx):
            return RuleResult.not_triggered(self.name)

        # LOW_ML_GUARD チェック
        if self._is_low_ml_guarded(ctx):
            return RuleResult(
                triggered=False,
                rule_name=self.name,
                reasoning="Blocked by LOW_ML_GUARD",
                details={"skip_reason": "low_ml_guard"},
            )

        # ctx threshold の決定 (TLD + ドメイン長による調整)
        tld_cat = ctx.precheck.get("tld_category", "unknown")
        dom_len = ctx.precheck.get("domain_length_category", "normal")
        any_dangerous = _has_any_dangerous_tld(ctx)

        if tld_cat == "legitimate" and dom_len in ("normal", "long") and not any_dangerous:
            threshold = self._ctx_threshold_legit_tld
        else:
            threshold = self._ctx_threshold

        # ctx threshold チェック
        if ctx.ctx_score < threshold:
            return RuleResult.not_triggered(self.name)

        # PHISHING
        return RuleResult(
            triggered=True,
            rule_name=self.name,
            issue_tag="policy_r1",
            force_phishing=True,
            confidence_floor=0.55,
            risk_level_bump="medium-high",
            reasoning=(
                f"R1: ML={ctx.ml_probability:.3f} < {self._ml_threshold}, "
                f"DV cert, ctx={ctx.ctx_score:.3f} >= {threshold}, strong evidence"
            ),
            details={
                "ml_probability": ctx.ml_probability,
                "ctx_score": ctx.ctx_score,
                "threshold": threshold,
                "has_dv_issues": True,
            },
        )

    def _is_low_ml_guarded(self, ctx: RuleContext) -> bool:
        """LOW_ML_GUARD条件に該当するか"""
        return (
            ctx.ml_probability < 0.25
            and _has_dv_issues(ctx)
            and not _has_any_dangerous_tld(ctx)
            and not ctx.brand_details.get("detected_brands")
        )


class PolicyR2Rule(DetectionRule):
    """Policy R2: Low ML + No Org + (Free CA or Short) + Strong Evidence.

    ML < 0.30 + no_org + (free_ca or short) + ctx >= 0.34 + strong_evidence → PHISHING

    変更履歴:
        - 2026-01-27: llm_final_decision.py から移植
    """

    def __init__(
        self,
        enabled: bool = True,
        ml_threshold: float = 0.30,
        ctx_threshold: float = 0.38,  # 2026-02-04: 0.34 → 0.38 (FP削減)
    ):
        super().__init__(enabled=enabled)
        self._ml_threshold = ml_threshold
        self._ctx_threshold = ctx_threshold

    @property
    def name(self) -> str:
        return "policy_r2"

    @property
    def description(self) -> str:
        return f"PHISHING: ML < {self._ml_threshold} + no_org + (free_ca/short) + ctx >= {self._ctx_threshold}"

    def _evaluate(self, ctx: RuleContext) -> RuleResult:
        # ML threshold チェック
        if ctx.ml_probability >= self._ml_threshold:
            return RuleResult.not_triggered(self.name)

        # no_org チェック
        all_issues = ctx.issue_set | ctx.ctx_issues
        cert_issues = set(ctx.cert_details.get("issues", []) or [])
        combined = all_issues | cert_issues
        if "no_org" not in combined:
            return RuleResult.not_triggered(self.name)

        # free_ca or short チェック
        has_free_ca = "free_ca" in combined
        has_short = "short" in ctx.issue_set or "very_short" in ctx.issue_set
        if not (has_free_ca or has_short):
            return RuleResult.not_triggered(self.name)

        # ctx threshold チェック
        if ctx.ctx_score < self._ctx_threshold:
            return RuleResult.not_triggered(self.name)

        # 強証拠チェック
        if not _has_strong_evidence(ctx):
            return RuleResult.not_triggered(self.name)

        # PHISHING
        return RuleResult(
            triggered=True,
            rule_name=self.name,
            issue_tag="policy_r2",
            force_phishing=True,
            confidence_floor=0.55,
            risk_level_bump="medium-high",
            reasoning=(
                f"R2: ML={ctx.ml_probability:.3f} < {self._ml_threshold}, "
                f"no_org + {'free_ca' if has_free_ca else 'short'}, "
                f"ctx={ctx.ctx_score:.3f} >= {self._ctx_threshold}"
            ),
            details={
                "ml_probability": ctx.ml_probability,
                "ctx_score": ctx.ctx_score,
                "has_free_ca": has_free_ca,
                "has_short": has_short,
            },
        )


class PolicyR3Rule(DetectionRule):
    """Policy R3: Medium-Low ML + Short + No Org + Strong Evidence.

    ML < 0.40 + short + no_org + ctx >= 0.36 + strong_evidence → PHISHING

    変更履歴:
        - 2026-01-27: llm_final_decision.py から移植
    """

    def __init__(
        self,
        enabled: bool = True,
        ml_threshold: float = 0.40,
        ctx_threshold: float = 0.36,
    ):
        super().__init__(enabled=enabled)
        self._ml_threshold = ml_threshold
        self._ctx_threshold = ctx_threshold

    @property
    def name(self) -> str:
        return "policy_r3"

    @property
    def description(self) -> str:
        return f"PHISHING: ML < {self._ml_threshold} + short + no_org + ctx >= {self._ctx_threshold}"

    def _evaluate(self, ctx: RuleContext) -> RuleResult:
        # ML threshold チェック
        if ctx.ml_probability >= self._ml_threshold:
            return RuleResult.not_triggered(self.name)

        # short チェック
        has_short = "short" in ctx.issue_set or "very_short" in ctx.issue_set
        if not has_short:
            return RuleResult.not_triggered(self.name)

        # no_org チェック
        all_issues = ctx.issue_set | ctx.ctx_issues
        cert_issues = set(ctx.cert_details.get("issues", []) or [])
        combined = all_issues | cert_issues
        if "no_org" not in combined:
            return RuleResult.not_triggered(self.name)

        # ctx threshold チェック
        if ctx.ctx_score < self._ctx_threshold:
            return RuleResult.not_triggered(self.name)

        # 強証拠チェック
        if not _has_strong_evidence(ctx):
            return RuleResult.not_triggered(self.name)

        # PHISHING
        return RuleResult(
            triggered=True,
            rule_name=self.name,
            issue_tag="policy_r3",
            force_phishing=True,
            confidence_floor=0.55,
            risk_level_bump="medium-high",
            reasoning=(
                f"R3: ML={ctx.ml_probability:.3f} < {self._ml_threshold}, "
                f"short + no_org, ctx={ctx.ctx_score:.3f} >= {self._ctx_threshold}"
            ),
            details={
                "ml_probability": ctx.ml_probability,
                "ctx_score": ctx.ctx_score,
                "has_short": True,
            },
        )


class PolicyR4Rule(DetectionRule):
    """Policy R4: Medium ML + DV + Strong Evidence.

    ML < 0.50 + free_ca & no_org + ctx >= threshold + strong_evidence → PHISHING
    ML が 0.30〜0.50 帯に張り付く FN を救済する。

    変更履歴:
        - 2026-01-27: llm_final_decision.py から移植
    """

    def __init__(
        self,
        enabled: bool = True,
        ml_threshold: float = 0.50,
        ctx_threshold: float = 0.40,  # 2026-02-04: 0.34 → 0.40 (FP削減、最優先対応)
        ctx_threshold_legit_tld: float = 0.42,  # 2026-02-04: 0.35 → 0.42 (FP削減)
        ctx_threshold_mrf: float = 0.38,  # 2026-02-04: 0.33 → 0.38 (FP削減)
    ):
        super().__init__(enabled=enabled)
        self._ml_threshold = ml_threshold
        self._ctx_threshold = ctx_threshold
        self._ctx_threshold_legit_tld = ctx_threshold_legit_tld
        self._ctx_threshold_mrf = ctx_threshold_mrf

    @property
    def name(self) -> str:
        return "policy_r4"

    @property
    def description(self) -> str:
        return f"PHISHING: ML < {self._ml_threshold} + DV cert + ctx >= {self._ctx_threshold} + strong evidence"

    def _evaluate(self, ctx: RuleContext) -> RuleResult:
        # ML threshold チェック
        if ctx.ml_probability >= self._ml_threshold:
            return RuleResult.not_triggered(self.name)

        # DV証明書チェック
        if not _has_dv_issues(ctx):
            return RuleResult.not_triggered(self.name)

        # 強証拠チェック
        if not _has_strong_evidence(ctx):
            return RuleResult.not_triggered(self.name)

        # ctx threshold の決定 (TLD + ドメイン長 + MRFによる調整)
        tld_cat = ctx.precheck.get("tld_category", "unknown")
        dom_len = ctx.precheck.get("domain_length_category", "normal")
        any_dangerous = _has_any_dangerous_tld(ctx)

        if tld_cat == "legitimate" and dom_len in ("normal", "long") and not any_dangerous:
            # multiple_risk_factors がある場合は緩和
            if "multiple_risk_factors" in ctx.ctx_issues:
                threshold = self._ctx_threshold_mrf
            else:
                threshold = self._ctx_threshold_legit_tld
        else:
            threshold = self._ctx_threshold

        # ctx threshold チェック
        if ctx.ctx_score < threshold:
            return RuleResult.not_triggered(self.name)

        # PHISHING
        return RuleResult(
            triggered=True,
            rule_name=self.name,
            issue_tag="policy_r4",
            force_phishing=True,
            confidence_floor=0.55,
            risk_level_bump="medium-high",
            reasoning=(
                f"R4: ML={ctx.ml_probability:.3f} < {self._ml_threshold}, "
                f"DV cert, ctx={ctx.ctx_score:.3f} >= {threshold}"
            ),
            details={
                "ml_probability": ctx.ml_probability,
                "ctx_score": ctx.ctx_score,
                "threshold": threshold,
            },
        )


class PolicyR5Rule(DetectionRule):
    """Policy R5: Medium ML + Dangerous TLD + No Org.

    ML < 0.50 + dangerous_tld + no_org + ctx >= 0.33 → PHISHING
    free_ca が無くても「危険TLD × DVっぽい（no_org）」は強めに扱う。

    変更履歴:
        - 2026-01-27: llm_final_decision.py から移植
    """

    def __init__(
        self,
        enabled: bool = True,
        ml_threshold: float = 0.50,
        ctx_threshold: float = 0.33,
    ):
        super().__init__(enabled=enabled)
        self._ml_threshold = ml_threshold
        self._ctx_threshold = ctx_threshold

    @property
    def name(self) -> str:
        return "policy_r5"

    @property
    def description(self) -> str:
        return f"PHISHING: ML < {self._ml_threshold} + dangerous TLD + no_org + ctx >= {self._ctx_threshold}"

    def _evaluate(self, ctx: RuleContext) -> RuleResult:
        # ML threshold チェック
        if ctx.ml_probability >= self._ml_threshold:
            return RuleResult.not_triggered(self.name)

        # dangerous_tld チェック
        if not _has_any_dangerous_tld(ctx):
            return RuleResult.not_triggered(self.name)

        # no_org チェック
        all_issues = ctx.issue_set | ctx.ctx_issues
        cert_issues = set(ctx.cert_details.get("issues", []) or [])
        combined = all_issues | cert_issues
        if "no_org" not in combined:
            return RuleResult.not_triggered(self.name)

        # ctx threshold チェック
        if ctx.ctx_score < self._ctx_threshold:
            return RuleResult.not_triggered(self.name)

        # PHISHING
        return RuleResult(
            triggered=True,
            rule_name=self.name,
            issue_tag="policy_r5",
            force_phishing=True,
            confidence_floor=0.55,
            risk_level_bump="medium-high",
            reasoning=(
                f"R5: ML={ctx.ml_probability:.3f} < {self._ml_threshold}, "
                f"dangerous TLD + no_org, ctx={ctx.ctx_score:.3f} >= {self._ctx_threshold}"
            ),
            details={
                "ml_probability": ctx.ml_probability,
                "ctx_score": ctx.ctx_score,
                "has_dangerous_tld": True,
            },
        )


class PolicyR6Rule(DetectionRule):
    """Policy R6: ML Paradox + Dangerous TLD + DV.

    ML < 0.30 + dangerous_tld + free_ca & no_org + ctx >= 0.35 → PHISHING
    Stage1が安全(ml<0.3)だがStage2/contextualがリスクを検出(ctx>=0.35)。

    変更履歴:
        - 2026-01-27: llm_final_decision.py から移植
    """

    def __init__(
        self,
        enabled: bool = True,
        ml_threshold: float = 0.30,
        ctx_threshold: float = 0.35,
    ):
        super().__init__(enabled=enabled)
        self._ml_threshold = ml_threshold
        self._ctx_threshold = ctx_threshold

    @property
    def name(self) -> str:
        return "policy_r6"

    @property
    def description(self) -> str:
        return f"PHISHING: ML < {self._ml_threshold} + dangerous TLD + DV cert + ctx >= {self._ctx_threshold}"

    def _evaluate(self, ctx: RuleContext) -> RuleResult:
        # ML threshold チェック
        if ctx.ml_probability >= self._ml_threshold:
            return RuleResult.not_triggered(self.name)

        # dangerous_tld チェック
        if not _has_any_dangerous_tld(ctx):
            return RuleResult.not_triggered(self.name)

        # DV証明書チェック
        if not _has_dv_issues(ctx):
            return RuleResult.not_triggered(self.name)

        # ctx threshold チェック
        if ctx.ctx_score < self._ctx_threshold:
            return RuleResult.not_triggered(self.name)

        # PHISHING
        return RuleResult(
            triggered=True,
            rule_name=self.name,
            issue_tag="policy_r6",
            force_phishing=True,
            confidence_floor=0.55,
            risk_level_bump="medium-high",
            reasoning=(
                f"R6: ML Paradox - ML={ctx.ml_probability:.3f} < {self._ml_threshold}, "
                f"dangerous TLD + DV cert, ctx={ctx.ctx_score:.3f} >= {self._ctx_threshold}"
            ),
            details={
                "ml_probability": ctx.ml_probability,
                "ctx_score": ctx.ctx_score,
                "has_dangerous_tld": True,
                "has_dv_issues": True,
            },
        )


def create_policy_rules(enabled: bool = True) -> list:
    """Create all policy rules.

    Args:
        enabled: Whether rules are enabled by default

    Returns:
        List of policy rule instances
    """
    return [
        PolicyR1Rule(enabled=enabled),
        PolicyR2Rule(enabled=enabled),
        PolicyR3Rule(enabled=enabled),
        PolicyR4Rule(enabled=enabled),
        PolicyR5Rule(enabled=enabled),
        PolicyR6Rule(enabled=enabled),
    ]
