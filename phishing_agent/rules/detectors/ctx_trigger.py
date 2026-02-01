# -*- coding: utf-8 -*-
"""
phishing_agent.rules.detectors.ctx_trigger
-------------------------------------------
Contextual score trigger rules.

Hard and soft triggers based on contextual risk assessment score.

変更履歴:
    - 2026-01-31: 初版作成（ルールモジュール移行計画 Step 2.1）
"""

from typing import Set
from .base import DetectionRule, RuleContext, RuleResult


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


class HardCtxTriggerRule(DetectionRule):
    """Hard Contextual Trigger Rule.

    ctx >= 0.65 の場合、無条件で phishing 判定にオーバーライドする。

    変更履歴:
        - 2026-01-31: 初版作成 (llm_final_decision.py の hard_ctx_ge_0.65 から移植)
    """

    def __init__(
        self,
        enabled: bool = True,
        ctx_threshold: float = 0.65,
        confidence_floor: float = 0.70,
    ):
        super().__init__(enabled=enabled)
        self._ctx_threshold = ctx_threshold
        self._confidence_floor = confidence_floor

    @property
    def name(self) -> str:
        return "hard_ctx_trigger"

    @property
    def description(self) -> str:
        return f"Force phishing when ctx >= {self._ctx_threshold} (unconditional)"

    def _evaluate(self, ctx: RuleContext) -> RuleResult:
        # 既に phishing なら何もしない
        if ctx.llm_is_phishing:
            return RuleResult.not_triggered(self.name)

        # ctx threshold チェック
        if ctx.ctx_score < self._ctx_threshold:
            return RuleResult.not_triggered(self.name)

        # phishing 強制
        return RuleResult(
            triggered=True,
            rule_name=self.name,
            issue_tag="hard_ctx_trigger",
            force_phishing=True,
            confidence_floor=self._confidence_floor,
            risk_level_bump="high",
            reasoning=(
                f"Hard ctx trigger: ctx={ctx.ctx_score:.3f} >= {self._ctx_threshold}, "
                f"unconditional phishing"
            ),
            details={
                "ctx_score": ctx.ctx_score,
                "threshold": self._ctx_threshold,
            },
        )


class SoftCtxTriggerRule(DetectionRule):
    """Soft Contextual Trigger Rule.

    ctx >= 0.50 かつ強証拠がある場合、phishing 判定にオーバーライドする。

    強証拠:
    - brand_detected
    - ドメイン強証拠 (dangerous_tld, idn_homograph, high_entropy, etc.)
    - 証明書強証拠 (self_signed, dv_multi_risk_combo)
    - コンテキスト強証拠 (ml_paradox, high_risk_words)
    - random_pattern + short/dangerous_tld の組み合わせ

    変更履歴:
        - 2026-01-31: 初版作成 (llm_final_decision.py の ctx_ge_0.50_with_strong_evidence から移植)
    """

    def __init__(
        self,
        enabled: bool = True,
        ctx_threshold: float = 0.50,
        confidence_floor: float = 0.60,
    ):
        super().__init__(enabled=enabled)
        self._ctx_threshold = ctx_threshold
        self._confidence_floor = confidence_floor

    @property
    def name(self) -> str:
        return "soft_ctx_trigger"

    @property
    def description(self) -> str:
        return f"Force phishing when ctx >= {self._ctx_threshold} with strong evidence"

    def _evaluate(self, ctx: RuleContext) -> RuleResult:
        # 既に phishing なら何もしない
        if ctx.llm_is_phishing:
            return RuleResult.not_triggered(self.name)

        # Hard trigger の範囲は除外（そちらで処理）
        if ctx.ctx_score >= 0.65:
            return RuleResult.not_triggered(self.name)

        # ctx threshold チェック
        if ctx.ctx_score < self._ctx_threshold:
            return RuleResult.not_triggered(self.name)

        # 強証拠チェック
        if not _has_strong_evidence(ctx):
            return RuleResult.not_triggered(self.name)

        # phishing 強制
        return RuleResult(
            triggered=True,
            rule_name=self.name,
            issue_tag="soft_ctx_trigger",
            force_phishing=True,
            confidence_floor=self._confidence_floor,
            risk_level_bump="medium-high",
            reasoning=(
                f"Soft ctx trigger: ctx={ctx.ctx_score:.3f} >= {self._ctx_threshold}, "
                f"with strong evidence"
            ),
            details={
                "ctx_score": ctx.ctx_score,
                "threshold": self._ctx_threshold,
                "has_strong_evidence": True,
            },
        )


def create_ctx_trigger_rules(enabled: bool = True) -> list:
    """Create all contextual trigger rules.

    Args:
        enabled: Whether rules are enabled by default

    Returns:
        List of contextual trigger rule instances
    """
    return [
        HardCtxTriggerRule(enabled=enabled),
        SoftCtxTriggerRule(enabled=enabled),
    ]
