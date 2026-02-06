# -*- coding: utf-8 -*-
"""
phishing_agent.rules.detectors.ml_guard
---------------------------------------
ML-based guard rules for phishing detection.

These rules adjust the final decision based on ML probability thresholds,
ensuring that high-confidence ML predictions are respected and low-confidence
predictions are properly gated.

変更履歴:
    - 2026-02-04: HighMLOverrideRule をデフォルト無効化 (Precision 23.8%, Net -11)
    - 2026-01-27: 初版作成 (llm_final_decision.py から移植)
"""

from typing import Set, Optional
from .base import DetectionRule, RuleContext, RuleResult
from ..data.tlds import HIGH_DANGER_TLDS, MEDIUM_DANGER_TLDS


# ランダム系シグナル（短ドメイン分析から検出される）
RANDOM_SIGNALS: Set[str] = frozenset({
    "digit_mixed_random",
    "consonant_cluster_random",
    "rare_bigram_random",
    "random_pattern",
    "high_entropy",
})

# 信頼TLD（オーバーライド除外）
TRUSTED_TLDS: Set[str] = frozenset({
    "org", "edu", "gov", "mil", "int"
})


class VeryHighMLOverrideRule(DetectionRule):
    """Very High ML Override Rule.

    ML >= 0.85 の場合、AI Agent の判定に関係なく phishing にオーバーライドする。
    Stage1 XGBoost が 0.85+ を出す場合、それ自体が強い phishing シグナル。

    除外条件:
    - allowlist に含まれるドメイン
    - 信頼TLD (.org, .edu, .gov, .mil, .int)
    - 政府/教育ドメイン

    変更履歴:
        - 2026-01-27: llm_final_decision.py から移植
    """

    def __init__(
        self,
        enabled: bool = True,
        ml_threshold: float = 0.85,
        confidence_floor: float = 0.80,
    ):
        super().__init__(enabled=enabled)
        self._ml_threshold = ml_threshold
        self._confidence_floor = confidence_floor

    @property
    def name(self) -> str:
        return "very_high_ml_override"

    @property
    def description(self) -> str:
        return f"Override to phishing when ML >= {self._ml_threshold} (unconditional)"

    def _evaluate(self, ctx: RuleContext) -> RuleResult:
        # 条件チェック: 現在 benign/low risk 判定 & ML >= threshold
        if ctx.llm_is_phishing:
            return RuleResult.not_triggered(self.name)

        if ctx.ml_probability < self._ml_threshold:
            return RuleResult.not_triggered(self.name)

        if ctx.llm_risk_level not in {"low", "medium"}:
            return RuleResult.not_triggered(self.name)

        # 除外条件チェック
        if ctx.is_known_legitimate:
            return RuleResult.not_triggered(self.name)

        tld = ctx.tld.lower().strip(".")
        if tld in TRUSTED_TLDS or any(tld.endswith(f".{t}") for t in TRUSTED_TLDS):
            return RuleResult.not_triggered(self.name)

        if self._is_gov_edu_tld(ctx):
            return RuleResult.not_triggered(self.name)

        # オーバーライド発動
        return RuleResult(
            triggered=True,
            rule_name=self.name,
            issue_tag="very_high_ml_override",
            force_phishing=True,
            confidence_floor=self._confidence_floor,
            risk_level_bump="high",
            reasoning=(
                f"Very high ML override: ML={ctx.ml_probability:.3f} >= {self._ml_threshold}, "
                f"unconditional phishing"
            ),
            details={
                "ml_probability": ctx.ml_probability,
                "threshold": self._ml_threshold,
                "llm_risk_level": ctx.llm_risk_level,
            },
        )

    def _is_gov_edu_tld(self, ctx: RuleContext) -> bool:
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


class HighMLOverrideRule(DetectionRule):
    """High ML Override Rule.

    ML >= 0.40 かつ追加トリガー（ランダムシグナル or 危険TLD）がある場合、
    AI Agent の benign/low risk 判定を phishing にオーバーライドする。

    トリガー条件:
    - ランダム系シグナル (random_pattern, consonant_cluster_random, etc.)
    - 危険TLD (HIGH_DANGER_TLDS or MEDIUM_DANGER_TLDS)

    除外条件:
    - allowlist に含まれるドメイン
    - 信頼TLD (.org, .edu, .gov, .mil, .int)
    - 政府/教育ドメイン

    変更履歴:
        - 2026-01-27: llm_final_decision.py から移植
    """

    def __init__(
        self,
        enabled: bool = True,
        ml_threshold: float = 0.40,
        confidence_floor: float = 0.65,
        random_signals: Set[str] = RANDOM_SIGNALS,
    ):
        super().__init__(enabled=enabled)
        self._ml_threshold = ml_threshold
        self._confidence_floor = confidence_floor
        self._random_signals = random_signals

    @property
    def name(self) -> str:
        return "high_ml_override"

    @property
    def description(self) -> str:
        return f"Override to phishing when ML >= {self._ml_threshold} with random/dangerous_tld triggers"

    def _evaluate(self, ctx: RuleContext) -> RuleResult:
        # 条件チェック: 現在 benign/low risk 判定 & ML >= threshold
        if ctx.llm_is_phishing:
            return RuleResult.not_triggered(self.name)

        if ctx.ml_probability < self._ml_threshold:
            return RuleResult.not_triggered(self.name)

        if ctx.llm_risk_level not in {"low", "medium"}:
            return RuleResult.not_triggered(self.name)

        # VeryHighMLOverrideRule の範囲は除外（そちらで処理）
        if ctx.ml_probability >= 0.85:
            return RuleResult.not_triggered(self.name)

        # トリガーチェック
        random_signals_found = ctx.issue_set & self._random_signals
        has_dangerous_tld = self._has_dangerous_tld(ctx)

        if not random_signals_found and not has_dangerous_tld:
            return RuleResult.not_triggered(self.name)

        # 除外条件チェック
        if ctx.is_known_legitimate:
            return RuleResult.not_triggered(self.name)

        tld = ctx.tld.lower().strip(".")
        if tld in TRUSTED_TLDS or any(tld.endswith(f".{t}") for t in TRUSTED_TLDS):
            return RuleResult.not_triggered(self.name)

        if self._is_gov_edu_tld(ctx):
            return RuleResult.not_triggered(self.name)

        # トリガー情報
        if random_signals_found:
            trigger_desc = list(random_signals_found)
        else:
            trigger_desc = ["dangerous_tld"]

        # オーバーライド発動
        return RuleResult(
            triggered=True,
            rule_name=self.name,
            issue_tag="high_ml_override",
            force_phishing=True,
            confidence_floor=self._confidence_floor,
            risk_level_bump="high",
            reasoning=(
                f"High ML override: ML={ctx.ml_probability:.3f} >= {self._ml_threshold}, "
                f"triggers={trigger_desc}"
            ),
            details={
                "ml_probability": ctx.ml_probability,
                "threshold": self._ml_threshold,
                "trigger_signals": trigger_desc,
                "random_signals": list(random_signals_found),
                "has_dangerous_tld": has_dangerous_tld,
            },
        )

    def _has_dangerous_tld(self, ctx: RuleContext) -> bool:
        """危険TLDシグナルがあるかどうか判定.

        注意: TLDメンバーシップではなく、実際に検出されたdangerous_tldシグナルのみ確認。
        これはinline版のhas_dangerous_tld_signalと同じ動作。

        変更履歴:
            - 2026-01-31: TLDメンバーシップ判定を削除（inline版と整合性確保）
        """
        return (
            "dangerous_tld" in ctx.issue_set
            or "dangerous_tld" in ctx.ctx_issues
        )

    def _is_gov_edu_tld(self, ctx: RuleContext) -> bool:
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


class UltraLowMLBlockRule(DetectionRule):
    """Ultra Low ML Block Rule.

    ML < 0.05 かつブランド未検出かつ危険TLD無しの場合、
    phishing 判定をブロックして benign に戻す。

    FP分析: ML < 0.1 での AI 過検知が多く、その大半を削減する。

    変更履歴:
        - 2026-01-27: llm_final_decision.py から移植
    """

    def __init__(
        self,
        enabled: bool = True,
        ml_threshold: float = 0.05,
        confidence_ceiling: float = 0.60,
    ):
        super().__init__(enabled=enabled)
        self._ml_threshold = ml_threshold
        self._confidence_ceiling = confidence_ceiling

    @property
    def name(self) -> str:
        return "ultra_low_ml_block"

    @property
    def description(self) -> str:
        return f"Block phishing when ML < {self._ml_threshold}, no brand, no dangerous TLD"

    def _evaluate(self, ctx: RuleContext) -> RuleResult:
        # 条件チェック: 現在 phishing 判定 & ML < threshold
        if not ctx.llm_is_phishing:
            return RuleResult.not_triggered(self.name)

        if ctx.ml_probability >= self._ml_threshold:
            return RuleResult.not_triggered(self.name)

        # ブランド検出チェック
        brand_detected = bool(ctx.brand_details.get("detected_brands"))
        if brand_detected:
            return RuleResult.not_triggered(self.name)

        # 危険TLDチェック
        if self._has_dangerous_tld(ctx):
            return RuleResult.not_triggered(self.name)

        # ブロック発動
        return RuleResult(
            triggered=True,
            rule_name=self.name,
            issue_tag="ultra_low_ml_block",
            force_benign=True,
            confidence_ceiling=self._confidence_ceiling,
            risk_level_bump="low",
            reasoning=(
                f"Ultra low ML block: ML={ctx.ml_probability:.3f} < {self._ml_threshold}, "
                f"no brand, no dangerous TLD"
            ),
            details={
                "ml_probability": ctx.ml_probability,
                "threshold": self._ml_threshold,
                "brand_detected": brand_detected,
            },
        )

    def _has_dangerous_tld(self, ctx: RuleContext) -> bool:
        """危険TLDシグナルがあるかどうか判定.

        注意: TLDメンバーシップではなく、実際に検出されたdangerous_tldシグナルのみ確認。
        これはinline版のhas_dangerous_tld_signalと同じ動作。

        変更履歴:
            - 2026-01-31: TLDメンバーシップ判定を削除（inline版と整合性確保）
        """
        return (
            "dangerous_tld" in ctx.issue_set
            or "dangerous_tld" in ctx.ctx_issues
        )


class PostLLMFlipGateRule(DetectionRule):
    """Post-LLM Flip Gate Rule.

    低ML + LLM phishing判定の場合、特定条件がなければブロックする。

    TLD危険度に応じた閾値:
    - 高危険TLD: ゲート無効化（フィッシング検出を最優先）
    - 中危険TLD: 0.04（バランス重視）
    - 非危険TLD: 0.30（FP削減重視）

    バイパス条件:
    - ハードトリガー (ctx >= 0.65)
    - ブランド検出
    - random_pattern + short の組み合わせ + ctx >= 0.50
    - 高リスクキーワード検出 + ctx >= 0.50
    - ランダムシグナル + ctx >= 0.50

    変更履歴:
        - 2026-01-27: llm_final_decision.py から移植
    """

    def __init__(
        self,
        enabled: bool = True,
        high_danger_threshold: float = 0.0,
        medium_danger_threshold: float = 0.04,
        non_danger_threshold: float = 0.30,
        hard_ctx_threshold: float = 0.65,
        soft_ctx_threshold: float = 0.50,
    ):
        super().__init__(enabled=enabled)
        self._high_danger_threshold = high_danger_threshold
        self._medium_danger_threshold = medium_danger_threshold
        self._non_danger_threshold = non_danger_threshold
        self._hard_ctx_threshold = hard_ctx_threshold
        self._soft_ctx_threshold = soft_ctx_threshold

    @property
    def name(self) -> str:
        return "post_llm_flip_gate"

    @property
    def description(self) -> str:
        return "Block low-ML LLM phishing predictions (TLD-aware thresholds)"

    def _evaluate(self, ctx: RuleContext) -> RuleResult:
        # 条件チェック: 現在 phishing 判定
        if not ctx.llm_is_phishing:
            return RuleResult.not_triggered(self.name)

        # TLD危険度による閾値決定
        tld = ctx.tld.lower().strip(".")
        is_high_danger = tld in HIGH_DANGER_TLDS
        is_medium_danger = tld in MEDIUM_DANGER_TLDS

        if is_high_danger:
            threshold = self._high_danger_threshold
        elif is_medium_danger:
            threshold = self._medium_danger_threshold
        else:
            threshold = self._non_danger_threshold

        # ゲート適用判定: ML < threshold
        if ctx.ml_probability >= threshold:
            return RuleResult.not_triggered(self.name)

        # バイパス条件チェック
        bypass_reason = self._check_bypass(ctx, is_high_danger)
        if bypass_reason:
            return RuleResult(
                triggered=False,
                rule_name=self.name,
                reasoning=f"Gate bypassed: {bypass_reason}",
                details={
                    "bypass_reason": bypass_reason,
                    "ml_probability": ctx.ml_probability,
                    "threshold": threshold,
                },
            )

        # ブロック発動
        return RuleResult(
            triggered=True,
            rule_name=self.name,
            issue_tag="post_llm_flip_gate",
            force_benign=True,
            confidence_ceiling=0.70,
            risk_level_bump="medium",
            reasoning=(
                f"Post-LLM flip gate: ML={ctx.ml_probability:.3f} < {threshold}, "
                f"tld_danger={'high' if is_high_danger else 'medium' if is_medium_danger else 'low'}"
            ),
            details={
                "ml_probability": ctx.ml_probability,
                "threshold": threshold,
                "tld": tld,
                "tld_danger_level": "high" if is_high_danger else "medium" if is_medium_danger else "low",
            },
        )

    def _check_bypass(self, ctx: RuleContext, is_high_danger: bool) -> Optional[str]:
        """バイパス条件をチェック"""
        # 高危険TLD + dangerous_tld シグナル
        if is_high_danger and self._has_dangerous_tld_signal(ctx):
            return "high_danger_tld"

        # ハードトリガー (ctx >= 0.65)
        if ctx.ctx_score >= self._hard_ctx_threshold:
            return "hard_ctx_trigger"

        # ブランド検出
        if ctx.brand_details.get("detected_brands"):
            return "brand_detected"

        # 政府/教育ドメインでない場合のみランダム系バイパスを適用
        if not self._is_gov_edu_tld(ctx):
            # random_pattern + short の組み合わせ + ctx >= 0.50
            if self._has_random_pattern_combo(ctx) and ctx.ctx_score >= self._soft_ctx_threshold:
                return "random_pattern_combo_with_soft_ctx"

            # ランダムシグナル + ctx >= 0.50
            random_signals = ctx.issue_set & RANDOM_SIGNALS
            if random_signals and ctx.ctx_score >= self._soft_ctx_threshold:
                return "random_signal_with_soft_ctx"

        # 高リスクキーワード + ctx >= 0.50
        if "high_risk_words" in ctx.ctx_issues and ctx.ctx_score >= self._soft_ctx_threshold:
            return "high_risk_words_with_soft_ctx"

        return None

    def _has_random_pattern_combo(self, ctx: RuleContext) -> bool:
        """random_pattern + short の組み合わせがあるか"""
        if "random_pattern" not in ctx.issue_set:
            return False
        short_signals = {"short", "very_short", "consonant_cluster_random", "rare_bigram_random", "digit_mixed_random"}
        return bool(ctx.issue_set & short_signals)

    def _has_dangerous_tld_signal(self, ctx: RuleContext) -> bool:
        """dangerous_tld シグナルがあるか"""
        return "dangerous_tld" in ctx.issue_set or "dangerous_tld" in ctx.ctx_issues

    def _is_gov_edu_tld(self, ctx: RuleContext) -> bool:
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


class HighMLCtxRescueRule(DetectionRule):
    """High ML + Ctx Rescue Rule (#16).

    ML >= 0.35 かつ Ctx >= 0.40 で benign 判定されている場合、
    phishing にオーバーライドして FN を救済する。

    分析結果 (2026-01-31):
    - 対象: ML高スコアなのにCtxが0.40-0.50で見逃されているFN
    - FN救済: 66件, FP増加: 7件 (Precision 90.4%)
    - F1 +1.69pp の改善効果

    除外条件:
    - allowlist に含まれるドメイン
    - 信頼TLD (.org, .edu, .gov, .mil, .int)
    - 政府/教育ドメイン

    変更履歴:
        - 2026-01-31: #16 FN救済ルールとして新規作成
    """

    def __init__(
        self,
        enabled: bool = True,
        ml_threshold: float = 0.35,
        ctx_threshold: float = 0.40,
        ctx_upper: float = 0.50,
        confidence_floor: float = 0.70,
    ):
        super().__init__(enabled=enabled)
        self._ml_threshold = ml_threshold
        self._ctx_threshold = ctx_threshold
        self._ctx_upper = ctx_upper
        self._confidence_floor = confidence_floor

    @property
    def name(self) -> str:
        return "high_ml_ctx_rescue"

    @property
    def description(self) -> str:
        return (
            f"Rescue FN when ML >= {self._ml_threshold} and "
            f"Ctx in [{self._ctx_threshold}, {self._ctx_upper})"
        )

    def _evaluate(self, ctx: RuleContext) -> RuleResult:
        # 条件チェック: 現在 benign 判定
        if ctx.llm_is_phishing:
            return RuleResult.not_triggered(self.name)

        # ML閾値チェック
        if ctx.ml_probability < self._ml_threshold:
            return RuleResult.not_triggered(self.name)

        # Ctx スコアチェック: 中程度の範囲 [threshold, upper)
        if ctx.ctx_score < self._ctx_threshold:
            return RuleResult.not_triggered(self.name)

        if ctx.ctx_score >= self._ctx_upper:
            # Ctx >= 0.50 は既に phishing 判定されているはず
            return RuleResult.not_triggered(self.name)

        # 除外条件チェック
        if ctx.is_known_legitimate:
            return RuleResult.not_triggered(self.name)

        tld = ctx.tld.lower().strip(".")
        if tld in TRUSTED_TLDS or any(tld.endswith(f".{t}") for t in TRUSTED_TLDS):
            return RuleResult.not_triggered(self.name)

        if self._is_gov_edu_tld(ctx):
            return RuleResult.not_triggered(self.name)

        # 救済発動
        return RuleResult(
            triggered=True,
            rule_name=self.name,
            issue_tag="high_ml_ctx_rescue",
            force_phishing=True,
            confidence_floor=self._confidence_floor,
            risk_level_bump="high",
            reasoning=(
                f"High ML + Ctx rescue: ML={ctx.ml_probability:.3f} >= {self._ml_threshold}, "
                f"Ctx={ctx.ctx_score:.3f} in [{self._ctx_threshold}, {self._ctx_upper})"
            ),
            details={
                "ml_probability": ctx.ml_probability,
                "ml_threshold": self._ml_threshold,
                "ctx_score": ctx.ctx_score,
                "ctx_threshold": self._ctx_threshold,
                "ctx_upper": self._ctx_upper,
            },
        )

    def _is_gov_edu_tld(self, ctx: RuleContext) -> bool:
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


def create_ml_guard_rules(enabled: bool = True) -> list:
    """Create all ML guard rules.

    Args:
        enabled: Whether rules are enabled by default

    Returns:
        List of ML guard rule instances
    """
    return [
        VeryHighMLOverrideRule(enabled=enabled),
        # 2026-02-04: HighMLOverrideRule をデフォルト無効化
        # 理由: Precision 23.8% (TP:5, FP:16), Net Benefit -11
        # 分析: ルール効果分析で、FPを多く引き起こす問題ルールと判明
        HighMLOverrideRule(enabled=False),  # 無効化
        HighMLCtxRescueRule(enabled=enabled),  # #16 FN救済ルール (2026-01-31追加)
        UltraLowMLBlockRule(enabled=enabled),
        PostLLMFlipGateRule(enabled=enabled),
    ]
