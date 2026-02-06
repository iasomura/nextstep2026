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


class CrlDpRandomPatternRelaxRule(DetectionRule):
    """CRL DP + Random Pattern Relax Rule.

    has_crl_dp（高品質証明書）を持つドメインで、random_patternのみが
    検出されている場合、FPを抑制するためbenign判定にする。

    条件:
    - 現在 phishing 判定
    - has_crl_dp が benign_indicators にある
    - domain_issues に random_pattern がある
    - ブランド検出がない
    - ML < 0.25（低いML確率）
    - 危険TLDでない

    例: frmtr.com, wfqqmy.com, hl-rmc.com

    変更履歴:
        - 2026-02-04: 初版作成（FP削減: ランダムパターン緩和）
    """

    def __init__(
        self,
        enabled: bool = True,
        ml_threshold: float = 0.25,
        confidence_ceiling: float = 0.30,
    ):
        super().__init__(enabled=enabled)
        self._ml_threshold = ml_threshold
        self._confidence_ceiling = confidence_ceiling

    @property
    def name(self) -> str:
        return "crl_dp_random_pattern_relax"

    @property
    def description(self) -> str:
        return f"Relax random_pattern detection when has_crl_dp with ML < {self._ml_threshold}"

    def _evaluate(self, ctx: RuleContext) -> RuleResult:
        # benign なら何もしない
        if not ctx.llm_is_phishing:
            return RuleResult.not_triggered(self.name)

        # has_crl_dp チェック
        if "has_crl_dp" not in ctx.benign_indicators:
            return RuleResult.not_triggered(self.name)

        # random_pattern チェック
        if "random_pattern" not in ctx.issue_set:
            return RuleResult.not_triggered(self.name)

        # ブランド検出チェック
        brand_detected = bool(ctx.brand_details.get("detected_brands"))
        if brand_detected:
            return RuleResult.not_triggered(self.name)

        # ML threshold チェック
        if ctx.ml_probability >= self._ml_threshold:
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

        # 他の強いリスクシグナルチェック
        strong_signals = {
            "idn_homograph", "high_entropy", "very_high_entropy",
            "self_signed", "no_cert", "brand_detected",
        }
        all_issues = ctx.issue_set | ctx.ctx_issues
        if all_issues & strong_signals:
            return RuleResult.not_triggered(self.name)

        # benign 強制
        return RuleResult(
            triggered=True,
            rule_name=self.name,
            issue_tag="crl_dp_random_pattern_relax",
            force_benign=True,
            confidence_ceiling=self._confidence_ceiling,
            risk_level_bump="low",
            reasoning=(
                f"CRL DP random pattern relax: {ctx.domain} has has_crl_dp "
                f"with random_pattern and ML={ctx.ml_probability:.3f} < {self._ml_threshold}"
            ),
            details={
                "ml_probability": ctx.ml_probability,
                "ml_threshold": self._ml_threshold,
                "benign_indicator": "has_crl_dp",
                "domain_issues": list(ctx.issue_set),
            },
        )


class DangerousTldLowMlRelaxRule(DetectionRule):
    """Dangerous TLD + Low ML Relax Rule.

    高FP率の危険TLDで、MLスコアが非常に低く、ctx_scoreも低い場合、
    FPを抑制するためbenign判定にする。

    対象TLD（FP率 > 60%）: .cc, .shop, .cyou, .top, .xyz
    除外TLD（FP率 < 55%）: .cn, .icu（実際のPhishingが多い）

    条件:
    - 現在 phishing 判定
    - TLD が対象TLD（cc, shop, cyou, top, xyz）
    - ML < 0.15（非常に低いML確率）
    - ctx_score < 0.50（低いコンテキストリスク）
    - ブランド検出がない

    期待効果（全件分析）:
    - FP削減: 49件
    - FN増加: 10件
    - 純効果: +39件

    変更履歴:
        - 2026-02-05: 初版作成（Task #22: FP削減: 危険TLD+極低MLゲート調整）
    """

    # 対象TLD（高FP率）
    TARGET_TLDS: Set[str] = frozenset({"cc", "shop", "cyou", "top", "xyz"})

    def __init__(
        self,
        enabled: bool = True,
        ml_threshold: float = 0.15,
        ctx_threshold: float = 0.50,
        confidence_ceiling: float = 0.30,
    ):
        super().__init__(enabled=enabled)
        self._ml_threshold = ml_threshold
        self._ctx_threshold = ctx_threshold
        self._confidence_ceiling = confidence_ceiling

    @property
    def name(self) -> str:
        return "dangerous_tld_low_ml_relax"

    @property
    def description(self) -> str:
        return (
            f"Relax phishing on high-FP-rate TLDs (cc,shop,cyou,top,xyz) "
            f"when ML < {self._ml_threshold} and ctx < {self._ctx_threshold}"
        )

    def _evaluate(self, ctx: RuleContext) -> RuleResult:
        # benign なら何もしない
        if not ctx.llm_is_phishing:
            return RuleResult.not_triggered(self.name)

        # TLDチェック（対象TLDのみ）
        tld = ctx.tld.lower().strip(".")
        if tld not in self.TARGET_TLDS:
            return RuleResult.not_triggered(self.name)

        # ML threshold チェック
        if ctx.ml_probability >= self._ml_threshold:
            return RuleResult(
                triggered=False,
                rule_name=self.name,
                reasoning=f"ML too high: {ctx.ml_probability:.3f} >= {self._ml_threshold}",
                details={
                    "skip_reason": "ml_too_high",
                    "ml_probability": ctx.ml_probability,
                    "ml_threshold": self._ml_threshold,
                },
            )

        # ctx threshold チェック
        if ctx.ctx_score >= self._ctx_threshold:
            return RuleResult(
                triggered=False,
                rule_name=self.name,
                reasoning=f"ctx too high: {ctx.ctx_score:.3f} >= {self._ctx_threshold}",
                details={
                    "skip_reason": "ctx_too_high",
                    "ctx_score": ctx.ctx_score,
                    "ctx_threshold": self._ctx_threshold,
                },
            )

        # ブランド検出チェック
        brand_detected = bool(ctx.brand_details.get("detected_brands"))
        if brand_detected:
            return RuleResult(
                triggered=False,
                rule_name=self.name,
                reasoning=f"Brand detected: {ctx.brand_details.get('detected_brands')}",
                details={
                    "skip_reason": "brand_detected",
                    "detected_brands": ctx.brand_details.get("detected_brands"),
                },
            )

        # benign 強制
        return RuleResult(
            triggered=True,
            rule_name=self.name,
            issue_tag="dangerous_tld_low_ml_relax",
            force_benign=True,
            confidence_ceiling=self._confidence_ceiling,
            risk_level_bump="low",
            reasoning=(
                f"Dangerous TLD low ML relax: {ctx.domain} has high-FP-rate TLD (.{tld}) "
                f"with ML={ctx.ml_probability:.3f} < {self._ml_threshold} "
                f"and ctx={ctx.ctx_score:.3f} < {self._ctx_threshold}, no brand detected"
            ),
            details={
                "domain": ctx.domain,
                "tld": tld,
                "ml_probability": ctx.ml_probability,
                "ml_threshold": self._ml_threshold,
                "ctx_score": ctx.ctx_score,
                "ctx_threshold": self._ctx_threshold,
                "brand_detected": False,
                "target_tlds": list(self.TARGET_TLDS),
            },
        )


class FuzzyBrandLowMlRelaxRule(DetectionRule):
    """Fuzzy Brand + Low ML Relax Rule.

    ブランド検出がfuzzy2/substringのみで、MLスコアが非常に低い場合、
    FPを抑制するためbenign判定にする。

    分析結果（Stage3単体評価 3000件）:
    - ブランド検出ありFPの88.9%がML < 0.05
    - ML < 0.05 + fuzzy2/substringのみ → FP削減20件、FN増加0件

    条件:
    - 現在 phishing 判定
    - ブランド検出あり
    - 検出ブランドがすべてfuzzy2またはsubstringマッチ
    - ML < 0.05（非常に低いML確率）

    除外:
    - exact match（例: google, dhl）
    - critical_brand（例: bank, login）
    - compound match（例: wise (compound)）
    - fuzzy match（fuzzy2より厳格）

    期待効果:
    - FP削減: 20件
    - FN増加: 0件
    - 純効果: +20件

    変更履歴:
        - 2026-02-05: 初版作成（Task #20: FP削減: ブランド誤検知対策）
    """

    # 緩和対象のマッチタイプ
    RELAXABLE_MATCH_TYPES = frozenset({"fuzzy2", "substring"})

    def __init__(
        self,
        enabled: bool = True,
        ml_threshold: float = 0.05,
        confidence_ceiling: float = 0.30,
    ):
        super().__init__(enabled=enabled)
        self._ml_threshold = ml_threshold
        self._confidence_ceiling = confidence_ceiling

    @property
    def name(self) -> str:
        return "fuzzy_brand_low_ml_relax"

    @property
    def description(self) -> str:
        return (
            f"Relax phishing when brand detection is fuzzy2/substring only "
            f"and ML < {self._ml_threshold}"
        )

    def _is_relaxable_brand_match(self, detected_brands: list) -> tuple:
        """Check if all detected brands are fuzzy2/substring matches.

        Returns:
            (is_relaxable, match_types):
                is_relaxable: True if all matches are fuzzy2/substring
                match_types: set of detected match types
        """
        if not detected_brands:
            return False, set()

        match_types = set()
        for brand in detected_brands:
            brand_str = str(brand).lower()

            # マッチタイプを抽出
            if "(fuzzy2)" in brand_str:
                match_types.add("fuzzy2")
            elif "(substring)" in brand_str:
                match_types.add("substring")
            elif "(fuzzy)" in brand_str:
                # fuzzy（fuzzy2ではない）は厳格なので緩和対象外
                match_types.add("fuzzy")
            elif "(compound)" in brand_str:
                match_types.add("compound")
            elif "(" not in brand_str:
                # 括弧なし = exact match
                match_types.add("exact")
            else:
                # その他（llm_confirmed等）
                match_types.add("other")

        # fuzzy2/substringのみかチェック
        is_relaxable = match_types.issubset(self.RELAXABLE_MATCH_TYPES)
        return is_relaxable, match_types

    def _evaluate(self, ctx: RuleContext) -> RuleResult:
        # benign なら何もしない
        if not ctx.llm_is_phishing:
            return RuleResult.not_triggered(self.name)

        # ブランド検出チェック
        detected_brands = ctx.brand_details.get("detected_brands", [])
        if not detected_brands:
            return RuleResult.not_triggered(self.name)

        # ML threshold チェック
        if ctx.ml_probability >= self._ml_threshold:
            return RuleResult(
                triggered=False,
                rule_name=self.name,
                reasoning=f"ML too high: {ctx.ml_probability:.3f} >= {self._ml_threshold}",
                details={
                    "skip_reason": "ml_too_high",
                    "ml_probability": ctx.ml_probability,
                    "ml_threshold": self._ml_threshold,
                },
            )

        # マッチタイプチェック
        is_relaxable, match_types = self._is_relaxable_brand_match(detected_brands)
        if not is_relaxable:
            return RuleResult(
                triggered=False,
                rule_name=self.name,
                reasoning=f"Non-relaxable match types: {match_types}",
                details={
                    "skip_reason": "non_relaxable_match_type",
                    "detected_brands": detected_brands,
                    "match_types": list(match_types),
                },
            )

        # benign 強制
        return RuleResult(
            triggered=True,
            rule_name=self.name,
            issue_tag="fuzzy_brand_low_ml_relax",
            force_benign=True,
            confidence_ceiling=self._confidence_ceiling,
            risk_level_bump="low",
            reasoning=(
                f"Fuzzy brand low ML relax: {ctx.domain} has only {match_types} brand matches "
                f"with ML={ctx.ml_probability:.3f} < {self._ml_threshold}"
            ),
            details={
                "domain": ctx.domain,
                "ml_probability": ctx.ml_probability,
                "ml_threshold": self._ml_threshold,
                "detected_brands": detected_brands,
                "match_types": list(match_types),
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

    変更履歴:
        - 2026-02-05: FuzzyBrandLowMlRelaxRule 追加 (Task #20)
        - 2026-02-05: DangerousTldLowMlRelaxRule 追加 (Task #22)
        - 2026-02-04: CrlDpRandomPatternRelaxRule 追加
    """
    return [
        PostRandomPatternOnlyGateRule(enabled=enabled),
        CrlDpRandomPatternRelaxRule(enabled=enabled),  # 2026-02-04追加
        DangerousTldLowMlRelaxRule(enabled=enabled),   # 2026-02-05追加 (Task #22)
        FuzzyBrandLowMlRelaxRule(enabled=enabled),     # 2026-02-05追加 (Task #20)
        MlNoMitigationGateRule(enabled=enabled),
        LowToMinMediumRule(enabled=enabled),
    ]
