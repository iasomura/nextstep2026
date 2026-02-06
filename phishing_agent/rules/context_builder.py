# -*- coding: utf-8 -*-
"""
phishing_agent.rules.context_builder
------------------------------------
RuleContext builder from pipeline data structures.

Converts tool_summary, precheck, ml_probability, and LLM assessment
into a RuleContext for rule evaluation.

変更履歴:
    - 2026-02-05: ブランド検出ソース統合（ツール検出 + LLM検出）
    - 2026-01-31: 初版作成（ルールモジュール移行計画 Step 1.1）
"""

from typing import Any, Dict, Optional, Set

try:
    from ..agent_foundations import PhishingAssessment
except ImportError:
    from phishing_agent.agent_foundations import PhishingAssessment

from .detectors.base import RuleContext


class RuleContextBuilder:
    """Builder for RuleContext from pipeline data structures.

    Converts the various data structures used in the phishing detection pipeline
    (tool_summary, precheck, ml_probability, llm_assessment) into a unified
    RuleContext object that can be used by all detection rules.

    Example:
        ctx = RuleContextBuilder.build(
            domain="example.com",
            ml_probability=0.35,
            tool_summary=tool_summary_dict,
            precheck=precheck_dict,
            llm_assessment=assessment_obj,
        )
        result = rule_engine.evaluate(ctx)
    """

    @staticmethod
    def build(
        domain: str,
        ml_probability: float,
        tool_summary: Dict[str, Any],
        precheck: Dict[str, Any],
        llm_assessment: Optional[PhishingAssessment] = None,
    ) -> RuleContext:
        """Build RuleContext from pipeline data structures.

        Args:
            domain: The domain being analyzed
            ml_probability: ML model's phishing probability (0.0-1.0)
            tool_summary: Summarized tool results (from _summarize_tool_signals)
            precheck: Precheck results dictionary
            llm_assessment: Optional LLM assessment result

        Returns:
            RuleContext populated with all relevant data
        """
        tsum = tool_summary or {}
        pre = precheck or {}

        # --- Extract brand info ---
        # 2026-02-05: ツール検出とLLM検出のブランドを統合
        brand_data = tsum.get("brand") or {}
        brand_issues = set(brand_data.get("issues", []) or [])

        # ツール検出ブランド
        tool_brands = list(brand_data.get("brands", []) or [])

        # LLM検出ブランド（llm_assessmentがある場合）
        llm_brands: list = []
        if llm_assessment is not None:
            llm_brands = list(getattr(llm_assessment, "detected_brands", []) or [])

        # 統合（重複除去、順序維持）
        merged_brands: list = []
        seen_brands: set = set()
        for brand in tool_brands + llm_brands:
            # ブランド名を正規化して重複チェック（括弧内のマッチタイプを除く）
            brand_str = str(brand).strip()
            brand_base = brand_str.split("(")[0].strip().lower()
            if brand_base and brand_base not in seen_brands:
                seen_brands.add(brand_base)
                merged_brands.append(brand_str)

        brand_details = {
            "risk_score": brand_data.get("risk_score", 0.0),
            "detected_brands": merged_brands,
            "issues": list(brand_issues),
            # 2026-02-05: ソース情報を追加（デバッグ用）
            "_tool_brands": tool_brands,
            "_llm_brands": llm_brands,
        }

        # --- Extract cert info ---
        cert_data = tsum.get("cert") or {}
        cert_details = dict(cert_data.get("details", {}) or {})
        cert_issues = set(cert_data.get("issues", []) or [])
        cert_details["issues"] = list(cert_issues)
        cert_details["risk_score"] = cert_data.get("risk_score", 0.0)

        # Extract benign indicators
        benign_indicators: Set[str] = set()
        raw_benign = cert_details.get("benign_indicators", []) or []
        if raw_benign:
            benign_indicators = set(raw_benign)
        else:
            # Backward compatibility: build from individual flags
            if cert_details.get("has_org") or cert_details.get("has_ov_ev_like_identity"):
                benign_indicators.add("ov_ev_cert")
            if cert_details.get("has_crl_dp"):
                benign_indicators.add("has_crl_dp")
            if cert_details.get("is_wildcard") and not cert_details.get("is_dangerous_tld"):
                benign_indicators.add("wildcard_cert")
            if cert_details.get("is_long_validity"):
                benign_indicators.add("long_validity")
            if cert_details.get("is_high_san") and not cert_details.get("is_dangerous_tld"):
                benign_indicators.add("high_san_count")

        # --- Extract domain info ---
        domain_data = tsum.get("domain") or {}
        domain_issues = set(domain_data.get("issues", []) or [])
        domain_details = dict(domain_data.get("details", {}) or {})
        domain_details["issues"] = list(domain_issues)
        domain_details["risk_score"] = domain_data.get("risk_score", 0.0)

        # Extract legitimate check
        is_known_legitimate = False
        try:
            lc = domain_details.get("legitimate_check", {}) or {}
            is_known_legitimate = (
                bool(lc.get("is_legitimate"))
                and float(lc.get("confidence", 0.0) or 0.0) >= 0.85
            )
        except Exception:
            pass

        # --- Extract contextual info ---
        ctx_data = tsum.get("contextual") or {}
        ctx_score = float(ctx_data.get("risk_score", 0.0) or 0.0)
        ctx_issues = set(ctx_data.get("issues", []) or [])

        # --- Extract TLD info ---
        tld = ""
        registered_domain = ""
        try:
            etld1 = pre.get("etld1", {}) or {}
            tld = (etld1.get("suffix", "") or "").lower().strip(".")
            registered_domain = (etld1.get("registered_domain", "") or "").lower()
        except Exception:
            pass

        # --- Combine all issues ---
        all_issues = domain_issues | cert_issues | ctx_issues

        # --- Build tool_risks ---
        tool_risks = {
            "brand": float(brand_data.get("risk_score", 0.0) or 0.0),
            "cert": float(cert_data.get("risk_score", 0.0) or 0.0),
            "domain": float(domain_data.get("risk_score", 0.0) or 0.0),
            "contextual": ctx_score,
        }

        # --- Extract LLM assessment fields ---
        llm_is_phishing: Optional[bool] = None
        llm_confidence: float = 0.0
        llm_risk_level: str = "low"

        if llm_assessment is not None:
            llm_is_phishing = getattr(llm_assessment, "is_phishing", None)
            llm_confidence = float(getattr(llm_assessment, "confidence", 0.0) or 0.0)
            llm_risk_level = str(getattr(llm_assessment, "risk_level", "low") or "low")

        # --- Build RuleContext ---
        return RuleContext(
            domain=domain,
            ml_probability=float(ml_probability or 0.0),
            issue_set=all_issues,
            tool_risks=tool_risks,
            cert_details=cert_details,
            brand_details=brand_details,
            domain_details=domain_details,
            is_known_legitimate=is_known_legitimate,
            tld=tld,
            registered_domain=registered_domain,
            # Phase6 fields
            ctx_score=ctx_score,
            ctx_issues=ctx_issues,
            precheck=pre,
            benign_indicators=benign_indicators,
            llm_is_phishing=llm_is_phishing,
            llm_confidence=llm_confidence,
            llm_risk_level=llm_risk_level,
        )

    @staticmethod
    def build_from_full_state(
        domain: str,
        graph_state: Dict[str, Any],
        llm_assessment: Optional[PhishingAssessment] = None,
    ) -> RuleContext:
        """Build RuleContext from full graph state.

        Convenience method that extracts tool_summary, precheck, and ml_probability
        from the graph state dictionary.

        Args:
            domain: The domain being analyzed
            graph_state: Full graph state dictionary
            llm_assessment: Optional LLM assessment result

        Returns:
            RuleContext populated with all relevant data
        """
        tool_results = graph_state.get("tool_results", {}) or {}
        precheck = graph_state.get("precheck", {}) or {}
        ml_probability = float(graph_state.get("ml_probability", 0.0) or 0.0)

        # Build tool_summary using the same logic as _summarize_tool_signals
        tool_summary = RuleContextBuilder._summarize_tool_signals(tool_results)

        return RuleContextBuilder.build(
            domain=domain,
            ml_probability=ml_probability,
            tool_summary=tool_summary,
            precheck=precheck,
            llm_assessment=llm_assessment,
        )

    @staticmethod
    def _summarize_tool_signals(tool_results: Dict[str, Any]) -> Dict[str, Any]:
        """Summarize tool results into a standard format.

        This mirrors the _summarize_tool_signals function in llm_final_decision.py.

        Args:
            tool_results: Raw tool results dictionary

        Returns:
            Summarized tool signals dictionary
        """
        tr = tool_results or {}

        def _rs(key: str) -> float:
            try:
                v = (tr.get(key) or {}).get("risk_score", 0.0)
                return float(v or 0.0)
            except Exception:
                return 0.0

        out = {
            "brand": {
                "risk_score": _rs("brand"),
                "issues": list((tr.get("brand") or {}).get("detected_issues", []) or []),
                "brands": list(((tr.get("brand") or {}).get("details", {}) or {}).get("detected_brands", []) or []),
            },
            "cert": {
                "risk_score": _rs("cert"),
                "issues": list((tr.get("cert") or {}).get("detected_issues", []) or []),
                "details": dict((tr.get("cert") or {}).get("details", {}) or {}),
            },
            "domain": {
                "risk_score": _rs("domain"),
                "issues": list((tr.get("domain") or {}).get("detected_issues", []) or []),
                "details": dict((tr.get("domain") or {}).get("details", {}) or {}),
            },
            "contextual": {
                "risk_score": max(_rs("contextual_risk_assessment"), _rs("contextual")),
                "issues": list((tr.get("contextual_risk_assessment") or tr.get("contextual") or {}).get("detected_issues", []) or []),
            },
        }
        out["baseline_risk"] = max(
            out["contextual"]["risk_score"],
            out["brand"]["risk_score"],
            out["cert"]["risk_score"],
            out["domain"]["risk_score"],
        )
        return out
