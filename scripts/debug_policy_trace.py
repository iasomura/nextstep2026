#!/usr/bin/env python3
"""
Policy Logic Debug Script

トレース: なぜR2/R5/R6が発火してis_phishing=Trueにならないのか
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from phishing_agent.llm_final_decision import _apply_policy_adjustments, _summarize_tool_signals
from phishing_agent.agent_foundations import PhishingAssessment


def trace_policy():
    """ポリシーロジックをトレース"""

    # 実際のツール結果構造をシミュレート
    tool_results = {
        "cert": {
            "risk_score": 0.0,
            "detected_issues": [],
            "details": {},
        },
        "domain": {
            "risk_score": 0.2,
            "detected_issues": ["dangerous_tld"],  # short_domain_analysis
            "details": {},
        },
        "contextual_risk_assessment": {
            "risk_score": 0.42,
            "detected_issues": ["free_ca", "no_org", "free_ca_no_org", "dangerous_tld"],
        },
        "brand": {
            "risk_score": 0.0,
            "detected_issues": [],
            "details": {"detected_brands": []},
        },
    }

    # precheck hints
    precheck = {
        "tld_category": "dangerous",  # cn is dangerous
        "domain_length_category": "normal",
    }

    # LLMの初期判定（benign）
    initial_asmt = PhishingAssessment(
        is_phishing=False,
        confidence=0.42,
        risk_level="medium",
        detected_brands=[],
        risk_factors=["free_ca", "no_org", "dangerous_tld"],
        reasoning="The domain hezemusheng.cn has multiple risk factors but ML probability is low. " * 3,
    )

    ml_prob = 0.24

    # ツールサマリ確認
    tsum = _summarize_tool_signals(tool_results)
    print("=" * 70)
    print("Tool Summary:")
    print(f"  brand: {tsum['brand']}")
    print(f"  cert: {tsum['cert']}")
    print(f"  domain: {tsum['domain']}")
    print(f"  contextual: {tsum['contextual']}")
    print(f"  baseline_risk: {tsum['baseline_risk']}")
    print()

    # 変数を手動でトレース
    b_issues = set((tsum.get("brand") or {}).get("issues", []) or [])
    b_names = set((tsum.get("brand") or {}).get("brands", []) or [])
    brand_detected = ("brand_detected" in b_issues) or bool(b_names)

    cert_issues = set((tsum.get("cert") or {}).get("issues", []) or [])
    domain_issues = set((tsum.get("domain") or {}).get("issues", []) or [])
    ctx = (tsum.get("contextual") or {})
    ctx_score = float(ctx.get("risk_score", 0.0) or 0.0)
    ctx_issues = set(ctx.get("issues", []) or [])

    print("Extracted Issues:")
    print(f"  brand_detected: {brand_detected}")
    print(f"  cert_issues: {cert_issues}")
    print(f"  domain_issues: {domain_issues}")
    print(f"  ctx_issues: {ctx_issues}")
    print(f"  ctx_score: {ctx_score}")
    print()

    tld_cat = precheck.get("tld_category")
    dom_len = precheck.get("domain_length_category")
    ml = ml_prob

    print(f"Precheck hints:")
    print(f"  tld_category: {tld_cat}")
    print(f"  domain_length_category: {dom_len}")
    print(f"  ml_probability: {ml}")
    print()

    # R1-R6の条件をチェック
    any_dangerous_tld = ("dangerous_tld" in domain_issues) or ("dangerous_tld" in ctx_issues)
    all_cert_ctx_issues = cert_issues | ctx_issues
    has_dv_issues = ("free_ca" in all_cert_ctx_issues) and ("no_org" in all_cert_ctx_issues)

    print("Policy Variables:")
    print(f"  any_dangerous_tld: {any_dangerous_tld}")
    print(f"  all_cert_ctx_issues: {all_cert_ctx_issues}")
    print(f"  has_dv_issues: {has_dv_issues}")
    print()

    # Low ML Guard
    low_ml_guard = (
        (ml < 0.25)
        and has_dv_issues
        and (not any_dangerous_tld)
        and (not brand_detected)
    )
    print(f"LOW_ML_GUARD: {low_ml_guard}")
    print(f"  ml < 0.25: {ml < 0.25}")
    print(f"  has_dv_issues: {has_dv_issues}")
    print(f"  not any_dangerous_tld: {not any_dangerous_tld}")
    print(f"  not brand_detected: {not brand_detected}")
    print()

    # Strong evidence check (simulate _has_strong_evidence)
    _strong_domain = {
        "dangerous_tld",
        "idn_homograph",
        "high_entropy",
        "very_high_entropy",
        "short_random_combo",
        "random_with_high_tld_stat",
        "very_short_dangerous_combo",
        "deep_chain_with_risky_tld",
    }

    strong_evidence = False
    if brand_detected:
        strong_evidence = True
        print("strong_evidence: True (brand_detected)")
    elif domain_issues & _strong_domain:
        strong_evidence = True
        print(f"strong_evidence: True (domain_issues & _strong_domain = {domain_issues & _strong_domain})")
    elif "dangerous_tld" in ctx_issues:
        strong_evidence = True
        print("strong_evidence: True (dangerous_tld in ctx_issues)")
    else:
        print("strong_evidence: False")
    print()

    # R1 conditions
    r1_th = 0.28
    if (tld_cat == "legitimate") and (dom_len in ("normal","long")) and (not any_dangerous_tld):
        r1_th = 0.34

    print("R1 Conditions:")
    print(f"  ml < 0.20: {ml < 0.20}")
    print(f"  has_dv_issues: {has_dv_issues}")
    print(f"  ctx_score >= r1_th ({r1_th}): {ctx_score >= r1_th}")
    print(f"  strong_evidence: {strong_evidence}")
    print(f"  not low_ml_guard: {not low_ml_guard}")
    r1_fires = (ml < 0.20) and has_dv_issues and (ctx_score >= r1_th) and strong_evidence and (not low_ml_guard)
    print(f"  R1 FIRES: {r1_fires}")
    print()

    # R2 conditions
    print("R2 Conditions:")
    print(f"  ml < 0.30: {ml < 0.30}")
    print(f"  'no_org' in all_cert_ctx_issues: {'no_org' in all_cert_ctx_issues}")
    has_free_ca_or_short = ("free_ca" in all_cert_ctx_issues) or ("short" in domain_issues) or ("very_short" in domain_issues)
    print(f"  'free_ca' in all_cert_ctx_issues OR short/very_short: {has_free_ca_or_short}")
    print(f"  ctx_score >= 0.34: {ctx_score >= 0.34}")
    print(f"  strong_evidence: {strong_evidence}")
    r2_fires = (ml < 0.30) and ("no_org" in all_cert_ctx_issues) and has_free_ca_or_short and (ctx_score >= 0.34) and strong_evidence
    print(f"  R2 FIRES: {r2_fires}")
    print()

    # R5 conditions
    print("R5 Conditions:")
    print(f"  ml < 0.50: {ml < 0.50}")
    print(f"  any_dangerous_tld: {any_dangerous_tld}")
    print(f"  'no_org' in all_cert_ctx_issues: {'no_org' in all_cert_ctx_issues}")
    print(f"  ctx_score >= 0.33: {ctx_score >= 0.33}")
    r5_fires = (ml < 0.50) and any_dangerous_tld and ("no_org" in all_cert_ctx_issues) and (ctx_score >= 0.33)
    print(f"  R5 FIRES: {r5_fires}")
    print()

    # R6 conditions
    print("R6 Conditions:")
    print(f"  ml < 0.30: {ml < 0.30}")
    print(f"  any_dangerous_tld: {any_dangerous_tld}")
    print(f"  has_dv_issues: {has_dv_issues}")
    print(f"  ctx_score >= 0.35: {ctx_score >= 0.35}")
    r6_fires = (ml < 0.30) and any_dangerous_tld and has_dv_issues and (ctx_score >= 0.35)
    print(f"  R6 FIRES: {r6_fires}")
    print()

    # POST_LLM_FLIP_GATE
    LOW_ML_FLIP_GATE_TH = 0.25
    has_dangerous_tld_signal = (
        ("dangerous_tld" in domain_issues)
        or ("dangerous_tld" in ctx_issues)
        or (tld_cat == "dangerous")
    )
    print("POST_LLM_FLIP_GATE:")
    print(f"  ml < {LOW_ML_FLIP_GATE_TH}: {ml < LOW_ML_FLIP_GATE_TH}")
    print(f"  has_dangerous_tld_signal: {has_dangerous_tld_signal}")
    print(f"    'dangerous_tld' in domain_issues: {'dangerous_tld' in domain_issues}")
    print(f"    'dangerous_tld' in ctx_issues: {'dangerous_tld' in ctx_issues}")
    print(f"    tld_cat == 'dangerous': {tld_cat == 'dangerous'}")
    gate_would_block = (ml < LOW_ML_FLIP_GATE_TH) and (not has_dangerous_tld_signal)
    print(f"  GATE WOULD BLOCK: {gate_would_block}")
    print()

    # 実際のポリシー適用
    print("=" * 70)
    print("RUNNING ACTUAL POLICY...")
    print("=" * 70)

    trace = []
    result = _apply_policy_adjustments(
        initial_asmt,
        tsum,
        ml_probability=ml_prob,
        precheck=precheck,
        trace=trace,
    )

    print()
    print("RESULT:")
    print(f"  is_phishing: {result.is_phishing}")
    print(f"  confidence: {result.confidence}")
    print(f"  risk_level: {result.risk_level}")
    print(f"  risk_factors: {result.risk_factors}")
    print()
    print("TRACE:")
    for t in trace:
        print(f"  {t}")


if __name__ == "__main__":
    trace_policy()
