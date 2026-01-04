# -*- coding: utf-8 -*-
"""
llm_final_decision.py (Phase6 v1.3.2-trace)
-------------------------------------------
- 安全側に倒しすぎる分岐（no_org 単体で True になり得る経路）を削除
- ML/Cert/Contextual の「複合条件」でのみ昇格（R1/R2/R3）
- decision_trace を graph_state に埋め込み、risk_factors に policyタグを追記
- 既存の I/F / Strict モード / SO 必須の契約は維持
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple, Optional
import json

try:
    # Phase1 型/例外
    from .agent_foundations import (
        PhishingAssessment, StructuredOutputError, get_risk_level, clip_confidence
    )
except Exception:
    from agent_foundations import (
        PhishingAssessment, StructuredOutputError, get_risk_level, clip_confidence
    )

# ------------------------- small utils -------------------------
def _json_dumps(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))

def _rs(tr: Dict[str, Any], key: str) -> float:
    try:
        v = (tr.get(key) or {}).get("risk_score", 0.0)
        return float(v or 0.0)
    except Exception:
        return 0.0

def _summarize_tool_signals(tool_results: Dict[str, Any]) -> Dict[str, Any]:
    tr = tool_results or {}
    out = {
        "brand": {
            "risk_score": _rs(tr, "brand"),
            "issues": list((tr.get("brand") or {}).get("detected_issues", []) or []),
            "brands": list(((tr.get("brand") or {}).get("details", {}) or {}).get("detected_brands", []) or []),
        },
        "cert": {
            "risk_score": _rs(tr, "cert"),
            "issues": list((tr.get("cert") or {}).get("detected_issues", []) or []),
            "details": dict((tr.get("cert") or {}).get("details", {}) or {}),
        },
        "domain": {
            "risk_score": _rs(tr, "domain"),
            "issues": list((tr.get("domain") or {}).get("detected_issues", []) or []),
            "details": dict((tr.get("domain") or {}).get("details", {}) or {}),
        },
        "contextual": {
            "risk_score": max(_rs(tr, "contextual_risk_assessment"), _rs(tr, "contextual")),
            "issues": list((tr.get("contextual_risk_assessment") or tr.get("contextual") or {}).get("detected_issues", []) or []),
        },
    }
    out["baseline_risk"] = max(out["contextual"]["risk_score"], out["brand"]["risk_score"], out["cert"]["risk_score"], out["domain"]["risk_score"])
    return out

def _priority_bump(current: str, minimum: str) -> str:
    order = ["low","medium","medium-high","high","critical"]
    try:
        return order[max(order.index(current or "low"), order.index(minimum or "low"))]
    except Exception:
        return minimum or current or "medium"

# ---------------------- policy adjustments ---------------------
def _apply_policy_adjustments(
    asmt: PhishingAssessment,
    tool_summary: Dict[str, Any],
    *,
    ml_probability: Optional[float] = None,
    precheck: Optional[Dict[str, Any]] = None,
    trace: Optional[List[Dict[str, Any]]] = None,
) -> PhishingAssessment:
    """
    仕様整合の最終補正 + Phase6ポリシールール（R1/R2/R3）。
    - ハード: contextual.risk_score >= 0.5 → True（維持）
    - ブランド×証明書の強連携は維持（brand_detected & {no_org, free_ca, no_cert}）
    - 旧: no_org 単体 → True の分岐は **削除**
    """
    tr = trace if isinstance(trace, list) else []
    c = clip_confidence(getattr(asmt, "confidence", 0.0))
    rl = getattr(asmt, "risk_level", "low") or "low"
    ip = bool(getattr(asmt, "is_phishing", False))

    # 低レベル補正
    if ip and rl == "low":
        rl = "medium"; tr.append({"rule":"low_to_min_medium","why":"is_phishing=True & level=low"})

    # ---- extract signals ----
    tsum = tool_summary or {}
    b_issues = set((tsum.get("brand") or {}).get("issues", []) or [])
    b_names  = set((tsum.get("brand") or {}).get("brands", []) or [])
    brand_detected = ("brand_detected" in b_issues) or bool(b_names)

    cert_issues = set((tsum.get("cert") or {}).get("issues", []) or [])
    domain_issues = set((tsum.get("domain") or {}).get("issues", []) or [])
    ctx = (tsum.get("contextual") or {})
    ctx_score = float(ctx.get("risk_score", 0.0) or 0.0)
    ctx_issues = set(ctx.get("issues", []) or [])

    ml = float(ml_probability or 0.0)
    pre = dict(precheck or {})
    tld_cat = pre.get("tld_category")
    dom_len = pre.get("domain_length_category")

    # ---- brand × cert （維持） ----
    if brand_detected and ({"no_cert","no_org","free_ca"} & cert_issues):
        ip = True
        c = max(c, 0.70)
        rl = _priority_bump(rl, "high")
        tr.append({"rule":"brand_cert_high","ip":True,"c_min":0.70})

    # ---- hard: contextual >= 0.5（維持） ----
    if ctx_score >= 0.50:
        if not ip:
            tr.append({"rule":"hard_ctx_ge_0.50","ip":True,"ctx":ctx_score})
        ip = True
        rl = _priority_bump(rl, "high")
        c = max(c, ctx_score, 0.50)

    else:
        # ---- Phase6 tightened rules (R1/R2/R3) ----
        # guard: legitimate TLD & long/normal length → R1 しきい値を引き上げ
        r1_th = 0.28
        if (tld_cat == "legitimate") and (dom_len in ("normal","long")) and ("dangerous_tld" not in domain_issues):
            r1_th = 0.34
            tr.append({"note":"legit_tld_guard","r1_threshold":r1_th})

        # R1: very_low-ML + free_ca & no_org + 中強度ctx
        if (ml < 0.20) and ({"free_ca","no_org"} <= cert_issues) and (ctx_score >= r1_th):
            ip = True
            rl = _priority_bump(rl, "medium-high")
            c = max(c, ctx_score, 0.55)
            tr.append({"rule":"R1","ml":ml,"ctx":ctx_score,"req":["ml<0.2","free_ca&no_org","ctx>=%.2f"%r1_th]})

        # R2: low-ML + no_org + (free_ca or short) + ctx>=0.34
        elif (ml < 0.30) and ("no_org" in cert_issues) and (("free_ca" in cert_issues) or (("short" in domain_issues) or ("very_short" in domain_issues))) and (ctx_score >= 0.34):
            ip = True
            rl = _priority_bump(rl, "medium-high")
            c = max(c, ctx_score, 0.55)
            tr.append({"rule":"R2","ml":ml,"ctx":ctx_score})

        # R3: <0.40 + short + no_org + ctx>=0.36
        elif (ml < 0.40) and ("no_org" in cert_issues) and (("short" in domain_issues) or ("very_short" in domain_issues)) and (ctx_score >= 0.36):
            ip = True
            rl = _priority_bump(rl, "medium-high")
            c = max(c, ctx_score, 0.55)
            tr.append({"rule":"R3","ml":ml,"ctx":ctx_score})

    # final clip + external risk level
    c = clip_confidence(c)
    try:
        rl_calc = get_risk_level(confidence=c, is_phishing=ip)  # Phase1 I/F
    except TypeError:
        rl_calc = get_risk_level(c)  # fallback
    rl = _priority_bump(rl, rl_calc)

    # risk_factors に policyタグを足しておく（デバッグ用）
    rf = list(getattr(asmt, "risk_factors", []) or [])
    for t in tr:
        if "rule" in t:
            rf.append(f"policy:{t['rule']}")
    asmt = PhishingAssessment(
        is_phishing=ip,
        confidence=c,
        risk_level=rl,
        detected_brands=list(getattr(asmt, "detected_brands", []) or []),
        risk_factors=rf,
        reasoning=str(getattr(asmt, "reasoning", "") or ""),
    )
    return asmt

# -------------------------- public API --------------------------

from enum import Enum
from pydantic import Field, field_validator

class ReasoningCategory(str, Enum):
    """最終判定の主な理由カテゴリ（事後分析用）"""
    SAFE_OFFICIAL_BRAND = "safe_official_brand"       # 正規ブランド公式サイト
    SAFE_GENERIC_CONTENT = "safe_generic_content"     # 一般的な個人・中小企業サイト（フィッシング要素なし）
    SAFE_PARKED_DOMAIN = "safe_parked_domain"         # ドメインパーキング（脅威なし）
    PHISHING_IMPERSONATION = "phishing_impersonation" # ブランドなりすまし
    PHISHING_CREDENTIALS = "phishing_credentials"     # 資格情報（ログイン情報）詐取
    SUSPICIOUS_DGA_DOMAIN = "suspicious_dga_domain"   # DGA と思われるランダムドメイン
    SUSPICIOUS_TLD_COMBO = "suspicious_tld_combo"     # 危険TLD × 無料証明書 × コンテンツ薄
    MALWARE_DISTRIBUTION = "malware_distribution"     # マルウェア配布の疑い

class PhishingAssessmentSO(PhishingAssessment):
    """Phase6 Structured Output schema (PhishingAssessment 拡張版)

    - primary_category: 最終判定に至った主な理由カテゴリ（ReasoningCategory）
    - mitigated_risk_factors: 「認識しているが無視したリスク要因」
      例: dangerous_tld は検知したが、正規ブランド公式サイトなので安全とみなした場合など
    """
    primary_category: ReasoningCategory = Field(
        default=ReasoningCategory.SAFE_GENERIC_CONTENT,
        description="最終判定に至った最も主要な理由カテゴリ",
    )
    mitigated_risk_factors: list[str] = Field(
        default_factory=list,
        description=(
            "リスク要因として検知したが、文脈から『安全・許容範囲』と判断して"
            "最終判定では採用しなかった要素。"
        ),
    )

    @field_validator("mitigated_risk_factors")
    @classmethod
    def _normalize_mitigated(cls, v: list[str]) -> list[str]:
        out: list[str] = []
        seen: set[str] = set()
        for item in v or []:
            s = (item or "").strip()
            if not s:
                continue
            if s not in seen:
                seen.add(s)
                out.append(s)
        return out


def final_decision(
    llm,
    domain: str,
    ml_probability: float,
    tool_results: dict[str, object],
    graph_state: dict[str, object],
    strict_mode: bool = False,
) -> PhishingAssessment:
    """Phase6 最終判定（SO必須）

    - LangChain の with_structured_output で PhishingAssessmentSO を取得
    - ML/ツール結果/事前チェックの矛盾を _apply_policy_adjustments で補正
    - mitigated_risk_factors を risk_factors にタグとして埋め込み
    - decision_trace と LLM の思考過程を graph_state に保存
    """
    # 1) シグナル集約
    tsum = _summarize_tool_signals(tool_results or {})

    ml = float(ml_probability or 0.0)
    if   ml < 0.2: ml_category = "very_low"
    elif ml < 0.4: ml_category = "low"
    elif ml < 0.6: ml_category = "medium"
    elif ml < 0.8: ml_category = "high"
    else:          ml_category = "very_high"

    ctx_score = float((tsum.get("contextual") or {}).get("risk_score", 0.0) or 0.0)
    ml_paradox = (ml < 0.3 and ctx_score >= 0.5)

    pre: dict[str, object] = {}
    if isinstance(graph_state, dict):
        pre = dict(graph_state.get("precheck_hints", {}) or {})

    # 2) LLM へのプロンプト構築
    system_text = (
        "あなたはサイバーセキュリティのエキスパートAIアナリストです。\n"
        "与えられた ML スコアと各種ツールの結果をもとに、このドメインがフィッシングかどうかを判定します。\n"
        "\n"
        "必ず Pydantic スキーマ PhishingAssessmentSO に従った JSON だけを出力してください。\n"
        "- is_phishing: bool\n"
        "- confidence: 0.0〜1.0 （迷いがあれば小さく）\n"
        "- risk_level: one of ['low','medium','medium-high','high','critical']\n"
        "- detected_brands: 検出したブランド名のリスト（なければ空）\n"
        "- risk_factors: 最終判定の根拠として採用したリスク要因（dangerous_tld, free_ca, no_org, ml_paradox など）\n"
        "- primary_category: ReasoningCategory から 1つ選ぶ\n"
        "- mitigated_risk_factors: 検知したが『安全/許容』と判断して無視したリスク要因\n"
        "- reasoning: 50文字以上で、なぜ is_phishing をその値にしたか、なぜ mitigated_risk_factors を無視できると考えたかを説明すること。\n"
        "\n"
        "重要ルール:\n"
        "1. DGA と思われるランダムドメイン（高エントロピー or 母音が少ないランダム文字列）は、\n"
        "   コンテンツが正常に見えても原則として危険寄りに評価すること。\n"
        "2. ブランド要素が無いからといって安全とは限らない。危険TLD (.icu, .xyz, .top 等) や free_ca, no_org が揃う場合はブランド無しでも強いリスク要因とみなすこと。\n"
        "3. contextual_risk_assessment.risk_score >= 0.5 のときは、必ず is_phishing=true にすること。\n"
        "4. dangerous_tld, free_ca, no_org, ml_paradox などの強いリスク要因が存在するにもかかわらず is_phishing=false と判断する場合は、\n"
        "   それらを risk_factors ではなく mitigated_risk_factors に入れ、explanation で『なぜそれでも安全とみなしたのか』を必ず説明すること。\n"
        "5. risk_factors / mitigated_risk_factors には、tool_signals.*.issues に現れる短い識別子（dangerous_tld, free_ca, brand_detected, high_entropy など）を優先して用いること。\n"
    )

    user_payload = {
        "domain": domain,
        "ml_probability": ml,
        "ml_category": ml_category,
        "ml_paradox_hint": ml_paradox,
        "tool_signals": tsum,
        "precheck_summary": {
            "tld_category": pre.get("tld_category"),
            "quick_risk": pre.get("quick_risk"),
            "potential_brands": pre.get("potential_brands", []),
            "ml_paradox_hint": pre.get("ml_paradox", False),
        },
        "policy": {
            "use_contextual_as_primary": True,
            "brand_plus_cert_elevate": True,
        },
    }

    messages = [
        {"role": "system", "content": system_text},
        {"role": "user", "content": _json_dumps(user_payload)},
    ]

    trace: list[dict[str, object]] = []
    trace.append({
        "phase6_version": "v1.4.0-mitigated",
        "ml": ml,
        "ml_category": ml_category,
        "ctx_score": ctx_score,
        "ml_paradox": ml_paradox,
    })

    # 3) Structured Output 呼び出し
    if not hasattr(llm, "with_structured_output"):
        # LLM 側が SO 非対応の場合は即座に例外（StrictMode の扱いは呼び出し側）
        raise StructuredOutputError(
            "LLM does not support with_structured_output",
            domain=domain,
            ml_probability=ml,
            step="final_decision",
        )

    try:
        chain = llm.with_structured_output(PhishingAssessmentSO)
        asmt_so: PhishingAssessmentSO = chain.invoke(messages)
        trace.append({
            "step": "llm_raw_output",
            "assessment": asmt_so.model_dump(),
        })

        # 4) ポリシー補正（R1/R2/R3 を適用）
        asmt2 = _apply_policy_adjustments(
            asmt_so,
            tsum,
            ml_probability=ml,
            precheck=pre,
            trace=trace,
        )

        # 5) mitigated_risk_factors を risk_factors にタグとして反映
        mitigated = list(getattr(asmt_so, "mitigated_risk_factors", []) or [])
        if mitigated:
            rf = list(getattr(asmt2, "risk_factors", []) or [])
            for f in mitigated:
                tag = f"mitigated:{f}"
                if tag not in rf:
                    rf.append(tag)
            asmt2 = PhishingAssessment(
                is_phishing=asmt2.is_phishing,
                confidence=asmt2.confidence,
                risk_level=asmt2.risk_level,
                detected_brands=list(asmt2.detected_brands or []),
                risk_factors=rf,
                reasoning=asmt2.reasoning,
            )

        # 6) graph_state へのトレース保存
        try:
            if isinstance(graph_state, dict):
                graph_state["phase6_policy_version"] = "v1.4.0-mitigated"
                dt = list(graph_state.get("decision_trace", []) or [])
                dt.append({
                    "phase6_version": "v1.4.0-mitigated",
                    "domain": domain,
                    "ml": ml,
                    "ml_category": ml_category,
                    "ctx_score": ctx_score,
                    "tool_summary": tsum,
                    "ml_paradox": ml_paradox,
                    "llm_primary_category": str(getattr(asmt_so, "primary_category", "")),
                    "llm_mitigated_risk_factors": mitigated,
                    "llm_risk_factors": list(getattr(asmt_so, "risk_factors", []) or []),
                    "policy_trace": trace,
                })
                graph_state["decision_trace"] = dt
        except Exception:
            # トレース保存はベストエフォート
            pass

        return asmt2

    except Exception as e:
        # 7) SO失敗時の扱い
        if strict_mode:
            # Strict=True の場合はそのまま例外を投げる
            raise StructuredOutputError(
                f"Phase6 final_decision SO failed: {e}",
                domain=domain,
                ml_probability=ml,
                step="final_decision",
                original_error=str(e),
            )

        # Strict=False: 安全側フォールバック（既存仕様と互換）
        try:
            if isinstance(graph_state, dict):
                locs = list(graph_state.get("fallback_locations", []) or [])
                locs.append("final_decision")
                graph_state["fallback_locations"] = locs
        except Exception:
            pass

        return PhishingAssessment(
            is_phishing=False,
            confidence=0.0,
            risk_level="low",
            detected_brands=[],
            risk_factors=[],
            reasoning="Structured Output not available; safe fallback (Phase6).",
        )

