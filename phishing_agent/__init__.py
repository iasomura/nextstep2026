# -*- coding: utf-8 -*-
"""
phishing_agent package — Phase1 + Phase2(v1.3 precheck) + Phase3 (tools) unified API
- Phase2の init 方針（相対→絶対のフォールバック、非破壊エクスポート）を考慮
- Phase3 の 05 連携（外部データローダ）とエージェント入口を保持
- Python 3.9 互換の型表記（Optional[...] を使用）
"""
# ---------------------------------------------------------------------
# Change history
# - 2026-01-03: dvguard4 - Added a small extra brand keyword seed ("whatsapp")
#               based on observed TP miss (brand not detected).
# ---------------------------------------------------------------------

from __future__ import annotations

from importlib import import_module
from types import ModuleType
from typing import Dict, Any, List, Optional

__version__ = "1.3.3-phase1+phase2+phase3"
__all__: List[str] = []

# ---------------------------------------------------------------------
# Helper: import relative first, then absolute (Phase2 init の方針を踏襲)
# ---------------------------------------------------------------------
def _import_optional(rel: str, absname: str) -> Optional[ModuleType]:
    try:
        return import_module(rel, package=__name__)
    except Exception:
        try:
            return import_module(absname)
        except Exception:
            return None

# ---------------------------------------------------------------------
# Phase1: agent_foundations re-exports（非破壊）
# ---------------------------------------------------------------------
_af = _import_optional(".agent_foundations", "agent_foundations")
if _af is not None:
    _PHASE1_EXPORTS = [
        "ToolSelectionResult","PhishingAssessment","AgentState",
        "PhishingAgentError","ToolExecutionError","ConfigurationError","DataValidationError",
        "LLMConnectionError","StructuredOutputError","GraphExecutionError","TimeoutError",
        "ERROR_CATEGORIES","AVAILABLE_TOOLS","TOOL_NAMES","TOOL_DESCRIPTIONS",
        "RISK_LEVELS","RISK_LEVEL_THRESHOLDS","STEP_NAMES",
        "clip_confidence","normalize_list","get_risk_level","convert_to_phase2_format",
        "merge_dicts","validate_and_normalize_data_sources","DataSources","run_all_tests",
    ]
    for name in _PHASE1_EXPORTS:
        try:
            globals()[name] = getattr(_af, name)
            if name not in __all__: __all__.append(name)
        except Exception:
            pass
    # Phase1テストの安定エイリアス
    if "run_all_tests" in globals() and "run_phase1_tests" not in globals():
        run_phase1_tests = globals()["run_all_tests"]  # type: ignore[assignment]
        globals()["run_phase1_tests"] = run_phase1_tests
        if "run_phase1_tests" not in __all__: __all__.append("run_phase1_tests")

# ---------------------------------------------------------------------
# Phase2: precheck exports（非破壊）
# ---------------------------------------------------------------------
_pm = _import_optional(".precheck_module", "precheck_module")
if _pm is not None:
    if hasattr(_pm, "generate_precheck_hints"):
        globals()["generate_precheck_hints"] = getattr(_pm, "generate_precheck_hints")
        if "generate_precheck_hints" not in __all__:
            __all__.append("generate_precheck_hints")
    if hasattr(_pm, "run_all_tests"):
        globals()["run_phase2_tests"] = getattr(_pm, "run_all_tests")
        if "run_phase2_tests" not in __all__:
            __all__.append("run_phase2_tests")
    # ツール側で参照するヘルパも公開（内部用途）
    for helper in ("_extract_etld1",):
        if hasattr(_pm, helper):
            globals()[helper] = getattr(_pm, helper)

# ---------------------------------------------------------------------
# Phase3: tools exports（相対 import; フォールバックなし）
# ---------------------------------------------------------------------
def _load_phase3() -> ModuleType:
    return import_module(".tools_module", package=__name__)

try:
    _tm = _load_phase3()
    for name in ("brand_impersonation_check","certificate_analysis",
                 "short_domain_analysis","contextual_risk_assessment",
                 "safe_tool_wrapper"):
        if hasattr(_tm, name):
            globals()[name] = getattr(_tm, name)
            if name not in __all__: __all__.append(name)
    if hasattr(_tm, "run_all_tests"):
        globals()["run_phase3_tests"] = getattr(_tm, "run_all_tests")
        if "run_phase3_tests" not in __all__:
            __all__.append("run_phase3_tests")
except Exception:
    # Phase3 が無い環境でも import 自体は通す（Phase1/2 のみの環境互換）
    pass

# ---------------------------------------------------------------------
# 05 Integration: artifacts loader（キー揺れ・DF/Series対応・3.9対応）
# ---------------------------------------------------------------------
import os, json, pickle

def _p(s: str) -> str:
    return os.path.expandvars(os.path.expanduser(s))

def _load_pickle(path: str):
    with open(_p(path), "rb") as f:
        return pickle.load(f)

def _load_json(path: str):
    with open(_p(path), "r", encoding="utf-8") as f:
        return json.load(f)

def _resolve_run_paths(run_id: str, base_dir: Optional[str] = None) -> Dict[str, str]:
    base = _p(base_dir or ".")
    art = os.path.join(base, "artifacts", run_id)
    handoff = os.path.join(art, "handoff")
    results = os.path.join(art, "results")
    return {
        "ARTIFACTS_DIR": art,
        "HANDOFF_DIR": handoff,
        "RESULTS_DIR": results,
        "PICKLE_04_2": os.path.join(handoff, "04-2_statistical_analysis.pkl"),
        "PICKLE_04_3": os.path.join(handoff, "04-3_llm_tools_setup_with_tools.pkl"),
        "JSON_TLD_STATS": os.path.join(results, "tld_statistics.json"),
    }

def _pick_list(obj: Dict[str, Any], keys: List[str]) -> Optional[List[Any]]:
    for k in keys:
        v = obj.get(k, None) if isinstance(obj, dict) else None
        if isinstance(v, list) and v:
            return list(v)
    return None

def _pick_dict(obj: Dict[str, Any], keys: List[str]) -> Optional[Dict[str, Any]]:
    for k in keys:
        v = obj.get(k, None) if isinstance(obj, dict) else None
        if isinstance(v, dict) and v:
            return dict(v)
        if v is not None and hasattr(v, "to_dict"):
            try:
                d = v.to_dict()
                if isinstance(d, dict) and d:
                    return dict(d)
            except Exception:
                pass
    return None

def _resolve_05_resources(*, run_id: str, base_dir: Optional[str] = None) -> Dict[str, Any]:
    paths = _resolve_run_paths(run_id, base_dir)

    brand_keywords: List[str] = []; cert_full_info_map: Dict[str, Any] = {}
    dangerous_tlds: List[str] = []; legitimate_tlds: List[str] = []; neutral_tlds: List[str] = []
    HIGH_RISK_WORDS: List[str] = []; KNOWN_DOMAINS: Dict[str, Any] = {}; TLD_STATS: Dict[str, Any] = {}

    # 04-3（brand/cert/cfg）
    try:
        pk43 = _load_pickle(paths["PICKLE_04_3"])
        brand_keywords = list(pk43.get("brand_keywords") or [])
        # dvguard4: Add a minimal set of high-value brands observed in regressions.
        # NOTE: Keep this small and precise to avoid brand-tool false positives.
        for _b in ["whatsapp"]:
            _b = str(_b).strip().lower()
            if _b and (_b not in brand_keywords):
                brand_keywords.append(_b)

        cert_full_info_map = dict(pk43.get("cert_full_info_map") or {})
        cfg = pk43.get("cfg") or {}
        tla = cfg.get("tld_analysis") or {}
        # TLD セット（cfg/tld_analysis から）
        for key, target in [
            (["dangerous_tlds","DANGEROUS_TLDS"], "dangerous"),
            (["legitimate_tlds","LEGITIMATE_TLDS"], "legitimate"),
            (["neutral_tlds","NEUTRAL_TLDS"], "neutral"),
        ]:
            lst = _pick_list(tla, key)
            if lst:
                if target == "dangerous":  dangerous_tlds  = lst
                if target == "legitimate": legitimate_tlds = lst
                if target == "neutral":    neutral_tlds    = lst
    except Exception:
        pass

    # 04-2（HIGH_RISK_WORDS / KNOWN_DOMAINS / TLD_STATS / TLD セット）
    try:
        pk42 = _load_pickle(paths["PICKLE_04_2"])
        HIGH_RISK_WORDS = list(pk42.get("HIGH_RISK_WORDS") or [])
        KD = pk42.get("KNOWN_DOMAINS")
        if isinstance(KD, dict): 
            KNOWN_DOMAINS = dict(KD)
        else:
            if KD is not None and hasattr(KD, "to_dict"):
                try: KNOWN_DOMAINS = dict(KD.to_dict())
                except Exception: KNOWN_DOMAINS = {}
        # TLD 統計（キー揺れ対応）
        TLD_STATS = _pick_dict(pk42, ["TLD_STATS","phishing_tld_stats","tld_stats"]) or {}
        # TLD セット（pkl 側にもあれば採用）
        if not dangerous_tlds:
            lst = _pick_list(pk42, ["DANGEROUS_TLDS","dangerous_tlds"])
            if lst: dangerous_tlds = lst
        if not legitimate_tlds:
            lst = _pick_list(pk42, ["LEGITIMATE_TLDS","legitimate_tlds"])
            if lst: legitimate_tlds = lst
        if not neutral_tlds:
            lst = _pick_list(pk42, ["NEUTRAL_TLDS","neutral_tlds"])
            if lst: neutral_tlds = lst
    except Exception:
        pass

    # results/tld_statistics.json（キー揺れ対応）
    try:
        js = _load_json(paths["JSON_TLD_STATS"])
        if not dangerous_tlds:
            lst = _pick_list(js, ["dangerous","dangerous_tlds","DANGEROUS_TLDS"])
            if lst: dangerous_tlds = lst
        if not legitimate_tlds:
            lst = _pick_list(js, ["legitimate","legitimate_tlds","LEGITIMATE_TLDS"])
            if lst: legitimate_tlds = lst
        if not neutral_tlds:
            lst = _pick_list(js, ["neutral","neutral_tlds","NEUTRAL_TLDS"])
            if lst: neutral_tlds = lst
        if not TLD_STATS:
            d = _pick_dict(js, ["phishing_tld_stats","TLD_STATS","tld_stats"])
            if d: TLD_STATS = d
    except Exception:
        pass

    return {
        "brand_keywords": brand_keywords,
        "cert_full_info_map": cert_full_info_map,
        "dangerous_tlds": dangerous_tlds,
        "legitimate_tlds": legitimate_tlds,
        "neutral_tlds": neutral_tlds,
        "phishing_tld_stats": TLD_STATS,
        "high_risk_words": HIGH_RISK_WORDS,
        "known_domains": KNOWN_DOMAINS,
        "paths": paths,
    }

# ---------------------------------------------------------------------
# Phase3 Agent Entrypoints（Phase2以降の更新も考慮）
# ---------------------------------------------------------------------
def run_phase3_agent(
    domain: str,
    ml_probability: float,
    *,
    brand_keywords: List[str],
    cert_full_info_map: Dict[str, Any],
    dangerous_tlds: List[str],
    legitimate_tlds: List[str],
    neutral_tlds: Optional[List[str]] = None,
    phishing_tld_stats: Optional[Dict[str, Any]] = None,
    high_risk_words: Optional[List[str]] = None,
    known_domains: Optional[Dict[str, Any]] = None,
    strict_mode: bool = False,
) -> Dict[str, Any]:
    """
    05が提供する外部データを受け取り、brand→cert→domain→contextual を一括実行。
    Phase2 の generate_precheck_hints には cert_full_info_map を必ず渡す（必須引数）。
    """
    precheck = generate_precheck_hints(
        domain=domain,
        ml_probability=ml_probability,
        brand_keywords=brand_keywords,
        dangerous_tlds=dangerous_tlds,
        legitimate_tlds=legitimate_tlds,
        neutral_tlds=neutral_tlds,
        cert_full_info_map=cert_full_info_map,
    )

    b = brand_impersonation_check(
        domain=domain,
        brand_keywords=brand_keywords,
        precheck_hints=precheck,
        ml_probability=ml_probability,
        strict_mode=strict_mode,
    )
    if b.get("success") is False: return b

    c = certificate_analysis(
        domain=domain,
        cert_full_info_map=cert_full_info_map,
        strict_mode=strict_mode,
    )
    if c.get("success") is False: return c

    s = short_domain_analysis(
        domain=domain,
        dangerous_tlds=dangerous_tlds,
        legitimate_tlds=legitimate_tlds,
        neutral_tlds=neutral_tlds,
        phishing_tld_stats=phishing_tld_stats,
        strict_mode=strict_mode,
    )
    if s.get("success") is False: return s

    tool_results = {
        "brand_impersonation_check": b["data"],
        "certificate_analysis": c["data"],
        "short_domain_analysis": s["data"],
    }
    ctx = contextual_risk_assessment(
        domain=domain,
        ml_probability=ml_probability,
        tool_results=tool_results,
        high_risk_words=high_risk_words,
        known_domains=known_domains,
        strict_mode=strict_mode,
    )
    if ctx.get("success") is False: return ctx

    ctx_data = ctx["data"]
    confidence = float(ctx_data.get("risk_score", 0.0))
    is_phishing = bool(confidence >= 0.5)
    risk_level = get_risk_level(confidence, is_phishing=is_phishing)

    final = {
        "is_phishing": is_phishing,
        "confidence": confidence,
        "risk_level": risk_level,
        "issues": ctx_data.get("detected_issues", []),
    }

    return {
        "success": True,
        "data": {
            "domain": domain,
            "ml_probability": ml_probability,
            "precheck_hints": precheck,
            "tools": {
                "brand_impersonation_check": b,
                "certificate_analysis": c,
                "short_domain_analysis": s,
                "contextual_risk_assessment": ctx,
            },
            "final": final,
        },
    }

def run_phase3_agent_from_05(
    domain: str,
    ml_probability: float,
    *,
    run_id: str,
    base_dir: Optional[str] = None,
    strict_mode: bool = False,
) -> Dict[str, Any]:
    """
    RUN_ID配下の 05 成果物から外部データを解決し、Phase3 エージェントを実行。
    """
    res = _resolve_05_resources(run_id=run_id, base_dir=base_dir)
    return run_phase3_agent(
        domain=domain,
        ml_probability=ml_probability,
        brand_keywords=res["brand_keywords"],
        cert_full_info_map=res["cert_full_info_map"],
        dangerous_tlds=res["dangerous_tlds"],
        legitimate_tlds=res["legitimate_tlds"],
        neutral_tlds=res["neutral_tlds"],
        phishing_tld_stats=res["phishing_tld_stats"],
        high_risk_words=res["high_risk_words"],
        known_domains=res["known_domains"],
        strict_mode=strict_mode,
    )

# 05 から直接 import しやすい公開シンボル
for name in ["run_phase3_agent","run_phase3_agent_from_05",
             "_resolve_run_paths","_resolve_05_resources"]:
    if name not in __all__: __all__.append(name)

# tidy up internals (Phase3: do NOT delete _import_optional because Phase4 append uses it)
del import_module, ModuleType

# ---------------------------------------------------------------------
# Phase4: LangGraph agent exports & helpers（遅延 import 版）
# ---------------------------------------------------------------------
def _lazy_import_l4():
    import importlib
    try:
        return importlib.import_module(".langgraph_module", __name__)
    except Exception:
        return importlib.import_module("phishing_agent.langgraph_module")

# 公開: LangGraphPhishingAgent（必要になった瞬間に解決）
def __getattr__(name):
    if name == "LangGraphPhishingAgent":
        L4 = _lazy_import_l4()
        return getattr(L4, "LangGraphPhishingAgent")
    raise AttributeError(name)

# 05 -> Phase4 エージェント
def make_phase4_agent(*, strict_mode=False, config_path=None, external_data=None):
    L4 = _lazy_import_l4()
    return L4.LangGraphPhishingAgent(
        strict_mode=strict_mode, config_path=config_path, external_data=external_data or {}
    )

def make_phase4_agent_with_05(*, run_id, base_dir=None, strict_mode=False, config_path=None):
    # Phase3 側で既に定義済みの 05 ローダを流用
    ext = _resolve_05_resources(run_id=run_id, base_dir=base_dir)
    L4 = _lazy_import_l4()
    return L4.LangGraphPhishingAgent(
        strict_mode=strict_mode, config_path=config_path, external_data=ext
    )

def run_phase4_agent(domain: str, ml_probability: float, *, external_data, strict_mode=False, config_path=None):
    ag = make_phase4_agent(strict_mode=strict_mode, config_path=config_path, external_data=external_data)
    return ag.evaluate(domain, ml_probability)

def run_phase4_agent_from_05(domain: str, ml_probability: float, *, run_id, base_dir=None, strict_mode=False, config_path=None):
    ag = make_phase4_agent_with_05(run_id=run_id, base_dir=base_dir, strict_mode=strict_mode, config_path=config_path)
    return ag.evaluate(domain, ml_probability)

for _name in (
    "make_phase4_agent", "make_phase4_agent_with_05",
    "run_phase4_agent", "run_phase4_agent_from_05",
):
    if _name not in __all__:
        __all__.append(_name)
