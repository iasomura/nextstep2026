
# -*- coding: utf-8 -*-
"""
langgraph_module.py — Phase 4 状態管理 (spec latest v1.3)
========================================================

- 目的: precheck → tool_selection → fanout → aggregate → (contextual?) → final の StateGraph
- Step1/Step3 は Structured Output（SO）必須（本実装はフック＋フォールバックを提供）
- 準必須化: 実行ツール数 >= 2 または (ml < 0.2 かつ 実行 >= 1) で contextual_check を追加
- precheck ノードは Phase2 I/F に ipynb データ（TLD集合/統計, brand, high_risk_words,
  KNOWN_DOMAINS, cert_map）をそのまま渡す

依存（同ディレクトリ）:
- agent_foundations.py  (Phase1)
- precheck_module.py    (Phase2 v1.3)
- tools_module.py       (Phase3 v1.3)

仕様: Phase4_spec_latest.md (v1.3, 2025-11-04)
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Callable, Tuple
import json, os, time, traceback

# ------------------------------------
# LangGraph (が無い場合にフォールバック)
# ------------------------------------
_HAS_LANGGRAPH = True
try:
    from langgraph.graph import StateGraph, START, END  # type: ignore
except Exception:
    _HAS_LANGGRAPH = False
    StateGraph = object  # sentinel
    START, END = "__start__", "__end__"

# ------------------------------------
# 合成パッケージ（tools_module 相対 import 対策）
# ------------------------------------
import sys, importlib.util as _iu, types as _types

def _ensure_synthetic_pkg(pkg_name: str = "phishpkg", base_dir: Optional[str] = None):
    if pkg_name in sys.modules:
        return sys.modules[pkg_name]
    base = base_dir or os.path.dirname(__file__)
    pkg = _types.ModuleType(pkg_name)
    pkg.__path__ = [base]
    sys.modules[pkg_name] = pkg
    # preload agent_foundations / precheck_module / tools_module under this pkg
    for modfile, modname in [
        ("agent_foundations.py", f"{pkg_name}.agent_foundations"),
        ("precheck_module.py",  f"{pkg_name}.precheck_module"),
        ("tools_module.py",     f"{pkg_name}.tools_module"),
    ]:
        path = os.path.join(base, modfile)
        if os.path.exists(path):
            spec = _iu.spec_from_file_location(modname, path, submodule_search_locations=[base] if modname.endswith("__init__") else None)
            if spec and spec.loader:
                m = _iu.module_from_spec(spec)
                sys.modules[modname] = m
                spec.loader.exec_module(m)  # type: ignore
    return pkg

_ensure_synthetic_pkg()

# ------------------------------------
# Phase1/2/3 の取り込み（v1.3 I/F）
# ------------------------------------
try:
    from phishpkg.agent_foundations import (
        AgentState, ToolSelectionResult, PhishingAssessment,
        PhishingAgentError, ToolExecutionError, GraphExecutionError,
        clip_confidence, get_risk_level, convert_to_phase2_format, merge_dicts
    )
except Exception as e:
    raise ImportError("agent_foundations が見つかりません。") from e

try:
    from phishpkg.precheck_module import generate_precheck_hints
except Exception as e:
    raise ImportError("precheck_module が見つかりません。") from e

try:
    from phishpkg.tools_module import (
        brand_impersonation_check,
        certificate_analysis,
        short_domain_analysis,
        contextual_risk_assessment,
    )
except Exception as e:
    raise ImportError("tools_module が見つかりません。") from e


# ------------------------------------
# LLM 設定（Phase5/6 で SO を実接続）
# ------------------------------------
@dataclass
class LLMConfig:
    enabled: bool = False
    provider: str = "vllm"
    base_url: Optional[str] = None
    model: str = "Qwen/Qwen3-14B-FP8"
    api_key: Optional[str] = None
    temperature: float = 0.1

def _resolve_config_path(explicit: Optional[str] = None) -> Optional[str]:
    # 優先度: 明示引数 → 環境変数 → CWD → モジュール隣接 → /mnt/data
    candidates: List[str] = []
    if explicit: candidates.append(explicit)
    for env in ("NEXTSTEP_CONFIG_JSON","AIA_CONFIG_JSON","CONFIG_JSON"):
        v = os.getenv(env)
        if v: candidates.append(v)
    try:
        # このモジュールと同じディレクトリ
        candidates.append(os.path.join(os.path.dirname(__file__), "config.json"))
    except Exception:
        pass
    candidates.append(os.path.join(os.getcwd(), "config.json"))
    candidates.append("/mnt/data/config.json")
    for p in candidates:
        if p and os.path.isfile(p):
            return p
    return None

def load_llm_config(config_path: Optional[str] = None) -> LLMConfig:
    path = _resolve_config_path(config_path)
    if not path:
        return LLMConfig()
    try:
        raw = json.load(open(path, "r", encoding="utf-8"))
        llm = raw.get("llm", {})
        return LLMConfig(
            enabled=bool(llm.get("enabled", False)),
            provider=str(llm.get("provider", "vllm")),
            base_url=llm.get("base_url"),
            model=str(llm.get("model", "Qwen/Qwen3-14B-FP8")),
            api_key=llm.get("api_key"),
            temperature=0.1,
        )
    except Exception:
        return LLMConfig()


# ------------------------------------
# SO（Structured Output）フック（Phase5/6で実接続）
# ------------------------------------
class _SOClient:
    def __init__(self, cfg: LLMConfig):
        self.cfg = cfg
        self.available = bool(cfg.enabled and cfg.base_url)

    def select_tools(self, domain: str, ml_probability: float, precheck_hints: Dict[str,Any]) -> ToolSelectionResult:
        # Phase 4 時点では「必須要件のフック」。失敗: 例外→Strict, 非Strict→フォールバック。
        raise RuntimeError("SO(select_tools) not wired in Phase 4 environment")

    def final_assessment(self, domain: str, ml_probability: float, tool_results: Dict[str,Any]) -> PhishingAssessment:
        # Phase 4 時点では「必須要件のフック」。失敗: 例外→Strict, 非Strict→フォールバック。
        raise RuntimeError("SO(final_assessment) not wired in Phase 4 environment")


# ------------------------------------
# エージェント本体（Phase4 v1.3）
# ------------------------------------
class LangGraphPhishingAgent:
    """
    Phase4 (spec v1.3) LangGraph 状態管理エージェント

    - Step1/Step3 は Structured Output 必須（本実装はフック + フォールバック）
    - precheck へ ipynb データを Phase2 I/F で渡す
    """

    def __init__(
        self,
        *,
        strict_mode: bool = True,
        use_llm_selection: bool = True,
        use_llm_decision: bool = True,
        config_path: Optional[str] = None,
        # 05 の成果物からロードする場合（任意）:
        external_data: Optional[Dict[str, Any]] = None,
        # LangGraph が無い環境でも順次で動作
    ) -> None:
        self.strict_mode = strict_mode
        self.use_llm_selection = use_llm_selection
        self.use_llm_decision = use_llm_decision
        self.llm_config = load_llm_config(config_path)
        self.so = _SOClient(self.llm_config)
        self.external_data = external_data or {}

        self.graph = self._build_graph() if _HAS_LANGGRAPH else None

    # --------------- Graph 構築 ---------------
    def _build_graph(self):
        g = StateGraph(AgentState)  # type: ignore
        g.add_node("precheck", self._precheck_node)
        g.add_node("tool_selection", self._tool_selection_node)
        g.add_node("fanout_dispatcher", self._fanout_dispatcher_node)
        g.add_node("tool_execution", self._tool_execution_node)
        g.add_node("aggregate", self._aggregate_node)
        g.add_node("contextual_check", self._contextual_check_node_delta)
        g.add_node("final_decision", self._final_decision_node)

        g.add_edge(START, "precheck")          # type: ignore
        g.add_edge("precheck", "tool_selection")
        g.add_edge("tool_selection", "fanout_dispatcher")
        # fan-out
        g.add_edge("fanout_dispatcher", "tool_execution")
        g.add_edge("tool_execution", "aggregate")
        # aggregate → 条件分岐
        g.add_conditional_edges(
            "aggregate",
            self._route_from_aggregate,
            {"contextual": "contextual_check", "final": "final_decision"},
        )
        g.add_edge("contextual_check", "final_decision")
        g.add_edge("final_decision", END)       # type: ignore
        return g.compile()

    # --------------- Util ---------------
    def _update_fallback(self, state: AgentState, where: str, error: Optional[str] = None) -> None:
        state["fallback_count"] = state.get("fallback_count", 0) + 1
        locs = list(state.get("fallback_locations", []) or [])
        locs.append(where if not error else f"{where}:{error}")
        state["fallback_locations"] = locs

    # --------------- Nodes ---------------
    def _precheck_node(self, state: AgentState) -> AgentState:
        """precheck: Phase2 I/F に ipynb データを渡す"""
        ed = self.external_data or {}
        try:
            hints = generate_precheck_hints(
                domain=state["domain"],
                ml_probability=state["ml_probability"],
                brand_keywords=ed.get("brand_keywords", []),
                cert_full_info_map=ed.get("cert_full_info_map", {}),
                dangerous_tlds=ed.get("dangerous_tlds", []),
                legitimate_tlds=ed.get("legitimate_tlds", []),
                neutral_tlds=ed.get("neutral_tlds", []),
                phishing_tld_stats=ed.get("phishing_tld_stats", {}),
                known_domains=ed.get("known_domains", {}),
                high_risk_words=ed.get("high_risk_words", []),
                strict_mode=self.strict_mode,
            )
            state["precheck_hints"] = hints
            state["current_step"] = "precheck"
            if isinstance(hints, dict) and hints.get("_fallback"):
                self._update_fallback(state, "precheck_fallback")
        except Exception as e:
            if self.strict_mode:
                raise PhishingAgentError(f"precheck failed: {e}")
            state["precheck_hints"] = {}
            self._update_fallback(state, "precheck_exception", str(e))
        return state

    def _tool_selection_node(self, state: AgentState) -> AgentState:
        """Step1: SO必須（Phase5で本接続）。ここではフック + フォールバックを実装。"""
        ml = float(state["ml_probability"] or 0.0)
        try:
            if self.use_llm_selection and self.so.available:
                # Phase4 環境：SOは未接続 → 例外でフォールバック動作へ
                sel = self.so.select_tools(state["domain"], ml, state.get("precheck_hints", {}))
                selected_tools = list(sel.selected_tools or [])
            else:
                raise RuntimeError("SO(select_tools) unavailable")
        except Exception as e:
            if self.strict_mode and self.use_llm_selection:
                raise PhishingAgentError(f"SO(select_tools) failed: {e}")
            # 非Strict or use_llm_selection=False → 仕様のMLルールでフォールバック
            if ml < 0.2:
                selected_tools = ["brand_impersonation_check","certificate_analysis","short_domain_analysis"]
            elif ml < 0.5:
                selected_tools = ["brand_impersonation_check","certificate_analysis","short_domain_analysis"]
            else:
                selected_tools = ["brand_impersonation_check","certificate_analysis"]
            self._update_fallback(state, "tool_selection_llm", str(e))

        state["selected_tools"] = selected_tools
        state["current_step"] = "tool_selection"
        return state

    def _fanout_dispatcher_node(self, state: AgentState) -> AgentState:
        sel = state.get("selected_tools", [])
        flags = {
            "brand": ("brand_impersonation_check" in sel),
            "cert":  ("certificate_analysis" in sel),
            "domain":("short_domain_analysis" in sel),
        }
        state["tool_execution_flags"] = flags
        state["current_step"] = "tool_execution"
        return state

    def _brand_check_node(self, state: AgentState) -> AgentState:
        if not state.get("tool_execution_flags", {}).get("brand", False):
            return state
        ed = self.external_data or {}
        try:
            res = brand_impersonation_check(
                domain=state["domain"],
                brand_keywords=ed.get("brand_keywords", []),
                precheck_hints=state.get("precheck_hints", {}),
                ml_probability=float(state.get("ml_probability", 0.0) or 0.0),
                strict_mode=self.strict_mode,
            )
            if "tool_results" not in state:
                state["tool_results"] = {}
            # v1.3: data に本体が入る
            if isinstance(res, dict) and res.get("success") is False:
                self._update_fallback(state, "tool_brand_fallback", str(res.get("error")))
            state["tool_results"]["brand"] = (res.get("data") or {})
        except Exception as e:
            if self.strict_mode:
                raise
            if "tool_results" not in state:
                state["tool_results"] = {}
            state["tool_results"]["brand"] = {"detected_issues": [], "risk_score": 0.0, "_fallback": True}
            self._update_fallback(state, "tool_brand_exception", str(e))
        return state

    def _cert_check_node(self, state: AgentState) -> AgentState:
        if not state.get("tool_execution_flags", {}).get("cert", False):
            return state
        ed = self.external_data or {}
        try:
            res = certificate_analysis(
                domain=state["domain"],
                cert_full_info_map=ed.get("cert_full_info_map", {}),
                strict_mode=self.strict_mode,
            )
            if "tool_results" not in state:
                state["tool_results"] = {}
            if isinstance(res, dict) and res.get("success") is False:
                self._update_fallback(state, "tool_cert_fallback", str(res.get("error")))
            state["tool_results"]["cert"] = (res.get("data") or {})
        except Exception as e:
            if self.strict_mode:
                raise
            if "tool_results" not in state:
                state["tool_results"] = {}
            state["tool_results"]["cert"] = {"detected_issues": [], "risk_score": 0.0, "_fallback": True}
            self._update_fallback(state, "tool_cert_exception", str(e))
        return state

    def _domain_check_node(self, state: AgentState) -> AgentState:
        if not state.get("tool_execution_flags", {}).get("domain", False):
            return state
        ed = self.external_data or {}
        try:
            res = short_domain_analysis(
                domain=state["domain"],
                dangerous_tlds=ed.get("dangerous_tlds", []),
                legitimate_tlds=ed.get("legitimate_tlds", []),
                neutral_tlds=ed.get("neutral_tlds", []),
                phishing_tld_stats=ed.get("phishing_tld_stats", {}),
                strict_mode=self.strict_mode,
            )
            if "tool_results" not in state:
                state["tool_results"] = {}
            if isinstance(res, dict) and res.get("success") is False:
                self._update_fallback(state, "tool_domain_fallback", str(res.get("error")))
            state["tool_results"]["domain"] = (res.get("data") or {})
        except Exception as e:
            if self.strict_mode:
                raise
            if "tool_results" not in state:
                state["tool_results"] = {}
            state["tool_results"]["domain"] = {"detected_issues": [], "risk_score": 0.0, "_fallback": True}
            self._update_fallback(state, "tool_domain_exception", str(e))
        return state

    def _aggregate_node(self, state: AgentState) -> AgentState:
        tr = state.get("tool_results", {}) or {}
        executed = len([k for k in ("brand","cert","domain") if k in tr])
        ml = float(state.get("ml_probability", 0.0) or 0.0)
        should_ctx = (executed >= 2) or (ml < 0.2 and executed >= 1)
        state["next_step"] = "contextual" if should_ctx else "final"
        state["current_step"] = "aggregate"
        return state

    def _route_from_aggregate(self, state: AgentState) -> str:
        tr = state.get("tool_results", {}) or {}
        executed = sum(1 for k in ("brand","cert","domain") if k in tr)
        ml = float(state.get("ml_probability", 0.0) or 0.0)
        should_ctx = (executed >= 2) or (ml < 0.2 and executed >= 1)
        return "contextual" if should_ctx else "final"

    def _contextual_check_node(self, state: AgentState) -> AgentState:
        ed = self.external_data or {}
        tr = state.get("tool_results", {}) or {}
        try:
            res = contextual_risk_assessment(
                domain=state["domain"],
                ml_probability=float(state.get("ml_probability", 0.0) or 0.0),
                tool_results={
                    "brand_impersonation_check": tr.get("brand", {}),
                    "certificate_analysis": tr.get("cert", {}),
                    "short_domain_analysis": tr.get("domain", {}),
                },
                high_risk_words=ed.get("high_risk_words", []),
                known_domains=ed.get("known_domains", {}),
                strict_mode=self.strict_mode,
            )
            if "tool_results" not in state:
                state["tool_results"] = {}
            if isinstance(res, dict) and res.get("success") is False:
                self._update_fallback(state, "tool_contextual_fallback", str(res.get("error")))
            state["tool_results"]["contextual_risk_assessment"] = (res.get("data") or {})
        except Exception as e:
            if self.strict_mode:
                raise
            if "tool_results" not in state:
                state["tool_results"] = {}
            state["tool_results"]["contextual_risk_assessment"] = {"detected_issues": [], "risk_score": 0.0, "_fallback": True}
            self._update_fallback(state, "tool_contextual_exception", str(e))
        return state

    def _final_decision_node(self, state: AgentState) -> AgentState:
        """Step3: SO必須。Phase6で本接続。ここではフォールバックを規定どおり実装。"""
        ml = float(state.get("ml_probability", 0.0) or 0.0)
        try:
            if self.use_llm_decision and self.so.available:
                asmt = self.so.final_assessment(state["domain"], ml, state.get("tool_results", {}))
                state["final_assessment"] = asmt
                state["current_step"] = "completed"
                return state
            else:
                raise RuntimeError("SO(final_assessment) unavailable")
        except Exception as e:
            if self.strict_mode and self.use_llm_decision:
                raise PhishingAgentError(f"SO(final_assessment) failed: {e}")
            # 非Strict: ルールベースのフォールバック
            tr = state.get("tool_results", {}) or {}
            cxs = float((tr.get("contextual_risk_assessment") or {}).get("risk_score", 0.0) or 0.0)
            if cxs <= 0.0:
                cxs = float((tr.get("contextual") or {}).get("risk_score", 0.0) or 0.0)
            # contextual が無ければ前段の平均/最大などで代替
            if cxs <= 0.0:
                parts = [float((tr.get(k) or {}).get("risk_score", 0.0) or 0.0) for k in ("brand","cert","domain")]
                cxs = max(parts) if parts else ml
            is_ph = bool(cxs >= 0.5)
            conf = clip_confidence(max(ml, cxs))
            risk_level = get_risk_level(confidence=conf, is_phishing=is_ph)
            asmt = PhishingAssessment(
                is_phishing=is_ph,
                confidence=conf,
                risk_level=risk_level,
                detected_brands=list((tr.get("brand") or {}).get("details", {}).get("detected_brands", []) or []),
                risk_factors=list((tr.get("contextual") or {}).get("detected_issues", []) or []),
                reasoning="SO(final_decision) fallback: contextual/aggregate riskを使用",
            )
            self._update_fallback(state, "final_decision_llm", str(e))
            state["final_assessment"] = asmt
            state["current_step"] = "completed"
            return state

    # ==== concurrency-safe delta wrappers (Phase4 fix) ====
    def _brand_check_node_delta(self, state: AgentState):
        _before = dict(state) if isinstance(state, dict) else {}
        _after = self._brand_check_node(dict(state))
        _prev = (_before.get("tool_results") or {})
        _curr = (_after.get("tool_results") or {})
        _delta = {}
        if isinstance(_curr, dict):
            for _k, _v in _curr.items():
                if _prev.get(_k) != _v:
                    _delta[_k] = _v
        _prev_loc = list(_before.get("fallback_locations", []) or [])
        _curr_loc = list(_after.get("fallback_locations", []) or [])
        _loc_delta = _curr_loc[len(_prev_loc):] if len(_curr_loc) >= len(_prev_loc) else []
        return {"tool_results": _delta, "fallback_locations": _loc_delta}

    def _cert_check_node_delta(self, state: AgentState):
        _before = dict(state) if isinstance(state, dict) else {}
        _after = self._cert_check_node(dict(state))
        _prev = (_before.get("tool_results") or {})
        _curr = (_after.get("tool_results") or {})
        _delta = {}
        if isinstance(_curr, dict):
            for _k, _v in _curr.items():
                if _prev.get(_k) != _v:
                    _delta[_k] = _v
        _prev_loc = list(_before.get("fallback_locations", []) or [])
        _curr_loc = list(_after.get("fallback_locations", []) or [])
        _loc_delta = _curr_loc[len(_prev_loc):] if len(_curr_loc) >= len(_prev_loc) else []
        return {"tool_results": _delta, "fallback_locations": _loc_delta}

    def _domain_check_node_delta(self, state: AgentState):
        _before = dict(state) if isinstance(state, dict) else {}
        _after = self._domain_check_node(dict(state))
        _prev = (_before.get("tool_results") or {})
        _curr = (_after.get("tool_results") or {})
        _delta = {}
        if isinstance(_curr, dict):
            for _k, _v in _curr.items():
                if _prev.get(_k) != _v:
                    _delta[_k] = _v
        _prev_loc = list(_before.get("fallback_locations", []) or [])
        _curr_loc = list(_after.get("fallback_locations", []) or [])
        _loc_delta = _curr_loc[len(_prev_loc):] if len(_curr_loc) >= len(_prev_loc) else []
        return {"tool_results": _delta, "fallback_locations": _loc_delta}

    def _contextual_check_node_delta(self, state: AgentState):
        # contextual は単独実行だが、安全のため delta 化しておく
        _before = dict(state) if isinstance(state, dict) else {}
        _after = self._contextual_check_node(dict(state))
        _prev = (_before.get("tool_results") or {})
        _curr = (_after.get("tool_results") or {})
        _delta = {}
        if isinstance(_curr, dict):
            for _k, _v in _curr.items():
                if _prev.get(_k) != _v:
                    _delta[_k] = _v
        _prev_loc = list(_before.get("fallback_locations", []) or [])
        _curr_loc = list(_after.get("fallback_locations", []) or [])
        _loc_delta = _curr_loc[len(_prev_loc):] if len(_curr_loc) >= len(_prev_loc) else []
        return {"tool_results": _delta, "fallback_locations": _loc_delta}
    # ==== end delta wrappers ====
    # --------------- Public API ---------------
    def evaluate(self, domain: str, ml_probability: float, *, external_data: Optional[Dict[str,Any]] = None) -> Dict[str, Any]:
        """1件評価を実行（Phase2形式の辞書へ整形）"""
        t0 = time.perf_counter()
        if external_data is not None:
            # on-call override
            self.external_data = external_data

        state: AgentState = {
            "domain": domain,
            "ml_probability": float(ml_probability or 0.0),
            "strict_mode": self.strict_mode,
            "current_step": "initial",
            "precheck_hints": {},
            "selected_tools": [],
            "tool_results": {},
            "final_assessment": None,
            "error": None,
            "retry_count": 0,
            "fallback_count": 0,
            "fallback_locations": [],
            "tool_execution_flags": {},
            "next_step": "",
        }

        try:
            if self.graph is not None:
                final_state = self.graph.invoke(state)  # type: ignore
            else:
                # フォールバック: 順次で等価動作
                s = state
                s = self._precheck_node(s)
                s = self._tool_selection_node(s)
                s = self._fanout_dispatcher_node(s)
                s = self._brand_check_node(s)
                s = self._cert_check_node(s)
                s = self._domain_check_node(s)
                s = self._aggregate_node(s)
                if s.get("next_step") == "contextual":
                    s = self._contextual_check_node(s)
                s = self._final_decision_node(s)
                final_state = s

            asmt: PhishingAssessment = final_state.get("final_assessment")  # type: ignore
            tools_used = list(final_state.get("tool_results", {}).keys())
            out = convert_to_phase2_format(
                domain=final_state["domain"],
                ml_probability=final_state["ml_probability"],
                assessment=asmt,
                tools_used=tools_used,
                processing_time=time.perf_counter() - t0,
                success=True,
                phase="phase4_v1.3",
            )
            out["graph_state"] = final_state
            return out
        except Exception as e:
            tb = traceback.format_exc(limit=4)
            err = f"{type(e).__name__}: {e}"
            return convert_to_phase2_format(
                domain=domain, ml_probability=float(ml_probability or 0.0),
                assessment=PhishingAssessment(
                    is_phishing=False, confidence=0.0, risk_level="low",
                    detected_brands=[], risk_factors=[], reasoning=("Graph execution failed; see error/traceback fields for diagnostic details (Phase4 safe fallback).")),
                tools_used=[], processing_time=time.perf_counter() - t0,
                success=False, error=err, error_category="graph_execution",
                traceback=tb, phase="phase4_v1.3"
            )


# ------------------------------
# 簡易テスト
# ------------------------------
def _make_min_external_data() -> Dict[str, Any]:
    """ipynbデータの最小モック（稼働確認用）"""
    return {
        "brand_keywords": ["paypal","mercari","ledger","google","apple"],
        "cert_full_info_map": {
            "paypal-secure-login.info": {"issuer":"Let's Encrypt", "subject":{"CN":"paypal-secure-login.info"}, "san":[ "*.paypal-secure-login.info" ], "valid_days": 60, "is_free_ca": True},
        },
        "dangerous_tlds": ["info","top","xyz","buzz","tk","ml","ga","cf","gq"],
        "legitimate_tlds": ["com","org","net","co.jp","jp"],
        "neutral_tlds": ["io","ai","co","me"],
        "phishing_tld_stats": {"info": 0.9, "tk": 0.8, "com": 0.2},
        "high_risk_words": ["secure","login","wallet","auth","verify"],
        "known_domains": {"paypal.com":"brand"},
    }

def run_all_tests() -> None:
    print("="*76)
    print("Phase 4 (v1.3) LangGraph 状態管理 - テスト")
    print("="*76)

    ext = _make_min_external_data()
    agent = LangGraphPhishingAgent(strict_mode=False, use_llm_selection=True, use_llm_decision=True, external_data=ext)

    # T1: 基本実行
    r1 = agent.evaluate("example.com", 0.33)
    assert r1["success"] is True
    print("✓ T1 基本実行 OK →", r1["ai_risk_level"], f"(conf={r1['ai_confidence']:.2f}) tools={r1['tools_used']}")

    # T2: ML<0.2 → fan-out + contextual 準必須
    r2 = agent.evaluate("mercari.buzz", 0.15)
    assert "brand" in r2["tools_used"] and "cert" in r2["tools_used"] and "domain" in r2["tools_used"]
    if "contextual" in r2["tools_used"]:
        print("✓ T2 contextual 追加 OK")
    else:
        print("ℹ T2 contextual は条件未達")

    # T3: paypal-secure-login.info → E2E
    r3 = agent.evaluate("paypal-secure-login.info", 0.18)
    print("✓ T3 E2E:", r3["ai_risk_level"], f"(conf={r3['ai_confidence']:.2f})", "issues=", r3.get("risk_factors"))

    # T4: SOフック失敗 → フォールバック記録
    gs = r3["graph_state"]
    assert any("tool_selection_llm" in x or "final_decision_llm" in x for x in gs.get("fallback_locations", [])), "SO fallback が記録されていない"
    print("✓ T4 SOフック失敗時のフォールバック記録 OK")

    print("\nすべてのテストが完了しました。")

if __name__ == "__main__":
    run_all_tests()
