# -*- coding: utf-8 -*-
"""
langgraph_module.py — Phase 4 状態管理 (spec latest v1.3, toolexec fix)
=====================================================================
- 目的: precheck → tool_selection → fanout → aggregate → (contextual?) → final の StateGraph
- Step1/Step3 は Structured Output（SO）必須（本実装はフック＋フォールバックを提供）
- 準必須化: 実行ツール数 >= 2 または (ml < 0.2 かつ 実行 >= 1) で contextual_check を追加
- precheck ノードは Phase2 I/F に ipynb データ（TLD集合/統計, brand, high_risk_words,
  KNOWN_DOMAINS, cert_map）をそのまま渡す

依存（同ディレクトリ）:
- agent_foundations.py  (Phase1)
- precheck_module.py    (Phase2 v1.3)
- tools_module.py       (Phase3 v1.3)

仕様: Phase4_v1.3_完全版_ipynb統合.md
"""

# ---------------------------------------------------------------------
# Change history
# - 2026-01-02: Added per-tool timings (tool_timings_ms) and
#              analysis-friendly logs (graph_state_slim + trace_* fields)
#              to make FP/FN postmortems easier.
# - 2026-01-02: Included phase6_rules_fired in graph_state_slim for
# - 2026-01-03: Exported phase6_policy_version / phase6_rules_fired / phase6_gate_* as top-level fields
#              in the evaluate() output so CSV logs can be analyzed without parsing JSON blobs.
#              one-glance policy debugging in downstream CSV logs.
# ---------------------------------------------------------------------

from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
import json, os, re, time, traceback, sys, importlib.util as _iu, types as _types

# Qwen3等が出力する<think>タグを除去するパターン
_THINK_TAG_PATTERN = re.compile(r"<think>.*?</think>", re.DOTALL)

def _strip_think_tags(text: str) -> str:
    """Qwen3等が出力する<think>タグを除去してJSONのみを抽出する。"""
    if not text:
        return text
    cleaned = _THINK_TAG_PATTERN.sub("", text)
    return cleaned.strip()

try:
    from langchain_core.messages import HumanMessage, AIMessage  # type: ignore
except Exception:  # LangChain 未インストール環境でも動くようにする
    HumanMessage = None
    AIMessage = None

__version__ = "1.3.4-phase4-toolexec-fix-2025-11-08"

def module_version() -> str:
    return __version__

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
from phishpkg.agent_foundations import (
    AgentState, ToolSelectionResult, PhishingAssessment,
    PhishingAgentError, ToolExecutionError, GraphExecutionError,
    clip_confidence, get_risk_level, convert_to_phase2_format
)

from phishpkg.precheck_module import generate_precheck_hints

# 1. Brand Tool
from .tools.brand_impersonation_check import brand_impersonation_check
# 2. Certificate Tool
from .tools.certificate_analysis import certificate_analysis
# 3. Short Domain Tool
from .tools.short_domain_analysis import short_domain_analysis
# 4. Contextual Risk Tool
from .tools.contextual_risk_assessment import contextual_risk_assessment

# 5. Phase6 LLM Final Decision (policy adjustments)
from .llm_final_decision import final_decision as phase6_final_decision

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
    # 優先度: 明示引数 → 環境変数 → モジュール隣接 → CWD → /mnt/data
    candidates: List[str] = []
    if explicit: candidates.append(explicit)
    for env in ("NEXTSTEP_CONFIG_JSON","AIA_CONFIG_JSON","CONFIG_JSON"):
        v = os.getenv(env)
        if v: candidates.append(v)
    try:
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
        raise RuntimeError("SO(select_tools) not wired in Phase 4 environment")

    def final_assessment(self, domain: str, ml_probability: float, tool_results: Dict[str,Any]) -> PhishingAssessment:
        raise RuntimeError("SO(final_assessment) not wired in Phase 4 environment")

# ------------------------------------
# エージェント本体（Phase4 v1.3 + tool_execution fix）
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
        external_data: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.strict_mode = strict_mode
        self.use_llm_selection = use_llm_selection
        self.use_llm_decision = use_llm_decision
        self.llm_config = load_llm_config(config_path)
        self.so = _SOClient(self.llm_config)
        self.external_data = external_data or {}
        self.module_version = __version__

        self.graph = self._build_graph() if _HAS_LANGGRAPH else None

    # --------------- Graph 構築 ---------------
    def _build_graph(self):
        g = StateGraph(AgentState)  # type: ignore
        g.add_node("precheck", self._precheck_node)
        g.add_node("tool_selection", self._tool_selection_node)
        g.add_node("fanout_dispatcher", self._fanout_dispatcher_node)
        g.add_node("tool_execution", self._tool_execution_node)  # ← fix: class method
        g.add_node("aggregate", self._aggregate_node)
        g.add_node("contextual_check", self._contextual_check_node_delta)
        g.add_node("final_decision", self._final_decision_node)

        g.add_edge(START, "precheck")          # type: ignore
        g.add_edge("precheck", "tool_selection")
        g.add_edge("tool_selection", "fanout_dispatcher")
        g.add_edge("fanout_dispatcher", "tool_execution")
        g.add_edge("tool_execution", "aggregate")
        g.add_conditional_edges(
            "aggregate",
            self._route_from_aggregate,
            {"contextual": "contextual_check", "final": "final_decision"},
        )
        g.add_edge("contextual_check", "final_decision")
        g.add_edge("final_decision", END)       # type: ignore
        return g.compile()

    # --------------- Debug: message channel ---------------
    def _append_debug_message(self, state: AgentState, content: str, *, role: str = "system") -> None:
        """LangGraph の stream から `messages[-1].pretty_print()` したい用のメッセージを積む。"""
        msg_obj: Any
        try:
            if HumanMessage is not None and AIMessage is not None:
                if role == "ai":
                    msg_obj = AIMessage(content=content)
                else:
                    msg_obj = HumanMessage(content=content)
            else:
                msg_obj = {"role": role, "content": content}
        except Exception:
            msg_obj = {"role": role, "content": content}
        msgs = list(state.get("messages", []) or [])
        msgs.append(msg_obj)
        state["messages"] = msgs


    # --------------- Util ---------------
    def _update_fallback(self, state: AgentState, where: str, error: Optional[str] = None) -> None:
        state["fallback_count"] = state.get("fallback_count", 0) + 1
        locs = list(state.get("fallback_locations", []) or [])
        locs.append(where if not error else f"{where}:{error}")
        state["fallback_locations"] = locs

    # --------------- Nodes ---------------
    def _precheck_node(self, state: AgentState) -> AgentState:
        """precheck: Phase2 I/F に ipynb データを渡す"""
        state["current_step"] = "precheck"

        dbg = getattr(self, "_append_debug_message", None)
        if callable(dbg):
            try:
                dbg(
                    state,
                    f"[precheck] start domain={state.get('domain')} ml={state.get('ml_probability')}",
                    role="system",
                )
            except Exception:
                pass

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
            if isinstance(hints, dict) and hints.get("_fallback"):
                self._update_fallback(state, "precheck_fallback")

            if callable(dbg):
                try:
                    dbg(
                        state,
                        "[precheck] "
                        f"ml_category={hints.get('ml_category')} "
                        f"tld_category={hints.get('tld_category')} "
                        f"quick_risk={hints.get('quick_risk')}",
                        role="ai",
                    )
                except Exception:
                    pass

        except Exception as e:
            if self.strict_mode:
                raise PhishingAgentError(f"precheck failed: {e}")
            state["precheck_hints"] = {}
            self._update_fallback(state, "precheck_exception", str(e))

            if callable(dbg):
                try:
                    dbg(
                        state,
                        f"[precheck] exception={type(e).__name__}: {e}",
                        role="ai",
                    )
                except Exception:
                    pass

        return state

    def _tool_selection_node(self, state: AgentState) -> AgentState:
        """Step1: SO必須（Phase5で本接続）。ここではフック + フォールバックを実装。"""
        state["current_step"] = "tool_selection"

        ml = float(state.get("ml_probability", 0.0) or 0.0)
        state["llm_used_selection"] = False
        state["llm_selection_error"] = None

        dbg = getattr(self, "_append_debug_message", None)
        if callable(dbg):
            try:
                dbg(
                    state,
                    "[tool_selection] start "
                    f"ml={ml} use_llm_selection={self.use_llm_selection} "
                    f"so_available={getattr(self.so, 'available', False)}",
                    role="system",
                )
            except Exception:
                pass

        try:
            if self.use_llm_selection and self.so.available:
                sel = self.so.select_tools(
                    state["domain"],
                    ml,
                    state.get("precheck_hints", {}),
                )
                selected_tools = list(sel.selected_tools or [])
                state["llm_used_selection"] = True

                if callable(dbg):
                    try:
                        dbg(
                            state,
                            f"[tool_selection] LLM selected_tools={selected_tools}",
                            role="ai",
                        )
                    except Exception:
                        pass
            else:
                raise RuntimeError("SO(select_tools) unavailable")
        except Exception as e:
            state["llm_used_selection"] = False
            state["llm_selection_error"] = f"{type(e).__name__}: {e}"

            # Step1 selection failure must not abort evaluation; continue with base tools (3 tools).
            selected_tools = [
                "brand_impersonation_check",
                "certificate_analysis",
                "short_domain_analysis",
            ]
            self._update_fallback(state, "tool_selection_llm", str(e))

            if callable(dbg):
                try:
                    dbg(
                        state,
                        "[tool_selection] fallback selected_tools="
                        f"{selected_tools} reason={e}",
                        role="ai",
                    )
                except Exception:
                    pass

        state["selected_tools"] = selected_tools
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

    def _tool_execution_node(self, state: AgentState) -> dict:
        """選択されたツール（brand/cert/domain）を順次実行し、差分 {"tool_results": {...}} のみ返す。"""
        sel = state.get("selected_tools", []) or []
        flags = {
            "brand": ("brand_impersonation_check" in sel),
            "cert": ("certificate_analysis" in sel),
            "domain": ("short_domain_analysis" in sel),
        }
        ed = self.external_data or {}
        domain = state["domain"]
        ml = float(state.get("ml_probability", 0.0) or 0.0)
        precheck = state.get("precheck_hints", {}) or {}

        updates: Dict[str, Any] = {}
        tr: Dict[str, Any] = {}
        tool_timings_ms: Dict[str, int] = {}

        dbg = getattr(self, "_append_debug_message", None)
        base_msgs = list(state.get("messages", []) or [])
        base_len = len(base_msgs)
        base_msgs = list(state.get("messages", []) or [])
        base_len = len(base_msgs)
        if callable(dbg):
            try:
                dbg(
                    state,
                    f"[tool_execution] start selected_tools={sel}",
                    role="system",
                )
            except Exception:
                pass

        if flags["brand"]:
            _t0 = time.perf_counter()
            # BrandTool は「必ず何かしらのデータを返す」方針に変更
            primary_error: Optional[str] = None
            data: Dict[str, Any] = {}

            try:
                # 1st: LLM 有りで実行（strict_mode は常に False に固定）
                r = brand_impersonation_check(
                    domain=domain,
                    brand_keywords=ed.get("brand_keywords", []),
                    precheck_hints=precheck,
                    ml_probability=ml,
                    strict_mode=False,
                    use_llm=True,
                )

                if isinstance(r, dict) and r.get("success") is False:
                    # safe_tool_wrapper がエラーを握っているケース
                    primary_error = str(r.get("error") or "")
                    # 2nd: LLM を切ってルールのみでもう一度
                    r2 = brand_impersonation_check(
                        domain=domain,
                        brand_keywords=ed.get("brand_keywords", []),
                        precheck_hints=precheck,
                        ml_probability=ml,
                        strict_mode=False,
                        use_llm=False,
                    )
                    data = (r2.get("data") or {}) if isinstance(r2, dict) else {}
                else:
                    data = (r.get("data") or {}) if isinstance(r, dict) else {}

            except Exception as e:
                primary_error = str(e)
                # BrandTool 内部で想定外例外が飛んだ場合も、LLM なしルールのみで最後まで粘る
                try:
                    r2 = brand_impersonation_check(
                        domain=domain,
                        brand_keywords=ed.get("brand_keywords", []),
                        precheck_hints=precheck,
                        ml_probability=ml,
                        strict_mode=False,
                        use_llm=False,
                    )
                    data = (r2.get("data") or {}) if isinstance(r2, dict) else {}
                except Exception as e2:
                    # それでもダメなときだけ、中立な結果を合成して返す
                    data = {
                        "tool_name": "brand_impersonation_check",
                        "detected_issues": [],
                        "risk_score": 0.0,
                        "details": {
                            "error": f"BrandTool failed (primary={primary_error}, fallback={e2})",
                        },
                        "reasoning": "BrandTool failed; returned neutral result.",
                    }

            # どのパスでも _fallback は一切セットしない
            details = data.setdefault("details", {})
            if primary_error and "error" not in details:
                details["error"] = primary_error

            tr["brand"] = data
            try:
                tool_timings_ms["brand"] = int((time.perf_counter() - _t0) * 1000)
            except Exception:
                pass

            if callable(dbg):
                try:
                    dbg(
                        state,
                        "[tool_execution] brand "
                        f"risk={data.get('risk_score')} "
                        f"issues={data.get('detected_issues')}",
                        role="ai",
                    )
                except Exception:
                    pass


        if flags["cert"]:
            _t0 = time.perf_counter()
            try:
                r = certificate_analysis(
                    domain=domain,
                    cert_full_info_map=ed.get("cert_full_info_map", {}),
                    strict_mode=self.strict_mode,
                )
                data = (r.get("data") or {}) if isinstance(r, dict) else {}
                tr["cert"] = data
                try:
                    tool_timings_ms["cert"] = int((time.perf_counter() - _t0) * 1000)
                except Exception:
                    pass

                if callable(dbg):
                    try:
                        dbg(
                            state,
                            "[tool_execution] cert "
                            f"risk={data.get('risk_score')} "
                            f"issues={data.get('detected_issues')}",
                            role="ai",
                        )
                    except Exception:
                        pass
            except Exception as e:
                if self.strict_mode:
                    raise
                tr["cert"] = {
                    "detected_issues": [],
                    "risk_score": 0.0,
                    "_fallback": True,
                }
                self._update_fallback(state, "tool_cert_exception", str(e))

                try:
                    tool_timings_ms["cert"] = int((time.perf_counter() - _t0) * 1000)
                except Exception:
                    pass

                if callable(dbg):
                    try:
                        dbg(
                            state,
                            f"[tool_execution] cert exception={type(e).__name__}: {e}",
                            role="ai",
                        )
                    except Exception:
                        pass

        if flags["domain"]:
            _t0 = time.perf_counter()
            try:
                r = short_domain_analysis(
                    domain=domain,
                    dangerous_tlds=ed.get("dangerous_tlds", []),
                    legitimate_tlds=ed.get("legitimate_tlds", []),
                    neutral_tlds=ed.get("neutral_tlds", []),
                    phishing_tld_stats=ed.get("phishing_tld_stats", {}),
                    strict_mode=self.strict_mode,
                )
                data = (r.get("data") or {}) if isinstance(r, dict) else {}
                tr["domain"] = data
                try:
                    tool_timings_ms["domain"] = int((time.perf_counter() - _t0) * 1000)
                except Exception:
                    pass

                if callable(dbg):
                    try:
                        dbg(
                            state,
                            "[tool_execution] domain "
                            f"risk={data.get('risk_score')} "
                            f"issues={data.get('detected_issues')}",
                            role="ai",
                        )
                    except Exception:
                        pass
            except Exception as e:
                if self.strict_mode:
                    raise
                tr["domain"] = {
                    "detected_issues": [],
                    "risk_score": 0.0,
                    "_fallback": True,
                }
                self._update_fallback(state, "tool_domain_exception", str(e))

                try:
                    tool_timings_ms["domain"] = int((time.perf_counter() - _t0) * 1000)
                except Exception:
                    pass

                if callable(dbg):
                    try:
                        dbg(
                            state,
                            f"[tool_execution] domain exception={type(e).__name__}: {e}",
                            role="ai",
                        )
                    except Exception:
                        pass

        if tr:
            updates["tool_results"] = tr
        if tool_timings_ms:
            updates["tool_timings_ms"] = tool_timings_ms

        # このノードで追加されたデバッグメッセージ差分のみを StateGraph に返す
        if callable(dbg):
            try:
                dbg(
                    state,
                    f"[tool_execution] done tools={list(tr.keys())}",
                    role="ai",
                )
            except Exception:
                pass

        all_msgs = list(state.get("messages", []) or [])
        if len(all_msgs) > base_len:
            updates['messages'] = all_msgs[base_len:]

        return updates

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
            state["tool_results"]["contextual_risk_assessment"] = (res.get("data") or {})
        except Exception as e:
            if self.strict_mode:
                raise
            if "tool_results" not in state:
                state["tool_results"] = {}
            state["tool_results"]["contextual_risk_assessment"] = {"detected_issues": [], "risk_score": 0.0, "_fallback": True}
            self._update_fallback(state, "tool_contextual_exception", str(e))
        return state

    # concurrency-safe delta wrapper（graphではこちらを使う）
    def _contextual_check_node_delta(self, state: AgentState):
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

    def _final_decision_node(self, state: AgentState) -> AgentState:
        """Step3: SO必須。Phase6で本接続。ここではフォールバックを規定どおり実装。"""
        ml = float(state.get("ml_probability", 0.0) or 0.0)
        try:
            if self.use_llm_decision and self.so.available:
                # Phase6: final_decision を使用（policy adjustments 適用）
                llm = _phase5__init_llm(self.so.cfg)
                if llm is None:
                    raise RuntimeError("LLM not available for phase6_final_decision")
                asmt = phase6_final_decision(
                    llm=llm,
                    domain=state["domain"],
                    ml_probability=ml,
                    tool_results=state.get("tool_results", {}),
                    graph_state=state,  # precheck_hints を含む
                    strict_mode=self.strict_mode,
                )
                state["final_assessment"] = asmt
                state["current_step"] = "completed"
                return state
            else:
                raise RuntimeError("SO(final_assessment) unavailable")
        except Exception as e:
            if self.strict_mode and self.use_llm_decision:
                raise PhishingAgentError(f"SO(final_assessment) failed: {e}")
            tr = state.get("tool_results", {}) or {}
            cxs = float((tr.get("contextual_risk_assessment") or {}).get("risk_score", 0.0) or 0.0)
            if cxs <= 0.0:
                cxs = float((tr.get("contextual") or {}).get("risk_score", 0.0) or 0.0)
            if cxs <= 0.0:
                parts = [float((tr.get(k) or {}).get("risk_score", 0.0) or 0.0) for k in ("brand","cert","domain")]
                cxs = max(parts) if parts else ml
            is_ph = bool(cxs >= 0.5)
            conf = clip_confidence(max(ml, cxs))
            # get_risk_level signature: allow is_phishing param if available; fallback to conf-only
            try:
                risk_level = get_risk_level(confidence=conf, is_phishing=is_ph)  # type: ignore
            except TypeError:
                risk_level = get_risk_level(conf)  # type: ignore
            asmt = PhishingAssessment(
                is_phishing=is_ph,
                confidence=conf,
                risk_level=risk_level,
                detected_brands=list((tr.get("brand") or {}).get("details", {}).get("detected_brands", []) or []),
                risk_factors=list((tr.get("contextual_risk_assessment") or {}).get("detected_issues", []) or []),
                reasoning="SO(final_decision) fallback: contextual/aggregate riskを使用",
            )
            self._update_fallback(state, "final_decision_llm", str(e))
            state["final_assessment"] = asmt
            state["current_step"] = "completed"
            return state

    # --------------- Public API ---------------
    def evaluate(self, domain: str, ml_probability: float, *, external_data: Optional[Dict[str,Any]] = None) -> Dict[str, Any]:
        """1件評価を実行（Phase2形式の辞書へ整形）"""
        t0 = time.perf_counter()
        if external_data is not None:
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
            # LangGraph debug / LLM trace
            "messages": [],
            "debug_llm_final": {},
            "llm_used_selection": None,
            "llm_selection_error": None,
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
                # tool_execution と等価
                delta = self._tool_execution_node(s)
                for k, v in delta.items():
                    if k == "tool_results":
                        s.setdefault("tool_results", {}).update(v)
                    else:
                        s[k] = v
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
            out["module_version"] = __version__

            # ------------------------------------------------------------------
            # Log/analysis-friendly trace (JSON serializable & flat columns)
            # NOTE(2026-01-02): 次回の FP/FN 解析を "超楽" にするため、
            #  - graph_state_slim: 重要フィールドだけ抜き出した JSON 互換 dict
            #  - graph_state_slim_json: その JSON 文字列
            #  - trace_*: CSV でも扱えるフラット列
            # を常に付与する（既存キーは保持）。
            # ------------------------------------------------------------------
            try:
                def _dumps(obj: Any) -> str:
                    return json.dumps(obj, ensure_ascii=False, sort_keys=True, default=str)

                pre = (final_state.get("precheck_hints") or {})
                tr = (final_state.get("tool_results") or {})
                ctx = (tr.get("contextual_risk_assessment") or {})
                ctx_details = (ctx.get("details") or {}) if isinstance(ctx, dict) else {}
                score_components = (ctx_details.get("score_components") or {}) if isinstance(ctx_details, dict) else {}

                fa = final_state.get("final_assessment")
                if hasattr(fa, "model_dump"):
                    fa_json = fa.model_dump()  # type: ignore
                elif isinstance(fa, dict):
                    fa_json = fa
                else:
                    fa_json = str(fa) if fa is not None else None

                slim = {
                    "domain": final_state.get("domain"),
                    "ml_probability": final_state.get("ml_probability"),
                    "precheck_hints": pre,
                    "selected_tools": final_state.get("selected_tools"),
                    "tool_execution_flags": final_state.get("tool_execution_flags"),
                    "tool_timings_ms": final_state.get("tool_timings_ms"),
                    "tool_results": tr,
                    "fallback_info": final_state.get("fallback_info"),
                    "phase6_policy_version": final_state.get("phase6_policy_version"),
                    "phase6_rules_fired": final_state.get("phase6_rules_fired"),
                    "decision_trace": final_state.get("decision_trace"),
                    "debug_llm_final": final_state.get("debug_llm_final"),
                    "llm_used_selection": final_state.get("llm_used_selection"),
                    "llm_used_final": final_state.get("llm_used_final"),
                    "final_assessment": fa_json,
                }

                out["graph_state_slim"] = slim
                out["graph_state_slim_json"] = _dumps(slim)

                # ---- Phase6 fields (CSV-friendly top-level) ----
                out["phase6_policy_version"] = final_state.get("phase6_policy_version")
                out["phase6_rules_fired"] = list(final_state.get("phase6_rules_fired") or [])
                try:
                    out["phase6_rules_fired_str"] = "|".join([str(x) for x in (out.get("phase6_rules_fired") or [])])
                except Exception:
                    out["phase6_rules_fired_str"] = ""
                gate = final_state.get("phase6_gate")
                out["phase6_gate"] = gate
                out["phase6_gate_blocked"] = bool(isinstance(gate, dict) and gate.get("rule") == "POST_LLM_FLIP_GATE")
                out["phase6_gate_threshold"] = (gate.get("threshold") if isinstance(gate, dict) else None)
                out["phase6_gate_ml"] = (gate.get("ml") if isinstance(gate, dict) else None)
                out["phase6_gate_tld_category"] = (gate.get("tld_category") if isinstance(gate, dict) else None)

                # ---- Flat trace columns (CSV-friendly) ----
                stats = (pre.get("stats") or {}) if isinstance(pre, dict) else {}

                b = (tr.get("brand") or {})
                c = (tr.get("cert") or {})
                d = (tr.get("domain") or {})

                b_det = ((b.get("details") or {}) if isinstance(b, dict) else {})
                c_det = ((c.get("details") or {}) if isinstance(c, dict) else {})
                d_det = ((d.get("details") or {}) if isinstance(d, dict) else {})

                paradox = (ctx_details.get("paradox") or {}) if isinstance(ctx_details, dict) else {}

                out.update({
                    "trace_schema_version": "v1",

                    # engine trace
                    "trace_llm_used_selection": final_state.get("llm_used_selection"),
                    "trace_llm_used_final": final_state.get("llm_used_final"),
                    "trace_fallback_count": int(final_state.get("fallback_count") or 0),
                    "trace_fallback_locations_json": _dumps(final_state.get("fallback_locations") or []),

                    # precheck
                    "trace_precheck_ml_category": str(pre.get("ml_category") or ""),
                    "trace_precheck_tld_category": str(pre.get("tld_category") or ""),
                    "trace_precheck_domain_length_category": str(pre.get("domain_length_category") or ""),
                    "trace_precheck_brand_detected": bool(pre.get("brand_detected") or False),
                    "trace_precheck_potential_brands_count": int(len(pre.get("potential_brands") or [])),
                    "trace_precheck_high_risk_hits": int(stats.get("high_risk_hits") or 0),
                    "trace_precheck_phishing_tld_weight": float(stats.get("phishing_tld_weight") or 0.0),
                    "trace_precheck_quick_risk": float(pre.get("quick_risk") or 0.0),

                    # tool selection/execution
                    "trace_selected_tools_json": _dumps(final_state.get("selected_tools") or []),
                    "trace_tool_timings_ms_json": _dumps(final_state.get("tool_timings_ms") or {}),

                    # brand
                    "trace_brand_risk_score": float(b.get("risk_score") or 0.0),
                    "trace_brand_issues_json": _dumps(b.get("detected_issues") or []),
                    "trace_brand_detected_brands_json": _dumps(b_det.get("detected_brands") or []),

                    # cert
                    "trace_cert_risk_score": float(c.get("risk_score") or 0.0),
                    "trace_cert_issues_json": _dumps(c.get("detected_issues") or []),
                    "trace_cert_issuer": str(c_det.get("issuer") or ""),
                    "trace_cert_is_free_ca": bool(c_det.get("is_free_ca") or False),
                    "trace_cert_has_org": bool(c_det.get("has_org") or False),
                    "trace_cert_is_self_signed": bool(c_det.get("is_self_signed") or False),
                    "trace_cert_is_wildcard": bool(c_det.get("is_wildcard") or False),

                    # domain
                    "trace_domain_risk_score": float(d.get("risk_score") or 0.0),
                    "trace_domain_issues_json": _dumps(d.get("detected_issues") or []),
                    "trace_domain_tld_category": str(d_det.get("tld_category") or ""),
                    "trace_domain_length_category": str(d_det.get("domain_length_category") or ""),
                    "trace_domain_entropy": float(d_det.get("entropy") or 0.0),
                    "trace_domain_label_count": int(d_det.get("label_count") or 0),

                    # contextual
                    "trace_ctx_risk_score": float(ctx.get("risk_score") or 0.0) if isinstance(ctx, dict) else 0.0,
                    "trace_ctx_issues_json": _dumps(ctx.get("detected_issues") or []) if isinstance(ctx, dict) else "[]",
                    "trace_ctx_is_ml_paradox": bool(paradox.get("is_paradox_strong") or False),
                    "trace_ctx_is_ml_paradox_weak": bool(paradox.get("is_paradox_weak") or False),
                    "trace_ctx_risk_signal_count": int(paradox.get("risk_signal_count") or 0),
                    "trace_ctx_score_components_json": _dumps(score_components),

                    # phase6/policy trace
                    "trace_phase6_policy_version": str(final_state.get("phase6_policy_version") or ""),
                    "trace_phase6_rules_fired_json": _dumps(final_state.get("phase6_rules_fired") or []),
                    "trace_decision_trace_json": _dumps(final_state.get("decision_trace") or []),
                    "trace_debug_llm_final_json": _dumps(final_state.get("debug_llm_final") or {}),
                })
            except Exception as _trace_e:
                out["trace_error"] = f"{type(_trace_e).__name__}: {_trace_e}"

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



# ==============================
# Phase5 Add-on (append-only)
# - LLM Structured Output wiring for Step1 / Step3
# - No deletions/overwrites of Phase4 code above
# - Requires: langchain-openai (ChatOpenAI) or compatible
# ==============================
from typing import List, Literal, Dict, Any, Optional
try:
    # pydantic v1 compatibility shims for type hints
    from pydantic import BaseModel, Field, constr, confloat
except Exception:  # pragma: no cover
    from pydantic.v1 import BaseModel, Field, constr, confloat  # type: ignore

# ---- SO Schemas (as provided in implementer memo) ----
class ToolSelectionSO(BaseModel):
    """
    Step1 tool selection (Structured Output).
    NOTE: Schema is intentionally tiny (no free-form long text) to prevent length-truncation
    that can break JSON parsing in provider-native structured output.
    """
    selected_tools: List[str] = Field(default_factory=list)

class FinalAssessmentSO(BaseModel):
    is_phishing: bool
    confidence: confloat(ge=0.0, le=1.0)
    risk_level: Literal["low","medium","medium-high","high","critical"]
    detected_brands: List[str] = Field(default_factory=list)
    risk_factors: List[str] = Field(default_factory=list)
    reasoning: constr(min_length=50)

_ALLOWED_TOOLS_SO = {"brand_impersonation_check","certificate_analysis","short_domain_analysis"}

def _phase5__init_llm(cfg: "LLMConfig"):
    if not (cfg and cfg.enabled and cfg.base_url):
        return None
    try:
        from langchain_openai import ChatOpenAI  # type: ignore
        # 思考モード無効化後、JSONレスポンスに十分なトークン数を確保
        # Phase6プロンプトが長いため、余裕を持って2048トークン
        max_tokens = 2048

        return ChatOpenAI(
            model=cfg.model or "gpt-4o-mini",
            base_url=cfg.base_url,
            api_key=cfg.api_key or "EMPTY",
            temperature=getattr(cfg, "temperature", 0.1) or 0.1,
            max_tokens=max_tokens,
            # Qwen3 thinking モードを無効化
            # vLLM OpenAI互換APIではextra_bodyで直接渡す
            extra_body={"chat_template_kwargs": {"enable_thinking": False}},
        )
    except Exception as e:  # pragma: no cover
        # LLM初期化失敗は上位でフォールバックさせる
        raise RuntimeError(f"LLM init failed: {e}")

def _phase5__enforce_policy(ml: float, tools: List[str]) -> List[str]:
    """Step1ポリシー: ml<0.2→3、0.2<=ml<0.5→3、>=0.5→2（Allowedのみ・重複排除）"""
    uniq = [t for i,t in enumerate(tools) if t in _ALLOWED_TOOLS_SO and t not in tools[:i]]
    if ml < 0.2 or ml < 0.5:
        # 0.0–0.5 は 3 ツール（Allowedは最大3）
        need = 3
    else:
        need = 2
    # パディング（brand→cert→domain の優先順）
    pad = ["brand_impersonation_check","certificate_analysis","short_domain_analysis"]
    out = uniq[:need]
    for t in pad:
        if len(out) >= need: break
        if t not in out: out.append(t)
    return out[:need]

# --- Extend existing _SOClient methods WITHOUT modifying the class signature ---

if "_SOClient" in globals():
    _OldSOClient = _SOClient  # keep original name

    class _SOClient(_OldSOClient):  # type: ignore
        """Phase5 SO-wired client (append-only override)."""
        def select_tools(self, domain: str, ml_probability: float, precheck_hints: Dict[str,Any]) -> "ToolSelectionResult":
            # llm 無効時は上位でフォールバック。ここは llm.enabled=True 想定で試行。
            llm = _phase5__init_llm(self.cfg)
            if llm is None:
                raise RuntimeError("LLM not available")

            pre = precheck_hints or {}

            # Keep prompts compact; schema has NO long free-form text fields.
            sys_text = (
                "Select security analysis tools for the given domain. Return ONLY ToolSelectionSO. "
                "Allowed tools: brand_impersonation_check, certificate_analysis, short_domain_analysis. "
                "Policy: ml<0.5 => 3 tools; ml>=0.5 => exactly 2 tools."
            )

            # Minimal precheck summary (keep small)
            potential_brands = list(pre.get('potential_brands', []) or [])[:3]
            high_risk_words = list(pre.get('high_risk_words', []) or [])[:3]
            known_flag = bool((pre.get('known_domain_info') or {}))
            quick_risk = pre.get('quick_risk')

            # Qwen3の思考モードを無効化するために /no_think プレフィックスを追加
            user_text = (
                f"/no_think domain: {domain}\n"
                f"ml_probability: {ml_probability:.6f}\n"
                f"tld_category: {pre.get('tld_category')}\n"
                f"potential_brands: {potential_brands}\n"
                f"high_risk_words: {high_risk_words}\n"
                f"known: {known_flag}\n"
                f"quick_risk: {quick_risk}\n"
            )

            # Hard cap tokens for Step1 output (stability against runaway generations).
            try:
                llm_sel = llm.bind(max_tokens=96, temperature=0)
            except Exception:
                llm_sel = llm

            errors = []
            for method in ('json_schema', 'function_calling', 'json_mode'):
                try:
                    chain = llm_sel.with_structured_output(ToolSelectionSO, method=method, include_raw=False)  # type: ignore
                    resp = chain.invoke([{'role':'system','content':sys_text}, {'role':'user','content':user_text}])  # type: ignore
                    so = resp.get('parsed') if isinstance(resp, dict) and 'parsed' in resp else resp

                    raw_tools = list(getattr(so, 'selected_tools', []) or [])
                    # Filter to allowed tools only (LLM may output extras when provider doesn't enforce schema strictly)
                    raw_tools = [t for t in raw_tools if t in _ALLOWED_TOOLS_SO]

                    tools = _phase5__enforce_policy(float(ml_probability or 0.0), raw_tools)

                    # Generate compact reasoning locally (avoid putting free-form text in schema)
                    reasoning = f"ToolSelection: ml={ml_probability:.3f} tld={pre.get('tld_category')} brands={potential_brands} known={known_flag} quick_risk={quick_risk}"
                    reasoning = ' '.join(str(reasoning).split())
                    if len(reasoning) > 480:
                        reasoning = reasoning[:480] + '...'

                    return ToolSelectionResult(selected_tools=tools, reasoning=reasoning, confidence=0.75)
                except Exception as e:
                    errors.append(f"{method}={type(e).__name__}:{e}")
                    continue

            # フォールバック: 生のLLM呼び出し + <think>タグ除去 + JSON手動パース
            try:
                raw_response = llm_sel.invoke([{'role':'system','content':sys_text}, {'role':'user','content':user_text}])
                raw_text = raw_response.content if hasattr(raw_response, "content") else str(raw_response)
                cleaned_text = _strip_think_tags(raw_text)

                json_start = cleaned_text.find("{")
                json_end = cleaned_text.rfind("}") + 1
                if json_start >= 0 and json_end > json_start:
                    json_str = cleaned_text[json_start:json_end]
                    parsed = json.loads(json_str)
                    raw_tools = list(parsed.get('selected_tools', []) or [])
                    raw_tools = [t for t in raw_tools if t in _ALLOWED_TOOLS_SO]
                    tools = _phase5__enforce_policy(float(ml_probability or 0.0), raw_tools)
                    reasoning = f"ToolSelection(fallback): ml={ml_probability:.3f} tld={pre.get('tld_category')}"
                    return ToolSelectionResult(selected_tools=tools, reasoning=reasoning, confidence=0.70)
            except Exception as e2:
                errors.append(f"fallback={type(e2).__name__}:{e2}")

            raise RuntimeError('SO(select_tools) failed: ' + ' | '.join(errors))
        def final_assessment(self, domain: str, ml_probability: float, tool_results: Dict[str,Any]) -> "PhishingAssessment":
            llm = _phase5__init_llm(self.cfg)
            if llm is None:
                raise RuntimeError("LLM not available")

            # リスクスコアの要約（contextualを強調）
            tr = tool_results or {}
            ctx = tr.get("contextual_risk_assessment") or {}
            cx = float(ctx.get("risk_score", 0.0) or 0.0)
            agg = max([float((tr.get(k) or {}).get("risk_score", 0.0) or 0.0) for k in ("brand","cert","domain")] + [0.0])
            baseline = max(cx, agg, float(ml_probability or 0.0))

            sys_text = (
                "You are the final assessor (Step3). Return output as FinalAssessmentSO. "
                "Use contextual_risk_assessment.risk_score as a strong signal when available. "
                "IMPORTANT: ctx_score>=0.5 MUST imply is_phishing=true, but ctx_score<0.5 does NOT imply safe. "
                "Do NOT set is_phishing=true based on ml_probability alone; if you mark phishing, include at least one non-ML risk_factors from tool outputs. "
                "Ensure confidence is in [0,1] and reasoning length>=50."
            )
            # Qwen3の思考モードを無効化するために /no_think プレフィックスを追加
            user_text = (
                f"/no_think domain: {domain}\n"
                f"ml_probability: {ml_probability:.6f}\n"
                f"baseline_risk: {baseline:.6f}\n"
                f"tool_results.keys: {list(tr.keys())}\n"
                f"contextual_risk_assessment: {ctx}\n"
                "Output: FinalAssessmentSO"
            )

            so = None
            errors = []

            # 方法1: with_structured_output を試行
            try:
                chain = llm.with_structured_output(FinalAssessmentSO)  # type: ignore
                so = chain.invoke([{"role":"system","content":sys_text},{"role":"user","content":user_text}])  # type: ignore
            except Exception as e1:
                errors.append(f"so={type(e1).__name__}:{e1}")

                # 方法2: 生のLLM呼び出し + <think>タグ除去 + JSON手動パース
                try:
                    raw_response = llm.invoke([{"role":"system","content":sys_text},{"role":"user","content":user_text}])
                    raw_text = raw_response.content if hasattr(raw_response, "content") else str(raw_response)
                    cleaned_text = _strip_think_tags(raw_text)

                    json_start = cleaned_text.find("{")
                    json_end = cleaned_text.rfind("}") + 1
                    if json_start >= 0 and json_end > json_start:
                        json_str = cleaned_text[json_start:json_end]
                        parsed = json.loads(json_str)
                        so = FinalAssessmentSO(**parsed)
                except Exception as e2:
                    errors.append(f"fallback={type(e2).__name__}:{e2}")

            if so is None:
                raise RuntimeError('SO(final_assessment) failed: ' + ' | '.join(errors))

            # 信頼度・レンジ再検証
            conf = float(so.confidence)
            conf = conf if 0.0 <= conf <= 1.0 else (baseline if 0.0 <= baseline <= 1.0 else 0.5)
            try:
                risk_level = get_risk_level(confidence=conf, is_phishing=bool(so.is_phishing))  # type: ignore
            except TypeError:
                risk_level = get_risk_level(conf)  # type: ignore

            return PhishingAssessment(
                is_phishing=bool(so.is_phishing),
                confidence=clip_confidence(conf),
                risk_level=str(so.risk_level),
                detected_brands=list(so.detected_brands or []),
                risk_factors=list(so.risk_factors or []),
                reasoning=str(so.reasoning),
            )
