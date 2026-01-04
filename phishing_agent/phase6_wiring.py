# -*- coding: utf-8 -*-
"""
phase6_wiring.py — Phase6 最終判定ノードの配線ユーティリティ
---------------------------------------------------------------
- 目的: 既存 LangGraphPhishingAgent の「final_decision」ノードを Phase6 実装に差し替え
- ポリシ: 既存 I/O 契約・Strict/Fallback 挙動を壊さない（非破壊のモンキーパッチ）
"""
from __future__ import annotations

import os
from typing import Any, Dict, Optional

def _compat_config_path() -> Optional[str]:
    # _compat/config.json を最優先
    for cand in ("./_compat/config.json", "/mnt/data/_compat/config.json"):
        if os.path.isfile(cand):
            return os.path.abspath(cand)
    return None

def _ensure_config_env(prefer_compat: bool = True) -> Optional[str]:
    path = None
    if prefer_compat:
        path = _compat_config_path()
    if path and not os.getenv("CONFIG_JSON"):
        os.environ["CONFIG_JSON"] = path
    return os.getenv("CONFIG_JSON") or path

def _load_cfg():
    # _compat のローダがある場合はそれを利用
    try:
        from _compat.paths import load_config  # shim
        return load_config(os.getenv("CONFIG_JSON"), strict=False)
    except Exception:
        # 最小フォールバック（config.json を探す）
        import json
        for p in (os.getenv("CONFIG_JSON"), "./config.json", "/mnt/data/config.json"):
            if p and os.path.isfile(p):
                try:
                    return json.load(open(p, "r", encoding="utf-8"))
                except Exception:
                    pass
        return {"llm": {"enabled": False}}

def _build_llm_from_cfg(cfg: Dict[str, Any]):
    """OpenAI互換 Chat クライアントの生成（with_structured_output が必要）"""
    llm_cfg = (cfg or {}).get("llm", {}) or {}
    enabled = bool(llm_cfg.get("enabled", False))
    base_url = llm_cfg.get("base_url") or llm_cfg.get("vllm_base_url") or llm_cfg.get("ollama_base_url")
    model = llm_cfg.get("model") or llm_cfg.get("vllm_model") or llm_cfg.get("ollama_model") or "gpt-4o-mini"
    if not (enabled and base_url):
        return None
    # API Key は空不可の実装があるため "EMPTY" を許容
    api_key = llm_cfg.get("api_key") or os.getenv("OPENAI_API_KEY") or "EMPTY"
    try:
        from langchain_openai import ChatOpenAI  # type: ignore
        return ChatOpenAI(model=model, base_url=base_url, api_key=api_key, temperature=float(llm_cfg.get("temperature", 0.1) or 0.1))
    except Exception as e:  # pragma: no cover
        raise RuntimeError(f"LLM init failed: {e}")

def wire_phase6(*, prefer_compat: bool = True, fake_llm: bool = False):
    """
    Phase6 の最終判定実装を LangGraphPhishingAgent に結線する。
    - prefer_compat=True: _compat/config.json を CONFIG_JSON に注入
    - fake_llm=True: テスト用ダミー LLM（構造化出力のスタブ）を使用
    """
    _ensure_config_env(prefer_compat=prefer_compat)

    # LangGraph エージェントと Phase6 実装を import
    import importlib
    L4 = importlib.import_module("phishing_agent.langgraph_module")  # class LangGraphPhishingAgent, LLMConfig
    P6 = importlib.import_module("phishing_agent.llm_final_decision")

    # LLM 準備
    llm = None
    if fake_llm:
        class _SOChainStub:
            def __init__(self, schema):
                self.schema = schema
            def invoke(self, *_msgs):
                # 安全側のデフォルト（テスト用）
                return self.schema(
                    is_phishing=False, confidence=0.0, risk_level="low",
                    detected_brands=[], risk_factors=[],
                    reasoning="Phase6 FakeLLM stub output (for wiring test). This reasoning is intentionally long to satisfy schema."
                )
        class _FakeLLM:
            def with_structured_output(self, schema):
                return _SOChainStub(schema)
        llm = _FakeLLM()
    else:
        cfg = _load_cfg()
        llm = _build_llm_from_cfg(cfg)

    # final_decision ノード差し替え（クラスメソッドをモンキーパッチ）
    def _patched_final_decision_node(self, state: "L4.AgentState"):  # type: ignore[name-defined]
        ml = float(state.get("ml_probability", 0.0) or 0.0)
        try:
            if self.use_llm_decision and llm is not None:
                asmt = P6.final_decision(
                    llm=llm,
                    domain=state["domain"],
                    ml_probability=ml,
                    tool_results=state.get("tool_results", {}) or {},
                    graph_state=state,
                    strict_mode=self.strict_mode,
                )
                state["final_assessment"] = asmt
                state["current_step"] = "completed"
                return state
            else:
                raise RuntimeError("SO(final_decision) unavailable")
        except Exception as e:
            # 既存 Phase4 のフォールバック規約を忠実に踏襲
            tr = state.get("tool_results", {}) or {}
            try:
                clip_confidence = L4.clip_confidence
                get_risk_level = L4.get_risk_level
                PhishingAssessment = L4.PhishingAssessment
            except Exception:
                raise

            cxs = float((tr.get("contextual_risk_assessment") or {}).get("risk_score", 0.0) or 0.0)
            if cxs <= 0.0:
                cxs = float((tr.get("contextual") or {}).get("risk_score", 0.0) or 0.0)
            if cxs <= 0.0:
                parts = [float((tr.get(k) or {}).get("risk_score", 0.0) or 0.0) for k in ("brand","cert","domain")]
                cxs = max(parts) if parts else ml
            is_ph = bool(cxs >= 0.5)
            conf = clip_confidence(max(ml, cxs))
            risk_level = get_risk_level(confidence=conf, is_phishing=is_ph)  # type: ignore
            asmt = PhishingAssessment(
                is_phishing=is_ph,
                confidence=conf,
                risk_level=risk_level,
                detected_brands=list((tr.get("brand") or {}).get("details", {}).get("detected_brands", []) or []),
                risk_factors=list((tr.get("contextual_risk_assessment") or {}).get("detected_issues", []) or []),
                reasoning="SO(final_decision) fallback: contextual/aggregate riskを使用 (Phase6 wiring).",
            )
            # 観測: フォールバック記録
            locs = list(state.get("fallback_locations", []) or [])
            locs.append(f"final_decision_llm:{e}")
            state["fallback_locations"] = locs
            state["final_assessment"] = asmt
            state["current_step"] = "completed"
            return state

    # 実パッチ適用
    setattr(L4.LangGraphPhishingAgent, "_final_decision_node", _patched_final_decision_node)
    return L4  # 利便のため返す

def make_agent_for_test(*, strict_mode: bool = False, prefer_compat: bool = True, fake_llm: bool = True, external_data: Optional[Dict[str, Any]] = None):
    """
    Phase6 配線後の LangGraphPhishingAgent を生成するユーティリティ（最小テスト用）
    """
    L4 = wire_phase6(prefer_compat=prefer_compat, fake_llm=fake_llm)
    return L4.LangGraphPhishingAgent(strict_mode=strict_mode, external_data=external_data or {})
