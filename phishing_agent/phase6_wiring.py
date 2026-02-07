# -*- coding: utf-8 -*-
"""
phase6_wiring.py — Phase6 最終判定ノードの配線ユーティリティ（fixed）
-------------------------------------------------------------------
- 目的: 既存 LangGraphPhishingAgent の「final_decision」ノードを Phase6 実装に差し替え
- ポリシ:
    - 既存 Phase4 の I/O 契約・Strict/Fallback 挙動を壊さない（非破壊のモンキーパッチ）
    - Structured Output が壊れた場合でも「何も検知しない」状態にしない
      → *SO 失敗に限り* graph を継続し、LLM なし deterministic fallback（Phase6 policy / Phase4互換集約）で最終判定を生成
      （失敗は state.debug_llm_final / phase6_final_decision_error / fallback_locations に記録）

変更履歴:
  - 2025-12-16: graph_state に phase6_policy_version を必ず残す（分析CSVでの追跡性向上）
"""
from __future__ import annotations

import os
from typing import Any, Dict, Optional


# ========================================
# 設定ファイル関連ユーティリティ
# ========================================

def _compat_config_path() -> Optional[str]:
    """_compat/config.json を最優先で探す。"""
    for cand in ("./_compat/config.json", "/mnt/data/_compat/config.json"):
        if os.path.isfile(cand):
            return os.path.abspath(cand)
    return None


def _ensure_config_env(*, prefer_compat: bool = True) -> None:
    """CONFIG_JSON 環境変数を設定（無ければ）"""
    cfg_env = os.getenv("CONFIG_JSON")
    if cfg_env and os.path.isfile(cfg_env):
        return

    cand = None
    if prefer_compat:
        cand = _compat_config_path()
    if not cand:
        for path in ("./config.json", "/mnt/data/config.json"):
            if os.path.isfile(path):
                cand = os.path.abspath(path)
                break
    if cand:
        os.environ["CONFIG_JSON"] = cand


def _load_cfg() -> Dict[str, Any]:
    """CONFIG_JSON から設定を読む。失敗時は最小構成。"""
    import json

    path = os.getenv("CONFIG_JSON") or _compat_config_path()
    if path and os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass

    # 最小フォールバック
    return {"llm": {"enabled": False}}


def _build_llm_from_cfg(cfg: Dict[str, Any]):
    """OpenAI互換 Chat クライアントの生成（with_structured_output が必要）"""
    llm_cfg = (cfg or {}).get("llm", {}) or {}
    enabled = bool(llm_cfg.get("enabled", False))
    base_url = (
        llm_cfg.get("base_url")
        or llm_cfg.get("vllm_base_url")
        or llm_cfg.get("ollama_base_url")
    )
    model = (
        llm_cfg.get("model")
        or llm_cfg.get("vllm_model")
        or llm_cfg.get("ollama_model")
        or "gpt-4o-mini"
    )
    if not (enabled and base_url):
        return None

    # API Key は空不可の実装があるため "EMPTY" を許容
    api_key = llm_cfg.get("api_key") or os.getenv("OPENAI_API_KEY") or "EMPTY"
    # 変更履歴:
    #   - 2026-02-07: max_tokens を 2048 → 4096 に変更（SO parse failure 16件の解消）
    #     注: 再評価時は一時的に8192+max-model-len=16384で実行。通常運用は4096+max-model-len=4096
    try:
        from langchain_openai import ChatOpenAI  # type: ignore

        return ChatOpenAI(
            model=model,
            base_url=base_url,
            api_key=api_key,
            temperature=float(llm_cfg.get("temperature", 0.1) or 0.1),
            max_tokens=4096,
            # Qwen3 thinking モードを無効化
            extra_body={"chat_template_kwargs": {"enable_thinking": False}},
        )
    except Exception as e:  # pragma: no cover
        raise RuntimeError(f"LLM init failed: {e}")


# ========================================
# Phase6 配線
# ========================================

# Globals for Phase6 wiring (set by wire_phase6)
L4 = None  # type: ignore[assignment]
P6 = None  # type: ignore[assignment]
llm = None
_ORIG_FINAL_DECISION = None


def wire_phase6(*, prefer_compat: bool = True, fake_llm: bool = False):
    """Phase6 の最終判定実装を LangGraphPhishingAgent に結線する。"""
    global L4, P6, llm, _ORIG_FINAL_DECISION

    _ensure_config_env(prefer_compat=prefer_compat)

    # LangGraph エージェントと Phase6 実装を import
    import importlib

    L4 = importlib.import_module("phishing_agent.langgraph_module")  # class LangGraphPhishingAgent, LLMConfig
    P6 = importlib.import_module("phishing_agent.llm_final_decision")

    # もともとの final_decision ノードを退避しておき、フォールバックで利用する
    if _ORIG_FINAL_DECISION is None:
        _ORIG_FINAL_DECISION = L4.LangGraphPhishingAgent._final_decision_node  # type: ignore[assignment]

    # LLM 準備
    if fake_llm:
        class _SOChainStub:
            def __init__(self, schema):
                self.schema = schema

            def invoke(self, _input):
                # 最小限のダミー Assessment を返す（テスト専用）
                try:
                    return self.schema(
                        is_phishing=False,
                        confidence=0.0,
                        risk_level="low",
                        detected_brands=[],
                        risk_factors=[],
                        reasoning="Phase6 FakeLLM stub output (for wire_phase6 test).",
                    )
                except Exception:
                    return {
                        "is_phishing": False,
                        "confidence": 0.0,
                        "risk_level": "low",
                        "detected_brands": [],
                        "risk_factors": [],
                        "reasoning": "Phase6 FakeLLM stub output (for wire_phase6 test).",
                    }

        class _FakeLLM:
            def with_structured_output(self, schema):
                return _SOChainStub(schema)

        llm = _FakeLLM()
    else:
        cfg = _load_cfg()
        llm = _build_llm_from_cfg(cfg)

    # 実パッチ適用
    setattr(L4.LangGraphPhishingAgent, "_final_decision_node", _patched_final_decision_node)
    return L4  # 利便のため呼び出し側で利用可


# ========================================
# Phase6 最終判定ノード本体
# ========================================

def _patched_final_decision_node(self, state: "L4.AgentState"):  # type: ignore[name-defined]
    """
    Phase6 の LLM 最終判定ノード（LLM必須モード）。
    - use_llm_decision=True かつ LLM が初期化されていることを前提とし、
      それ以外の状態はエラーとして扱う（Phase4フォールバックは行わない）。
    """
    global llm

    ml = float(state.get("ml_probability", 0.0) or 0.0)

    # --- Traceability: Phase6 policy version stamp ---
    # CSV で phase6_policy_version を確実に参照できるように、
    # Phase6 wiring の入口で state に stamp する（LLM成功/失敗に関わらず残す）。
    try:
        ver = getattr(P6, "PHASE6_POLICY_VERSION", None)
        if isinstance(state, dict) and ver:
            state["phase6_policy_version"] = str(ver)
    except Exception:
        pass

    # --- debug_llm_final 初期化 ---
    dbg_info = dict(state.get("debug_llm_final", {}) or {})
    use_llm_decision = bool(getattr(self, "use_llm_decision", False))
    strict_mode = bool(getattr(self, "strict_mode", False))
    dbg_info.update(
        {
            "use_llm_decision": use_llm_decision,
            "llm_is_none": llm is None,
            "ml": ml,
        }
    )
    state["debug_llm_final"] = dbg_info

    # メッセージログ用（あれば使う）
    _append = getattr(self, "_append_debug_message", None)

    def _log(msg: str, role: str = "system") -> None:
        if callable(_append):
            try:
                _append(state, msg, role=role)
            except Exception:
                pass

    # =========================
    # 0) 前提条件チェック：LLM必須
    # =========================
    if not use_llm_decision:
        reason = "use_llm_decision=False"
    elif llm is None:
        reason = "llm_is_none=True"
    else:
        reason = ""

    if reason:
        dbg_info["path"] = "invalid_config"
        dbg_info["error"] = reason
        state["debug_llm_final"] = dbg_info
        _log(f"[final_decision] ERROR: LLM not available ({reason})", role="ai")

        # Phase4 には戻らず、必ずエラーとして扱う
        raise L4.PhishingAgentError(
            message=f"SO(final_decision) not available: {reason}",
            domain=state.get("domain"),
            ml_probability=ml,
            step="final_decision",
            original_error=reason,
            context={"reason": reason},
        )

    def _is_structured_output_failure(exc: Exception) -> bool:
        """SO(JSON) 生成・パース・検証まわりの失敗だけを 'recoverable' として扱う判定。

        目的: strict=True のままでも、SO 由来の例外だけは graph を落とさずに継続し、
              state に記録して評価実験を安定させる。
        """
        name = type(exc).__name__
        msg = str(exc) or ""

        # Phase6 が投げるラッパ例外（agent_foundations.StructuredOutputError）
        try:
            if hasattr(P6, "StructuredOutputError") and isinstance(exc, getattr(P6, "StructuredOutputError")):
                return True
        except Exception:
            pass

        # LangChain / OpenAI互換で多いパターン
        low = msg.lower()
        if "could not parse response content" in low:
            return True
        if "length limit was reached" in low or "finish_reason" in low and "length" in low:
            return True
        if "outputparser" in name.lower() or "output parser" in low:
            return True
        if "validationerror" in name.lower() and ("phishing" in low or "assessment" in low):
            return True
        return False

    def _phase6_deterministic_fallback(*, error_msg: str) -> Any:
        """LLM を使わずに Phase6 の決定規則（ポリシー補正）だけで最終判定を作る。

        - LLM SO が壊れたときに『何も見ず benign』にならないようにする。
        - Phase6 の _apply_policy_adjustments が存在すればそれを優先。
        - 無ければ Phase4 互換の集約ロジックにフォールバック。
        """
        tr = state.get("tool_results", {}) or {}
        pre = state.get("precheck_hints", {}) or {}

        # まず Phase6 の deterministic policy で可能な限り再現
        try:
            if hasattr(P6, "_summarize_tool_signals") and hasattr(P6, "_apply_policy_adjustments") and hasattr(P6, "PhishingAssessment"):
                tsum = P6._summarize_tool_signals(tr)
                # base assessment（LLMなし）
                base = P6.PhishingAssessment(
                    is_phishing=False,
                    confidence=0.0,
                    risk_level="low",
                    detected_brands=list(((tr.get("brand") or {}).get("details", {}) or {}).get("detected_brands", []) or []),
                    risk_factors=["fallback:final_decision_so"],
                    reasoning=(
                        "Phase6 final_decision SO failed; used deterministic policy fallback. "
                        f"error={error_msg}"
                    )[:500],
                )
                trace = [{"note": "phase6_wiring_so_fallback", "error": error_msg[:200]}]
                asmt = P6._apply_policy_adjustments(
                    base,
                    tsum,
                    ml_probability=ml,
                    precheck=pre,
                    trace=trace,
                )

                # 事後分析: 発火した rule 一覧を state に保存（CSV展開が簡単になる）
                try:
                    if isinstance(state, dict):
                        rules_fired: list[str] = []
                        for t in trace:
                            if isinstance(t, dict) and t.get("rule"):
                                r = str(t.get("rule"))
                                if r not in rules_fired:
                                    rules_fired.append(r)
                        state["phase6_rules_fired"] = rules_fired
                except Exception:
                    pass
                # decision_trace へ最小限の痕跡を残す（巨大化防止）
                try:
                    if isinstance(state, dict):
                        dt = list(state.get("decision_trace", []) or [])
                        dt.append({
                            "phase": "phase6_wiring",
                            "event": "so_fallback",
                            "error": error_msg[:200],
                        })
                        state["decision_trace"] = dt
                except Exception:
                    pass
                return asmt
        except Exception:
            # deterministic fallback 自体が壊れても Phase4互換へ
            pass

        # Phase4互換: contextual/aggregate による最終判定（LLMなし）
        cxs = 0.0
        try:
            cxs = float((tr.get("contextual_risk_assessment") or {}).get("risk_score", 0.0) or 0.0)
        except Exception:
            cxs = 0.0
        if cxs <= 0.0:
            try:
                cxs = float((tr.get("contextual") or {}).get("risk_score", 0.0) or 0.0)
            except Exception:
                cxs = 0.0
        if cxs <= 0.0:
            parts = []
            for k in ("brand", "cert", "domain"):
                try:
                    parts.append(float((tr.get(k) or {}).get("risk_score", 0.0) or 0.0))
                except Exception:
                    pass
            cxs = max(parts) if parts else float(ml)

        is_ph = bool(cxs >= 0.5)
        conf = L4.clip_confidence(max(float(ml), float(cxs)))
        try:
            risk_level = L4.get_risk_level(confidence=conf, is_phishing=is_ph)  # type: ignore
        except TypeError:
            risk_level = L4.get_risk_level(conf)  # type: ignore

        return L4.PhishingAssessment(
            is_phishing=is_ph,
            confidence=conf,
            risk_level=risk_level,
            detected_brands=list(((tr.get("brand") or {}).get("details", {}) or {}).get("detected_brands", []) or []),
            risk_factors=list((tr.get("contextual_risk_assessment") or {}).get("detected_issues", []) or []) + ["fallback:final_decision_so"],
            reasoning=(
                "SO(final_decision) failed; used deterministic fallback (Phase6 wiring). "
                f"error={error_msg}"
            )[:500],
        )

    # =========================
    # 1) LLM 経路（Phase6）: 必須
    # =========================
    try:
        dbg_info["path"] = "llm"
        state["debug_llm_final"] = dbg_info
        _log(f"[final_decision] LLM path ml={ml}", role="system")

        tr = state.get("tool_results", {}) or {}
        domain = str(state.get("domain") or "")

        # Phase6 の final_decision を呼び出し（失敗はすべて例外として扱う）
        asmt = P6.final_decision(
            llm=llm,
            domain=domain,
            ml_probability=ml,
            tool_results=tr,
            graph_state=state,
            strict_mode=True,  # ここでは常に Strict に扱う
        )

        dbg_info["success"] = True
        dbg_info["error"] = None
        state["debug_llm_final"] = dbg_info

        _log("[final_decision] LLM done success=True (Phase6, strict)", role="ai")

        state["final_assessment"] = asmt
        state["current_step"] = "completed"
        return state

    except Exception as e:
        # =========================
        # 2) 例外発生時
        #   - SO 失敗だけは『継続 + 記録 + deterministic fallback』
        #   - それ以外は従来どおりエラー（問題を隠さない）
        # =========================
        err_msg = str(e)
        so_failure = _is_structured_output_failure(e)

        dbg_info["success"] = False
        dbg_info["error"] = err_msg
        dbg_info["path"] = "so_fallback" if so_failure else "error"
        dbg_info["so_failure"] = bool(so_failure)
        state["debug_llm_final"] = dbg_info

        if so_failure:
            # 記録
            try:
                state["phase6_final_decision_error"] = {
                    "type": type(e).__name__,
                    "message": err_msg[:400],
                }
            except Exception:
                pass
            try:
                # LangGraphPhishingAgent の既存メカニズムで fallback を記録
                if hasattr(self, "_update_fallback") and callable(getattr(self, "_update_fallback")):
                    self._update_fallback(state, "final_decision_so", type(e).__name__)  # type: ignore[attr-defined]
            except Exception:
                pass

            _log(f"[final_decision] SO failure → continue with deterministic fallback: {type(e).__name__}: {err_msg}", role="ai")

            asmt_fb = _phase6_deterministic_fallback(error_msg=f"{type(e).__name__}: {err_msg}")
            state["final_assessment"] = asmt_fb
            state["current_step"] = "completed"
            return state

        # SO 由来ではない例外は従来どおりエラー
        _log(f"[final_decision] ERROR during Phase6 LLM: {e}", role="ai")

        raise L4.PhishingAgentError(
            message=f"SO(final_decision) failed: {e}",
            domain=state.get("domain"),
            ml_probability=ml,
            step="final_decision",
            original_error=str(e),
            context={"exception_type": type(e).__name__},
        )

# ========================================
# テスト用ユーティリティ
# ========================================

def make_agent_for_test(
    *,
    strict_mode: bool = False,
    prefer_compat: bool = True,
    fake_llm: bool = True,
    external_data: Optional[Dict[str, Any]] = None,
):
    """Phase6 配線後の LangGraphPhishingAgent を生成するユーティリティ（最小テスト用）。"""
    L4_mod = wire_phase6(prefer_compat=prefer_compat, fake_llm=fake_llm)
    return L4_mod.LangGraphPhishingAgent(
        strict_mode=strict_mode,
        external_data=external_data or {},
    )