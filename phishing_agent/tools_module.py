# -*- coding: utf-8 -*-
"""
tools_module.py — Phase 3 v1.3 準拠（スリム化版）
- brand_impersonation_check と certificate_analysis は tools/ ディレクトリに移行済み。
- ここには short_domain_analysis と contextual_risk_assessment、および共通ヘルパーを残しています。
"""

# ---------------------------------------------------------------------
# Change history
# - 2026-01-02: safe_tool_wrapper now returns a neutral `data` payload even
#              on failure (error included in details) so downstream logic/logs
#              remain stable and analysis-friendly.
# ---------------------------------------------------------------------
from __future__ import annotations

import re
import unicodedata
import math
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

# Phase1 例外（Strict=Trueで送出）
try:
    from .agent_foundations import ToolExecutionError  # type: ignore
except Exception:  # minimal fallback
    class ToolExecutionError(RuntimeError):
        def __init__(self, msg: str, tool_name: str = "", original_error: str = ""):
            super().__init__(msg)
            self.tool_name = tool_name
            self.original_error = original_error

# ---- Phase2 ヘルパをベストエフォートで import ---------------------------------
try:
    from .precheck_module import _extract_etld1, _categorize_tld  # type: ignore
except Exception:
    _extract_etld1 = None  # type: ignore
    _categorize_tld = None  # type: ignore

# ---- ローカル Fallbacks --------------------------------------------------------
try:
    import tldextract  # type: ignore
except Exception:
    tldextract = None  # type: ignore

class _ETLD1Shim:
    def __init__(self, sub: str, dom: str, suf: str):
        self.subdomain = sub or ""
        self.domain = dom or ""
        self.suffix = suf or ""
    @property
    def registered_domain(self) -> str:
        return f"{self.domain}.{self.suffix}" if self.domain and self.suffix else (self.domain or "")

def _local_extract_etld1(host: str) -> _ETLD1Shim:
    h = (host or "").split("://")[-1].split("/")[0].strip(".")
    if tldextract:
        ext = tldextract.extract(h)
        return _ETLD1Shim(ext.subdomain, ext.domain, ext.suffix)
    parts = [p for p in h.split(".") if p]
    if len(parts) >= 2:
        return _ETLD1Shim(".".join(parts[:-2]), parts[-2], parts[-1])
    return _ETLD1Shim("", h, "")

def _ET(host: str):
    return (_extract_etld1 or _local_extract_etld1)(host)

# ---- TLD safety guard ---------------------------------------------------------
# upstream の統計/学習が壊れても、.com/.net/.org 等の汎用TLDを "dangerous" 扱いにしない
_COMMON_SAFE_TLDS = {
    "com", "net", "org",
    "jp", "co.jp", "ne.jp", "ac.jp", "go.jp",
    "edu", "gov",
}


def _local_categorize_tld(suffix: str, dangerous: List[str], legitimate: List[str], neutral: List[str]) -> str:
    s = (suffix or "").lower().strip(".")

    # Guard: common TLDs should never be treated as "dangerous"
    if s in _COMMON_SAFE_TLDS:
        return "legitimate"

    D = {x.lower().strip(".") for x in (dangerous or []) if x}
    L = {x.lower().strip(".") for x in (legitimate or []) if x}
    N = {x.lower().strip(".") for x in (neutral or []) if x}
    if s in D: return "dangerous"
    if s in L: return "legitimate"
    if s in N: return "neutral"
    return "unknown"

def _CT(suffix: str, danger: List[str], legit: List[str], neut: List[str]) -> str:
    return (_categorize_tld or _local_categorize_tld)(suffix, danger, legit, neut)

# ---------------------------------------------------------------------
# 共通ラッパ（v1.3）
# ---------------------------------------------------------------------
def safe_tool_wrapper(name_or_fn=None):
    from functools import wraps
    def _decorate(fn, tool_name=None):
        @wraps(fn)
        def _inner(*args, strict_mode: bool = False, **kwargs):
            try:
                if kwargs.pop("force_error", False):
                    raise RuntimeError("forced_error")
                data = fn(*args, **kwargs) or {}
                return {"success": True, "data": data}
            except Exception as e:
                if strict_mode:
                    raise ToolExecutionError(
                        f"{tool_name or fn.__name__} failed",
                        tool_name=(tool_name or fn.__name__),
                        original_error=str(e),
                    ) from e
                # --- logging/analysis friendly fallback ---
                # Always return a minimal neutral `data` payload even on failure.
                # This keeps downstream aggregation and log export schemas stable.
                err = str(e)
                tn = (tool_name or fn.__name__)
                return {
                    "success": False,
                    "error": err,
                    "data": {
                        "tool_name": tn,
                        "detected_issues": ["tool_error"],
                        "risk_score": 0.0,
                        "details": {
                            "error": err,
                            "exception_type": type(e).__name__,
                        },
                        "reasoning": f"Tool execution failed: {tn} ({type(e).__name__}).",
                    },
                    "_fallback": {"location": f"tool_{tn}"},
                }
        return _inner
    if callable(name_or_fn):
        return _decorate(name_or_fn, tool_name=None)
    def _wrapper(fn):
        return _decorate(fn, tool_name=name_or_fn)
    return _wrapper

# ---------------------------------------------------------------------
# 共通ヘルパー（Contextualなどで使用）
# ---------------------------------------------------------------------
_TOKEN_SPLIT = re.compile(r"[-.\d\W]+", flags=re.ASCII)

def _tokenize_domain_labels(et: Any) -> List[str]:
    labels: List[str] = []
    if getattr(et, "domain", None):
        labels.extend([t for t in _TOKEN_SPLIT.split(str(et.domain).lower()) if t])
    if getattr(et, "subdomain", None):
        labels.extend([t for t in _TOKEN_SPLIT.split(str(et.subdomain).lower()) if t])
    return [unicodedata.normalize("NFKC", t) for t in labels if t]


def _coerce_tld_stats_to_map(stats: Any) -> Dict[str, float]:
    """phishing_tld_stats の型ゆらぎ（dict / DataFrame / Series）を吸収して {tld: value} にする。"""
    if not stats:
        return {}
    if isinstance(stats, dict):
        out: Dict[str, float] = {}
        for k, v in stats.items():
            kk = str(k).lower().strip(".")
            try:
                out[kk] = float(v)
            except Exception:
                try:
                    if hasattr(v, "item"):
                        out[kk] = float(v.item())
                except Exception:
                    continue
        return out

    # pandas DataFrame: columns = ['tld', 'count'] など
    try:
        import pandas as pd  # type: ignore
        if isinstance(stats, pd.DataFrame) and ("tld" in stats.columns):
            col = "count" if "count" in stats.columns else None
            if col is None:
                num_cols = [c for c in stats.columns if c != "tld" and pd.api.types.is_numeric_dtype(stats[c])]
                col = num_cols[0] if num_cols else None
            if col:
                out: Dict[str, float] = {}
                for t, v in zip(stats["tld"], stats[col]):
                    tt = str(t).lower().strip(".")
                    try:
                        out[tt] = float(v)
                    except Exception:
                        try:
                            if hasattr(v, "item"):
                                out[tt] = float(v.item())
                        except Exception:
                            continue
                return out
    except Exception:
        pass

    # pandas Series / other dict-like
    try:
        if hasattr(stats, "to_dict"):
            d = stats.to_dict()  # type: ignore
            if isinstance(d, dict):
                out: Dict[str, float] = {}
                for k, v in d.items():
                    if isinstance(v, dict):
                        continue
                    kk = str(k).lower().strip(".")
                    try:
                        out[kk] = float(v)
                    except Exception:
                        try:
                            if hasattr(v, "item"):
                                out[kk] = float(v.item())
                        except Exception:
                            continue
                if out:
                    return out
    except Exception:
        pass

    return {}


def _tld_stat_weight(suffix: str, phishing_tld_stats: Optional[Any]) -> float:
    """
    TLD統計から 0.0〜0.30 の重みを計算するヘルパー（頑健化版）

    - stats が 0〜1 の確率/比率っぽい場合: 0.30*v
    - stats が count-like（>1）場合:
        * 汎用TLD（.com/.net/.org 等）は weight=0.0（頻度≠危険度のため）
        * それ以外は log scaling で 0.0〜0.30 に収める
    """
    if not suffix or not phishing_tld_stats:
        return 0.0

    sfx = str(suffix).lower().strip(".")
    if sfx in _COMMON_SAFE_TLDS:
        return 0.0

    stats_map = _coerce_tld_stats_to_map(phishing_tld_stats)
    if not stats_map:
        return 0.0

    # key は lower を想定（念のため2通り）
    val = stats_map.get(sfx, stats_map.get(suffix, 0.0))
    try:
        v = float(val)
    except Exception:
        try:
            if hasattr(val, "item"):
                v = float(val.item())
            else:
                return 0.0
        except Exception:
            return 0.0

    if v <= 0.0:
        return 0.0

    # 0〜1 の範囲ならそのままスケール（確率/比率）
    if v <= 1.0:
        return max(0.0, min(0.30, 0.30 * v))

    # count-like: log scaling
    try:
        vmax = max([float(x) for x in stats_map.values() if x is not None] + [1.0])
        if vmax <= 1.0:
            return 0.0
        w = 0.30 * (math.log1p(v) / math.log1p(vmax))
        return max(0.0, min(0.30, float(w)))
    except Exception:
        return 0.0

# ---------------------------------------------------------------------
# Tool re-exports（本体は phishing_agent.tools.* にあり）
# ここでは「遅延 import ラッパ」として定義し、循環 import を防ぐ。
# ---------------------------------------------------------------------
from typing import Any, Dict, Optional, List  # ファイル上部で import 済なら不要


def short_domain_analysis(
    domain: str,
    dangerous_tlds: Optional[List[str]] = None,
    legitimate_tlds: Optional[List[str]] = None,
    neutral_tlds: Optional[List[str]] = None,
    phishing_tld_stats: Optional[Dict[str, Any]] = None,
    **kwargs: Any,
) -> Dict[str, Any]:
    """
    互換用ラッパ関数。
    実体は phishing_agent.tools.short_domain_analysis.short_domain_analysis に委譲する。
    """
    from .tools.short_domain_analysis import short_domain_analysis as _impl
    return _impl(
        domain=domain,
        dangerous_tlds=dangerous_tlds,
        legitimate_tlds=legitimate_tlds,
        neutral_tlds=neutral_tlds,
        phishing_tld_stats=phishing_tld_stats,
        **kwargs,
    )


def contextual_risk_assessment(
    domain: str,
    ml_probability: float = 0.0,
    tool_results: Optional[Dict[str, Any]] = None,
    high_risk_words: Optional[List[str]] = None,
    known_domains: Optional[Dict[str, Any]] = None,
    **kwargs: Any,
) -> Dict[str, Any]:
    """
    互換用ラッパ関数。
    実体は phishing_agent.tools.contextual_risk_assessment.contextual_risk_assessment に委譲する。
    """
    from .tools.contextual_risk_assessment import contextual_risk_assessment as _impl
    return _impl(
        domain=domain,
        ml_probability=ml_probability,
        tool_results=tool_results,
        high_risk_words=high_risk_words,
        known_domains=known_domains,
        **kwargs,
    )

