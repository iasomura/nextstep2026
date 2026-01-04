
# -*- coding: utf-8 -*-
"""phishing_agent.batch - Phase1 shim for 05 integration"""
from __future__ import annotations
from typing import Any, Dict, Iterable, List, Optional, Union
from time import perf_counter
try:
    from . import PhishingAssessment, convert_to_phase2_format
except Exception:
    import agent_foundations as _AF
    PhishingAssessment = _AF.PhishingAssessment
    convert_to_phase2_format = _AF.convert_to_phase2_format
__all__ = ["FoundationsOnlyAgent","create_agent_from_handoff","batch_evaluate_domains"]
class FoundationsOnlyAgent:
    def __init__(self, strict_mode: bool=True, default_tools: Optional[List[str]]=None)->None:
        self.strict_mode = strict_mode; self.default_tools=list(default_tools or [])
    def evaluate_domain(self, domain: str, ml_probability: Optional[float]=None, **kw: Any)->Dict[str, Any]:
        t0=perf_counter()
        pa = PhishingAssessment(is_phishing=False, confidence=0.0, risk_level="low",
                                detected_brands=[], risk_factors=[], reasoning="Phase1 stub result.")
        return convert_to_phase2_format(domain=domain or "", ml_probability=float(ml_probability or 0.0),
                                        assessment=pa, tools_used=[], processing_time=perf_counter()-t0,
                                        success=True, phase="phase1_stub")
def create_agent_from_handoff(*a: Any, strict_mode: bool=True, default_tools: Optional[List[str]]=None, **k: Any)->FoundationsOnlyAgent:
    return FoundationsOnlyAgent(strict_mode=strict_mode, default_tools=default_tools)
def batch_evaluate_domains(domains: Iterable[Union[Dict[str, Any], str]], agent: Optional[FoundationsOnlyAgent]=None,
                           ml_probability_key: str="ml_probability", domain_key: str="domain", **kw: Any)->List[Dict[str, Any]]:
    ag = agent or FoundationsOnlyAgent(); default_mlp=float(kw.get("default_ml_probability", 0.0)); out: List[Dict[str, Any]]=[]
    for item in domains or []:
        if isinstance(item, str):
            d=item; mlp=default_mlp
        elif isinstance(item, dict):
            d=(item.get(domain_key) or item.get("domain") or ""); mlp=item.get(ml_probability_key, item.get("prediction_proba", default_mlp))
        else: continue
        out.append(ag.evaluate_domain(d, ml_probability=mlp))
    return out
