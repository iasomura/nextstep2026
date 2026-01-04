# -*- coding: utf-8 -*-
"""
phishing_agent.tools.brand_impersonation_check
----------------------------------------------
Brand Impersonation Check - Rule-based core + optional LLM helper

- Uses tools_module.safe_tool_wrapper for unified error handling.
- Integrates Phase2 precheck_hints (ML category / TLD / length / quick_risk).
- Detects ML paradox for brand cases (ml_paradox_brand).
- Returns Phase3-standard tool data structure:

    {
        "tool_name": "brand_impersonation_check",
        "detected_issues": [...],
        "risk_score": float,
        "details": {...},
        "reasoning": str,
    }

Public function `brand_impersonation_check(...)` keeps backward-
compatible arguments and returns {"success": True/False, "data": {...}}.
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple, Optional
import json
import os

# ---------------------------------------------------------------------------
# Imports: safe_tool_wrapper & whitelist helpers
# ---------------------------------------------------------------------------
try:
    # Phase3 shared wrapper
    from ..tools_module import safe_tool_wrapper
except Exception:  # pragma: no cover - minimal standalone fallback
    def safe_tool_wrapper(tool_name: str):
        def _wrap(fn):
            def _inner(*args, strict_mode: bool = False, **kwargs):
                try:
                    data = fn(*args, **kwargs) or {}
                    return {"success": True, "data": data}
                except Exception as e:
                    if strict_mode:
                        raise
                    return {
                        "success": False,
                        "error": str(e),
                        "data": {
                            "tool_name": tool_name,
                            "detected_issues": [],
                            "risk_score": 0.0,
                            "details": {"error": str(e)},
                            "reasoning": f"Error: {e}",
                        },
                        "_fallback": {"location": f"tool_{tool_name}"},
                    }
            return _inner
        return _wrap

# 正規ドメインホワイトリスト
try:
    from .legitimate_domains import is_legitimate_domain, should_skip_llm_check
except Exception:  # pragma: no cover - fallback for tests
    def is_legitimate_domain(domain: str) -> Dict[str, Any]:
        return {"is_legitimate": False, "brand": None, "confidence": 0.0, "reason": "not_in_whitelist"}

    def should_skip_llm_check(domain: str, ml_probability: float) -> bool:
        return False

# Optional LLM stack (not required for core behaviour)
try:  # pragma: no cover
    from langchain_openai import ChatOpenAI  # type: ignore
    LANGCHAIN_AVAILABLE = True
except Exception:  # pragma: no cover
    ChatOpenAI = None  # type: ignore
    LANGCHAIN_AVAILABLE = False

# ---------------------------------------------------------------------------
# Small utilities
# ---------------------------------------------------------------------------

def _split_labels(domain: str) -> List[str]:
    return [p for p in (domain or "").lower().strip(".").split(".") if p]

def _normalize_token(s: str) -> str:
    """Keep only ascii letters/digits and lowercase."""
    return "".join(ch for ch in (s or "").lower() if ("a" <= ch <= "z") or ("0" <= ch <= "9"))

def _tokenize_label(label: str) -> List[str]:
    """
    Split a label into tokens by '-' etc and keep tokens >=3 chars.
    Example: "merccari-shop" -> ["merccari", "shop"]
    """
    toks: List[str] = []
    label = label or ""
    for raw in label.replace("_", "-").split("-"):
        t = _normalize_token(raw)
        if len(t) >= 3:
            toks.append(t)
    if not toks:
        t = _normalize_token(label)
        if len(t) >= 3:
            toks = [t]
    return toks

def _calculate_edit_distance(s1: str, s2: str) -> int:
    """Standard dynamic-programming Levenshtein distance (small strings)."""
    s1 = s1 or ""
    s2 = s2 or ""
    m, n = len(s1), len(s2)
    if m == 0:
        return n
    if n == 0:
        return m
    # simple DP
    prev = list(range(n + 1))
    curr = [0] * (n + 1)
    for i in range(1, m + 1):
        curr[0] = i
        c1 = s1[i - 1]
        for j in range(1, n + 1):
            c2 = s2[j - 1]
            if c1 == c2:
                curr[j] = prev[j - 1]
            else:
                curr[j] = 1 + min(prev[j], curr[j - 1], prev[j - 1])
        prev, curr = curr, prev
    return prev[n]

def _ed_le1(a: str, b: str) -> bool:
    """Lightweight edit-distance<=1 check used as a pre-filter."""
    if a == b:
        return True
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return False
    i = j = diff = 0
    while i < la and j < lb:
        if a[i] == b[j]:
            i += 1
            j += 1
        else:
            diff += 1
            if diff > 1:
                return False
            if la == lb:
                i += 1
                j += 1
            elif la > lb:
                i += 1
            else:
                j += 1
    diff += (la - i) + (lb - j)
    return diff <= 1

def _check_brand_substring(token: str, brand: str) -> Tuple[bool, str]:
    """
    Check four match types between a token and a brand keyword:
    - exact
    - substring
    - fuzzy (edit distance <=1)
    - compound (brand embedded with extra chars)
    """
    token = token or ""
    brand = brand or ""
    if not token or not brand:
        return False, ""

    # exact
    if token == brand:
        return True, "exact"

    # substring (token contains brand with small prefix/suffix)
    if len(token) > len(brand) and brand in token:
        idx = token.find(brand)
        prefix_len = idx
        suffix_len = len(token) - idx - len(brand)
        if prefix_len + suffix_len <= 4:
            return True, "substring"

    # fuzzy (strict)
    if _ed_le1(token, brand):
        return True, "fuzzy"

    # compound: brand appears but with more noise around it
    if len(token) >= len(brand) + 2 and brand in token:
        return True, "compound"

    return False, ""

# ---------------------------------------------------------------------------
# LLM helper (optional)
# ---------------------------------------------------------------------------

def _resolve_config_path(explicit: Optional[str] = None) -> Optional[str]:
    """
    Find config.json path.
    Priority:
      1. explicit argument
      2. env: NEXTSTEP_CONFIG_JSON / AIA_CONFIG_JSON / CONFIG_JSON
      3. ./config.json (cwd)
      4. module_dir/../config.json
      5. /mnt/data/config.json
    """
    if explicit and os.path.isfile(explicit):
        return explicit
    for env in ("NEXTSTEP_CONFIG_JSON", "AIA_CONFIG_JSON", "CONFIG_JSON"):
        v = os.getenv(env)
        if v and os.path.isfile(v):
            return v
    cwd_candidate = os.path.join(os.getcwd(), "config.json")
    if os.path.isfile(cwd_candidate):
        return cwd_candidate
    try:
        here = os.path.dirname(__file__)
        mod_candidate = os.path.join(here, "..", "config.json")
        if os.path.isfile(mod_candidate):
            return mod_candidate
    except Exception:
        pass
    mnt_candidate = "/mnt/data/config.json"
    if os.path.isfile(mnt_candidate):
        return mnt_candidate
    return None

def _load_llm_client(config_path: Optional[str] = None):
    """
    Minimal ChatOpenAI client loader used only for brand LLM detection.
    Returns None if not available or disabled.
    """
    if not (LANGCHAIN_AVAILABLE and ChatOpenAI):
        return None
    path = _resolve_config_path(config_path)
    if not path:
        return None
    try:
        raw = json.load(open(path, "r", encoding="utf-8"))
        llm_cfg = (raw.get("llm") or {})
        if not llm_cfg.get("enabled"):
            return None
        base_url = llm_cfg.get("base_url") or llm_cfg.get("vllm_base_url") or llm_cfg.get("ollama_base_url")
        model = llm_cfg.get("model") or llm_cfg.get("vllm_model") or llm_cfg.get("ollama_model")
        if not (base_url and model):
            return None
        api_key = llm_cfg.get("api_key") or os.getenv("OPENAI_API_KEY") or "EMPTY"
        temperature = float(llm_cfg.get("temperature", 0.1) or 0.1)
        return ChatOpenAI(model=model, base_url=base_url, api_key=api_key, temperature=temperature)
    except Exception:
        return None

def _llm_brand_detect(
    domain: str,
    brands_sample: List[str],
    ml_probability: float,
    *,
    config_path: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """
    Ask the LLM to judge brand impersonation.
    Returns normalized dict or None on any failure.
    """
    llm = _load_llm_client(config_path)
    if llm is None:
        return None

    sys_text = (
        "You are a cybersecurity expert specializing in phishing and brand impersonation detection. "
        "Respond ONLY with a compact JSON dictionary containing keys: "
        "is_brand_impersonation (bool), detected_brand (string or null), confidence (0.0-1.0), reasoning (string)."
    )
    user_payload = {
        "domain": domain,
        "ml_probability": float(ml_probability or 0.0),
        "brand_keywords_sample": list(brands_sample or [])[:20],
        "instructions": [
            "Flag true if the domain is likely a fake / phishing site impersonating a known brand.",
            "Treat official / legitimate domains (e.g., paypal.com, google.com, accounts.google.com) as NOT impersonation.",
            "Consider typosquatting, extra words like 'secure', 'login', 'verify', and suspicious TLDs.",
        ],
    }
    try:
        msg = llm.invoke(
            [
                {"role": "system", "content": sys_text},
                {"role": "user", "content": json.dumps(user_payload, ensure_ascii=False)},
            ]
        )
        content = getattr(msg, "content", "") if msg is not None else ""
        if not content:
            return None
        # Try to locate JSON in content
        start = content.find("{")
        end = content.rfind("}")
        if start == -1 or end == -1 or end <= start:
            return None
        raw_json = content[start : end + 1]
        data = json.loads(raw_json)
        return {
            "detected": bool(data.get("is_brand_impersonation", False)),
            "brand": (data.get("detected_brand") or None),
            "confidence": float(data.get("confidence", 0.0) or 0.0),
            "reasoning": str(data.get("reasoning", "") or ""),
            "method": "llm",
        }
    except Exception:
        return None

# ---------------------------------------------------------------------------
# Core logic (no safe_tool_wrapper here)
# ---------------------------------------------------------------------------

def _normalize_brand_list(brand_keywords: List[str], potential_brands: Optional[List[str]]) -> List[str]:
    """
    Normalize and deduplicate brand candidates (dynamic + precheck).
    """
    seen: set[str] = set()
    out: List[str] = []
    for src in (brand_keywords or []):
        b = _normalize_token(str(src))
        if b and b not in seen:
            seen.add(b)
            out.append(b)
    for src in (potential_brands or []):
        b = _normalize_token(str(src))
        if b and b not in seen:
            seen.add(b)
            out.append(b)
    return out

def _compute_rule_matches(
    domain: str,
    brands_norm: List[str],
) -> Tuple[List[Dict[str, Any]], List[str]]:
    """
    Scan domain labels and return (rule_hits, detected_brands_labels).
    rule_hits: list of dicts containing brand, token, label, match_type, edit_distance.
    detected_brands_labels: human-friendly labels like 'paypal (substring)'.
    """
    labels = [l for l in _split_labels(domain) if l != "www"]
    rule_hits: List[Dict[str, Any]] = []
    detected_brands: List[str] = []

    if not labels or not brands_norm:
        return rule_hits, detected_brands

    for label in labels:
        tokens = _tokenize_label(label)
        if not tokens:
            normalized = _normalize_token(label)
            if len(normalized) >= 3:
                tokens = [normalized]

        full_label = _normalize_token(label)
        if full_label and full_label not in tokens and len(full_label) >= 3:
            tokens.append(full_label)

        for tok in tokens:
            for brand in brands_norm:
                is_match, mtype = _check_brand_substring(tok, brand)
                if not is_match:
                    continue
                # Edit distance for diagnostics
                ed = 0
                if mtype in ("fuzzy", "substring", "compound"):
                    ed = _calculate_edit_distance(tok, brand)
                rule_hits.append(
                    {
                        "brand": brand,
                        "token": tok,
                        "label": label,
                        "match_type": mtype,
                        "edit_distance": int(ed),
                    }
                )
                if mtype == "exact":
                    label_str = brand
                else:
                    label_str = f"{brand} ({mtype})"
                if label_str not in detected_brands:
                    detected_brands.append(label_str)
                # stop at first match for this token
                break

    return rule_hits, detected_brands

def _base_score_from_match(rule_hits: List[Dict[str, Any]]) -> Tuple[float, str]:
    """
    Decide base risk score and dominant match_type from rule hits.
    Priority: exact > substring/compound > fuzzy.
    """
    has_exact = any(h.get("match_type") == "exact" for h in rule_hits)
    has_sub = any(h.get("match_type") == "substring" for h in rule_hits)
    has_comp = any(h.get("match_type") == "compound" for h in rule_hits)
    has_fuzzy = any(h.get("match_type") == "fuzzy" for h in rule_hits)

    if has_exact:
        return 0.40, "exact"
    if has_sub or has_comp:
        return 0.35, "substring" if has_sub else "compound"
    if has_fuzzy:
        return 0.30, "fuzzy"
    return 0.0, "none"

def _apply_precheck_boosts(
    base_score: float,
    *,
    tld_category: str,
    domain_length_category: str,
    quick_risk: float,
) -> float:
    """
    Apply additive boosts from precheck hints.
    """
    score = float(base_score)
    if tld_category == "dangerous":
        score += 0.05
    if domain_length_category in ("very_short", "short"):
        score += 0.05
    if quick_risk is not None and float(quick_risk) >= 0.5:
        score += 0.05
    return min(1.0, score)

def _compute_ml_category(p: float) -> str:
    if p < 0.2:
        return "very_low"
    if p < 0.4:
        return "low"
    if p < 0.6:
        return "medium"
    if p < 0.8:
        return "high"
    return "very_high"

def _brand_impersonation_check_core(
    domain: str,
    brand_keywords: List[str],
    precheck_hints: Optional[Dict[str, Any]] = None,
    ml_probability: Optional[float] = None,
    *,
    use_llm: bool = False,
    llm_threshold: float = 0.72,
    fail_on_llm_error: bool = False,
    config_path: Optional[str] = None,
    **kwargs: Any,
) -> Dict[str, Any]:
    """
    Core implementation returning ONLY the tool payload (no success flag).
    This function is wrapped by safe_tool_wrapper in the public API.
    """
    domain = (domain or "").strip()
    ml_p = float(ml_probability or 0.0)

    # --- Precheck integration ------------------------------------------------
    pre = dict(precheck_hints or {})
    tld_category = pre.get("tld_category", "unknown")
    domain_length_category = pre.get("domain_length_category", "unknown")
    quick_risk = float(pre.get("quick_risk", 0.0) or 0.0)
    ml_category = pre.get("ml_category") or _compute_ml_category(ml_p)
    ml_paradox_flag = bool(pre.get("ml_paradox", False))

    # --- Whitelist check -----------------------------------------------------
    legit = is_legitimate_domain(domain)
    whitelist_info = {
        "is_legitimate": bool(legit.get("is_legitimate", False)),
        "brand": legit.get("brand"),
        "confidence": float(legit.get("confidence", 0.0) or 0.0),
        "reason": legit.get("reason") or "",
    }
    wl_conf = whitelist_info["confidence"]

    # High-confidence legitimate domain → early safe return
    if whitelist_info["is_legitimate"] and wl_conf >= 0.95:
        details = {
            "detected_brands": [],
            "match_type": "none",
            "rule_hits": [],
            "whitelist": whitelist_info,
            "used_llm": False,
            "llm_confidence": None,
            "llm_reasoning": None,
            "issue_flags": [],
            "precheck": {
                "ml_probability": ml_p,
                "ml_category": ml_category,
                "tld_category": tld_category,
                "domain_length_category": domain_length_category,
                "quick_risk": quick_risk,
                "ml_paradox_flag_from_precheck": ml_paradox_flag,
            },
        }
        return {
            "tool_name": "brand_impersonation_check",
            "detected_issues": [],
            "risk_score": 0.0,
            "details": details,
            "reasoning": f"Domain '{domain}' is in the legitimate whitelist ({whitelist_info['reason']}); brand impersonation is not suspected.",
        }

    # Medium-confidence legitimate domain → downscale risks
    risk_adjustment = 0.3 if (whitelist_info["is_legitimate"] and wl_conf >= 0.90) else 1.0

    # --- Brand candidate list ------------------------------------------------
    brands_norm = _normalize_brand_list(
        brand_keywords or [],
        pre.get("potential_brands") or [],
    )

    # If we have no brands at all, we still return a valid payload
    if not brands_norm:
        details = {
            "detected_brands": [],
            "match_type": "none",
            "rule_hits": [],
            "whitelist": whitelist_info,
            "used_llm": False,
            "llm_confidence": None,
            "llm_reasoning": None,
            "issue_flags": [],
            "precheck": {
                "ml_probability": ml_p,
                "ml_category": ml_category,
                "tld_category": tld_category,
                "domain_length_category": domain_length_category,
                "quick_risk": quick_risk,
                "ml_paradox_flag_from_precheck": ml_paradox_flag,
            },
        }
        return {
            "tool_name": "brand_impersonation_check",
            "detected_issues": [],
            "risk_score": 0.0,
            "details": details,
            "reasoning": "No brand keywords available; brand impersonation cannot be evaluated by rules.",
        }

    # --- Rule-based detection -----------------------------------------------
    rule_hits, detected_brands = _compute_rule_matches(domain, brands_norm)
    base_score, match_type = _base_score_from_match(rule_hits)

    detected_issues: List[str] = []
    issue_flags: List[str] = []
    used_llm = False
    llm_confidence: Optional[float] = None
    llm_reasoning: Optional[str] = None

    if base_score > 0.0:
        detected_issues.append("brand_detected")
        if match_type == "exact":
            detected_issues.append("brand_exact_match")
        elif match_type == "substring":
            detected_issues.append("brand_substring")
        elif match_type == "compound":
            detected_issues.append("brand_compound")
        elif match_type == "fuzzy":
            detected_issues.append("brand_fuzzy")

        # brand + unusual TLD
        if tld_category in ("dangerous", "unknown"):
            detected_issues.append("brand_tld_mismatch")

        issue_flags = list(dict.fromkeys(detected_issues))
        risk_score = _apply_precheck_boosts(
            base_score,
            tld_category=tld_category,
            domain_length_category=domain_length_category,
            quick_risk=quick_risk,
        )
        risk_score *= risk_adjustment
    else:
        risk_score = 0.0

    # --- Optional LLM detection ---------------------------------------------
    # Cost-saving: only call when explicitly enabled and rule-based score is low/zero.
    if (
        use_llm
        and not should_skip_llm_check(domain, ml_p)
        and (risk_score < 0.35)
    ):
        try:
            llm_raw = _llm_brand_detect(domain, brands_norm, ml_p, config_path=config_path)
            if llm_raw:
                used_llm = True
                llm_confidence = float(llm_raw.get("confidence", 0.0) or 0.0)
                llm_reasoning = (llm_raw.get("reasoning") or "")[:500] or None
                if llm_raw.get("detected") and llm_confidence >= float(llm_threshold):
                    brand_label = (llm_raw.get("brand") or "").strip()
                    label_str = f"{brand_label} (llm)" if brand_label else "unknown (llm)"
                    if label_str not in detected_brands:
                        detected_brands.append(label_str)
                    if "brand_detected" not in detected_issues:
                        detected_issues.append("brand_detected")
                    if "brand_llm" not in detected_issues:
                        detected_issues.append("brand_llm")
                    # base LLM score similar to fuzzy
                    llm_base = 0.30
                    llm_score = _apply_precheck_boosts(
                        llm_base,
                        tld_category=tld_category,
                        domain_length_category=domain_length_category,
                        quick_risk=quick_risk,
                    )
                    llm_score *= risk_adjustment
                    risk_score = max(risk_score, llm_score)
        except Exception as e:
            if fail_on_llm_error:
                # This exception will be handled by safe_tool_wrapper (strict_mode decides)
                raise RuntimeError(f"LLM brand detection failed for {domain}: {e}") from e
            # otherwise: just ignore and continue with rule-based result

    # --- ML paradox for brand -----------------------------------------------
    brand_found = risk_score > 0.0 or "brand_detected" in detected_issues
    if brand_found:
        # derived category if missing
        ml_cat = ml_category or _compute_ml_category(ml_p)
        paradox_cond = (
            (ml_p < 0.2 or ml_cat == "very_low")
            and (tld_category == "dangerous" or domain_length_category in ("very_short", "short"))
        )
        if paradox_cond or ml_paradox_flag:
            if "ml_paradox_brand" not in detected_issues:
                detected_issues.append("ml_paradox_brand")
            risk_score = max(risk_score, 0.5)

    # Clip final score
    risk_score = max(0.0, min(1.0, risk_score))

    # --- details & reasoning -------------------------------------------------
    issue_flags = list(dict.fromkeys(detected_issues)) if detected_issues else []

    details: Dict[str, Any] = {
        "detected_brands": detected_brands,
        "match_type": match_type if brand_found else "none",
        "rule_hits": rule_hits,
        "whitelist": whitelist_info,
        "used_llm": used_llm,
        "llm_confidence": llm_confidence,
        "llm_reasoning": llm_reasoning,
        "issue_flags": issue_flags,
        "precheck": {
            "ml_probability": ml_p,
            "ml_category": ml_category,
            "tld_category": tld_category,
            "domain_length_category": domain_length_category,
            "quick_risk": quick_risk,
            "ml_paradox_flag_from_precheck": ml_paradox_flag,
        },
    }

    # Short human-readable reasoning
    reasoning_parts: List[str] = []
    if brand_found:
        if detected_brands:
            reasoning_parts.append(f"ブランド候補 {', '.join(detected_brands)} を含むドメイン構造を検出")
        else:
            reasoning_parts.append("ブランド名に類似するパターンを検出")
        if tld_category == "dangerous":
            reasoning_parts.append("危険または不自然なTLDと組み合わさっている")
        if domain_length_category in ("very_short", "short"):
            reasoning_parts.append(f"短いベースドメイン（{domain_length_category}）")
    else:
        reasoning_parts.append("既知ブランド名に対する明確ななりすましパターンは検出されなかった")

    if "ml_paradox_brand" in detected_issues:
        reasoning_parts.append("ML確率が非常に低い一方でブランド+TLDが高リスク（ML paradox brand）と判断")

    if not reasoning_parts:
        reasoning_parts.append("Brand impersonation risk could not be clearly assessed.")

    reasoning = " / ".join(reasoning_parts)

    return {
        "tool_name": "brand_impersonation_check",
        "detected_issues": detected_issues,
        "risk_score": risk_score,
        "details": details,
        "reasoning": reasoning,
    }

# ---------------------------------------------------------------------------
# Public API (safe_tool_wrapper + error-shape normalization)
# ---------------------------------------------------------------------------

@safe_tool_wrapper("brand_impersonation_check")
def _brand_impersonation_check_wrapped(
    domain: str,
    brand_keywords: List[str],
    precheck_hints: Optional[Dict[str, Any]] = None,
    ml_probability: Optional[float] = None,
    *,
    use_llm: bool = False,
    llm_threshold: float = 0.72,
    fail_on_llm_error: bool = False,
    config_path: Optional[str] = None,
    **kwargs: Any,
) -> Dict[str, Any]:
    """
    Internal wrapped entry point. safe_tool_wrapper will turn this into
    {"success": True/False, "data": {...}} and handle ToolExecutionError
    when strict_mode=True.
    """
    return _brand_impersonation_check_core(
        domain=domain,
        brand_keywords=brand_keywords,
        precheck_hints=precheck_hints,
        ml_probability=ml_probability,
        use_llm=use_llm,
        llm_threshold=llm_threshold,
        fail_on_llm_error=fail_on_llm_error,
        config_path=config_path,
        **kwargs,
    )

def brand_impersonation_check(
    domain: str,
    brand_keywords: List[str],
    precheck_hints: Optional[Dict[str, Any]] = None,
    ml_probability: Optional[float] = None,
    *,
    strict_mode: bool = False,
    use_llm: bool = False,
    llm_threshold: float = 0.72,
    fail_on_llm_error: bool = False,
    config_path: Optional[str] = None,
    **kwargs: Any,
) -> Dict[str, Any]:
    """
    Public tool function.

    Returns:
        {"success": True/False, "data": {...}} compatible with other tools.

    On error (success=False), this function ensures that `data` contains at
    least:
        - tool_name
        - detected_issues
        - risk_score
        - details["error"]
        - reasoning
    """
    res = _brand_impersonation_check_wrapped(
        domain=domain,
        brand_keywords=brand_keywords,
        precheck_hints=precheck_hints,
        ml_probability=ml_probability,
        use_llm=use_llm,
        llm_threshold=llm_threshold,
        fail_on_llm_error=fail_on_llm_error,
        config_path=config_path,
        strict_mode=strict_mode,
        **kwargs,
    )
    # safe_tool_wrapper already returns {"success":..., "data":...} for success.
    if isinstance(res, dict) and res.get("success") is False:
        err_msg = str(res.get("error") or "unknown error")
        # Ensure data exists with minimum fields
        data = res.get("data") or {
            "tool_name": "brand_impersonation_check",
            "detected_issues": [],
            "risk_score": 0.0,
            "details": {"error": err_msg},
            "reasoning": f"Error: {err_msg}",
        }
        # Normalize minimal structure
        if not isinstance(data, dict):
            data = {
                "tool_name": "brand_impersonation_check",
                "detected_issues": [],
                "risk_score": 0.0,
                "details": {"error": err_msg},
                "reasoning": f"Error: {err_msg}",
            }
        else:
            data.setdefault("tool_name", "brand_impersonation_check")
            data.setdefault("detected_issues", [])
            data.setdefault("risk_score", 0.0)
            det = data.setdefault("details", {})
            if not isinstance(det, dict):
                data["details"] = {"error": err_msg}
            else:
                det.setdefault("error", err_msg)
            data.setdefault("reasoning", f"Error: {err_msg}")
        res["data"] = data
    return res

# ---------------------------------------------------------------------------
# Minimal tests (can be called from external test harness)
# ---------------------------------------------------------------------------

def run_all_tests() -> None:  # pragma: no cover - simple smoke tests
    """
    Basic behavioural tests for the brand_impersonation_check tool.
    These avoid LLM usage (use_llm=False).
    """
    print("[T1] paypal.com should be treated as legitimate (risk_score=0)")
    r1 = brand_impersonation_check(
        domain="paypal.com",
        brand_keywords=["paypal"],
        precheck_hints={
            "tld_category": "legitimate",
            "domain_length_category": "normal",
            "ml_category": "low",
            "ml_paradox": False,
            "quick_risk": 0.0,
            "potential_brands": ["paypal"],
        },
        ml_probability=0.1,
        strict_mode=False,
        use_llm=False,
    )
    assert r1.get("success") is True
    d1 = r1["data"]
    assert d1["risk_score"] == 0.0
    assert "brand_detected" not in d1["detected_issues"]
    print("  -> OK")

    print("[T2] paypal-secure-login.info should detect brand with risk>=0.4")
    r2 = brand_impersonation_check(
        domain="paypal-secure-login.info",
        brand_keywords=["paypal"],
        precheck_hints={
            "tld_category": "dangerous",
            "domain_length_category": "long",
            "ml_category": "medium",
            "ml_paradox": False,
            "quick_risk": 0.7,
            "potential_brands": ["paypal"],
        },
        ml_probability=0.3,
        strict_mode=False,
        use_llm=False,
    )
    assert r2.get("success") is True
    d2 = r2["data"]
    assert "brand_detected" in d2["detected_issues"]
    assert d2["risk_score"] >= 0.4
    print("  -> OK")

    print("[T3] pineapple.com with brand 'apple' should NOT detect brand")
    r3 = brand_impersonation_check(
        domain="pineapple.com",
        brand_keywords=["apple"],
        precheck_hints={
            "tld_category": "legitimate",
            "domain_length_category": "normal",
            "ml_category": "low",
            "ml_paradox": False,
            "quick_risk": 0.0,
            "potential_brands": ["apple"],
        },
        ml_probability=0.2,
        strict_mode=False,
        use_llm=False,
    )
    assert r3.get("success") is True
    d3 = r3["data"]
    assert d3["risk_score"] == 0.0
    assert "brand_detected" not in d3["detected_issues"]
    print("  -> OK")

    print("[T4] ML paradox brand: very_low ML + dangerous TLD + brand")
    r4 = brand_impersonation_check(
        domain="paypal-secure-login.info",
        brand_keywords=["paypal"],
        precheck_hints={
            "tld_category": "dangerous",
            "domain_length_category": "short",
            "ml_category": "very_low",
            "ml_paradox": True,
            "quick_risk": 0.8,
            "potential_brands": ["paypal"],
        },
        ml_probability=0.1,
        strict_mode=False,
        use_llm=False,
    )
    assert r4.get("success") is True
    d4 = r4["data"]
    assert "ml_paradox_brand" in d4["detected_issues"], d4["detected_issues"]
    assert d4["risk_score"] >= 0.5, d4["risk_score"]
    print("  -> OK")

    print("All brand_impersonation_check tests passed.")

if __name__ == "__main__":  # pragma: no cover
    run_all_tests()
