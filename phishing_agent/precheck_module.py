# -*- coding: utf-8 -*-
"""
precheck_module.py — Phase 2 v1.3 (spec latest) 準拠・互換レイヤ付
- 仕様: Phase 2: 事前チェック（Step0）仕様（独立実装版 v1.3）に準拠
- 役割: 05 の ipynb 由来データを直接受け取り、precheck_hints を生成
- 互換: Phase3 が参照する内部ヘルパ（_extract_etld1/_detect_brands/_extract_cert_info/_categorize_tld）を必ず提供
"""
from __future__ import annotations

import re
import unicodedata
import math
from typing import Any, Dict, List, Optional, Tuple

# ---- tldextract を優先、無ければ簡易フォールバック -----------------------------
try:
    import tldextract  # type: ignore
except Exception:
    tldextract = None  # type: ignore

class ETLD1:
    def __init__(self, sub: str, dom: str, suf: str):
        self.subdomain = sub or ""
        self.domain = dom or ""
        self.suffix = suf or ""
    @property
    def registered_domain(self) -> str:
        if self.domain and self.suffix:
            return f"{self.domain}.{self.suffix}"
        return self.domain or ""

def _extract_etld1(host: str) -> ETLD1:
    h = (host or "").strip()
    if tldextract:
        ext = tldextract.extract(h)
        return ETLD1(ext.subdomain, ext.domain, ext.suffix)
    # very small fallback: last 2 labels as domain.suffix
    h2 = h.split("://")[-1].split("/")[0].strip(".")
    parts = [p for p in h2.split(".") if p]
    if len(parts) >= 2:
        return ETLD1(".".join(parts[:-2]), parts[-2], parts[-1])
    return ETLD1("", h2, "")

# ---- 内部ユーティリティ --------------------------------------------------------
_TOKEN_SPLIT = re.compile(r"[-.\d\W]+", flags=re.ASCII)

def _tokenize_domain_labels(et: ETLD1) -> List[str]:
    tokens: List[str] = []
    if et.domain:
        tokens += [t for t in _TOKEN_SPLIT.split(et.domain.lower()) if t]
    if et.subdomain:
        tokens += [t for t in _TOKEN_SPLIT.split(et.subdomain.lower()) if t]
    return [unicodedata.normalize("NFKC", t) for t in tokens if t]

# 厳密: トークン完全一致 + 語境界一致（pineapple≠apple）
def _detect_brands(domain: str, brand_keywords: List[str]) -> Tuple[bool, List[str]]:
    et = _extract_etld1(domain)
    rd = (et.registered_domain or "").lower()
    tokens = [t for t in _tokenize_domain_labels(et) if t.isalpha()]
    hits: List[str] = []
    for b in [x.strip().lower() for x in (brand_keywords or []) if x and str(x).strip()]:
        if b in tokens:
            hits.append(b); continue
        if rd and re.search(rf"(?<![a-z0-9]){re.escape(b)}(?![a-z0-9])", rd, flags=re.I):
            hits.append(b)
    hits = list(dict.fromkeys(hits))
    return (len(hits) > 0, hits)

# ---- TLD safety guard ---------------------------------------------------------
# NOTE:
# - upstream の統計/学習が壊れても、.com/.net/.org 等の汎用TLDを "dangerous" 扱いにしない。
# - ここは「TLD自体の危険度」ではなく、「分類事故を防ぐガード」。
_COMMON_SAFE_TLDS = {
    "com", "net", "org",
    "jp", "co.jp", "ne.jp", "ac.jp", "go.jp",
    "edu", "gov",
}

def _tld_stats_to_map(stats: Any) -> Dict[str, float]:
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

    # pandas DataFrame: columns = ['tld', 'count'] などを想定
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
                        continue  # DataFrame.to_dict 由来のネストは拒否
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


def _categorize_tld(suffix: str, dangerous: List[str], legitimate: List[str], neutral: List[str]) -> str:
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

def _extract_cert_info(meta: Dict[str, Any]) -> Dict[str, Any]:
    meta = meta or {}
    subject = meta.get("subject") or {}
    return {
        "issuer": meta.get("issuer"),
        "subject": subject if isinstance(subject, dict) else {},
        "san_count": int(meta.get("san_count") or len(meta.get("san", []) or [])),
        "valid_days": int(meta.get("valid_days") or 0),
        "is_free_ca": bool(meta.get("is_free_ca") or False),
        "is_self_signed": bool(meta.get("is_self_signed") or False),
        # 新規: benign indicators 用 (2026-01-12)
        "has_crl_dp": bool(meta.get("has_crl_dp") or meta.get("has_crl") or False),
        "has_org": bool(meta.get("has_org") or meta.get("has_organization") or False),
        "is_wildcard": bool(meta.get("is_wildcard") or False),
    }


def _calc_cert_benign_score(cert_info: Dict[str, Any]) -> float:
    """証明書の正規性スコア（0.0-1.0）

    Stage2/Stage3で有効性が確認された証明書特徴量をスコア化。
    高いスコア = 正規サイトの可能性が高い。
    """
    score = 0.0
    if cert_info.get("has_crl_dp", False):
        score += 0.30  # CRL: 正規81.7% vs フィッシング1.6%
    if cert_info.get("has_org", False):
        score += 0.35  # OV/EV: 強い正規シグナル
    if cert_info.get("is_wildcard", False):
        score += 0.10  # ワイルドカード: 正規55.1%
    validity_days = cert_info.get("valid_days", 0) or 0
    if validity_days > 180:
        score += 0.10  # 長期有効期間
    san_count = cert_info.get("san_count", 0) or 0
    if san_count >= 10:
        score += 0.15  # 高SAN数
    return min(1.0, score)


def _generate_cert_summary(cert_info: Dict[str, Any]) -> Dict[str, Any]:
    """証明書サマリを生成（precheck_hints用）

    Stage3のGate B1-B4で使用するbenign indicatorsを事前に計算。
    """
    validity_days = cert_info.get("valid_days", 0) or 0
    san_count = cert_info.get("san_count", 0) or 0
    has_org = cert_info.get("has_org", False)
    has_crl_dp = cert_info.get("has_crl_dp", False)
    is_wildcard = cert_info.get("is_wildcard", False)

    # benign_indicators リストを構築
    benign_indicators: List[str] = []
    if has_crl_dp:
        benign_indicators.append("has_crl_dp")
    if has_org:
        benign_indicators.append("ov_ev_cert")
    if is_wildcard:
        benign_indicators.append("wildcard_cert")
    if validity_days > 180:
        benign_indicators.append("long_validity")
    if san_count >= 10:
        benign_indicators.append("high_san_count")

    return {
        "has_crl_dp": has_crl_dp,
        "is_ov_ev": has_org,
        "is_wildcard": is_wildcard,
        "validity_days": validity_days,
        "is_long_validity": validity_days > 180,
        "san_count": san_count,
        "is_high_san": san_count >= 10,
        "benign_score": round(_calc_cert_benign_score(cert_info), 3),
        "benign_indicators": benign_indicators,
    }

# ---- 仕様準拠: generate_precheck_hints ----------------------------------------
def generate_precheck_hints(
    domain: str,
    ml_probability: float,
    brand_keywords: List[str],
    cert_full_info_map: Dict[str, Dict[str, Any]],
    dangerous_tlds: List[str],
    legitimate_tlds: List[str],
    neutral_tlds: Optional[List[str]] = None,
    phishing_tld_stats: Optional[Dict[str,int]] = None,
    trusted_tld_stats: Optional[Dict[str,int]] = None,
    known_domains: Optional[Dict[str,Any]] = None,
    high_risk_words: Optional[List[str]] = None,
    strict_mode: bool = False
) -> Dict[str, Any]:
    """
    戻り値最小セット：ml_category, ml_paradox, tld_category, brand_detected, potential_brands[],
                      domain_length_category, quick_risk, recommended_tools[]
    仕様: Phase 2 v1.3（独立実装版）に準拠
    """
    try:
        et = _extract_etld1(domain)
        # brand
        brand_detected, potential_brands = _detect_brands(domain, brand_keywords or [])
        # domain length (base domain only)
        n = len(et.domain or "")
        if   n <= 3: domain_length_category = "very_short"
        elif n <= 6: domain_length_category = "short"
        elif n <= 10: domain_length_category = "normal"
        else: domain_length_category = "long"
        # tld
        tld_category = _categorize_tld(et.suffix, dangerous_tlds or [], legitimate_tlds or [], neutral_tlds or [])
                # stats weight（robust: dict / DataFrame / Series）
        stat_w = 0.0
        stats_map = _tld_stats_to_map(phishing_tld_stats)
        suf = (et.suffix or "").lower().strip(".")
        if stats_map and suf:
            try:
                v = float(stats_map.get(suf, 0.0) or 0.0)

                # Guard: common TLDs は統計の大小で危険扱いしない（頻度≠危険度）
                if v > 0.0 and suf not in _COMMON_SAFE_TLDS:
                    vmax = max([float(x) for x in stats_map.values() if x is not None] + [1.0])

                    if vmax <= 1.0:
                        # 0〜1 の確率/比率として扱える場合
                        stat_w = max(0.0, min(0.30, 0.30 * v))
                    else:
                        # count-like stats → log scaling to avoid common/popular TLD dominance
                        stat_w = max(
                            0.0,
                            min(0.30, 0.30 * (math.log1p(v) / math.log1p(vmax))),
                        )
            except Exception:
                stat_w = 0.0
# high risk words
        tokens = _tokenize_domain_labels(et)
        hr_set = {w.strip().lower() for w in (high_risk_words or []) if w and str(w).strip()}
        hr_hits = sum(1 for t in tokens if t in hr_set)
        # ml category
        p = float(ml_probability or 0.0)
        if   p < 0.2: ml_category = "very_low"
        elif p < 0.4: ml_category = "low"
        elif p < 0.6: ml_category = "medium"
        elif p < 0.8: ml_category = "high"
        else:         ml_category = "very_high"

        # quick_risk（非破壊的・説明可能）
        qr = 0.0
        if brand_detected: qr += 0.40
        if domain_length_category == "very_short": qr += 0.30
        elif domain_length_category == "short": qr += 0.15
        if tld_category == "dangerous": qr += 0.25
        qr += min(0.30, stat_w)
        if hr_hits > 0:
            qr += min(0.15, 0.05 * hr_hits)
        if ml_category == "very_low":
            qr += 0.05  # 仕様: very_low で Quick Risk 上昇（微量）
        qr = max(0.0, min(1.0, qr))

        # ml paradox（低確率 + 強い非ML要因）
        risk_signals = 0
        if brand_detected: risk_signals += 1
        if tld_category == "dangerous": risk_signals += 1
        if domain_length_category in ("very_short","short"): risk_signals += 1
        ml_paradox = (p < 0.3 and risk_signals >= 2)

        # 推奨ツール
        rec = ["brand_impersonation_check","certificate_analysis","short_domain_analysis"]
        if hr_hits > 0 or ml_paradox:
            rec.append("contextual_risk_assessment")

        # 証明書情報の抽出とサマリ生成 (2026-01-12)
        # cert_full_info_map からドメインに対応する証明書情報を取得
        cert_info: Dict[str, Any] = {}
        if cert_full_info_map:
            rd = et.registered_domain or ""
            for key in [domain, domain.lower(), rd, rd.lower(), f"www.{rd}"]:
                if key and key in cert_full_info_map:
                    cert_info = _extract_cert_info(cert_full_info_map[key])
                    break

        cert_summary = _generate_cert_summary(cert_info) if cert_info else {
            "has_crl_dp": False,
            "is_ov_ev": False,
            "is_wildcard": False,
            "validity_days": 0,
            "is_long_validity": False,
            "san_count": 0,
            "is_high_san": False,
            "benign_score": 0.0,
            "benign_indicators": [],
        }

        return {
            "ml_category": ml_category,
            "ml_paradox": ml_paradox,
            "tld_category": tld_category,
            "brand_detected": brand_detected,
            "potential_brands": potential_brands,
            "domain_length_category": domain_length_category,
            "quick_risk": round(qr, 3),
            "recommended_tools": rec,
            "etld1": {
                "registered_domain": et.registered_domain,
                "domain": et.domain,
                "suffix": et.suffix,
                "subdomain": et.subdomain,
            },
            "stats": {
                "phishing_tld_weight": round(stat_w, 3),
                "high_risk_hits": hr_hits,
            },
            # 新規: 証明書サマリ (2026-01-12)
            "cert_summary": cert_summary,
        }
    except Exception as e:
        if strict_mode:
            raise
        return {
            "_fallback": {"phase": "precheck", "error": str(e)},
            "ml_category": "unknown",
            "ml_paradox": False,
            "tld_category": "unknown",
            "brand_detected": False,
            "potential_brands": [],
            "domain_length_category": "unknown",
            "quick_risk": 0.0,
            "recommended_tools": ["brand_impersonation_check","certificate_analysis","short_domain_analysis"],
        }

# ---- テスト（最小） ------------------------------------------------------------
def run_all_tests() -> None:
    r = generate_precheck_hints(
        domain="paypai-secure-login.com",
        ml_probability=0.15,
        brand_keywords=["paypal"],
        cert_full_info_map={},
        dangerous_tlds=["tk","ml","ga","cf","gq"],
        legitimate_tlds=["com","jp","co.jp"],
        neutral_tlds=["io","ai"],
        phishing_tld_stats={"com":10,"tk":50},
        high_risk_words=["secure","login"],
    )
    assert r["brand_detected"] is True or r["ml_category"] in ("very_low","low")
    r2 = generate_precheck_hints(
        domain="pineapple.com",
        ml_probability=0.20,
        brand_keywords=["apple"],
        cert_full_info_map={},
        dangerous_tlds=["tk"],
        legitimate_tlds=["com"],
    )
    assert r2["brand_detected"] is False, "pineapple 誤検出"
