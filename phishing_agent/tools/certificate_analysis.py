from __future__ import annotations
from typing import Any, Dict, Optional, List
import copy
from functools import wraps

# ------------------------------------------------------------
# Safe Wrapper Setup
# ------------------------------------------------------------
try:
    from ..tools_module import safe_tool_wrapper
except (ImportError, ValueError):
    # Standalone fallback (Notebook / isolated testing 用)
    def safe_tool_wrapper(tool_name: str):
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                try:
                    result = func(*args, **kwargs)
                    return {"success": True, "data": result}
                except Exception as e:
                    # Phase3 互換を完全には再現できないが、
                    # certificate_analysis の I/F だけは維持する
                    return {
                        "success": False,
                        "data": {
                            "tool_name": tool_name,
                            "detected_issues": [],
                            "risk_score": 0.0,
                            "details": {"error": str(e)},
                            "reasoning": f"Error: {str(e)}",
                        },
                    }
            return wrapper
        return decorator

# ------------------------------------------------------------
# Legitimate Domains Setup
# ------------------------------------------------------------
try:
    from .legitimate_domains import is_legitimate_domain
    HAS_LEGITIMATE = True
except Exception:
    HAS_LEGITIMATE = False

    def is_legitimate_domain(domain: str) -> Dict[str, Any]:  # type: ignore[override]
        return {"is_legitimate": False, "confidence": 0.0, "brand": None, "reason": "module_not_available"}


# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------
def _pick_cert_from_map(domain: str, cert_full_info_map: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """cert_full_info_map から対象ドメインの証明書メタデータを引くヘルパー"""
    if not cert_full_info_map:
        return None

    # 簡易 registered domain 抽出（example.co.jp → example.co.jp / example.jp 等は別途処理）
    parts = (domain or "").lower().split(".")
    if len(parts) >= 2:
        registered = ".".join(parts[-2:])
    else:
        registered = (domain or "").lower()

    candidates = [domain, (domain or "").lower(), registered, f"www.{registered}"]

    for key in candidates:
        if not key:
            continue
        if key in cert_full_info_map:
            data = cert_full_info_map[key]
            if isinstance(data, dict):
                data = copy.deepcopy(data)
                data["_source"] = f"cert_map[{key}]"
            return data
    return None


def _load_cert_config() -> Dict[str, Any]:
    """証明書分析用の静的設定値（Phase3 v1.3 互換 + 追加パラメータ）"""
    return {
        # 無料/低保証 CA の代表例
        "free_ca_list": [
            "Let's Encrypt",
            "ZeroSSL",
            "Cloudflare",
            "cPanel",
            "Sectigo",
            "SSL.com",
            "Google Trust Services",
            "GoGetSSL",
        ],
        # 短期証明書とみなす閾値（日数）
        "short_term_days": 90,
        # SAN の数がこの閾値以上なら many_san とみなす
        "many_san_threshold": 10,
        # 長期有効とみなす閾値（日数）
        "long_validity_days": 180,
        # 高SAN数とみなす閾値（Stage3 benign indicator用）
        "high_san_threshold": 10,
        # 危険TLD（benign indicatorの判定で使用）
        "dangerous_tlds": [
            "tk", "ml", "ga", "cf", "gq",  # Freenom TLDs
            "xyz", "top", "work", "click", "link", "online",
            "site", "club", "icu", "buzz", "monster",
            "cfd", "sbs", "rest",
        ],
    }


def _normalize_issuer(issuer_data: Any) -> str:
    """issuer 情報を人間可読な文字列に正規化"""
    if isinstance(issuer_data, str):
        return issuer_data
    if isinstance(issuer_data, dict):
        for key in ("O", "organizationName", "CN", "commonName"):
            if key in issuer_data and issuer_data[key]:
                return str(issuer_data[key])
    return str(issuer_data) if issuer_data else ""


def _adapt_cert_meta(cert_meta: Dict[str, Any]) -> Dict[str, Any]:
    """証明書メタデータのキー揺れを吸収するアダプタ"""
    adapted = copy.deepcopy(cert_meta or {})

    # issuer_org → issuer などの後方互換対応
    if "issuer" not in adapted and "issuer_org" in adapted:
        adapted["issuer"] = adapted["issuer_org"]

    # has_organization → has_org
    if "has_org" not in adapted and "has_organization" in adapted:
        adapted["has_org"] = adapted["has_organization"]

    # not_before / not_after から valid_days を計算
    if "valid_days" not in adapted or not adapted.get("valid_days"):
        not_before = adapted.get("not_before")
        not_after = adapted.get("not_after")
        if not_before and not_after:
            try:
                from datetime import datetime
                # 文字列の場合はパース
                if isinstance(not_before, str):
                    # ISO format or common date formats
                    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
                        try:
                            not_before = datetime.strptime(not_before.split(".")[0], fmt)
                            break
                        except ValueError:
                            continue
                if isinstance(not_after, str):
                    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
                        try:
                            not_after = datetime.strptime(not_after.split(".")[0], fmt)
                            break
                        except ValueError:
                            continue
                # datetime オブジェクトの場合
                if hasattr(not_before, 'timestamp') and hasattr(not_after, 'timestamp'):
                    delta = not_after - not_before
                    adapted["valid_days"] = max(0, delta.days)
            except Exception:
                pass  # パース失敗時はvalid_days=0のまま

    return adapted


def _extract_tld(domain: str) -> str:
    """ドメインからTLDを抽出"""
    if not domain:
        return ""
    parts = domain.lower().strip().split(".")
    if len(parts) >= 1:
        return parts[-1]
    return ""


def _is_dangerous_tld(domain: str, config: Dict[str, Any]) -> bool:
    """危険TLDかどうかを判定"""
    tld = _extract_tld(domain)
    dangerous_tlds = config.get("dangerous_tlds", [])
    return tld in dangerous_tlds


def _mitigate_score_for_legit_domain(
    domain: str,
    detected_issues: List[str],
    risk_score: float,
    details: Dict[str, Any],
) -> float:
    """正規ドメインホワイトリストに基づくスコア緩和ロジック"""
    if risk_score <= 0.0 or not HAS_LEGITIMATE:
        return risk_score

    try:
        info = is_legitimate_domain(domain)
    except Exception:
        return risk_score

    # details にホワイトリスト情報だけは埋めておく（他ツールは参照しない想定）
    try:
        details["legitimate_domain"] = dict(info)
    except Exception:
        pass

    if not info or not info.get("is_legitimate"):
        return risk_score

    conf = 0.0
    try:
        conf = float(info.get("confidence") or 0.0)
    except Exception:
        conf = 0.0

    # self_signed を含む場合は「本当におかしい」ので緩和しない
    severe = ("self_signed" in detected_issues)
    if severe:
        return risk_score

    factor = 1.0
    if conf >= 0.95:
        factor = 0.30   # 70% 減衰
    elif conf >= 0.90:
        factor = 0.50   # 50% 減衰
    elif conf >= 0.80:
        factor = 0.70   # 30% 減衰

    if factor < 1.0:
        detected_issues.append("legitimate_domain_mitigation")
        mitigated = risk_score * factor
        # スコアは決して増やさず [0, risk_score] に収める
        mitigated = max(0.0, min(mitigated, risk_score))
        return mitigated

    return risk_score



# ------------------------------------------------------------
# Core Analysis Logic
# ------------------------------------------------------------
def _analyze_certificate_core(domain: str, cert_meta: Optional[Dict[str, Any]], config: Dict[str, Any]) -> Dict[str, Any]:
    detected_issues: List[str] = []
    benign_indicators: List[str] = []  # 新規: 正規性シグナル
    risk_score: float = 0.0

    short_term_days = int(config.get("short_term_days") or 90)
    many_san_threshold = int(config.get("many_san_threshold") or 10)
    long_validity_days = int(config.get("long_validity_days") or 180)
    high_san_threshold = int(config.get("high_san_threshold") or 10)
    is_dangerous_tld = _is_dangerous_tld(domain, config)

    details: Dict[str, Any] = {
        "has_cert": False,
        "issuer": "",
        "is_free_ca": False,
        "has_org": False,
        "san_count": 0,
        "is_domain_matched": True,  # SAN が無い場合は判定不能なので True 扱い
        "valid_days": 0,
        "is_short_term": False,
        "is_many_san": False,
        "is_self_signed": False,
        "is_wildcard": False,
        # identity attributes (approximation)
        "subject_org": None,
        "validation_level": None,
        "identity_level": None,
        "has_ov_ev_like_identity": False,
        # 新規: benign indicators 関連
        "has_crl_dp": False,
        "is_long_validity": False,
        "is_high_san": False,
        "is_dangerous_tld": is_dangerous_tld,
        "tld": _extract_tld(domain),
    }

    # --- 1. 証明書メタデータが無い場合（no_cert） --------------------------
    if not cert_meta:
        detected_issues.append("no_cert")
        # データ不足として扱い、単体では high に行かないように抑える
        risk_score = 0.20  # ← 0.70 ではなく「弱いシグナル」扱い

        # 正規ドメインであればさらに緩和（no_cert 自体は強異常とはみなさない）
        risk_score = _mitigate_score_for_legit_domain(domain, detected_issues, risk_score, details)

        return {
            "tool_name": "certificate_analysis",
            "detected_issues": detected_issues,
            "benign_indicators": benign_indicators,  # 新規追加
            "risk_score": min(1.0, risk_score),
            "details": details,
            "reasoning": "Certificate metadata not available (treated as low signal, not high risk)",
        }

    # --- 2. メタデータあり：正規化して解析 ---------------------------------
    meta = _adapt_cert_meta(cert_meta)
    details["has_cert"] = True

    # 2-1. Issuer
    issuer = _normalize_issuer(meta.get("issuer"))
    details["issuer"] = issuer

    # 2-2. free_ca 判定（フラグ優先、なければ issuer 文字列から判定）
    if meta.get("is_free_ca") is True:
        is_free_ca = True
    else:
        free_ca_list = config.get("free_ca_list") or []
        is_free_ca = bool(
            issuer
            and any(str(ca).lower() in issuer.lower() for ca in free_ca_list)
        )
    details["is_free_ca"] = bool(is_free_ca)

    # 2-3. Organization 情報
    if "has_org" in meta:
        has_org = bool(meta["has_org"])
    else:
        subj = meta.get("subject", {})
        has_org = isinstance(subj, dict) and bool(subj.get("O") or subj.get("organizationName"))
    details["has_org"] = has_org

    # 2-3b. Optional identity attributes (OV/EV/DV approximation)
    subj = meta.get("subject", {})
    subject_org = None
    try:
        if isinstance(subj, dict):
            subject_org = subj.get("O") or subj.get("organizationName") or None
    except Exception:
        subject_org = None

    details["subject_org"] = subject_org

    val_level = None
    for k in ("validation_level", "validation", "cert_type", "type"):
        v = meta.get(k)
        if isinstance(v, str) and v.strip():
            val_level = v.strip()
            break
    details["validation_level"] = val_level

    vnorm = str(val_level or "").upper()
    if vnorm in ("EV", "OV", "DV"):
        identity_level = vnorm
    else:
        # Fallback: any subject organization implies OV/EV-like identity
        identity_level = "OV" if has_org else "DV"
    details["identity_level"] = identity_level
    details["has_ov_ev_like_identity"] = bool(has_org)

    # 2-4. SAN 情報
    san_raw = meta.get("san")
    san_count = meta.get("san_count", 0)
    try:
        san_count = int(san_count)
    except Exception:
        san_count = 0
    if isinstance(san_raw, list):
        san_count = len(san_raw)
    details["san_count"] = san_count
    no_san = san_count == 0

    # 2-5. 有効日数（短期証明書）
    valid_days = 0
    try:
        valid_days = int(meta.get("valid_days") or 0)
    except Exception:
        valid_days = 0
    details["valid_days"] = valid_days
    is_short_term = bool(valid_days > 0 and valid_days <= short_term_days)
    details["is_short_term"] = is_short_term

    # 2-6. SAN が多すぎるかどうか
    is_many_san = bool(san_count and san_count >= many_san_threshold)
    details["is_many_san"] = is_many_san

    # 2-7. その他フラグ
    is_self_signed = bool(meta.get("is_self_signed") or False)
    details["is_self_signed"] = is_self_signed

    is_wildcard = bool(meta.get("is_wildcard") or False)
    details["is_wildcard"] = is_wildcard

    # 2-8. 新規: CRL Distribution Points（正規サイトの81.7%が保有）
    has_crl_dp = bool(meta.get("has_crl_dp") or meta.get("has_crl") or False)
    details["has_crl_dp"] = has_crl_dp

    # 2-9. 新規: 長期有効期間（180日超 = 正規サイトの27%）
    is_long_validity = bool(valid_days > long_validity_days)
    details["is_long_validity"] = is_long_validity

    # 2-10. 新規: 高SAN数（10以上 = 正規サイトの可能性高）
    # Handoff分析: FP Riskは平均SAN 13.2、低シグナルフィッシングは4.3
    is_high_san = bool(san_count >= high_san_threshold)
    details["is_high_san"] = is_high_san

    # --- 2-B. Benign Indicators 収集 -----------------------------------------
    # Stage2と同じ証明書特徴量をStage3でも活用

    # B1. CRL Distribution Points（正規81.7%が保有、フィッシング1.6%）
    if has_crl_dp:
        benign_indicators.append("has_crl_dp")

    # B2. OV/EV証明書（Subject Organization有り）
    if has_org:
        benign_indicators.append("ov_ev_cert")

    # B3. ワイルドカード証明書（正規55.1%、フィッシング1.5%）
    # 危険TLD以外の場合のみbenign indicator
    if is_wildcard and not is_dangerous_tld:
        benign_indicators.append("wildcard_cert")

    # B4. 長期有効期間（180日超 = 正規27%、フィッシング1%）
    if is_long_validity:
        benign_indicators.append("long_validity")

    # B5. 多数のSAN（10以上 = CDN、大規模サービスで使用）
    # 危険TLD以外の場合のみbenign indicator
    if is_high_san and not is_dangerous_tld:
        benign_indicators.append("high_san_count")

    # --- 3. スコアリング ---------------------------------------------------
    # 3-1. 単体シグナルのベース重み（単独では中〜低）
    if is_self_signed:
        detected_issues.append("self_signed")
        risk_score += 0.60  # 自己署名は強いシグナル

    if is_free_ca:
        detected_issues.append("free_ca")
        risk_score += 0.10

    if not has_org:
        detected_issues.append("no_org")
        risk_score += 0.06

    if no_san:
        detected_issues.append("no_san")
        risk_score += 0.06

    if is_short_term:
        detected_issues.append("short_term")
        risk_score += 0.06

    # many_san と wildcard は危険TLDの場合のみリスクとして扱う
    # 非危険TLDでは benign_indicators として扱われる（上記 2-B セクション参照）
    if is_many_san and is_dangerous_tld:
        detected_issues.append("many_san")
        risk_score += 0.04

    if is_wildcard and is_dangerous_tld:
        detected_issues.append("wildcard")
        risk_score += 0.05

    # 3-2. 重要コンボ: free_ca + no_org (+α) を強く扱う
    if is_free_ca and not has_org:
        if "free_ca_no_org" not in detected_issues:
            detected_issues.append("free_ca_no_org")
        # DV + 無料/低保証 CA
        risk_score = max(risk_score, 0.40)

        # 短期 or SAN なし / 多すぎ → さらに怪しい
        if is_short_term or no_san or is_many_san:
            if "dv_weak_identity" not in detected_issues:
                detected_issues.append("dv_weak_identity")
            risk_score = max(risk_score, 0.55)

        # 短期 + (no_san or many_san) + wildcard → かなり強いパターン
        if is_short_term and (no_san or is_many_san) and is_wildcard:
            if "dv_multi_risk_combo" not in detected_issues:
                detected_issues.append("dv_multi_risk_combo")
            risk_score = max(risk_score, 0.70)

    # 自己署名は他のシグナルと合算しても 0.8 付近まで
    if is_self_signed:
        risk_score = max(risk_score, 0.75)

    # 上限クリップ
    risk_score = min(1.0, risk_score)

    # --- 3-3. 新規: Benign Indicators による減算 ----------------------------
    # 正規性シグナルがある場合、リスクスコアを減算
    # 自己署名の場合は減算しない（強いリスクシグナル）
    if not is_self_signed and benign_indicators:
        benign_reduction = 0.0

        if "has_crl_dp" in benign_indicators:
            benign_reduction += 0.15  # CRL: 最大効果（正規81.7% vs フィッシング1.6%）
        if "ov_ev_cert" in benign_indicators:
            benign_reduction += 0.20  # OV/EV: 強い正規シグナル
        if "wildcard_cert" in benign_indicators:
            benign_reduction += 0.10  # ワイルドカード（非危険TLD）
        if "long_validity" in benign_indicators:
            benign_reduction += 0.08  # 長期有効期間
        if "high_san_count" in benign_indicators:
            benign_reduction += 0.12  # 高SAN数（非危険TLD）

        if benign_reduction > 0:
            original_score = risk_score
            risk_score = max(0.0, risk_score - benign_reduction)
            # benign reductionが適用されたことを記録
            if risk_score < original_score:
                detected_issues.append("benign_cert_mitigation")
                details["benign_reduction"] = benign_reduction
                details["original_risk_score"] = original_score

    # --- 4. 正規ドメインホワイトリストによる緩和 ---------------------------
    risk_score = _mitigate_score_for_legit_domain(domain, detected_issues, risk_score, details)

    # --- 5. Reasoning 生成 --------------------------------------------------
    reason_bits: List[str] = []

    if "self_signed" in detected_issues:
        reason_bits.append("Self-signed certificate")
    if is_free_ca:
        reason_bits.append("Issued by free/low-assurance CA")
    if not has_org:
        reason_bits.append("No organization (O=) field in subject")
    if no_san:
        reason_bits.append("No SAN entries")
    if is_short_term:
        reason_bits.append(f"Short validity period ({valid_days} days ≤ {short_term_days})")
    if "many_san" in detected_issues:
        reason_bits.append(f"Many SAN entries on dangerous TLD (san_count={san_count})")
    if "wildcard" in detected_issues:
        reason_bits.append("Wildcard certificate on dangerous TLD")
    if "legitimate_domain_mitigation" in detected_issues:
        reason_bits.append("Domain is in legitimate whitelist; certificate risk mitigated")

    # 新規: Benign indicators の reasoning
    benign_bits: List[str] = []
    if "has_crl_dp" in benign_indicators:
        benign_bits.append("Has CRL Distribution Points")
    if "ov_ev_cert" in benign_indicators:
        benign_bits.append("OV/EV certificate (has Organization)")
    if "wildcard_cert" in benign_indicators:
        benign_bits.append("Wildcard cert (non-dangerous TLD)")
    if "long_validity" in benign_indicators:
        benign_bits.append(f"Long validity ({valid_days} days)")
    if "high_san_count" in benign_indicators:
        benign_bits.append(f"High SAN count ({san_count}, non-dangerous TLD)")
    if "benign_cert_mitigation" in detected_issues:
        benign_bits.append("Certificate risk mitigated by benign indicators")

    if not reason_bits and not benign_bits:
        reason_bits.append("No significant certificate risk indicators found")

    reasoning = " / ".join(reason_bits) if reason_bits else ""
    if benign_bits:
        benign_str = " / ".join(benign_bits)
        if reasoning:
            reasoning += f" | BENIGN: {benign_str}"
        else:
            reasoning = f"BENIGN: {benign_str}"
    if issuer:
        reasoning += f" / Issuer: {issuer}"

    # details に benign_indicators を追加
    details["benign_indicators"] = benign_indicators

    return {
        "tool_name": "certificate_analysis",
        "detected_issues": detected_issues,
        "benign_indicators": benign_indicators,  # 新規追加
        "risk_score": risk_score,
        "details": details,
        "reasoning": reasoning,
    }



# ------------------------------------------------------------
# Public API
# ------------------------------------------------------------
@safe_tool_wrapper("certificate_analysis")
def certificate_analysis(
    domain: str,
    cert_metadata: Optional[Dict[str, Any]] = None,
    cert_full_info_map: Optional[Dict[str, Any]] = None,
    precheck_hints: Optional[Dict[str, Any]] = None,
    ml_probability: Optional[float] = None,
    strict_mode: bool = False,
    **kwargs: Any,
) -> Dict[str, Any]:
    """Phase3 v1.3 互換の証明書リスク分析ツール（API 互換・内部ロジック強化版）"""
    cert_meta = _pick_cert_from_map(domain, cert_full_info_map) or cert_metadata
    config = _load_cert_config()
    return _analyze_certificate_core(domain, cert_meta, config)
