# 正規ドメインホワイトリスト
# 主要ブランドの公式ドメインを定義
from __future__ import annotations

from typing import Dict, Any, Optional


# ---------------------------------------------------------------------------
# ホワイトリスト定義
# ---------------------------------------------------------------------------
LEGITIMATE_DOMAINS: Dict[str, Dict[str, Any]] = {
    # Global Tech Companies
    "google.com": {"brand": "Google", "type": "official"},
    "amazon.com": {"brand": "Amazon", "type": "official"},
    "apple.com": {"brand": "Apple", "type": "official"},
    "microsoft.com": {"brand": "Microsoft", "type": "official"},
    "facebook.com": {"brand": "Facebook", "type": "official"},
    "meta.com": {"brand": "Meta", "type": "official"},

    # Japanese Companies
    "rakuten.co.jp": {"brand": "Rakuten", "type": "official"},
    "mercari.com": {"brand": "Mercari", "type": "official"},
    "line.me": {"brand": "LINE", "type": "official"},
    "softbank.jp": {"brand": "SoftBank", "type": "official"},
    "docomo.ne.jp": {"brand": "NTT Docomo", "type": "official"},
    "au.com": {"brand": "au/KDDI", "type": "official"},

    # Japanese Financial Institutions
    "mufg.jp": {"brand": "MUFG", "type": "official"},
    "smbc.co.jp": {"brand": "SMBC", "type": "official"},
    "mizuho-fg.co.jp": {"brand": "Mizuho", "type": "official"},
    "resonabank.co.jp": {"brand": "Resona", "type": "official"},
    "japanpost.jp": {"brand": "Japan Post", "type": "official"},

    # Payment Services
    "paypal.com": {"brand": "PayPal", "type": "official"},
    "stripe.com": {"brand": "Stripe", "type": "official"},
    "square.com": {"brand": "Square", "type": "official"},

    # Crypto/Blockchain
    "metamask.io": {"brand": "MetaMask", "type": "official"},
    "binance.com": {"brand": "Binance", "type": "official"},
    "coinbase.com": {"brand": "Coinbase", "type": "official"},
    "kraken.com": {"brand": "Kraken", "type": "official"},
}

# 正規サブドメインパターン
LEGITIMATE_SUBDOMAINS = [
    # Google services
    "accounts.google.com",
    "mail.google.com",
    "drive.google.com",
    "docs.google.com",
    "calendar.google.com",
    "meet.google.com",

    # Amazon services
    "www.amazon.com",
    "smile.amazon.com",
    "aws.amazon.com",
    "sellercentral.amazon.com",

    # Microsoft services
    "login.microsoft.com",
    "outlook.microsoft.com",
    "azure.microsoft.com",
    "docs.microsoft.com",

    # Japanese banks
    "direct.mufg.jp",
    "entry11.bk.mufg.jp",
    "www.smbc.co.jp",
    "direct.smbc.co.jp",
]


# ---------------------------------------------------------------------------
# 内部ユーティリティ
# ---------------------------------------------------------------------------

_MULTI_LEVEL_TLDS = [
    # Japan
    "co.jp", "ne.jp", "or.jp", "ac.jp",
    # UK
    "co.uk", "gov.uk", "ac.uk",
    # Other common multi-level ccTLDs (拡張しやすいようにしておく)
    "com.au", "com.br", "com.cn",
]


def _normalize_registered_domain(domain: str) -> str:
    """eTLD+1 ベースの registered domain を素朴に推定する.

    - まずスキーム・パスを削ってホスト部だけにする
    - よく使われるマルチレベルTLD (.co.jp など) を優先的に扱う
    - それ以外は「最後の2ラベル」を registered domain と見なす
    """
    if not domain:
        return ""

    host = str(domain).strip().lower()
    # scheme / path を除去
    if "://" in host:
        host = host.split("://", 1)[1]
    host = host.split("/", 1)[0].strip(".")

    if not host:
        return ""

    labels = [p for p in host.split(".") if p]
    if not labels:
        return ""

    host_str = ".".join(labels)

    # 1) マルチレベルTLD優先
    for tld in _MULTI_LEVEL_TLDS:
        suffix = "." + tld
        if host_str.endswith(suffix):
            before = host_str[: -len(suffix)].strip(".")
            if not before:
                # まれなケースだが、そのまま返す
                return host_str
            parts = before.split(".")
            return f"{parts[-1]}.{tld}"

    # 2) フォールバック: 最後の2ラベル
    if len(labels) >= 2:
        return ".".join(labels[-2:])
    return labels[0]


def _make_base_result(normalized_domain: str) -> Dict[str, Any]:
    """is_legitimate_domain のデフォルト戻り値を生成."""
    return {
        "is_legitimate": False,
        "brand": None,
        "confidence": 0.0,
        "reason": "not_in_whitelist",
        "normalized_domain": normalized_domain,
        "trust_level": "none",
    }


# ---------------------------------------------------------------------------
# 公開API
# ---------------------------------------------------------------------------

def is_legitimate_domain(domain: str) -> Dict[str, Any]:
    """正規ドメインかどうかを判定する.

    戻り値スキーマ:
        {
            "is_legitimate": bool,
            "brand": Optional[str],
            "confidence": float,
            "reason": str,  # 例: exact_match_official_domain, official_subdomain, ...
            "normalized_domain": str,  # eTLD+1 (例: accounts.google.com -> google.com)
            "trust_level": "strict" | "moderate" | "none",
        }
    """
    domain_lower = (domain or "").strip().lower().strip(".")
    normalized = _normalize_registered_domain(domain_lower)
    result = _make_base_result(normalized)

    if not domain_lower:
        return result

    # --- strict: 明確な公式ドメイン / サブドメイン ------------------------
    # 1) 完全一致 (registered domain 自体が公式)
    if domain_lower in LEGITIMATE_DOMAINS:
        info = LEGITIMATE_DOMAINS[domain_lower]
        result.update(
            is_legitimate=True,
            brand=info.get("brand"),
            confidence=1.0,
            reason="exact_match_official_domain",
            normalized_domain=domain_lower,
            trust_level="strict",
        )
        return result

    # 2) www エイリアス (www.google.com -> google.com)
    if domain_lower.startswith("www."):
        parent = domain_lower[4:]
        if parent in LEGITIMATE_DOMAINS:
            info = LEGITIMATE_DOMAINS[parent]
            result.update(
                is_legitimate=True,
                brand=info.get("brand"),
                confidence=0.99,
                reason="www_alias_official_domain",
                normalized_domain=parent,
                trust_level="strict",
            )
            return result

    # 3) 代表的な「正規サブドメイン」一覧に完全一致
    if domain_lower in LEGITIMATE_SUBDOMAINS:
        # 親ドメインを LEGITIMATE_DOMAINS から推定
        parent_domain: Optional[str] = None
        for off in LEGITIMATE_DOMAINS.keys():
            if domain_lower == off or domain_lower.endswith("." + off):
                parent_domain = off
                break

        if parent_domain:
            info = LEGITIMATE_DOMAINS[parent_domain]
            result.update(
                is_legitimate=True,
                brand=info.get("brand"),
                confidence=0.99,
                reason="official_subdomain",
                normalized_domain=parent_domain,
                trust_level="strict",
            )
            return result

    # 4) registered_domain (eTLD+1) が公式ドメイン
    if normalized in LEGITIMATE_DOMAINS:
        info = LEGITIMATE_DOMAINS[normalized]
        result.update(
            is_legitimate=True,
            brand=info.get("brand"),
            confidence=0.98,
            reason="official_registered_domain",
            normalized_domain=normalized,
            trust_level="strict",
        )
        return result

    # --- moderate: かなり正規に近いが、ややゆるいパターン ---------------
    # 例: amazon.co.jp / google.co.uk など country TLD バリエーション
    country_tlds = ["co.jp", "co.uk", "de", "fr", "ca", "in", "cn"]
    major_brand_map = {
        "amazon": "Amazon",
        "google": "Google",
        "microsoft": "Microsoft",
        "apple": "Apple",
        "paypal": "PayPal",
    }

    host = domain_lower
    brand_label: Optional[str] = None
    brand_tld: Optional[str] = None

    for tld in country_tlds:
        suffix = "." + tld
        if host.endswith(suffix):
            before = host[: -len(suffix)].strip(".")
            if not before:
                continue
            parts = before.split(".")
            candidate = parts[-1]
            if candidate in major_brand_map:
                brand_label = candidate
                brand_tld = tld
                break

    if brand_label and brand_tld:
        brand_name = major_brand_map[brand_label]
        normalized_candidate = f"{brand_label}.{brand_tld}"
        result.update(
            is_legitimate=True,
            brand=brand_name,
            confidence=0.90,
            reason="major_brand_country_tld",
            normalized_domain=normalized_candidate,
            trust_level="moderate",
        )
        return result

    # --- ホワイトリスト外 -----------------------------------------------
    return result


def should_skip_llm_check(
    domain: str,
    ml_probability: float,
    precheck_hints: Optional[Dict[str, Any]] = None,
) -> bool:
    """LLM チェックをスキップすべきかどうかを判定する.

    方針:
    - 強いホワイトリスト (trust_level=strict) では積極的にスキップ
      ただし ML のスコアが極端に高い場合 (例: >=0.9) は再確認として LLM を許可
    - moderate では ML が低〜中程度のときだけスキップ
    - ホワイトリスト外ドメインでは "ML 確率が低い" だけを理由にスキップしない
    """
    info = is_legitimate_domain(domain)
    trust = info.get("trust_level", "none")
    try:
        conf = float(info.get("confidence", 0.0) or 0.0)
    except Exception:
        conf = 0.0
    try:
        p = float(ml_probability or 0.0)
    except Exception:
        p = 0.0

    # 1) strict な正規ドメインは原則スキップ
    if trust == "strict" and conf >= 0.98:
        # ただし ML が 0.9 以上など、極端に怪しい場合は LLM で再確認してもよい
        if p < 0.9:
            return True

    # 2) moderate な正規ドメイン
    if trust == "moderate" and conf >= 0.90:
        # ML が低〜中程度なら LLM スキップしてもよい
        if p < 0.5:
            return True

    # 3) precheck_hints を使った将来拡張のフック
    # 例: quick_risk が極端に低い場合は追加でスキップする、など。
    # （現時点では安全側のため使用しない）
    _ = precheck_hints  # unused for now

    # 4) それ以外（ホワイトリストに載らないドメイン）は
    #    「ホワイトリストだけを理由に LLM を止めない」
    return False


# Export functions
__all__ = [
    "LEGITIMATE_DOMAINS",
    "LEGITIMATE_SUBDOMAINS",
    "is_legitimate_domain",
    "should_skip_llm_check",
]


# ---------------------------------------------------------------------------
# 簡易セルフテスト
# ---------------------------------------------------------------------------

def _self_test() -> None:
    tests = [
        ("google.com", 0.05),
        ("accounts.google.com", 0.30),
        ("amazon.co.jp", 0.40),
        ("example.net", 0.02),
        ("my-ledger-secure.com", 0.02),
        ("paypal.com", 0.95),
    ]
    for dom, p in tests:
        info = is_legitimate_domain(dom)
        skip = should_skip_llm_check(dom, p)
        print(
            f"{dom:25s} p={p:.2f} -> "
            f"legit={info['is_legitimate']}, "
            f"trust={info.get('trust_level')}, "
            f"conf={info.get('confidence'):.2f}, "
            f"skip_llm={skip}, "
            f"normalized={info.get('normalized_domain')} "
            f"reason={info.get('reason')}"
        )


if __name__ == "__main__":
    _self_test()
