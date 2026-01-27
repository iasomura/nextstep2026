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
# ---------------------------------------------------------------------
# Change history
# - 2026-01-03: dvguard4 - Added guard for very short brand keywords (<=3)
#               to avoid false positives from substring/compound matches.
# - 2026-01-18: FN救済強化
#   - 編集距離2までのタイポスクワッティング検出を追加（長いブランドのみ）
#   - サブストリングマッチングの条件緩和（prefix+suffix合計6文字まで）
#   - 日本語ブランドキーワードの拡充（jibunbank, aiful等）
# - 2026-01-19: TLD fuzzyマッチング除外バグ修正
#   - TLD（com, net等）をfuzzyマッチングから除外
#   - "com" → "acom" (edit distance 1) などの誤検知を防止
#   - COMMON_TLDS_FOR_FUZZY_EXCLUSION を追加
# - 2026-01-24: CRITICAL_BRAND_KEYWORDS に国際ブランド追加 (FN削減)
#   - ポルトガル/フランス/スペイン/北米/配送/暗号通貨/欧州銀行/セキュリティ
# - 2026-01-25: ブランド検出→phishing判定強化 (FN削減)
#   - _base_score_from_match() に has_critical_brand フラグ追加
#   - CRITICAL_BRAND_KEYWORDS検出 + 非正規ドメインで最低リスクスコア保証
#   - 危険TLD + critical_brand で最低0.50、それ以外で最低0.40
# - 2026-01-25: CRITICAL_BRAND_KEYWORDS に日本の銀行追加 (FN分析: meiosbi-jp.icu等)
#   - sbi, mufg, mizuho, resona, suruga を追加
# ---------------------------------------------------------------------

from __future__ import annotations

from typing import Any, Dict, List, Tuple, Optional
import json
import os

try:
    from pydantic import BaseModel, Field, confloat, constr  # type: ignore
except Exception:  # pragma: no cover
    # pydantic v1 fallback
    from pydantic.v1 import BaseModel, Field, confloat, constr  # type: ignore

try:
    from ..agent_foundations import StructuredOutputError  # type: ignore
except Exception:  # pragma: no cover
    class StructuredOutputError(Exception):  # type: ignore
        """Structured Output error (local fallback for brand tool)."""
        pass

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
# Common TLDs to exclude from fuzzy brand matching - 2026-01-19
# ---------------------------------------------------------------------------
# These TLDs should not be matched with fuzzy/fuzzy2 rules to prevent
# false positives like "com" → "acom" (edit distance 1).
# Note: exact matching is still allowed (e.g., if a brand is literally "co").

COMMON_TLDS_FOR_FUZZY_EXCLUSION = frozenset([
    # Generic TLDs
    "com", "net", "org", "edu", "gov", "mil", "int",
    # Country code TLDs (common)
    "co", "io", "ai", "me", "us", "uk", "de", "jp", "cn", "ru", "br", "fr",
    "in", "au", "ca", "es", "it", "nl", "pl", "kr", "tw", "hk", "sg",
    # New gTLDs (common)
    "info", "biz", "xyz", "top", "online", "site", "tech", "app", "dev",
    "shop", "store", "club", "cloud", "live", "pro", "fun", "link", "work",
    "news", "blog", "web", "asia", "mobi", "tel", "name", "coop", "museum",
])

# ---------------------------------------------------------------------------
# Boundary-required brand keywords (FP対策) - 2026-01-26
# ---------------------------------------------------------------------------
# These short brand keywords frequently cause false positives when matched
# as substrings of common English words:
#   - "line" → "online", "frontlines", "doxycycline"
#   - "ing" → "dating", "learning", "finishing"
#   - "au" → "auto", "australia", "glaucoma"
#   - "ups" → "pushups", "startups", "upshift"
#   - "visa" → "visajourney", "advisor"
#   - "ana" → "banana", "analysis", "americana"
#   - "chase" → "purchase"
# For these keywords, we require word boundary matching (preceded/followed by
# non-alphanumeric or string boundary) to reduce FP.
# Note: exact token match (e.g., token="line" brand="line") is always allowed.

BOUNDARY_REQUIRED_BRANDS = frozenset([
    "line", "ing", "au", "ups", "visa", "ana", "chase",
])

# Common words that contain these brands as substrings (FP exclusion list)
# If the token matches one of these common words, we skip the brand match.
BRAND_FP_EXCLUSION_WORDS = frozenset([
    # "line" false positives
    "online", "frontline", "frontlines", "hotline", "pipeline", "deadline",
    "headline", "guideline", "timeline", "streamline", "airline", "outline",
    "baseline", "byline", "dateline", "beeline", "mainline", "hairline",
    "feline", "canine", "bovine", "equine", "saline", "oline", "aline",
    "doxycycline", "gasoline", "trampoline", "crystalline", "discipline",
    # "ing" false positives (common -ing words)
    "dating", "learning", "finishing", "sporting", "changing", "building",
    "marketing", "shopping", "banking", "trading", "hosting", "listing",
    "meeting", "parking", "betting", "booking", "cooking", "drinking",
    "working", "spring", "string", "thing", "king", "ring", "wing", "sing",
    # "au" false positives
    "auto", "audio", "australia", "australian", "austria", "authentic",
    "author", "authority", "autumn", "beautiful", "because", "caught",
    "daughter", "fault", "fraud", "gauge", "haul", "launch", "laundry",
    "pause", "sauce", "vault", "restaurant", "bureau", "plateau", "chateau",
    "glaucoma", "aurora", "aurus", "audit", "audience",
    # "ups" false positives
    "pushups", "situps", "pullups", "startups", "backups", "checkups",
    "coverups", "followups", "grownups", "lineups", "linkups", "makeups",
    "markups", "meetups", "mixups", "pickups", "pileups", "popups",
    "roundups", "setups", "signups", "standups", "upshift", "upstream",
    "upside", "upstate", "update", "upgrade", "upload", "upscale",
    # "visa" false positives
    "advisor", "advisory", "ivisable", "advisable", "visar", "visage",
    "visajourney", "visapro",
    # "ana" false positives
    "banana", "analysis", "analyst", "analyze", "americana", "manager",
    "manage", "management", "anagram", "analog", "analogy", "anatomy",
    "anarchy", "panacea", "canadapost", "montana", "indiana", "louisiana",
    # "chase" false positives
    "purchase", "purchaser", "purchases",
])

# ---------------------------------------------------------------------------
# Critical brand keywords (static fallback) - 2026-01-18
# ---------------------------------------------------------------------------
# These brands are always checked, even if not in the dynamic brand_keywords list.
# FN分析で検出漏れが確認されたブランドを追加。
# 変更履歴:
#   - 2026-01-24: 国際ブランド追加 (ポルトガル/フランス/スペイン/北米/配送/暗号通貨)

CRITICAL_BRAND_KEYWORDS = frozenset([
    # 日本の金融機関（FN分析より）
    "jibunbank", "jibun",  # じぶん銀行
    "aiful",               # アイフル
    "acom",                # アコム
    "promise", "smbc",     # プロミス/SMBC
    "rakutenbank", "rakuten",  # 楽天銀行/楽天
    "paypay",              # PayPay
    # 2026-01-25追加: FN分析 (meiosbi-jp.icu等)
    # 2026-01-26更新: "sbi" を短いキーワード許可リストから除外、代替追加
    "sbi", "sbisec", "sbinet", "sbibank", "netbksbi",  # SBI証券/住信SBIネット銀行
    "mufg",                # 三菱UFJ銀行
    "mizuho",              # みずほ銀行
    "resona",              # りそな銀行
    "suruga",              # スルガ銀行
    # 2026-01-26追加: FN分析より (vpass, shinkansen, mercari等)
    "vpass", "vpasso",     # 三井住友VISAカード VPass
    "shinkansen",          # 新幹線 (JR偽装)
    "mercari", "merucari", # メルカリ (typo含む)
    "ekinet", "eki-net",   # えきねっと
    "coincheck",           # コインチェック

    # グローバルサービス（FN分析より）
    "telegram",            # Telegram
    "zoom",                # Zoom
    "coinbase",            # Coinbase
    "binance",             # Binance
    "metamask",            # MetaMask
    "ledger",              # Ledger

    # 配送・物流（FN分析より）
    "sagawa", "kuroneko", "yamato",  # 佐川/ヤマト
    "japanpost", "yuubin",           # 日本郵便
    "nzta",                          # NZ Transport Agency

    # その他よく偽装されるブランド
    "americanexpress", "amex",  # American Express
    "mastercard", "visa",       # クレジットカード
    "instagram", "whatsapp",    # Meta系
    "tiktok", "wechat",         # SNS

    # --- 2026-01-24 追加: 国際ブランド (FN分析より) ---

    # ポルトガル語圏 (CGD, Millennium BCP 等)
    "cgd", "caixageral", "millenniumbcp", "novobanco",
    "multibanco", "mbway", "ctt", "cttexpresso",

    # フランス語圏 (La Poste, Crédit Agricole 等)
    "laposte", "banquepostale", "creditagricole",
    "societegenerale", "caissedepargne",
    "ameli", "impots", "colissimo", "chronopost",
    "creditmutuel", "banquepopulaire",

    # スペイン語圏 (BBVA, CaixaBank, Correos 等)
    "caixabank", "correos", "movistar", "endesa",
    "agenciatributaria", "bizum",

    # 北米追加 (EZ Pass, IRS, 通信事業者等)
    "ezpass", "sunpass", "ipass", "tollway",
    "costco", "walmart", "target", "bestbuy",
    "verizon", "tmobile", "zelle", "venmo", "cashapp",
    "fidelity", "schwab", "robinhood",

    # 配送・物流 (グローバル)
    "postnl", "hermes", "evri", "dpd", "gls",
    "deutschepost", "bpost", "posteitaliane",
    "correios", "auspost", "canadapost",

    # ストリーミング
    "disney", "disneyplus", "hulu", "hbomax",

    # フィンテック
    "revolut", "wise", "monzo", "klarna", "chime",

    # 暗号通貨追加
    "phantom", "solana", "uniswap", "opensea",
    "trezor", "kucoin", "bybit", "okx",
    "pancakeswap", "raydium",
    # 2026-01-25追加: FN分析 (etherwallet.mobilelab.vn等)
    "etherwallet", "myetherwallet", "ethereum", "ether",
    "trustwallet", "atomicwallet", "exoduswallet",

    # 欧州銀行
    "barclays", "natwest", "nationwide", "halifax",
    "commerzbank", "nordea", "danske", "swedbank",

    # セキュリティ・認証
    "okta", "lastpass", "protonmail",

    # --- 2026-01-25 追加: 主要ブランド欠落の修正 ---
    # 変更履歴:
    #   - 2026-01-25: amazon-account-server.com FN発見により追加

    # Amazon/AWS
    "amazon", "aws", "amazonprime", "amazonseller",

    # Apple
    "apple", "icloud", "appleid", "itunes", "appstore",

    # Microsoft
    "microsoft", "outlook", "office365", "onedrive", "azure",
    "hotmail", "msn", "skype", "xbox", "linkedin",

    # Google
    "google", "gmail", "googledrive", "googlecloud", "gcp",
    "youtube", "android",

    # Meta/Facebook
    "facebook", "meta", "messenger",

    # Other major tech
    "netflix", "spotify", "twitter", "dropbox", "adobe",
    "salesforce", "oracle", "sap", "servicenow",

    # PayPal & major payment
    "paypal", "stripe", "square",

    # US banks
    "chase", "jpmorgan", "bankofamerica", "bofa",
    "wellsfargo", "citibank", "citi", "usbank",
    "capitalone", "pnc", "truist",

    # HSBC & global banks
    "hsbc", "ubs", "creditsuisse", "ing", "santander",

    # Shipping (major)
    "ups", "fedex", "dhl", "usps",

    # E-commerce
    "ebay", "aliexpress", "alibaba", "shopify", "etsy",

    # Yahoo
    "yahoo", "aol",

    # --- 2026-01-26 追加: FN分析より ---
    # 変更履歴:
    #   - 2026-01-26: citifinanceswiftbank.com, whatsapp-jq.com 等のFN対応

    # 金融機関追加
    "citi", "citibank", "citigroup", "swift",

    # 政府機関偽装パターン
    # 注: "ato" は aviator, elevator 等で誤検出するため除外
    # "irs" は短すぎて first,airs 等で誤検出の可能性あり
    "courts", "judiciary", "hmrc", "revenue",

    # 通信/SNS追加
    # 注: "line" は "online" と誤検出するため除外
    # LINE は "linemessenger", "lineapp", "linepay" 等で検出
    "linemessenger", "lineapp", "linepay", "viber", "signal",
])

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

def _ed_le2(a: str, b: str) -> bool:
    """Lightweight edit-distance<=2 check for typosquatting detection."""
    if a == b:
        return True
    la, lb = len(a), len(b)
    if abs(la - lb) > 2:
        return False
    # Full DP for edit distance (small strings)
    return _calculate_edit_distance(a, b) <= 2


def _check_brand_substring(token: str, brand: str, *, is_tld: bool = False) -> Tuple[bool, str]:
    """
    Check five match types between a token and a brand keyword:
    - exact
    - substring
    - fuzzy (edit distance <=1)
    - fuzzy2 (edit distance <=2, for brands >= 6 chars) [2026-01-18追加]
    - compound (brand embedded with extra chars)

    Args:
        token: The token from the domain to check
        brand: The brand keyword to match against
        is_tld: If True, skip fuzzy matching to prevent false positives like "com" → "acom"

    変更履歴:
      - 2026-01-26: BOUNDARY_REQUIRED_BRANDS による FP 削減
                   "line", "ing", "au" 等の短いキーワードは一般英単語に含まれやすいため、
                   BRAND_FP_EXCLUSION_WORDS に該当するトークンではマッチをスキップ
    """
    token = token or ""
    brand = brand or ""
    if not token or not brand:
        return False, ""

    # exact
    if token == brand:
        return True, "exact"

    # dvguard4: For very short brand keywords (<=3 chars),
    # avoid substring/compound matches inside unrelated words (e.g., "att" in "attack").
    # Only exact token matches are considered reliable at this length.
    # 2026-01-25: CRITICAL_BRAND_KEYWORDS に含まれる短いブランド (sbi等) は例外的に許可
    # 2026-01-26: FP分析より "sbi" を除外 (sbigblog, sbiketraders等で誤検出)
    #             "ups" は BOUNDARY_REQUIRED_BRANDS でカバー
    _short_critical_brands = {"dhl", "irs", "nhs", "rbc", "bmo", "td"}
    if len(brand) <= 3 and brand not in _short_critical_brands:
        return False, ""

    # 2026-01-26: FP削減 - BOUNDARY_REQUIRED_BRANDS のキーワードは境界チェック厳格化
    # トークンが一般的な英単語に含まれる場合はマッチをスキップ
    if brand in BOUNDARY_REQUIRED_BRANDS:
        # トークン全体が FP 除外リストに含まれる場合はスキップ
        if token in BRAND_FP_EXCLUSION_WORDS:
            return False, ""
        # トークンが除外リストの単語を含む場合もスキップ (e.g., "onlinestore" contains "online")
        for excl_word in BRAND_FP_EXCLUSION_WORDS:
            if excl_word in token and brand in excl_word:
                return False, ""

    # 2026-01-19: Skip fuzzy matching for TLDs to prevent false positives
    # (e.g., "com" → "acom" with edit distance 1)
    # Substring and compound matching are still allowed for TLDs.
    skip_fuzzy = is_tld or (token in COMMON_TLDS_FOR_FUZZY_EXCLUSION)

    # substring (token contains brand with small prefix/suffix)
    # 2026-01-18: 条件緩和 prefix+suffix <= 6 (was 4)
    if len(token) > len(brand) and brand in token:
        idx = token.find(brand)
        prefix_len = idx
        suffix_len = len(token) - idx - len(brand)
        if prefix_len + suffix_len <= 6:
            return True, "substring"

    # fuzzy (strict) - edit distance 1
    # 2026-01-26: 短いブランド(< 6文字)でのFPを防ぐため、最低6文字を要求
    # 例: "gonzo" → "monzo" は誤検出のため除外
    # ただし、先頭文字が一致する場合は5文字でも許可 (例: "paypl" → "paypal")
    _fuzzy_allowed = (
        not skip_fuzzy
        and (
            len(brand) >= 6
            or (len(brand) >= 5 and len(token) >= 5 and token[0] == brand[0])
        )
    )
    if _fuzzy_allowed and _ed_le1(token, brand):
        return True, "fuzzy"

    # fuzzy2 (2026-01-18追加) - edit distance 2 for longer brands
    # タイポスクワッティング: amaznoeom → amazon, americaexpre → americanexpress
    # 短いブランドでの誤検知を防ぐため、brand >= 6文字の場合のみ
    if not skip_fuzzy and len(brand) >= 6 and _ed_le2(token, brand):
        return True, "fuzzy2"

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
        max_tokens = int(llm_cfg.get('brand_max_tokens') or llm_cfg.get('max_tokens') or 256)
        # Brand tool は短い SO 応答だけ欲しいので max_tokens を小さく固定
        return ChatOpenAI(
            model=model,
            base_url=base_url,
            api_key=api_key,
            temperature=temperature,
            max_tokens=max_tokens,
            # Qwen3 thinking モードを無効化
            extra_body={"chat_template_kwargs": {"enable_thinking": False}},
        )
    except Exception:
        return None


class BrandDetectionSO(BaseModel):
    """Structured Output schema for brand impersonation detection.

    Important:
    - evidence_token MUST be an exact substring (case-insensitive) found in the domain.
      (Do not invent tokens. If none exists, set evidence_token=null and is_brand_impersonation=false.)
    - Keep reasoning short (1-2 sentences).
    """

    is_brand_impersonation: bool = Field(
        description="Whether this domain is impersonating a known brand."
    )
    detected_brand: Optional[str] = Field(
        default=None,
        description="Detected brand name, or null if none.",
    )
    evidence_token: Optional[constr(min_length=3, max_length=60)] = Field(
        default=None,
        description=(
            "Evidence token taken from the domain labels (must appear in the domain as a substring)."
        ),
    )
    confidence: confloat(ge=0.0, le=1.0) = Field(
        default=0.0,
        description="Confidence in the impersonation judgement (0.0-1.0).",
    )
    reasoning: constr(min_length=10, max_length=360) = Field(
        default="",
        description="Short explanation for the decision.",
    )


def _llm_brand_detect(
    domain: str,
    brands_sample: List[str],
    ml_probability: float,
    *,
    config_path: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """
    Ask the LLM to judge brand impersonation via Structured Output.

    - Returns a normalized dict on success:
        {
            "detected": bool,
            "brand": Optional[str],
            "confidence": float,
            "reasoning": str,
            "method": "llm_so",
        }
    - Returns None when the LLM client is not available / disabled.
    - Raises StructuredOutputError when Structured Output cannot be executed or validated.
    """
    llm = _load_llm_client(config_path)
    # LLM クライアントが無効 / 未設定の場合は、従来どおり LLM を使わずに None を返す
    if llm is None:
        return None

    # SO をサポートしていない LLM はエラー扱いにする
    if not hasattr(llm, "with_structured_output"):
        raise StructuredOutputError(
            "LLM client does not support with_structured_output for brand detection",
        )

    sys_text = (
        "You are a cybersecurity analyst specializing in phishing and brand impersonation detection.\n"
        "Return ONLY a BrandDetectionSO object.\n"
        "Rules (strict):\n"
        "- evidence_token must be an exact substring found in the domain (case-insensitive).\n"
        "- If you cannot point to an evidence_token, set is_brand_impersonation=false and detected_brand=null.\n"
        "- Keep reasoning to 1-2 short sentences.\n"
    )

    user_payload = {
        "domain": domain,
        "domain_labels": _split_labels(domain),
        "ml_probability": float(ml_probability or 0.0),
        "brand_keywords_sample": list(brands_sample or [])[:24],
        "instructions": [
            "If the domain is impersonating a brand, set is_brand_impersonation=true.",
            "If you set is_brand_impersonation=true, you MUST also provide evidence_token (a substring found in the domain) and detected_brand.",
            "Treat official / legitimate domains as NOT impersonation.",
            "Consider typosquatting and extra words like secure/login/verify.",
        ],
    }

    messages = [
        {"role": "system", "content": sys_text},
        {"role": "user", "content": json.dumps(user_payload, ensure_ascii=False)},
    ]

    try:
        chain = llm.with_structured_output(BrandDetectionSO)  # type: ignore[attr-defined]
    except Exception as e:
        raise StructuredOutputError(
            f"Failed to initialize structured output chain for brand detection: {e}",
        ) from e

    try:
        so = chain.invoke(messages)  # type: ignore[assignment]
    except Exception as e:
        raise StructuredOutputError(
            f"Structured output invocation for brand detection failed: {e}",
        ) from e

    # 通常は BrandDetectionSO インスタンスだが、dict が返ってきた場合も受ける
    if isinstance(so, BrandDetectionSO):
        parsed = so
    elif isinstance(so, dict):
        try:
            parsed = BrandDetectionSO(**so)
        except Exception as e:
            raise StructuredOutputError(
                f"LLM returned a dict that does not conform to BrandDetectionSO: {e}",
            ) from e
    else:
        raise StructuredOutputError(
            f"LLM returned an unexpected type for BrandDetectionSO: {type(so)!r}",
        )

    return {
        "detected": bool(parsed.is_brand_impersonation),
        "brand": (parsed.detected_brand or None),
        "evidence_token": (getattr(parsed, "evidence_token", None) or None),
        "confidence": float(parsed.confidence),
        "reasoning": str(parsed.reasoning or ""),
        "method": "llm_so",
    }


# ---------------------------------------------------------------------------
# Core logic (no safe_tool_wrapper here)
# ---------------------------------------------------------------------------

def _normalize_brand_list(brand_keywords: List[str], potential_brands: Optional[List[str]]) -> List[str]:
    """
    Normalize and deduplicate brand candidates (dynamic + precheck + critical static).
    2026-01-18: CRITICAL_BRAND_KEYWORDS を常に含めるよう変更
    """
    seen: set[str] = set()
    out: List[str] = []

    # 1. Dynamic brand keywords from training
    for src in (brand_keywords or []):
        b = _normalize_token(str(src))
        if b and b not in seen:
            seen.add(b)
            out.append(b)

    # 2. Potential brands from precheck
    for src in (potential_brands or []):
        b = _normalize_token(str(src))
        if b and b not in seen:
            seen.add(b)
            out.append(b)

    # 3. Critical static brands (always included) - 2026-01-18
    for src in CRITICAL_BRAND_KEYWORDS:
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

    # Identify the TLD (last label) for fuzzy matching exclusion
    # 2026-01-19: TLDはfuzzyマッチングから除外して "com" → "acom" などの誤検知を防ぐ
    tld_label = labels[-1] if labels else ""

    for label in labels:
        is_tld_label = (label == tld_label)
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
                is_match, mtype = _check_brand_substring(tok, brand, is_tld=is_tld_label)
                if not is_match:
                    continue
                # Edit distance for diagnostics
                ed = 0
                if mtype in ("fuzzy", "fuzzy2", "substring", "compound"):
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

def _base_score_from_match(rule_hits: List[Dict[str, Any]]) -> Tuple[float, str, bool]:
    """
    Decide base risk score and dominant match_type from rule hits.
    Priority: exact > substring/compound > fuzzy > fuzzy2.

    Returns:
        (base_score, match_type, has_critical_brand)
        has_critical_brand: True if any matched brand is in CRITICAL_BRAND_KEYWORDS

    変更履歴:
      - 2026-01-25: CRITICAL_BRAND_KEYWORDS検出フラグを戻り値に追加（FN削減）
    """
    has_exact = any(h.get("match_type") == "exact" for h in rule_hits)
    has_sub = any(h.get("match_type") == "substring" for h in rule_hits)
    has_comp = any(h.get("match_type") == "compound" for h in rule_hits)
    has_fuzzy = any(h.get("match_type") == "fuzzy" for h in rule_hits)
    has_fuzzy2 = any(h.get("match_type") == "fuzzy2" for h in rule_hits)

    # 2026-01-25: CRITICAL_BRAND_KEYWORDS に含まれるブランドが検出されたかチェック
    has_critical_brand = False
    for h in rule_hits:
        brand_norm = _normalize_token(h.get("brand", "") or "")
        if brand_norm in CRITICAL_BRAND_KEYWORDS:
            has_critical_brand = True
            break

    if has_exact:
        return 0.40, "exact", has_critical_brand
    if has_sub or has_comp:
        return 0.35, "substring" if has_sub else "compound", has_critical_brand
    if has_fuzzy:
        return 0.30, "fuzzy", has_critical_brand
    # fuzzy2: 編集距離2のタイポスクワッティング（やや弱めのスコア）
    if has_fuzzy2:
        return 0.28, "fuzzy2", has_critical_brand
    return 0.0, "none", False

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

    # If we have no brand keywords, we can still run the LLM (LLM-first mode)
    no_brand_keywords = not brands_norm
    if no_brand_keywords and not use_llm:
        details = {
            'detected_brands': [],
            'match_type': 'none',
            'rule_hits': [],
            'whitelist': whitelist_info,
            'used_llm': False,
            'llm_confidence': None,
            'llm_reasoning': None,
            'issue_flags': ['no_brand_keywords'],
            'precheck': {
                'ml_probability': ml_p,
                'ml_category': ml_category,
                'tld_category': tld_category,
                'domain_length_category': domain_length_category,
                'quick_risk': quick_risk,
                'ml_paradox_flag_from_precheck': ml_paradox_flag,
            },
        }
        return {
            'tool_name': 'brand_impersonation_check',
            'detected_issues': ['no_brand_keywords'],
            'risk_score': 0.0,
            'details': details,
            'reasoning': 'No brand keywords available and LLM is disabled; cannot evaluate brand impersonation.',
        }

    # --- Rule-based detection -----------------------------------------------
    rule_hits, detected_brands = _compute_rule_matches(domain, brands_norm)
    base_score, match_type, has_critical_brand = _base_score_from_match(rule_hits)

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
        elif match_type == "fuzzy2":
            detected_issues.append("brand_fuzzy2")
            detected_issues.append("brand_typosquat")  # タイポスクワッティング検出フラグ

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

        # 2026-01-25: CRITICAL_BRAND_KEYWORDS検出時の最低リスクフロア強化
        # FN分析より、ブランド検出 + 非正規ドメインなのにphishing判定に至らなかったケースが26件。
        # CRITICAL_BRAND_KEYWORDS に該当するブランドが検出された場合、
        # 非正規ドメインでは最低リスクスコアを保証する。
        if has_critical_brand and risk_adjustment >= 1.0:
            # 危険TLDの場合はさらに高い最低スコア
            if tld_category == "dangerous":
                risk_score = max(risk_score, 0.50)
                if "critical_brand_dangerous_tld" not in detected_issues:
                    detected_issues.append("critical_brand_dangerous_tld")
            else:
                risk_score = max(risk_score, 0.40)
            if "critical_brand" not in detected_issues:
                detected_issues.append("critical_brand")
    else:
        risk_score = 0.0

    # --- Optional LLM detection ---------------------------------------------
    # LLM-first 方針: ルールで拾えないケース（辞書漏れ）を埋める用途。
    # - ルールで brand_detected が立っている場合は LLM を追加で呼ばない
    # - evidence_token がドメインに存在しない場合は「不採用」
    llm_evidence_token: Optional[str] = None
    llm_detected_brand: Optional[str] = None
    llm_match_distance: Optional[int] = None
    llm_match_ratio: Optional[float] = None
    llm_candidate_quality: Optional[str] = None  # confirmed/suspected/rejected/none

    rules_found = (base_score > 0.0) or ("brand_detected" in detected_issues)
    # "suspected" 判定は confirmed よりも広く拾うが、FP を増やしやすい。
    # そのため「precheck 上の怪しさ」がある場合だけ、やや低い confidence でも疑いとして採用する。
    # - quick_risk の閾値を少し下げる
    # - ML が中低域（<0.5）でも疑いとして拾えるようにする
    precheck_suspicious = (
        (tld_category in ("dangerous", "unknown"))
        or (domain_length_category in ("very_short", "short"))
        or (quick_risk is not None and float(quick_risk) >= 0.45)
        or (ml_p is not None and float(ml_p) < 0.50)
    )
    # suspected 用の最低 confidence（confirmed とは別）
    # llm_threshold を尊重しつつ、0.48〜0.55 の範囲に収める
    if llm_threshold:
        suspect_threshold = max(0.48, min(0.55, float(llm_threshold) - 0.12))
    else:
        suspect_threshold = 0.55

    if (
        use_llm
        and not rules_found
        and not should_skip_llm_check(domain, ml_p)
    ):
        try:
            # brands_norm が空でも LLM は動作（辞書無し運用のため）
            llm_raw = _llm_brand_detect(domain, brands_norm, ml_p, config_path=config_path)
            if llm_raw:
                used_llm = True
                llm_confidence = float(llm_raw.get("confidence", 0.0) or 0.0)
                llm_reasoning = (llm_raw.get("reasoning") or "")[:320] or None

                llm_detected_brand = (llm_raw.get("brand") or None)
                llm_evidence_token = (llm_raw.get("evidence_token") or None)

                dom_norm = _normalize_token(domain)
                ev_norm = _normalize_token(llm_evidence_token or "")
                br_norm = _normalize_token(llm_detected_brand or "")

                evidence_ok = bool(ev_norm and len(ev_norm) >= 3 and ev_norm in dom_norm)
                llm_candidate_quality = "rejected"

                if bool(llm_raw.get("detected")) and evidence_ok and br_norm:
                    ed = _calculate_edit_distance(ev_norm, br_norm)
                    llm_match_distance = int(ed)
                    llm_match_ratio = round(ed / max(len(br_norm), 1), 3)

                    # confirmed: 強い一致（substring noise 小 or ed<=1）+ 高信頼
                    confirmed = (
                        llm_confidence >= float(llm_threshold)
                        and (
                            (ev_norm == br_norm)
                            or (_ed_le1(ev_norm, br_norm))
                            or (br_norm in ev_norm and (len(ev_norm) - len(br_norm) <= 4))
                        )
                    )

                    # suspected: edit distance 2 を許容するが、短いブランドで暴発しないよう比率で制限
                    suspected = (
                        (llm_confidence >= float(suspect_threshold))
                        and precheck_suspicious
                        and (
                            (
                                ed <= 2
                                and (ed / max(len(br_norm), 1)) <= 0.25
                                and abs(len(ev_norm) - len(br_norm)) <= 2
                            )
                            or (br_norm in ev_norm and (len(ev_norm) - len(br_norm) <= 8))
                            or (ev_norm in br_norm and len(ev_norm) >= 5 and (len(br_norm) - len(ev_norm) <= 10))
                        )
                    )

                    if confirmed:
                        llm_candidate_quality = "confirmed"
                        label = (llm_detected_brand or "").strip() or "unknown"
                        label_str = f"{label} (llm_confirmed)"
                        if label_str not in detected_brands:
                            detected_brands.append(label_str)
                        if "brand_detected" not in detected_issues:
                            detected_issues.append("brand_detected")
                        detected_issues.append("brand_llm")
                        detected_issues.append("brand_llm_confirmed")

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
                        match_type = "llm_confirmed"

                    elif suspected:
                        llm_candidate_quality = "suspected"
                        label = (llm_detected_brand or "").strip() or "unknown"
                        label_str = f"{label} (llm_suspected)"
                        if label_str not in detected_brands:
                            detected_brands.append(label_str)
                        detected_issues.append("brand_suspected")
                        detected_issues.append("brand_llm_candidate")

                        # suspected は弱めに加点（単体で high に行かせない）
                        llm_base = 0.18
                        llm_score = _apply_precheck_boosts(
                            llm_base,
                            tld_category=tld_category,
                            domain_length_category=domain_length_category,
                            quick_risk=quick_risk,
                        )
                        llm_score = min(0.32, llm_score)  # 上限
                        llm_score *= risk_adjustment
                        risk_score = max(risk_score, llm_score)
                        match_type = "llm_suspected"

                # evidence_token が無い/不整合なら、品質は rejected のまま
        except Exception as e:
            if fail_on_llm_error:
                raise RuntimeError(f"LLM brand detection failed for {domain}: {e}") from e
            # otherwise: just ignore and continue with rule-based result

    # --- ML paradox for brand -----------------------------------------------
    # NOTE: ml_paradox_brand は「ブランド強検知」があるときだけ発火させる（suspected では暴発しやすい）
    brand_detected_flag = ("brand_detected" in detected_issues) or any("(llm_confirmed)" in b for b in detected_brands)
    brand_suspected_flag = ("brand_suspected" in detected_issues) or any("(llm_suspected)" in b for b in detected_brands)
    brand_found = brand_detected_flag or brand_suspected_flag

    if brand_detected_flag:
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
    detected_issues = list(dict.fromkeys(detected_issues)) if detected_issues else []
    issue_flags = list(detected_issues)

    details: Dict[str, Any] = {
        "detected_brands": detected_brands,
        "match_type": match_type if brand_found else "none",
        "rule_hits": rule_hits,
        "whitelist": whitelist_info,
        "used_llm": used_llm,
        "llm_confidence": llm_confidence,
        "llm_reasoning": llm_reasoning,
        # LLM candidate diagnostics (short & analysis-friendly)
        "llm_detected_brand": llm_detected_brand,
        "llm_evidence_token": llm_evidence_token,
        "llm_match_distance": llm_match_distance,
        "llm_match_ratio": llm_match_ratio,
        "llm_candidate_quality": llm_candidate_quality,
        # convenience flags
        "brand_detected": brand_detected_flag,
        "brand_suspected": brand_suspected_flag,
        "has_critical_brand": has_critical_brand,
        "no_brand_keywords": bool(no_brand_keywords),
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
            joined = ", ".join(detected_brands)
            if brand_detected_flag and not brand_suspected_flag:
                reasoning_parts.append(f"ブランド候補 {joined} を含むドメイン構造を検出")
            elif brand_detected_flag and brand_suspected_flag:
                reasoning_parts.append(f"ブランド候補 {joined} を検出（強/弱混在）")
            else:
                reasoning_parts.append(f"ブランド候補 {joined} を弱く検出（LLM候補）")
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

    # 2026-01-19: Changed to orangejuice.com (unrelated word)
    # pineapple.com now matches apple due to relaxed substring/compound thresholds
    print("[T3] orangejuice.com with brand 'apple' should NOT detect brand (no relation)")
    r3 = brand_impersonation_check(
        domain="orangejuice.com",
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
    assert d3["risk_score"] == 0.0, f"Expected 0.0, got {d3['risk_score']}"
    assert "brand_detected" not in d3["detected_issues"], d3["detected_issues"]
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

    # 2026-01-19: TLD fuzzy matching exclusion test
    print("[T5] TLD should not fuzzy match brands (e.g., 'com' should not match 'acom')")
    r5 = brand_impersonation_check(
        domain="example.com",
        brand_keywords=["acom"],  # brand that is close to TLD "com"
        precheck_hints={
            "tld_category": "legitimate",
            "domain_length_category": "normal",
            "ml_category": "low",
            "ml_paradox": False,
            "quick_risk": 0.0,
        },
        ml_probability=0.1,
        strict_mode=False,
        use_llm=False,
    )
    assert r5.get("success") is True
    d5 = r5["data"]
    # TLD "com" should NOT fuzzy match brand "acom"
    assert d5["risk_score"] == 0.0, f"Expected 0.0 (no TLD fuzzy match), got {d5['risk_score']}"
    assert "brand_detected" not in d5["detected_issues"], f"TLD should not match brand: {d5['detected_issues']}"
    print("  -> OK")

    # But legitimate brand "acom" in SLD should still be detected (on non-legitimate domains)
    # 2026-01-24: example.com is now in Tranco Top 100K, so use a non-Tranco domain
    print("[T6] Brand 'acom' in SLD position should be detected (exact match)")
    r6 = brand_impersonation_check(
        domain="acom.unknownsite99.info",
        brand_keywords=["acom"],
        precheck_hints={
            "tld_category": "dangerous",
            "domain_length_category": "normal",
            "ml_category": "low",
            "ml_paradox": False,
            "quick_risk": 0.0,
        },
        ml_probability=0.1,
        strict_mode=False,
        use_llm=False,
    )
    assert r6.get("success") is True
    d6 = r6["data"]
    assert "brand_detected" in d6["detected_issues"], f"Brand in SLD should be detected: {d6}"
    print("  -> OK")

    print("All brand_impersonation_check tests passed.")

if __name__ == "__main__":  # pragma: no cover
    run_all_tests()
