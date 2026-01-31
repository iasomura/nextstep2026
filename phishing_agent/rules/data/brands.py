# -*- coding: utf-8 -*-
"""
phishing_agent.rules.data.brands
--------------------------------
Brand-related data for phishing detection rules.
"""

from typing import FrozenSet

# Critical brand keywords - always checked for impersonation
# These are high-value targets frequently abused in phishing campaigns.
CRITICAL_BRAND_KEYWORDS: FrozenSet[str] = frozenset([
    # Japanese financial institutions
    "jibunbank", "jibun",  # じぶん銀行
    "aiful",               # アイフル
    "acom",                # アコム
    "promise", "smbc",     # プロミス/SMBC
    "rakutenbank", "rakuten",  # 楽天銀行/楽天
    "paypay",              # PayPay
    "sbi", "sbisec", "sbinet", "sbibank", "netbksbi",  # SBI証券/住信SBIネット銀行
    "mufg",                # 三菱UFJ銀行
    "mizuho",              # みずほ銀行
    "resona",              # りそな銀行
    "suruga",              # スルガ銀行
    "vpass", "vpasso",     # 三井住友VISAカード VPass
    "shinkansen",          # 新幹線 (JR偽装)
    "mercari", "merucari", # メルカリ
    "ekinet", "eki-net",   # えきねっと
    "coincheck",           # コインチェック

    # Global services
    "telegram", "zoom", "coinbase", "binance",
    "metamask", "ledger",

    # Shipping/Logistics - Japan
    "sagawa", "kuroneko", "yamato",  # 佐川/ヤマト
    "japanpost", "yuubin",           # 日本郵便
    "nzta",                          # NZ Transport Agency

    # Credit cards
    "americanexpress", "amex",
    "mastercard", "visa",

    # Social media
    "instagram", "whatsapp", "tiktok", "wechat",

    # Portuguese (CGD, Millennium BCP)
    "cgd", "caixageral", "millenniumbcp", "novobanco",
    "multibanco", "mbway", "ctt", "cttexpresso",

    # French (La Poste, banks)
    "laposte", "banquepostale", "creditagricole",
    "societegenerale", "caissedepargne",
    "ameli", "impots", "colissimo", "chronopost",
    "creditmutuel", "banquepopulaire",

    # Spanish (BBVA, CaixaBank)
    "caixabank", "correos", "movistar", "endesa",
    "agenciatributaria", "bizum",

    # North America (EZ Pass, carriers)
    "ezpass", "sunpass", "ipass", "tollway",
    "costco", "walmart", "target", "bestbuy",
    "verizon", "tmobile", "zelle", "venmo", "cashapp",
    "fidelity", "schwab", "robinhood",

    # Global shipping
    "postnl", "hermes", "evri", "dpd", "gls",
    "deutschepost", "bpost", "posteitaliane",
    "correios", "auspost", "canadapost",

    # Streaming
    "disney", "disneyplus", "hulu", "hbomax",

    # Fintech
    "revolut", "wise", "monzo", "klarna", "chime",

    # Cryptocurrency
    "phantom", "solana", "uniswap", "opensea",
    "trezor", "kucoin", "bybit", "okx",
    "pancakeswap", "raydium",
    "etherwallet", "myetherwallet", "ethereum", "ether",
    "trustwallet", "atomicwallet", "exoduswallet",

    # European banks
    "barclays", "natwest", "nationwide", "halifax",
    "commerzbank", "nordea", "danske", "swedbank",

    # Security/Auth
    "okta", "lastpass", "protonmail",

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

    # Other tech
    "netflix", "spotify", "twitter", "dropbox", "adobe",
    "salesforce", "oracle", "sap", "servicenow",

    # Payment
    "paypal", "stripe", "square",

    # US banks
    "chase", "jpmorgan", "bankofamerica", "bofa",
    "wellsfargo", "citibank", "citi", "usbank",
    "capitalone", "pnc", "truist",

    # Global banks
    "hsbc", "ubs", "creditsuisse", "ing", "santander",

    # Major shipping
    "ups", "fedex", "dhl", "usps",

    # E-commerce
    "ebay", "aliexpress", "alibaba", "shopify", "etsy",

    # Yahoo
    "yahoo", "aol",

    # Government patterns
    "courts", "judiciary", "hmrc", "revenue",

    # Communication apps
    "linemessenger", "lineapp", "linepay", "viber", "signal",
])

# Brands requiring word boundary matching to avoid FP
# These short keywords frequently appear as substrings of common words.
BOUNDARY_REQUIRED_BRANDS: FrozenSet[str] = frozenset([
    "line",   # "online", "frontlines"
    "ing",    # "dating", "learning"
    "au",     # "auto", "australia"
    "ups",    # "pushups", "startups"
    "visa",   # "visajourney", "advisor"
    "ana",    # "banana", "analysis"
    "chase",  # "purchase"
    # 2026-01-28追加
    "citi",      # "cities"
    "swift",     # "swiftly"
    "meta",      # "metadata"
    "hermes",    # "hi-res"
    "appstore",  # "educationalappstore"
    # 2026-01-29追加: fuzzy match FP対策
    "costco",    # "costa"
    "youtube",   # "yourule"
    "laposte",   # "lacoste"
    "sbinet",    # "biznet"
    # 2026-01-29追加: v2評価で発見したFP
    "steam",     # "stream"
    "roblox",    # "oblog"
    "eshop",     # "noodleshop"
    # 2026-01-29追加: #10 fuzzy2 FP対策
    "bestbuy",   # "bitbuy"
    "binance",   # "balance", "finance"
    "usbank",    # "unisbank"
    "signal",    # "sigsac"
    "nordea",    # "norge"
    "shopify",   # "shoppy"
    # 2026-01-29追加: #11 compound/substring FP対策
    "acom",      # "comunicar"
    "wise",      # "worldwise"
    "stripe",    # "stripes"
    "tmobile",   # "xtmobile"
    "promise",   # "americaspromise"
    "disney",    # "disneydriven"
    "mastercard",  # "mastercardfdn"
])

# Common words that contain brand keywords as substrings (FP exclusion)
BRAND_FP_EXCLUSION_WORDS: FrozenSet[str] = frozenset([
    # "line" false positives
    "online", "frontline", "frontlines", "hotline", "pipeline", "deadline",
    "headline", "guideline", "timeline", "streamline", "airline", "outline",
    "baseline", "byline", "dateline", "beeline", "mainline", "hairline",
    "feline", "canine", "bovine", "equine", "saline", "oline", "aline",
    "doxycycline", "gasoline", "trampoline", "crystalline", "discipline",
    # "ing" false positives
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
    # 2026-01-28追加: "citi" false positives
    "cities", "city", "twincities", "citiesorg", "changingcities",
    "publicities", "electricity", "municipality", "velocities", "capacities",
    "simplicities", "atrocities", "audacities", "ferocities",
    # 2026-01-28追加: "swift" false positives
    "swifterm", "swiftly", "swiftness", "swiftui", "swiftkey",
    "swiftmailer", "swiftlang", "swiftpm",
    # 2026-01-28追加: "meta" false positives
    "metaflow", "metadata", "metalwork", "metaphor", "metamorphosis",
    "metasploit", "metatag", "metaverse", "metabase", "metabolism",
    "metacritic", "metallic", "metaprotection", "metalprotection",
    "asmetalwork", "metal",
    # 2026-01-28追加: "hermes" false positives
    "hermesonlineshop", "hermesshop", "hermesstore", "hermescourier",
    "hermesdelivery", "hermesparcel", "hermesuk", "hermesworld",
    # 2026-01-28追加: "appstore" false positives
    "educationalappstore", "iosappstore", "androidappstore",
    "appstoreconnect", "appstorereview",
    # 2026-01-29追加: fuzzy match FP対策
    "costa", "costarica", "custo", "costumer", "costume",  # costco
    "hires", "highres", "lozanohemmer", "hemmer",  # hermes
    "rinet", "biznet",  # sbinet
    "lacoste",  # laposte
    "yourule", "yourtube",  # youtube
    # 2026-01-29追加: v2評価で発見したFP
    "stream", "upstream", "downstream", "mainstream", "livestream",  # steam
    "oblog", "noblog", "blog",  # roblox
    "noodleshop", "coffeeshop", "workshop", "bookshop",  # eshop
    # 2026-01-29追加: #10 fuzzy2 FP対策
    "bitbuy", "buybuy", "buybit",  # bestbuy
    "balance", "finance", "refinance", "alliance", "vigilance",  # binance
    "unisbank", "unibank",  # usbank
    "sigsac", "sigact", "sigmod", "sigchi", "sigplan", "sigops",  # signal (ACM SIG系)
    "norge", "nordic", "nordia",  # nordea
    "shoppy", "shoppie", "shopping",  # shopify
    # 2026-01-29追加: #11 compound/substring FP対策
    "revistacomunicar", "pharmacomedicale", "comunicar", "comedicale", "pharmacom", "telecom", "dotcom", "intercom",  # acom
    "worldwise", "otherwise", "likewise", "clockwise", "pairwise", "stepwise",  # wise
    "stripes", "starsandstripes", "pinstripe", "pinstripes",  # stripe
    "xtmobile",  # tmobile
    "americaspromise", "compromise", "compromises",  # promise
    "disneydriven", "disneyfan", "disneylife",  # disney
    "mastercardfdn", "mastercardfoundation",  # mastercard
])

# Common TLDs to exclude from fuzzy brand matching
# These should not be matched with fuzzy rules (e.g., "com" -> "acom")
COMMON_TLDS_FOR_FUZZY_EXCLUSION: FrozenSet[str] = frozenset([
    # Generic TLDs
    "com", "net", "org", "edu", "gov", "mil", "int",
    # Country code TLDs
    "co", "io", "ai", "me", "us", "uk", "de", "jp", "cn", "ru", "br", "fr",
    "in", "au", "ca", "es", "it", "nl", "pl", "kr", "tw", "hk", "sg",
    # New gTLDs
    "info", "biz", "xyz", "top", "online", "site", "tech", "app", "dev",
    "shop", "store", "club", "cloud", "live", "pro", "fun", "link", "work",
    "news", "blog", "web", "asia", "mobi", "tel", "name", "coop", "museum",
])


def is_critical_brand(keyword: str) -> bool:
    """Check if a keyword is a critical brand."""
    return keyword.lower() in CRITICAL_BRAND_KEYWORDS


def requires_boundary_match(brand: str) -> bool:
    """Check if a brand requires word boundary matching."""
    return brand.lower() in BOUNDARY_REQUIRED_BRANDS


def is_fp_exclusion_word(word: str) -> bool:
    """Check if a word is in the FP exclusion list."""
    return word.lower() in BRAND_FP_EXCLUSION_WORDS
