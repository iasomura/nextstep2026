# -*- coding: utf-8 -*-
"""
phishing_agent.rules.data.tlds
------------------------------
TLD (Top-Level Domain) related data for detection rules.
"""

from typing import Dict

# High danger TLDs (>50% phishing rate based on analysis)
# 変更履歴:
#   - 2026-02-04: .shop を追加 (FN分析: authenticationaua.shop等で見逃し)
#   - 2026-01-27: llm_final_decision.py と整合化
HIGH_DANGER_TLDS: frozenset = frozenset([
    "tk", "ml", "ga", "cf", "gq",  # 無料TLD（フィッシング頻出）
    "icu", "cfd", "sbs", "rest", "cyou",  # フィッシング特化
    "pw", "buzz", "lat",  # 高フィッシング率
    "shop",  # 2026-02-04追加: ECサイト偽装に多用
])

# Medium danger TLDs (>20% phishing rate or commonly abused)
# 変更履歴:
#   - 2026-02-04: .shop を HIGH_DANGER_TLDS に移動
#   - 2026-01-27: llm_final_decision.py から追加
MEDIUM_DANGER_TLDS: frozenset = frozenset([
    "top", "xyz", "cc", "online", "site", "website",  # .shop は HIGH に移動
    "club", "vip", "asia", "one", "link", "click", "live",
    "cn", "tokyo", "dev", "me", "pe", "ar", "cl", "mw", "ci",
])

# Dangerous TLDs (combined high + medium for backward compatibility)
DANGEROUS_TLDS: frozenset = HIGH_DANGER_TLDS | MEDIUM_DANGER_TLDS | frozenset([
    "info", "work", "su",  # その他の危険TLD
])

# Safe TLDs (established, low phishing rate)
SAFE_TLDS: frozenset = frozenset([
    "com", "org", "net", "edu", "gov", "mil",
    "co", "io", "me", "us", "uk", "ca", "au", "de", "fr", "jp",
])

# Country-code TLD to country name mapping
CCTLD_COUNTRIES: Dict[str, str] = {
    "ac": "Ascension Island",
    "ad": "Andorra",
    "ae": "United Arab Emirates",
    "af": "Afghanistan",
    "ag": "Antigua and Barbuda",
    "ai": "Anguilla",
    "al": "Albania",
    "am": "Armenia",
    "ao": "Angola",
    "ar": "Argentina",
    "at": "Austria",
    "au": "Australia",
    "az": "Azerbaijan",
    "ba": "Bosnia and Herzegovina",
    "bd": "Bangladesh",
    "be": "Belgium",
    "bg": "Bulgaria",
    "bh": "Bahrain",
    "bi": "Burundi",
    "bj": "Benin",
    "bn": "Brunei",
    "bo": "Bolivia",
    "br": "Brazil",
    "bs": "Bahamas",
    "bt": "Bhutan",
    "bw": "Botswana",
    "by": "Belarus",
    "bz": "Belize",
    "ca": "Canada",
    "cd": "DR Congo",
    "ch": "Switzerland",
    "ci": "Ivory Coast",
    "cl": "Chile",
    "cm": "Cameroon",
    "cn": "China",
    "co": "Colombia",
    "cr": "Costa Rica",
    "cu": "Cuba",
    "cv": "Cape Verde",
    "cy": "Cyprus",
    "cz": "Czech Republic",
    "de": "Germany",
    "dj": "Djibouti",
    "dk": "Denmark",
    "dm": "Dominica",
    "do": "Dominican Republic",
    "dz": "Algeria",
    "ec": "Ecuador",
    "ee": "Estonia",
    "eg": "Egypt",
    "es": "Spain",
    "et": "Ethiopia",
    "fi": "Finland",
    "fj": "Fiji",
    "fm": "Micronesia",
    "fo": "Faroe Islands",
    "fr": "France",
    "ga": "Gabon",
    "gb": "United Kingdom",
    "ge": "Georgia",
    "gh": "Ghana",
    "gi": "Gibraltar",
    "gl": "Greenland",
    "gm": "Gambia",
    "gn": "Guinea",
    "gr": "Greece",
    "gt": "Guatemala",
    "gy": "Guyana",
    "hk": "Hong Kong",
    "hn": "Honduras",
    "hr": "Croatia",
    "ht": "Haiti",
    "hu": "Hungary",
    "id": "Indonesia",
    "ie": "Ireland",
    "il": "Israel",
    "in": "India",
    "iq": "Iraq",
    "ir": "Iran",
    "is": "Iceland",
    "it": "Italy",
    "jm": "Jamaica",
    "jo": "Jordan",
    "jp": "Japan",
    "ke": "Kenya",
    "kg": "Kyrgyzstan",
    "kh": "Cambodia",
    "kr": "South Korea",
    "kw": "Kuwait",
    "kz": "Kazakhstan",
    "la": "Laos",
    "lb": "Lebanon",
    "li": "Liechtenstein",
    "lk": "Sri Lanka",
    "lt": "Lithuania",
    "lu": "Luxembourg",
    "lv": "Latvia",
    "ly": "Libya",
    "ma": "Morocco",
    "mc": "Monaco",
    "md": "Moldova",
    "me": "Montenegro",
    "mg": "Madagascar",
    "mk": "North Macedonia",
    "mm": "Myanmar",
    "mn": "Mongolia",
    "mo": "Macau",
    "mt": "Malta",
    "mu": "Mauritius",
    "mv": "Maldives",
    "mw": "Malawi",
    "mx": "Mexico",
    "my": "Malaysia",
    "mz": "Mozambique",
    "na": "Namibia",
    "ne": "Niger",
    "ng": "Nigeria",
    "ni": "Nicaragua",
    "nl": "Netherlands",
    "no": "Norway",
    "np": "Nepal",
    "nz": "New Zealand",
    "om": "Oman",
    "pa": "Panama",
    "pe": "Peru",
    "pg": "Papua New Guinea",
    "ph": "Philippines",
    "pk": "Pakistan",
    "pl": "Poland",
    "pr": "Puerto Rico",
    "ps": "Palestine",
    "pt": "Portugal",
    "py": "Paraguay",
    "qa": "Qatar",
    "ro": "Romania",
    "rs": "Serbia",
    "ru": "Russia",
    "rw": "Rwanda",
    "sa": "Saudi Arabia",
    "sc": "Seychelles",
    "sd": "Sudan",
    "se": "Sweden",
    "sg": "Singapore",
    "si": "Slovenia",
    "sk": "Slovakia",
    "sl": "Sierra Leone",
    "sn": "Senegal",
    "so": "Somalia",
    "sr": "Suriname",
    "sv": "El Salvador",
    "sy": "Syria",
    "th": "Thailand",
    "tj": "Tajikistan",
    "tm": "Turkmenistan",
    "tn": "Tunisia",
    "to": "Tonga",
    "tr": "Turkey",
    "tt": "Trinidad and Tobago",
    "tw": "Taiwan",
    "tz": "Tanzania",
    "ua": "Ukraine",
    "ug": "Uganda",
    "uk": "United Kingdom",
    "us": "United States",
    "uy": "Uruguay",
    "uz": "Uzbekistan",
    "ve": "Venezuela",
    "vn": "Vietnam",
    "ws": "Samoa",
    "ye": "Yemen",
    "za": "South Africa",
    "zm": "Zambia",
    "zw": "Zimbabwe",
}

# Dangerous country-code TLDs (commonly abused)
DANGEROUS_CCTLDS: frozenset = frozenset([
    "cn",  # China - high volume, mixed use
    "cc",  # Cocos Islands - often abused
    "tk",  # Tokelau - free, heavily abused
    "ml",  # Mali - free, heavily abused
    "ga",  # Gabon - free, heavily abused
    "cf",  # Central African Republic - free, heavily abused
    "gq",  # Equatorial Guinea - free, heavily abused
    "su",  # Soviet Union (legacy) - suspicious
    "pw",  # Palau - often abused
])


def is_dangerous_tld(tld: str) -> bool:
    """Check if a TLD is considered dangerous."""
    return tld.lower().strip(".") in DANGEROUS_TLDS


def is_high_danger_tld(tld: str) -> bool:
    """Check if a TLD is considered high danger."""
    return tld.lower().strip(".") in HIGH_DANGER_TLDS


def is_safe_tld(tld: str) -> bool:
    """Check if a TLD is considered safe."""
    return tld.lower().strip(".") in SAFE_TLDS


def is_cctld(tld: str) -> bool:
    """Check if a TLD is a country-code TLD."""
    return tld.lower().strip(".") in CCTLD_COUNTRIES


def get_country_name(tld: str) -> str:
    """Get country name for a ccTLD."""
    return CCTLD_COUNTRIES.get(tld.lower().strip("."), "")
