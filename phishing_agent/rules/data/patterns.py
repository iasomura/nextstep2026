# -*- coding: utf-8 -*-
"""
phishing_agent.rules.data.patterns
----------------------------------
Pattern data for detection rules (risk words, bigrams, etc.)
"""

# High risk words commonly found in phishing domains (English)
HIGH_RISK_WORDS: frozenset = frozenset([
    # Authentication/Security
    "login", "signin", "sign-in", "logon", "signon",
    "secure", "security", "verify", "verification",
    "confirm", "confirmation", "validate", "validation",
    "authenticate", "authentication", "auth",
    # Account/Access
    "account", "password", "credential", "access",
    "unlock", "suspend", "suspended", "restrict", "restricted",
    "update", "upgrade", "renew", "expire", "expired",
    # Finance
    "wallet", "banking", "payment", "billing", "invoice",
    "refund", "reward", "prize", "winner", "bonus",
    # Urgency
    "urgent", "alert", "warning", "notice", "action",
    "required", "immediate", "limited", "expire",
])

# Multilingual risk words (non-English phishing indicators)
MULTILINGUAL_RISK_WORDS: frozenset = frozenset([
    # French
    "connexion", "verification", "confirmer", "actualiser", "securite",
    "authentification", "identifiant", "compte", "messagerie",
    # Portuguese
    "verificar", "confirmar", "atualizar", "seguranca", "autenticacao",
    "acesso", "conta", "pagamento",
    # Spanish
    "verificacion", "actualizar", "seguridad", "autenticacion",
    "pago", "factura",
    # German
    "anmeldung", "bestatigung", "sicherheit", "konto", "passwort",
    # Italian
    "verifica", "sicurezza",
    # Japanese (Romaji)
    "kakunin", "anzen", "kouza",
    # General patterns (language-agnostic)
    "webmail", "portail", "espace", "client", "membre",
])

# Rare bigrams (extremely uncommon in natural language)
# Presence indicates likely random/generated string
RARE_BIGRAMS: frozenset = frozenset([
    "qx", "qz", "zx", "xz", "jq", "qj", "vx", "xv",
    "zq", "qk", "kq", "fq", "qf", "jx", "xj", "vq",
    "wq", "qw", "zj", "jz", "xq", "qv", "bx", "xb",
    "hx", "xh", "kx", "xk", "wx", "xw", "zv", "vz",
    "fz", "zf", "pq", "qp", "mq", "qm", "nq", "qn",
    "cq", "qc", "dq", "qd", "gq", "qg", "hq", "qh",
    "jv", "vj", "kv", "vk", "wv", "vw", "zw", "wz",
    "bq", "qb", "sz", "zs", "tz", "zt",
])

# Issue tags that indicate random pattern detection
RANDOM_PATTERN_INDICATORS: frozenset = frozenset([
    "random_pattern",
    "high_entropy",
    "very_high_entropy",
    "short_random_combo",
    "random_with_high_tld_stat",
    "consonant_cluster_random",
    "rare_bigram_random",
])

# Strong non-ML signals (structural indicators)
STRONG_NON_ML_SIGNALS: frozenset = frozenset([
    "dangerous_tld",
    "idn_homograph",
    "random_pattern",
    "high_entropy",
    "very_high_entropy",
    "short_random_combo",
    "random_with_high_tld_stat",
    "very_short_dangerous_combo",
    "deep_chain_with_risky_tld",
    "consonant_cluster_random",
    "rare_bigram_random",
    "brand_detected",
])

# Domain structural signals
DOMAIN_STRONG_SIGNALS: frozenset = frozenset([
    "dangerous_tld",
    "idn_homograph",
    "random_pattern",
    "high_entropy",
    "very_high_entropy",
    "short_random_combo",
    "random_with_high_tld_stat",
    "very_short_dangerous_combo",
    "deep_chain_with_risky_tld",
    "consonant_cluster_random",
    "rare_bigram_random",
])

# Certificate strong signals
CERT_STRONG_SIGNALS: frozenset = frozenset([
    "self_signed",
    "dv_multi_risk_combo",
])

# Weak identity signals (common in both phishing and benign)
WEAK_IDENTITY_SIGNALS: frozenset = frozenset([
    "free_ca",
    "no_org",
    "free_ca_no_org",
    "dv_weak_identity",
])


def count_high_risk_words(text: str) -> int:
    """Count high risk words in text."""
    text_lower = text.lower()
    count = 0
    for word in HIGH_RISK_WORDS:
        if word in text_lower:
            count += 1
    for word in MULTILINGUAL_RISK_WORDS:
        if word in text_lower:
            count += 1
    return count


def count_rare_bigrams(text: str) -> int:
    """Count rare bigrams in text."""
    text_lower = text.lower()
    count = 0
    for i in range(len(text_lower) - 1):
        bigram = text_lower[i:i+2]
        if bigram in RARE_BIGRAMS:
            count += 1
    return count


def rare_bigram_ratio(text: str) -> float:
    """Calculate ratio of rare bigrams."""
    if len(text) < 2:
        return 0.0
    total_bigrams = len(text) - 1
    rare_count = count_rare_bigrams(text)
    return rare_count / total_bigrams
