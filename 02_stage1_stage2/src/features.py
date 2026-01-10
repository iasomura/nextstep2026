"""
Feature engineering module for domain and certificate features.

This module extracts features from domain names and SSL/TLS certificates
for phishing detection.
"""

import math
from collections import Counter
from typing import List, Dict, Optional, Any
import pandas as pd
import numpy as np


# Feature order (validated in 04_cross_validation.py)
FEATURE_ORDER = [
    # Domain features (15)
    'domain_length', 'dot_count', 'hyphen_count', 'digit_count', 'digit_ratio',
    'tld_length', 'subdomain_count', 'longest_part_length', 'entropy',
    'vowel_ratio', 'max_consonant_length', 'has_special_chars',
    'non_alphanumeric_count', 'contains_brand', 'has_www',

    # Certificate features (existing 5 + extended 15 = 20)
    'cert_validity_days', 'cert_is_wildcard', 'cert_san_count',
    'cert_issuer_length', 'cert_is_self_signed',
    'cert_cn_length', 'cert_subject_has_org', 'cert_subject_org_length',
    'cert_san_dns_count', 'cert_san_ip_count', 'cert_cn_matches_domain',
    'cert_san_matches_domain', 'cert_san_matches_etld1', 'cert_has_ocsp',
    'cert_has_crl_dp', 'cert_has_sct', 'cert_sig_algo_weak',
    'cert_pubkey_size', 'cert_key_type_code', 'cert_is_lets_encrypt',

    # New certificate features (added via feature search, +0.28% AUC)
    'cert_key_bits_normalized', 'cert_issuer_country_code', 'cert_serial_entropy',
    'cert_has_ext_key_usage', 'cert_has_policies', 'cert_issuer_type',
]


def calculate_entropy(text: str) -> float:
    """
    Calculate Shannon entropy of a string.

    Args:
        text: Input string

    Returns:
        Entropy value
    """
    if not text:
        return 0.0

    char_counts = Counter(text)
    length = len(text)

    entropy = 0.0
    for count in char_counts.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)

    return entropy


def extract_domain_features(domain: str, brand_keywords: List[str]) -> Dict[str, Any]:
    """
    Extract features from domain name.

    Args:
        domain: Domain name
        brand_keywords: List of brand keywords to check

    Returns:
        Dictionary of domain features
    """
    features = {}

    # Basic features
    features['domain_length'] = len(domain)
    features['dot_count'] = domain.count('.')
    features['hyphen_count'] = domain.count('-')

    # Digit features
    digits = sum(c.isdigit() for c in domain)
    features['digit_count'] = digits
    features['digit_ratio'] = digits / len(domain) if len(domain) > 0 else 0.0

    # TLD (Top-Level Domain)
    parts = domain.split('.')
    if len(parts) > 1:
        features['tld_length'] = len(parts[-1])
    else:
        features['tld_length'] = 0

    # Subdomain count
    features['subdomain_count'] = len(parts) - 2 if len(parts) > 2 else 0

    # Longest part length
    features['longest_part_length'] = max(len(part) for part in parts) if parts else 0

    # Entropy
    features['entropy'] = calculate_entropy(domain)

    # Vowel ratio
    vowels = sum(c.lower() in 'aeiou' for c in domain if c.isalpha())
    letters = sum(c.isalpha() for c in domain)
    features['vowel_ratio'] = vowels / letters if letters > 0 else 0.0

    # Maximum consecutive consonant length
    consonant_lengths = []
    current_length = 0
    for c in domain:
        if c.isalpha() and c.lower() not in 'aeiou':
            current_length += 1
        else:
            if current_length > 0:
                consonant_lengths.append(current_length)
            current_length = 0
    if current_length > 0:
        consonant_lengths.append(current_length)
    features['max_consonant_length'] = max(consonant_lengths) if consonant_lengths else 0

    # Special characters
    special_chars = sum(not c.isalnum() and c not in '.-' for c in domain)
    features['has_special_chars'] = 1 if special_chars > 0 else 0
    features['non_alphanumeric_count'] = special_chars

    # Brand check (using dynamic BRAND_KEYWORDS)
    domain_lower = domain.lower()
    features['contains_brand'] = 1 if any(brand in domain_lower for brand in brand_keywords) else 0

    # WWW check
    features['has_www'] = 1 if domain.lower().startswith('www.') else 0

    return features


def _naive_etld1(domain: str) -> str:
    """
    Naive eTLD+1 extractor (no PSL).
    Good enough for most gTLDs and some ccTLD 2LDs.

    Args:
        domain: Domain name

    Returns:
        eTLD+1 (e.g., "example.com")
    """
    if not domain:
        return ""
    d = domain.strip(".").lower()
    parts = [p for p in d.split(".") if p]
    if len(parts) < 2:
        return d

    # Small heuristic for common ccTLD 2LD patterns
    cc2 = {"jp", "uk", "kr", "au", "nz", "za"}
    second_level = {"co", "or", "ne", "ac", "go", "ed", "gr", "lg", "com", "net", "org"}
    if len(parts) >= 3 and parts[-1] in cc2 and parts[-2] in second_level:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _wildcard_matches(pattern: str, domain: str) -> bool:
    """
    Simple wildcard matcher for patterns like '*.example.com'.
    Only supports a single left-most wildcard.

    Args:
        pattern: Wildcard pattern (e.g., "*.example.com")
        domain: Domain to match

    Returns:
        True if domain matches pattern
    """
    if not pattern or not domain:
        return False
    p = pattern.lower().strip(".")
    d = domain.lower().strip(".")
    if not p.startswith("*."):
        return p == d
    suffix = p[2:]
    if not d.endswith("." + suffix):
        return False
    # '*.example.com' matches 'a.example.com' but NOT 'a.b.example.com'
    d_labels = d.split(".")
    s_labels = suffix.split(".")
    return len(d_labels) == len(s_labels) + 1


def extract_certificate_features(cert_data: Any, domain: Optional[str] = None) -> Dict[str, Any]:
    """
    Extract features from certificate data (DER/PEM/BASE64).

    Args:
        cert_data: Certificate data (various formats supported)
        domain: Optional domain name for consistency checks

    Returns:
        Dictionary of certificate features
    """
    features = {
        # Existing 5 features
        'cert_validity_days': 0,
        'cert_is_wildcard': 0,
        'cert_san_count': 0,
        'cert_issuer_length': 0,
        'cert_is_self_signed': 0,

        # Extended features
        'cert_cn_length': 0,
        'cert_subject_has_org': 0,
        'cert_subject_org_length': 0,
        'cert_san_dns_count': 0,
        'cert_san_ip_count': 0,
        'cert_cn_matches_domain': 0,
        'cert_san_matches_domain': 0,
        'cert_san_matches_etld1': 0,
        'cert_has_ocsp': 0,
        'cert_has_crl_dp': 0,
        'cert_has_sct': 0,
        'cert_sig_algo_weak': 0,
        'cert_pubkey_size': 0,
        'cert_key_type_code': 0,  # 0=unknown, 1=RSA, 2=EC, 3=DSA/other
        'cert_is_lets_encrypt': 0,

        # New certificate features (added via feature search, +0.28% AUC)
        'cert_key_bits_normalized': 0.0,  # Key size normalized (0-1 scale)
        'cert_issuer_country_code': 0,    # 0=unknown, 1=US, 2=other
        'cert_serial_entropy': 0.0,       # Serial number entropy
        'cert_has_ext_key_usage': 0,      # Has Extended Key Usage extension
        'cert_has_policies': 0,           # Has Certificate Policies extension
        'cert_issuer_type': 0,            # 0=unknown, 1=LE, 2=Google, 3=Cloudflare, 4=Commercial
    }

    if cert_data is None:
        return features

    d = (domain or "").lower().strip(".")
    etld1 = _naive_etld1(d) if d else ""

    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
        from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID

        # Robust certificate parsing (supports dict, PEM, DER, base64)
        _cert_bytes = None
        _cd = cert_data

        # Dict-like payload (best-effort)
        if isinstance(_cd, dict):
            for _k in ("der", "cert_der", "bytes", "data", "raw", "pem", "cert_pem", "certificate"):
                if _k in _cd and _cd[_k] is not None:
                    _cd = _cd[_k]
                    break

        # Normalize to bytes
        if isinstance(_cd, (bytearray, memoryview)):
            _cert_bytes = bytes(_cd)
        elif isinstance(_cd, bytes):
            _cert_bytes = _cd
        elif isinstance(_cd, str):
            _s = _cd.strip()
            if "BEGIN CERTIFICATE" in _s:
                _cert_bytes = _s.encode("utf-8", errors="ignore")
            else:
                # Try base64 → bytes
                try:
                    import base64 as _b64
                    _cert_bytes = _b64.b64decode(_s, validate=True)
                except Exception:
                    _cert_bytes = _s.encode("utf-8", errors="ignore")
        else:
            try:
                _cert_bytes = bytes(_cd)
            except Exception:
                _cert_bytes = None

        if not _cert_bytes:
            return features

        cert = None
        try:
            cert = x509.load_der_x509_certificate(_cert_bytes, default_backend())
        except Exception:
            try:
                cert = x509.load_pem_x509_certificate(_cert_bytes, default_backend())
            except Exception:
                cert = None

        if cert is None:
            return features

        # Validity (days)
        validity_period = cert.not_valid_after - cert.not_valid_before
        features['cert_validity_days'] = int(getattr(validity_period, 'days', 0) or 0)

        # CN + wildcard flag
        cn = ""
        try:
            cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value or ""
        except Exception:
            cn = ""
        cn_l = str(cn)
        features['cert_cn_length'] = len(cn_l)
        features['cert_is_wildcard'] = 1 if cn_l.lower().startswith('*.') else 0

        # Subject O (organization)
        try:
            org = cert.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)[0].value or ""
            org_s = str(org)
            features['cert_subject_has_org'] = 1 if len(org_s) > 0 else 0
            features['cert_subject_org_length'] = len(org_s)
        except Exception:
            features['cert_subject_has_org'] = 0
            features['cert_subject_org_length'] = 0

        # Issuer length + Let's Encrypt flag
        issuer_name = cert.issuer.rfc4514_string()
        issuer_l = issuer_name.lower()
        features['cert_issuer_length'] = len(issuer_name)
        features['cert_is_lets_encrypt'] = 1 if ("let's encrypt" in issuer_l or "lets encrypt" in issuer_l) else 0

        # Self-signed
        features['cert_is_self_signed'] = 1 if cert.issuer == cert.subject else 0

        # SAN analysis
        dns_names = []
        ip_names = []
        try:
            san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
            dns_names = [str(x).lower().strip(".") for x in san.get_values_for_type(x509.DNSName)]
            ip_names = [str(x) for x in san.get_values_for_type(x509.IPAddress)]
        except Exception:
            dns_names, ip_names = [], []

        features['cert_san_dns_count'] = len(dns_names)
        features['cert_san_ip_count'] = len(ip_names)
        features['cert_san_count'] = len(dns_names)  # Legacy compatibility

        # CN/SAN ↔ domain consistency
        if d:
            # CN match
            cn_lower = cn_l.lower().strip(".")
            if cn_lower == d:
                features['cert_cn_matches_domain'] = 1
            elif cn_lower.startswith("*.") and _wildcard_matches(cn_lower, d):
                features['cert_cn_matches_domain'] = 1

            # SAN match
            for san_entry in dns_names:
                if san_entry == d or _wildcard_matches(san_entry, d):
                    features['cert_san_matches_domain'] = 1
                    break

            # eTLD+1 match
            if etld1:
                for san_entry in dns_names:
                    san_etld1 = _naive_etld1(san_entry)
                    if san_etld1 == etld1 or _wildcard_matches(san_entry, etld1):
                        features['cert_san_matches_etld1'] = 1
                        break

        # OCSP (Authority Information Access)
        try:
            aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
            has_ocsp = any(
                desc.access_method == AuthorityInformationAccessOID.OCSP
                for desc in aia
            )
            features['cert_has_ocsp'] = 1 if has_ocsp else 0
        except Exception:
            features['cert_has_ocsp'] = 0

        # CRL Distribution Points
        try:
            crl = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS).value
            has_crl = any(getattr(dp, 'full_name', None) for dp in crl)
            features['cert_has_crl_dp'] = 1 if has_crl else 0
        except Exception:
            features['cert_has_crl_dp'] = 0

        # SCT (Certificate Transparency)
        try:
            try:
                cert.extensions.get_extension_for_oid(ExtensionOID.SIGNED_CERTIFICATE_TIMESTAMPS)
                features['cert_has_sct'] = 1
            except Exception:
                # Fallback to OID string
                oid = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2")
                cert.extensions.get_extension_for_oid(oid)
                features['cert_has_sct'] = 1
        except Exception:
            features['cert_has_sct'] = 0

        # Key type + key size
        try:
            pk = cert.public_key()
            if isinstance(pk, rsa.RSAPublicKey):
                features['cert_key_type_code'] = 1
                features['cert_pubkey_size'] = int(pk.key_size)
            elif isinstance(pk, ec.EllipticCurvePublicKey):
                features['cert_key_type_code'] = 2
                features['cert_pubkey_size'] = int(pk.key_size)
            elif isinstance(pk, dsa.DSAPublicKey):
                features['cert_key_type_code'] = 3
                features['cert_pubkey_size'] = int(pk.key_size)
            else:
                features['cert_key_type_code'] = 0
                features['cert_pubkey_size'] = 0
        except Exception:
            features['cert_key_type_code'] = 0
            features['cert_pubkey_size'] = 0

        # Weak signature hash (sha1 / md5)
        try:
            h = getattr(cert, "signature_hash_algorithm", None)
            hname = (getattr(h, "name", "") or "").lower()
            features['cert_sig_algo_weak'] = 1 if ("sha1" in hname or "md5" in hname) else 0
        except Exception:
            features['cert_sig_algo_weak'] = 0

        # === New certificate features (added via feature search) ===

        # Key size normalized (0-1 scale, 2048=0.5, 4096=1.0, 256=0.5 for EC)
        try:
            pk = cert.public_key()
            key_size = pk.key_size
            if key_size <= 256:  # EC keys
                features['cert_key_bits_normalized'] = key_size / 512
            else:  # RSA keys
                features['cert_key_bits_normalized'] = min(key_size / 4096, 1.0)
        except Exception:
            features['cert_key_bits_normalized'] = 0.0

        # Issuer country code (0=unknown, 1=US, 2=other)
        try:
            from cryptography.x509.oid import NameOID
            country_attrs = cert.issuer.get_attributes_for_oid(NameOID.COUNTRY_NAME)
            if country_attrs:
                country = country_attrs[0].value.upper()
                features['cert_issuer_country_code'] = 1 if country == 'US' else 2
        except Exception:
            features['cert_issuer_country_code'] = 0

        # Serial number entropy
        try:
            serial_hex = format(cert.serial_number, 'x')
            features['cert_serial_entropy'] = calculate_entropy(serial_hex)
        except Exception:
            features['cert_serial_entropy'] = 0.0

        # Extended Key Usage extension
        try:
            cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
            features['cert_has_ext_key_usage'] = 1
        except Exception:
            features['cert_has_ext_key_usage'] = 0

        # Certificate Policies extension
        try:
            cert.extensions.get_extension_for_oid(ExtensionOID.CERTIFICATE_POLICIES)
            features['cert_has_policies'] = 1
        except Exception:
            features['cert_has_policies'] = 0

        # Issuer type (0=unknown, 1=LE, 2=Google, 3=Cloudflare, 4=Commercial)
        # Note: cert_is_lets_encrypt already extracts issuer_l, reuse logic
        if "let's encrypt" in issuer_l or "letsencrypt" in issuer_l:
            features['cert_issuer_type'] = 1
        elif 'google' in issuer_l:
            features['cert_issuer_type'] = 2
        elif 'cloudflare' in issuer_l:
            features['cert_issuer_type'] = 3
        elif any(ca in issuer_l for ca in ['digicert', 'comodo', 'sectigo', 'geotrust', 'thawte', 'entrust', 'globalsign']):
            features['cert_issuer_type'] = 4

    except Exception:
        # Keep defaults
        pass

    return features


def extract_features(domain: str, cert_data: Any, brand_keywords: List[str]) -> List[Any]:
    """
    Extract all features from domain and certificate.

    Args:
        domain: Domain name
        cert_data: Certificate data (various formats)
        brand_keywords: List of brand keywords

    Returns:
        List of feature values in FEATURE_ORDER
    """
    # Domain features
    domain_features = extract_domain_features(domain, brand_keywords)

    # Certificate features
    cert_features = extract_certificate_features(cert_data, domain)

    # Combine
    all_features = {**domain_features, **cert_features}

    # Order according to FEATURE_ORDER
    ordered_features = [all_features[feature] for feature in FEATURE_ORDER]

    return ordered_features


class FeatureEngineer:
    """
    Feature engineering class for domain and certificate features.

    Example:
        >>> engineer = FeatureEngineer(brand_keywords=['google', 'amazon'])
        >>> features = engineer.extract_features('phishing-amazon.com', None)
        >>> print(len(features))
        35
    """

    def __init__(self, brand_keywords: List[str], cert_extra: bool = True):
        """
        Initialize feature engineer.

        Args:
            brand_keywords: List of brand keywords for matching
            cert_extra: Include extended certificate features (always True for now)
        """
        self.brand_keywords = brand_keywords
        self.cert_extra = cert_extra
        self.feature_names = FEATURE_ORDER

    def extract_features(self, domain: str, cert_data: Any = None) -> List[Any]:
        """
        Extract features from domain and certificate.

        Args:
            domain: Domain name
            cert_data: Optional certificate data

        Returns:
            List of feature values
        """
        return extract_features(domain, cert_data, self.brand_keywords)

    def build_feature_matrix(self, df: pd.DataFrame) -> np.ndarray:
        """
        Build feature matrix from DataFrame.

        Args:
            df: DataFrame with 'domain' and 'cert_data' columns

        Returns:
            Feature matrix (n_samples x n_features)
        """
        features_list = []
        for idx, row in df.iterrows():
            domain = row['domain']
            cert_data = row.get('cert_data', None)
            features = self.extract_features(domain, cert_data)
            features_list.append(features)

        return np.array(features_list)

    def get_feature_names(self) -> List[str]:
        """Get feature names in order."""
        return self.feature_names.copy()

    def print_feature_info(self) -> None:
        """Print feature information."""
        print(f"Total features: {len(self.feature_names)}")
        print(f"Brand keywords: {len(self.brand_keywords)}")
        print("\nFeature list:")
        print("[Domain features]")
        for i, feature in enumerate(self.feature_names[:15], 1):
            print(f"  {i:2d}. {feature}")
        print("\n[Certificate features]")
        for i, feature in enumerate(self.feature_names[15:], 16):
            print(f"  {i:2d}. {feature}")
