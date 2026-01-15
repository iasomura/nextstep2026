#!/usr/bin/env python3
"""
Stage3 Certificate Enhancement Integration Test
Tests all components modified for certificate-based benign gates.
"""

import sys
sys.path.insert(0, ".")

print("=" * 70)
print("Stage3 Certificate Enhancement Integration Test")
print("=" * 70)

# Test 1: Import all modified modules
print("\n[Test 1] Import all modified modules...")
try:
    from phishing_agent.tools.certificate_analysis import certificate_analysis
    from phishing_agent.llm_final_decision import final_decision, PHASE6_POLICY_VERSION
    from phishing_agent.tools.contextual_risk_assessment import contextual_risk_assessment
    from phishing_agent.precheck_module import _generate_cert_summary, _calc_cert_benign_score
    print(f"  ✓ All imports successful")
    print(f"  ✓ llm_final_decision version: {PHASE6_POLICY_VERSION}")
except Exception as e:
    print(f"  ✗ Import error: {e}")
    sys.exit(1)

# Test 2: Certificate analysis with benign_indicators
print("\n[Test 2] Certificate analysis with benign_indicators...")

# Simulate OV/EV certificate (flattened format expected by the function)
cert_ov_ev = {
    "subject": {"O": "Example Inc.", "CN": "example.com"},
    "issuer": "DigiCert Inc",
    "san": ["example.com", "www.example.com"],
    "has_crl_dp": True,  # Direct flag
    "valid_days": 730,  # 2 years
}
result = certificate_analysis("example.com", cert_metadata=cert_ov_ev)
# Result is wrapped: {"success": true, "data": {...}}
data = result.get("data", result)  # fallback to result if no wrapper
benign_ind = data.get("benign_indicators", [])
print(f"  OV/EV cert: benign_indicators = {benign_ind}")
assert "ov_ev_cert" in benign_ind, "Should detect OV/EV"
assert "has_crl_dp" in benign_ind, "Should detect CRL"
assert "long_validity" in benign_ind, "Should detect long validity (730 days)"
print(f"  ✓ OV/EV, CRL, and long validity detection passed")

# Simulate wildcard on safe TLD
cert_wildcard = {
    "subject": {"CN": "*.example.com"},
    "issuer": "DigiCert Inc",
    "san": ["*.example.com"],
    "is_wildcard": True,  # Direct flag
    "valid_days": 365,
}
result = certificate_analysis("sub.example.com", cert_metadata=cert_wildcard)
data = result.get("data", result)
benign_ind = data.get("benign_indicators", [])
print(f"  Wildcard cert: benign_indicators = {benign_ind}")
assert "wildcard_cert" in benign_ind, "Should detect wildcard"
print(f"  ✓ Wildcard detection passed")

# Simulate high SAN count
cert_high_san = {
    "subject": {"CN": "cdn.example.com"},
    "issuer": "DigiCert Inc",
    "san": [f"cdn{i}.example.com" for i in range(15)],  # 15 SANs
    "san_count": 15,
    "valid_days": 365,
}
result = certificate_analysis("cdn.example.com", cert_metadata=cert_high_san)
data = result.get("data", result)
benign_ind = data.get("benign_indicators", [])
print(f"  High SAN cert: benign_indicators = {benign_ind}")
assert "high_san_count" in benign_ind, "Should detect high SAN count"
print(f"  ✓ High SAN count detection passed")

# Test 3: Contextual risk with low-signal phishing detection
print("\n[Test 3] Contextual risk assessment...")

# Normal case with certificate info
tool_results_normal = {
    "certificate": {
        "success": True,
        "data": {
            "score": 0.2,
            "issues": [],
            "validity_days": 365,
            "san_count": 5,
            "benign_indicators": ["long_validity"],
        }
    }
}
ctx_result = contextual_risk_assessment(
    domain="example.com",
    ml_probability=0.15,
    tool_results=tool_results_normal,
)
ctx_score = ctx_result.get("score", 0)
print(f"  Normal case: score={ctx_score:.2f}")
print(f"  ✓ Contextual risk assessment executed")

# Test 4: Precheck module cert_summary generation
print("\n[Test 4] Precheck module _generate_cert_summary...")

cert_info_for_summary = {
    "has_crl_dp": True,
    "has_org": True,
    "is_wildcard": True,
    "valid_days": 500,  # Long validity
    "san_count": 15,  # High SAN
}
cert_summary = _generate_cert_summary(cert_info_for_summary)
print(f"  cert_summary = {cert_summary}")
assert cert_summary.get("has_crl_dp") == True, "Should detect CRL"
assert cert_summary.get("is_ov_ev") == True, "Should detect OV/EV"
assert cert_summary.get("is_wildcard") == True, "Should detect wildcard"
assert cert_summary.get("is_high_san") == True, "Should detect high SAN"
assert cert_summary.get("is_long_validity") == True, "Should detect long validity"
assert "has_crl_dp" in cert_summary.get("benign_indicators", [])
assert "ov_ev_cert" in cert_summary.get("benign_indicators", [])
assert "wildcard_cert" in cert_summary.get("benign_indicators", [])
assert "long_validity" in cert_summary.get("benign_indicators", [])
assert "high_san_count" in cert_summary.get("benign_indicators", [])
print(f"  ✓ cert_summary generation passed (5 benign indicators)")

# Test 5: Gate B1-B4 integration
print("\n[Test 5] Gate B1-B4 integration...")

from phishing_agent.llm_final_decision import _apply_benign_cert_gate
from phishing_agent.agent_foundations import PhishingAssessment

# Create a valid PhishingAssessment (is_phishing=True to test gate)
def make_phishing_asmt():
    return PhishingAssessment(
        is_phishing=True,
        confidence=0.7,
        risk_level="medium",
        detected_brands=[],
        risk_factors=["test_factor"],
        reasoning="Test case for benign cert gate testing purposes",
    )

# Test Gate B1: OV/EV certificate
# Note: uses "cert" key (not "certificate"), "details.benign_indicators"
tool_summary_b1 = {
    "cert": {
        "score": 0.2,
        "issues": [],
        "details": {"benign_indicators": ["ov_ev_cert"]},
    },
    "contextual": {"risk_score": 0.40},  # < 0.50 threshold
}
asmt_b1 = make_phishing_asmt()
trace_b1 = []
result_b1 = _apply_benign_cert_gate(
    asmt=asmt_b1,
    tool_summary=tool_summary_b1,
    ml_probability=0.2,
    precheck={"ml_probability": 0.2},
    trace=trace_b1,
)
print(f"  Gate B1 (OV/EV): is_phishing=True → {result_b1.is_phishing}")
assert result_b1.is_phishing == False, "Gate B1 should trigger and set is_phishing=False"
print(f"  ✓ Gate B1 passed")

# Test Gate B2: CRL + low ML
tool_summary_b2 = {
    "cert": {
        "score": 0.2,
        "issues": [],
        "details": {"benign_indicators": ["has_crl_dp"]},
    },
    "contextual": {"risk_score": 0.40},  # < 0.45 threshold
}
asmt_b2 = make_phishing_asmt()
trace_b2 = []
result_b2 = _apply_benign_cert_gate(
    asmt=asmt_b2,
    tool_summary=tool_summary_b2,
    ml_probability=0.25,  # < 0.30 threshold
    precheck={"ml_probability": 0.25},
    trace=trace_b2,
)
print(f"  Gate B2 (CRL): is_phishing=True → {result_b2.is_phishing}")
assert result_b2.is_phishing == False, "Gate B2 should trigger"
print(f"  ✓ Gate B2 passed")

# Test Gate B3: Wildcard + low ctx
tool_summary_b3 = {
    "cert": {
        "score": 0.2,
        "issues": [],
        "details": {"benign_indicators": ["wildcard_cert"]},
    },
    "contextual": {"risk_score": 0.35},  # < 0.40 threshold
}
asmt_b3 = make_phishing_asmt()
trace_b3 = []
result_b3 = _apply_benign_cert_gate(
    asmt=asmt_b3,
    tool_summary=tool_summary_b3,
    ml_probability=0.3,
    precheck={"ml_probability": 0.3},
    trace=trace_b3,
)
print(f"  Gate B3 (Wildcard): is_phishing=True → {result_b3.is_phishing}")
assert result_b3.is_phishing == False, "Gate B3 should trigger"
print(f"  ✓ Gate B3 passed")

# Test Gate B4: High SAN + low ctx
tool_summary_b4 = {
    "cert": {
        "score": 0.2,
        "issues": [],
        "details": {"benign_indicators": ["high_san_count"]},
    },
    "contextual": {"risk_score": 0.40},  # < 0.45 threshold
}
asmt_b4 = make_phishing_asmt()
trace_b4 = []
result_b4 = _apply_benign_cert_gate(
    asmt=asmt_b4,
    tool_summary=tool_summary_b4,
    ml_probability=0.3,
    precheck={"ml_probability": 0.3},
    trace=trace_b4,
)
print(f"  Gate B4 (High SAN): is_phishing=True → {result_b4.is_phishing}")
assert result_b4.is_phishing == False, "Gate B4 should trigger"
print(f"  ✓ Gate B4 passed")

# Test: brand_detected should skip gate
tool_summary_brand = {
    "cert": {
        "score": 0.2,
        "issues": [],
        "details": {"benign_indicators": ["ov_ev_cert", "has_crl_dp"]},
    },
    "brand": {"issues": ["brand_detected"]},  # brand detected!
    "contextual": {"risk_score": 0.35},
}
asmt_brand = make_phishing_asmt()
trace_brand = []
result_brand = _apply_benign_cert_gate(
    asmt=asmt_brand,
    tool_summary=tool_summary_brand,
    ml_probability=0.2,
    precheck={"ml_probability": 0.2},
    trace=trace_brand,
)
print(f"  Brand detected skip: is_phishing=True → {result_brand.is_phishing}")
assert result_brand.is_phishing == True, "Gate should not trigger when brand detected"
print(f"  ✓ Brand detection skip passed")

# Test 6: Low Signal Phishing Gate (P1-P3)
print("\n[Test 6] Low Signal Phishing Gate (P1-P3)...")

from phishing_agent.llm_final_decision import _apply_low_signal_phishing_gate

# Create a valid PhishingAssessment (is_phishing=False to test gate)
def make_benign_asmt():
    return PhishingAssessment(
        is_phishing=False,
        confidence=0.7,
        risk_level="low",
        detected_brands=[],
        risk_factors=[],
        reasoning="Test case for low signal phishing gate testing",
    )

# Test Gate P1: Brand detected + short cert + low ML → PHISHING
tool_summary_p1 = {
    "brand": {"issues": ["brand_detected"]},
    "cert": {
        "issues": [],
        "details": {
            "valid_days": 60,  # Short cert (≤90)
            "san_count": 3,
            "benign_indicators": [],  # No benign indicators
        },
    },
    "contextual": {"risk_score": 0.30},
}
asmt_p1 = make_benign_asmt()
trace_p1 = []
result_p1 = _apply_low_signal_phishing_gate(
    asmt=asmt_p1,
    tool_summary=tool_summary_p1,
    ml_probability=0.15,  # Low ML < 0.30
    precheck={"ml_probability": 0.15},
    trace=trace_p1,
)
print(f"  Gate P1 (Brand + Short Cert): is_phishing=False → {result_p1.is_phishing}")
assert result_p1.is_phishing == True, "Gate P1 should trigger and set is_phishing=True"
print(f"  ✓ Gate P1 passed")

# Test Gate P2: Brand suspected + short cert + low SAN + low ML → PHISHING
tool_summary_p2 = {
    "brand": {"issues": ["brand_suspected"], "details": {"brand_suspected": True}},
    "cert": {
        "issues": [],
        "details": {
            "valid_days": 80,  # Short cert (≤90)
            "san_count": 4,  # Low SAN (≤5)
            "benign_indicators": [],
        },
    },
    "contextual": {"risk_score": 0.25},
}
asmt_p2 = make_benign_asmt()
trace_p2 = []
result_p2 = _apply_low_signal_phishing_gate(
    asmt=asmt_p2,
    tool_summary=tool_summary_p2,
    ml_probability=0.20,  # Low ML < 0.25
    precheck={"ml_probability": 0.20},
    trace=trace_p2,
)
print(f"  Gate P2 (Suspected + Compound): is_phishing=False → {result_p2.is_phishing}")
assert result_p2.is_phishing == True, "Gate P2 should trigger"
print(f"  ✓ Gate P2 passed")

# Test Gate P3: Dangerous TLD + short cert + very low SAN + very low ML → risk bump (not phishing)
tool_summary_p3 = {
    "brand": {"issues": []},
    "cert": {
        "issues": [],
        "details": {
            "valid_days": 60,  # Short cert (≤90)
            "san_count": 2,  # Very low SAN (≤3)
            "benign_indicators": [],
            "is_dangerous_tld": True,
        },
    },
    "domain": {"issues": ["dangerous_tld"]},
    "contextual": {"risk_score": 0.20},
}
asmt_p3 = make_benign_asmt()
trace_p3 = []
result_p3 = _apply_low_signal_phishing_gate(
    asmt=asmt_p3,
    tool_summary=tool_summary_p3,
    ml_probability=0.10,  # Very low ML < 0.20
    precheck={"ml_probability": 0.10, "tld_category": "dangerous"},
    trace=trace_p3,
)
print(f"  Gate P3 (Dangerous TLD + Cert Risk): is_phishing=False → {result_p3.is_phishing}, risk_level={result_p3.risk_level}")
assert result_p3.is_phishing == False, "Gate P3 should NOT force phishing"
assert result_p3.risk_level == "medium", "Gate P3 should bump risk_level to medium"
print(f"  ✓ Gate P3 passed (risk bump only)")

# Test: benign_indicators should skip P1
tool_summary_skip = {
    "brand": {"issues": ["brand_detected"]},
    "cert": {
        "issues": [],
        "details": {
            "valid_days": 60,
            "san_count": 3,
            "benign_indicators": ["has_crl_dp"],  # Strong benign indicator
        },
    },
    "contextual": {"risk_score": 0.30},
}
asmt_skip = make_benign_asmt()
trace_skip = []
result_skip = _apply_low_signal_phishing_gate(
    asmt=asmt_skip,
    tool_summary=tool_summary_skip,
    ml_probability=0.15,
    precheck={"ml_probability": 0.15},
    trace=trace_skip,
)
print(f"  Benign indicator skip: is_phishing=False → {result_skip.is_phishing}")
assert result_skip.is_phishing == False, "Gate should not trigger when benign_indicators present"
print(f"  ✓ Benign indicator skip passed")

# Test: Already phishing should be unchanged
asmt_already_phishing = PhishingAssessment(
    is_phishing=True,
    confidence=0.8,
    risk_level="high",
    detected_brands=[],
    risk_factors=[],
    reasoning="Already detected as phishing for testing purposes",
)
trace_already = []
result_already = _apply_low_signal_phishing_gate(
    asmt=asmt_already_phishing,
    tool_summary=tool_summary_p1,
    ml_probability=0.15,
    precheck={"ml_probability": 0.15},
    trace=trace_already,
)
print(f"  Already phishing: is_phishing=True → {result_already.is_phishing}")
assert result_already.is_phishing == True, "Already phishing should remain phishing"
print(f"  ✓ Already phishing unchanged passed")

print("\n" + "=" * 70)
print("✅ All Stage3 certificate enhancement integration tests passed!")
print("=" * 70)
