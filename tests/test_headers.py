from __future__ import annotations

from pathlib import Path

from phishing_analyzer.header_analyzer import analyze_headers, extract_email_address
from phishing_analyzer.parser import parse_eml

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def test_authentication_results_from_suspicious_sample():
    parsed = parse_eml(SAMPLES / "suspicious.eml")
    checks, findings = analyze_headers(parsed)
    by_name = {check.name: check.result for check in checks}
    assert by_name == {"SPF": "Fail", "DKIM": "Fail", "DMARC": "Fail"}
    codes = {item.code for item in findings}
    assert "spf_fail" in codes
    assert "dkim_fail" in codes
    assert "dmarc_fail" in codes


def test_missing_auth_is_unavailable_and_unscored(incomplete_email):
    parsed = parse_eml(incomplete_email)
    checks, findings = analyze_headers(parsed)
    assert all(check.result == "Unavailable" for check in checks)
    assert all(item.code not in {"spf_fail", "dkim_fail", "dmarc_fail"} for item in findings)


def test_reply_to_domain_mismatch():
    parsed = parse_eml(SAMPLES / "suspicious.eml")
    _checks, findings = analyze_headers(parsed)
    mismatch = next(item for item in findings if item.code == "sender_reply_to_mismatch")
    assert mismatch.points == 10
    assert "paypa1-secure.xyz" in mismatch.evidence


def test_lookalike_and_display_name_impersonation():
    parsed = parse_eml(SAMPLES / "suspicious.eml")
    _checks, findings = analyze_headers(parsed)
    lookalike = next(item for item in findings if item.code == "lookalike_sender")
    assert lookalike.points == 15
    assert "paypal" in lookalike.details["brand"]


def test_benign_headers_have_no_auth_failures():
    parsed = parse_eml(SAMPLES / "benign.eml")
    checks, findings = analyze_headers(parsed)
    assert {check.result for check in checks} == {"Pass"}
    assert findings == []


def test_extract_email_address():
    assert extract_email_address("PayPal Security <support@paypa1-secure.xyz>") == (
        "support@paypa1-secure.xyz"
    )
