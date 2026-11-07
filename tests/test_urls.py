from __future__ import annotations

from pathlib import Path

from phishing_analyzer.parser import parse_eml
from phishing_analyzer.url_analyzer import analyze_urls

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def test_mismatch_and_ip_and_shortener():
    parsed = parse_eml(SAMPLES / "suspicious.eml")
    records, findings = analyze_urls(parsed)
    codes = {item.code for item in findings}
    assert "link_mismatch" in codes
    assert "suspicious_url_pattern" in codes
    mismatch = next(item for item in findings if item.code == "link_mismatch")
    assert mismatch.points == 20
    pattern = next(item for item in findings if item.code == "suspicious_url_pattern")
    assert pattern.points == 10
    flags = {flag for record in records for flag in record["patterns"]}
    assert "ip_address" in flags
    assert "shortener" in flags


def test_matching_link_is_clean():
    parsed = parse_eml(SAMPLES / "benign.eml")
    records, findings = analyze_urls(parsed)
    assert findings == []
    assert records
    assert all(not record["mismatch"] for record in records)
    assert all(not record["patterns"] for record in records)


def test_no_urls(incomplete_email):
    parsed = parse_eml(incomplete_email)
    records, findings = analyze_urls(parsed)
    assert records == []
    assert findings == []
