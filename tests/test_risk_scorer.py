from __future__ import annotations

from pathlib import Path

from phishing_analyzer import Finding
from phishing_analyzer.header_analyzer import analyze_headers
from phishing_analyzer.main import analyze_file
from phishing_analyzer.parser import parse_eml
from phishing_analyzer.risk_scorer import category_for, score_findings
from phishing_analyzer.url_analyzer import analyze_urls

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def test_categories():
    assert category_for(0) == "Low"
    assert category_for(19) == "Low"
    assert category_for(20) == "Medium"
    assert category_for(50) == "High"
    assert category_for(75) == "Critical"
    assert category_for(100) == "Critical"


def test_cap_and_no_points_for_zero():
    findings = [
        Finding("vt_malicious_url", "malicious url", 35, "e", "vt"),
        Finding("vt_malicious_sender_domain", "malicious domain", 25, "e", "vt"),
        Finding("link_mismatch", "mismatch", 20, "e", "url"),
        Finding("spf_fail", "spf", 10, "e", "auth"),
        Finding("dkim_fail", "dkim", 10, "e", "auth"),
        Finding("dmarc_fail", "dmarc", 15, "e", "auth"),
        Finding("lookalike_sender", "lookalike", 15, "e", "from"),
        Finding("info", "info", 0, "e", "local"),
    ]
    result = score_findings(findings)
    assert result.score == 100
    assert result.category == "Critical"


def test_duplicate_finding_not_double_counted():
    findings = [
        Finding("spf_fail", "spf", 10, "from auth-results", "Authentication-Results"),
        Finding("spf_fail", "spf again", 10, "from received-spf", "Received-SPF"),
    ]
    result = score_findings(findings)
    assert result.score == 10
    assert len(result.dropped) == 1


def test_unavailable_data_adds_no_points(incomplete_email):
    parsed = parse_eml(incomplete_email)
    _checks, header_findings = analyze_headers(parsed)
    _records, url_findings = analyze_urls(parsed)
    result = score_findings(header_findings + url_findings)
    assert result.score == 0
    assert result.category == "Low"


def test_suspicious_sample_scores_high(tmp_path: Path):
    parsed = parse_eml(SAMPLES / "suspicious.eml")
    _checks, header_findings = analyze_headers(parsed)
    _records, url_findings = analyze_urls(parsed)
    result = score_findings(header_findings + url_findings)
    # SPF 10 + DKIM 10 + DMARC 15 + mismatch 20 + pattern 10 + lookalike 15 + reply-to 10 = 90
    assert result.score == 90
    assert result.category == "Critical"
    report = analyze_file(SAMPLES / "suspicious.eml", tmp_path / "out.html")
    html = report.read_text(encoding="utf-8")
    assert "Risk score: 90 / 100" in html
    assert "Critical" in html
    assert "PayPal Security" in html
