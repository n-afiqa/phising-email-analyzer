from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from phishing_analyzer.main import main
from phishing_analyzer.parser import ExtractedUrl, parse_eml
from phishing_analyzer.report_generator import generate_report
from phishing_analyzer.reputation import (
    ReputationResult,
    check_dns_records,
    check_reputation,
)
from phishing_analyzer.risk_scorer import score_findings

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def test_version_one_skips_online_checks():
    parsed = parse_eml(SAMPLES / "suspicious.eml")
    result = check_reputation(parsed, enabled=False)
    assert result.enabled is False
    assert result.findings == []
    assert "offline" in result.skipped_reason.lower()


def test_reputation_runs_dns_checks_by_default(monkeypatch):
    parsed = parse_eml(SAMPLES / "suspicious.eml")
    dns_checks = []
    monkeypatch.setattr(
        "phishing_analyzer.reputation.check_dns_records",
        lambda email: dns_checks.append(email) or [],
    )

    result = check_reputation(parsed)

    assert result.enabled is True
    assert dns_checks == [parsed]


def test_missing_api_key_does_not_create_findings(monkeypatch):
    monkeypatch.setattr("phishing_analyzer.reputation.check_dns_records", lambda _parsed: [])
    parsed = parse_eml(SAMPLES / "benign.eml")
    result = check_reputation(parsed, enabled=True, api_key=None)
    assert result.findings == []
    assert "VIRUSTOTAL_API_KEY" in result.skipped_reason
    assert result.enabled is True


def test_dns_checks_spf_dkim_and_dmarc_records(monkeypatch):
    parsed = parse_eml(SAMPLES / "suspicious.eml")
    parsed.message["dkim-signature"] = "v=1; d=paypa1-secure.xyz; s=mail2026;"
    queried = []

    def resolve(target, record_type, *, lifetime):
        queried.append((target, record_type, lifetime))
        prefix = (
            "v=DMARC1; p=reject"
            if target.startswith("_dmarc.")
            else "v=DKIM1; p=public-key"
            if "._domainkey." in target
            else f"v=spf1 include:{target}"
        )
        return [SimpleNamespace(strings=(prefix.encode(),))]

    monkeypatch.setattr("phishing_analyzer.reputation.dns.resolver.resolve", resolve)
    checks = check_dns_records(parsed)
    assert [check["name"] for check in checks] == ["SPF", "DKIM", "DMARC"]
    assert [target for target, _kind, _timeout in queried] == [
        "accounts-reset.top",
        "mail2026._domainkey.paypa1-secure.xyz",
        "_dmarc.paypa1-secure.xyz",
    ]
    assert all(check["status"] == "Record found" for check in checks)


def test_virustotal_uses_existing_reports_and_scores_malicious_results(
    monkeypatch, incomplete_email
):
    parsed = parse_eml(incomplete_email)
    parsed.from_header = "sender@example.org"
    parsed.urls = [
        ExtractedUrl("https://bad.example/path", "bad.example", "text_body")
    ]
    monkeypatch.setattr("phishing_analyzer.reputation.check_dns_records", lambda _parsed: [])
    requests_made = []

    class Response:
        status_code = 200

        def raise_for_status(self):
            return None

        def json(self):
            return {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 2,
                            "suspicious": 1,
                            "harmless": 5,
                            "undetected": 3,
                        }
                    }
                }
            }

    def get(url, *, headers, timeout):
        requests_made.append((url, headers, timeout))
        return Response()

    monkeypatch.setattr("phishing_analyzer.reputation.requests.get", get)
    result = check_reputation(parsed, enabled=True, api_key="test-key")

    assert [finding.code for finding in result.findings] == [
        "vt_malicious_url",
        "vt_malicious_sender_domain",
        "vt_malicious_sender_domain",
    ]
    assert [finding.points for finding in result.findings] == [35, 25, 25]
    assert len(requests_made) == 3
    assert all(headers == {"x-apikey": "test-key"} for _, headers, _ in requests_made)
    assert all(timeout == 10 for _, _, timeout in requests_made)
    assert all(url.startswith("https://www.virustotal.com/api/v3/") for url, _, _ in requests_made)


def test_cli_loads_virustotal_key_from_dotenv_and_uses_it(monkeypatch, tmp_path):
    key = "dotenv-test-key"
    (tmp_path / ".env").write_text(
        f"VIRUSTOTAL_API_KEY={key}\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    monkeypatch.setattr(
        "phishing_analyzer.reputation.check_dns_records",
        lambda _parsed: [],
    )
    requests_made = []

    class Response:
        status_code = 200

        def raise_for_status(self):
            return None

        def json(self):
            return {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 0,
                            "suspicious": 0,
                            "harmless": 1,
                            "undetected": 0,
                        }
                    }
                }
            }

    def get(url, *, headers, timeout):
        requests_made.append((url, headers, timeout))
        return Response()

    monkeypatch.setattr("phishing_analyzer.reputation.requests.get", get)

    result = main(
        [
            str(SAMPLES / "suspicious.eml"),
            "--online-checks",
            "-o",
            str(tmp_path / "report.html"),
        ]
    )

    assert result == 0
    assert requests_made
    assert all(headers == {"x-apikey": key} for _, headers, _ in requests_made)
    assert all(timeout == 10 for _, _, timeout in requests_made)


def test_cli_runs_dns_checks_by_default(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    dns_checks = []
    monkeypatch.setattr(
        "phishing_analyzer.reputation.check_dns_records",
        lambda parsed: dns_checks.append(parsed) or [],
    )

    result = main(
        [
            str(SAMPLES / "suspicious.eml"),
            "-o",
            str(tmp_path / "default-online-report.html"),
        ]
    )

    assert result == 0
    assert len(dns_checks) == 1


def test_cli_offline_checks_disable_dns(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)

    def unexpected_dns(_parsed):
        raise AssertionError("DNS should not run")

    monkeypatch.setattr(
        "phishing_analyzer.reputation.check_dns_records",
        unexpected_dns,
    )

    result = main(
        [
            str(SAMPLES / "suspicious.eml"),
            "--offline-checks",
            "-o",
            str(tmp_path / "offline-report.html"),
        ]
    )

    assert result == 0
    assert (tmp_path / "offline-report.html").is_file()


def test_online_report_includes_dns_and_virustotal_sections(tmp_path):
    parsed = parse_eml(SAMPLES / "benign.eml")
    reputation = ReputationResult(
        enabled=True,
        skipped_reason="",
        findings=[],
        dns_checks=[
            {
                "name": "SPF",
                "target": "example.org",
                "status": "Record found",
                "records": ["v=spf1 -all"],
            }
        ],
        vt_checks=[
            {
                "type": "URL",
                "target": "https://example.org/",
                "status": "Report found",
                "malicious": 0,
                "suspicious": 0,
            }
        ],
    )
    report_path = generate_report(
        parsed=parsed,
        auth_checks=[],
        url_records=[],
        risk=score_findings([]),
        reputation=reputation,
        output_path=tmp_path / "online-report.html",
    )
    html = report_path.read_text(encoding="utf-8")
    assert "Current DNS authentication records" in html
    assert "v=spf1 -all" in html
    assert "VirusTotal reputation" in html
    assert "https://example.org/" in html
