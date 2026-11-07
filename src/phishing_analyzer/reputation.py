"""Optional VirusTotal reputation and DNS TXT-record lookups."""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

import dns.exception
import dns.resolver
import requests

from phishing_analyzer import Finding
from phishing_analyzer.header_analyzer import domain_of
from phishing_analyzer.parser import ParsedEmail

VIRUSTOTAL_API = "https://www.virustotal.com/api/v3"
DKIM_TAG_RE = re.compile(r"(?:^|;)\s*([sd])\s*=\s*([^;\s]+)", re.IGNORECASE)


@dataclass
class ReputationResult:
    enabled: bool
    skipped_reason: str
    findings: list[Finding]
    dns_checks: list[dict[str, object]] = field(default_factory=list)
    vt_checks: list[dict[str, object]] = field(default_factory=list)


def check_reputation(
    parsed: ParsedEmail,
    *,
    enabled: bool = True,
    api_key: str | None = None,
) -> ReputationResult:
    """Run requested DNS checks and VirusTotal lookups for an email."""
    if not enabled:
        return ReputationResult(
            enabled=False,
            skipped_reason=(
                "Offline mode: online checks are disabled, so no DNS or VirusTotal "
                "lookups were run."
            ),
            findings=[],
        )

    dns_checks = check_dns_records(parsed)
    if not api_key:
        return ReputationResult(
            enabled=True,
            skipped_reason=(
                "DNS record checks ran. VirusTotal checks were skipped because "
                "VIRUSTOTAL_API_KEY is not configured."
            ),
            findings=[],
            dns_checks=dns_checks,
        )

    vt_checks, findings = _check_virustotal(parsed, api_key)
    return ReputationResult(
        enabled=True,
        skipped_reason="",
        findings=findings,
        dns_checks=dns_checks,
        vt_checks=vt_checks,
    )


def check_dns_records(parsed: ParsedEmail) -> list[dict[str, object]]:
    """Inspect current SPF, DKIM selector, and DMARC TXT records with dnspython."""
    from_domain = domain_of(parsed.from_header)
    spf_domain = domain_of(parsed.return_path) or from_domain
    if not spf_domain:
        return [
            {
                "name": "SPF / DKIM / DMARC",
                "target": "",
                "status": "Unavailable: no sender domain could be extracted",
                "records": [],
            }
        ]

    checks: list[dict[str, object]] = []
    spf_target = spf_domain
    records, status = _query_txt(spf_target)
    spf_records = [record for record in records if record.lower().startswith("v=spf1")]
    checks.append(
        {
            "name": "SPF",
            "target": spf_target,
            "status": (
                "Record found"
                if spf_records
                else (
                    "No SPF record"
                    if status in {"Record found", "No TXT records"}
                    else status
                )
            ),
            "records": spf_records,
        }
    )

    dkim_tags: dict[str, set[str]] = {}
    for header in parsed.message.get_all("DKIM-Signature", []):
        tags = {
            name.lower(): value
            for name, value in DKIM_TAG_RE.findall(str(header))
        }
        selector, signing_domain = tags.get("s"), tags.get("d")
        if selector and signing_domain:
            dkim_tags.setdefault(signing_domain.lower().strip("."), set()).add(
                selector.lower().strip(".")
            )

    if not dkim_tags:
        checks.append(
            {
                "name": "DKIM",
                "target": from_domain or spf_domain,
                "status": "Unavailable: no DKIM selector found in message headers",
                "records": [],
            }
        )
    else:
        for signing_domain, selectors in sorted(dkim_tags.items()):
            for selector in sorted(selectors):
                target = f"{selector}._domainkey.{signing_domain}"
                records, status = _query_txt(target)
                checks.append(
                    {
                        "name": "DKIM",
                        "target": target,
                        "status": "Record found" if records else status,
                        "records": records,
                    }
                )

    if from_domain:
        dmarc_target = f"_dmarc.{from_domain}"
        records, status = _query_txt(dmarc_target)
        dmarc_records = [
            record for record in records if record.lower().startswith("v=dmarc1")
        ]
        checks.append(
            {
                "name": "DMARC",
                "target": dmarc_target,
                "status": (
                    "Record found"
                    if dmarc_records
                    else (
                        "No DMARC record"
                        if status in {"Record found", "No TXT records"}
                        else status
                    )
                ),
                "records": dmarc_records,
            }
        )
    else:
        checks.append(
            {
                "name": "DMARC",
                "target": "",
                "status": "Unavailable: no From domain could be extracted",
                "records": [],
            }
        )
    return checks


def _query_txt(target: str) -> tuple[list[str], str]:
    try:
        answer = dns.resolver.resolve(target, "TXT", lifetime=3.0)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return [], "No TXT records"
    except dns.exception.DNSException as exc:
        return [], f"DNS lookup failed: {exc}"

    records = [
        b"".join(record.strings).decode("utf-8", errors="replace")
        for record in answer
    ]
    return records, "Record found" if records else "No TXT records"


def _check_virustotal(
    parsed: ParsedEmail, api_key: str
) -> tuple[list[dict[str, object]], list[Finding]]:
    checks: list[dict[str, object]] = []
    findings: list[Finding] = []
    seen_urls: set[str] = set()
    seen_domains: set[str] = set()

    for item in parsed.urls:
        url = item.href
        if url in seen_urls:
            continue
        seen_urls.add(url)
        check = _vt_lookup("urls", _url_id(url), api_key)
        check.update({"type": "URL", "target": url})
        checks.append(check)
        if check["status"] == "Report found" and int(check["malicious"]) > 0:
            findings.append(
                Finding(
                    code="vt_malicious_url",
                    title="VirusTotal reports a malicious URL",
                    points=35,
                    evidence=(
                        f"VirusTotal lists `{url}` as malicious in "
                        f"{check['malicious']} engine report(s)."
                    ),
                    source="VirusTotal URL report",
                    details={"url": url, "stats": check},
                )
            )

    sender_domain = domain_of(parsed.from_header)
    if sender_domain:
        seen_domains.add(sender_domain)
    for item in parsed.urls:
        host = (urlparse(item.href).hostname or "").lower().strip(".")
        if host:
            seen_domains.add(host)

    for domain in sorted(seen_domains):
        check = _vt_lookup("domains", domain, api_key)
        check.update({"type": "Domain", "target": domain})
        checks.append(check)
        if check["status"] == "Report found" and int(check["malicious"]) > 0:
            findings.append(
                Finding(
                    code="vt_malicious_sender_domain",
                    title="VirusTotal reports a malicious domain",
                    points=25,
                    evidence=(
                        f"VirusTotal lists `{domain}` as malicious in "
                        f"{check['malicious']} engine report(s)."
                    ),
                    source="VirusTotal domain report",
                    details={"domain": domain, "stats": check},
                )
            )
    return checks, findings


def _url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")


def _vt_lookup(endpoint: str, identifier: str, api_key: str) -> dict[str, object]:
    try:
        response = requests.get(
            f"{VIRUSTOTAL_API}/{endpoint}/{identifier}",
            headers={"x-apikey": api_key},
            timeout=10,
        )
    except requests.RequestException as exc:
        return _empty_vt_check(f"Request failed: {exc}")

    if response.status_code == 404:
        return _empty_vt_check("No existing VirusTotal report")
    if response.status_code == 429:
        return _empty_vt_check("VirusTotal rate limit exceeded")
    if response.status_code in {401, 403}:
        return _empty_vt_check("VirusTotal rejected the API key or access")
    try:
        response.raise_for_status()
    except requests.HTTPError:
        return _empty_vt_check(f"VirusTotal returned HTTP {response.status_code}")

    try:
        stats = response.json()["data"]["attributes"]["last_analysis_stats"]
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        harmless = int(stats.get("harmless", 0))
        undetected = int(stats.get("undetected", 0))
    except (KeyError, TypeError, ValueError):
        return _empty_vt_check("VirusTotal returned an invalid report")

    return {
        "status": "Report found",
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
    }


def _empty_vt_check(status: str) -> dict[str, object]:
    return {
        "status": status,
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 0,
    }
