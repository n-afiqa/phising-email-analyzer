"""Compare link text with destinations and flag suspicious URL patterns."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import unquote, urlparse

from phishing_analyzer import Finding
from phishing_analyzer.header_analyzer import KNOWN_BRANDS, registrable_domain
from phishing_analyzer.parser import ExtractedUrl, ParsedEmail

SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "rebrand.ly",
    "tiny.cc",
    "rb.gy",
    "shorturl.at",
}

SUSPICIOUS_TLDS = {
    "xyz",
    "top",
    "click",
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    "zip",
    "mov",
    "country",
    "rest",
    "quest",
    "support",
}

RISKY_SCHEMES = {"javascript", "data", "file", "vbscript"}
DOMAIN_LIKE_RE = re.compile(
    r"^(?:https?://)?(?:www\.)?([a-z0-9.-]+\.[a-z]{2,})(?:[/:?#].*)?$",
    re.IGNORECASE,
)


def analyze_urls(parsed: ParsedEmail) -> tuple[list[dict], list[Finding]]:
    records: list[dict] = []
    mismatch_items: list[dict] = []
    pattern_items: list[dict] = []

    for item in parsed.urls:
        record, mismatch, patterns = _inspect_url(item)
        records.append(record)
        if mismatch:
            mismatch_items.append(mismatch)
        pattern_items.extend(patterns)

    findings: list[Finding] = []
    if mismatch_items:
        evidence_lines = [entry["evidence"] for entry in mismatch_items]
        findings.append(
            Finding(
                code="link_mismatch",
                title="Displayed link text materially misleads about destination",
                points=20,
                evidence=" ".join(evidence_lines),
                source="HTML/text URL comparison",
                details={"items": mismatch_items},
            )
        )

    if pattern_items:
        # One finding for the pattern category; evidence lists each URL.
        unique_patterns = []
        seen = set()
        for entry in pattern_items:
            key = (entry["pattern"], entry["href"])
            if key in seen:
                continue
            seen.add(key)
            unique_patterns.append(entry)
        findings.append(
            Finding(
                code="suspicious_url_pattern",
                title="Suspicious URL pattern",
                points=10,
                evidence=" ".join(entry["evidence"] for entry in unique_patterns),
                source="Local URL pattern inspection",
                details={"items": unique_patterns},
            )
        )

    return records, findings


def _inspect_url(item: ExtractedUrl) -> tuple[dict, dict | None, list[dict]]:
    href = item.href
    parsed_url = _parse(href)
    host = (parsed_url.hostname or "").lower()
    display = item.display_text
    mismatch = _mismatch(display, href, parsed_url)
    patterns = _patterns(href, parsed_url, host)

    record = {
        "href": href,
        "display_text": display,
        "hostname": host,
        "source": item.source,
        "mismatch": bool(mismatch),
        "patterns": [p["pattern"] for p in patterns],
        "explanation": _record_explanation(mismatch, patterns),
    }
    return record, mismatch, patterns


def _parse(href: str):
    candidate = href.strip()
    if candidate.lower().startswith("www."):
        candidate = "http://" + candidate
    return urlparse(candidate)


def _mismatch(display: str, href: str, parsed_url) -> dict | None:
    dest_host = (parsed_url.hostname or "").lower()
    if not dest_host:
        return None

    displayed_host = _host_from_display(display)
    dest_reg = registrable_domain(dest_host)

    if displayed_host:
        display_reg = registrable_domain(displayed_host)
        if display_reg and dest_reg and display_reg != dest_reg:
            return {
                "href": href,
                "display_text": display,
                "displayed_host": displayed_host,
                "destination_host": dest_host,
                "evidence": (
                    f"Visible text `{display}` points at `{displayed_host}` but the "
                    f"actual destination is `{dest_host}`."
                ),
            }

    brand = _brand_in_text(display)
    if brand:
        allowed = {registrable_domain(d) for d in KNOWN_BRANDS[brand]}
        if dest_reg not in allowed:
            return {
                "href": href,
                "display_text": display,
                "displayed_host": displayed_host or brand,
                "destination_host": dest_host,
                "evidence": (
                    f"Link text `{display}` suggests `{brand}` but the destination "
                    f"host is `{dest_host}`."
                ),
            }
    return None


def _host_from_display(display: str) -> str:
    text = unquote(display or "").strip()
    if not text:
        return ""
    if "://" in text or text.lower().startswith("www.") or DOMAIN_LIKE_RE.match(text):
        if "://" not in text and not text.lower().startswith("www."):
            parsed = urlparse("http://" + text)
        else:
            parsed = _parse(text)
        return (parsed.hostname or "").lower()
    return ""


def _brand_in_text(display: str) -> str | None:
    normalized = re.sub(r"[^a-z0-9]+", " ", (display or "").lower()).strip()
    if not normalized:
        return None
    for brand in KNOWN_BRANDS:
        if brand in normalized or brand.replace(" ", "") in normalized.replace(" ", ""):
            return brand
    return None


def _patterns(href: str, parsed_url, host: str) -> list[dict]:
    found: list[dict] = []
    scheme = (parsed_url.scheme or "").lower()

    def add(pattern: str, evidence: str) -> None:
        found.append({"pattern": pattern, "href": href, "hostname": host, "evidence": evidence})

    if scheme in RISKY_SCHEMES:
        add("risky_scheme", f"`{href}` uses the `{scheme}:` scheme.")

    if host:
        if _is_ip(host):
            add("ip_address", f"`{href}` uses an IP address (`{host}`) instead of a domain.")
        if host in SHORTENERS or registrable_domain(host) in SHORTENERS:
            add("shortener", f"`{href}` uses a URL shortener (`{host}`).")
        tld = host.rsplit(".", 1)[-1] if "." in host else ""
        if tld in SUSPICIOUS_TLDS:
            add("suspicious_tld", f"`{href}` uses uncommon TLD `.{tld}`.")
        if host.startswith("xn--") or ".xn--" in host:
            add("punycode", f"`{href}` uses punycode/IDN encoding (`{host}`).")
        if host.count("-") >= 3:
            add("hyphenated_host", f"`{href}` has an unusually hyphenated hostname (`{host}`).")
        if host.count(".") >= 4:
            add("deep_subdomains", f"`{href}` has unusually deep subdomains (`{host}`).")

    if parsed_url.username or "@" in href.split("://", 1)[-1].split("/", 1)[0]:
        add(
            "userinfo_at",
            f"`{href}` embeds credentials or an `@` before the host, which can hide the real destination.",
        )

    return found


def _is_ip(host: str) -> bool:
    candidate = host.strip("[]")
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        return False


def _record_explanation(mismatch: dict | None, patterns: list[dict]) -> str:
    parts = []
    if mismatch:
        parts.append(mismatch["evidence"])
    parts.extend(item["evidence"] for item in patterns)
    return " ".join(parts) if parts else "No local URL issues detected for this link."
