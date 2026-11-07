"""Interpret authentication results and sender inconsistencies."""

from __future__ import annotations

import re
from email.utils import parseaddr

from phishing_analyzer import AuthCheck, Finding
from phishing_analyzer.parser import ParsedEmail

AUTH_TOKEN_RE = re.compile(
    r"\b(spf|dkim|dmarc)\s*=\s*([a-z0-9_-]+)",
    re.IGNORECASE,
)
RECEIVED_SPF_RE = re.compile(
    r"\b(pass|fail|softfail|neutral|none|temperror|permerror)\b",
    re.IGNORECASE,
)

KNOWN_BRANDS = {
    "paypal": ["paypal.com"],
    "microsoft": ["microsoft.com", "office.com", "outlook.com", "live.com", "hotmail.com"],
    "google": ["google.com", "gmail.com", "googlemail.com", "youtube.com"],
    "apple": ["apple.com", "icloud.com", "me.com"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazonaws.com"],
    "facebook": ["facebook.com", "fb.com", "meta.com"],
    "instagram": ["instagram.com"],
    "netflix": ["netflix.com"],
    "linkedin": ["linkedin.com"],
    "github": ["github.com", "github.io"],
    "dropbox": ["dropbox.com"],
    "adobe": ["adobe.com"],
    "docusign": ["docusign.com", "docusign.net"],
    "wells fargo": ["wellsfargo.com"],
    "bank of america": ["bankofamerica.com"],
    "chase": ["chase.com"],
    "irs": ["irs.gov"],
    "dhl": ["dhl.com"],
    "ups": ["ups.com"],
    "fedex": ["fedex.com"],
    "office365": ["office.com", "microsoft.com", "office365.com"],
}

HOMOGLYPHS = str.maketrans(
    {
        "0": "o",
        "1": "l",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "@": "a",
        "$": "s",
    }
)


def analyze_headers(parsed: ParsedEmail) -> tuple[list[AuthCheck], list[Finding]]:
    auth_checks = _authentication_checks(parsed)
    findings: list[Finding] = []
    findings.extend(_auth_findings(auth_checks))
    findings.extend(_sender_mismatch_findings(parsed))
    findings.extend(_lookalike_findings(parsed))
    return auth_checks, findings


def extract_email_address(value: str) -> str:
    if not value:
        return ""
    _name, address = parseaddr(value)
    address = (address or "").strip().strip("<>").lower()
    if re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", address):
        return address
    match = re.search(r"[^@\s<>]+@[^@\s<>]+\.[^@\s<>]+", value)
    return match.group(0).lower() if match else ""


def extract_display_name(value: str) -> str:
    name, address = parseaddr(value or "")
    if name:
        return name.strip().strip('"')
    if address:
        return ""
    return (value or "").strip()


def domain_of(address_or_header: str) -> str:
    address = extract_email_address(address_or_header)
    if "@" in address:
        return address.rsplit("@", 1)[-1].lower().strip(".")
    host = (address_or_header or "").lower().strip().strip(".")
    if host.startswith("http"):
        return ""
    return host if "." in host else ""


def registrable_domain(host: str) -> str:
    parts = [p for p in (host or "").lower().strip(".").split(".") if p]
    if len(parts) < 2:
        return host.lower()
    multi = {"co", "com", "org", "net", "ac", "gov"}
    if len(parts) >= 3 and parts[-2] in multi:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _authentication_checks(parsed: ParsedEmail) -> list[AuthCheck]:
    combined = " ".join(parsed.authentication_results)
    parsed_tokens: dict[str, tuple[str, str]] = {}
    for match in AUTH_TOKEN_RE.finditer(combined):
        mechanism, result = match.group(1).lower(), match.group(2).lower()
        parsed_tokens[mechanism] = (result, combined)

    if "spf" not in parsed_tokens:
        for raw in parsed.received_spf:
            match = RECEIVED_SPF_RE.search(raw)
            if match:
                parsed_tokens["spf"] = (match.group(1).lower(), raw)
                break

    checks = []
    for name in ("spf", "dkim", "dmarc"):
        if name in parsed_tokens:
            result, raw = parsed_tokens[name]
            source = (
                "Authentication-Results"
                if parsed.authentication_results
                else "Received-SPF"
            )
            checks.append(
                AuthCheck(
                    name=name.upper(),
                    result=_normalize_auth_result(result),
                    raw=raw,
                    source=source,
                    available=True,
                )
            )
        else:
            checks.append(
                AuthCheck(
                    name=name.upper(),
                    result="Unavailable",
                    raw="",
                    source="",
                    available=False,
                )
            )
    return checks


def _normalize_auth_result(result: str) -> str:
    mapping = {
        "pass": "Pass",
        "fail": "Fail",
        "softfail": "Softfail",
        "neutral": "Neutral",
        "none": "None",
        "temperror": "Temperror",
        "permerror": "Permerror",
        "bestguesspass": "Bestguesspass",
        "policy": "Policy",
    }
    return mapping.get(result.lower(), result.title())


def _auth_findings(checks: list[AuthCheck]) -> list[Finding]:
    findings: list[Finding] = []
    for check in checks:
        if not check.available:
            continue
        result = check.result.lower()
        if check.name == "DMARC" and result == "fail":
            findings.append(
                Finding(
                    code="dmarc_fail",
                    title="DMARC authentication failure",
                    points=15,
                    evidence=f"DMARC result is {check.result}.",
                    source=check.source or "Authentication-Results",
                    details={"result": check.result, "raw": check.raw},
                )
            )
        elif check.name in {"SPF", "DKIM"} and result == "fail":
            findings.append(
                Finding(
                    code=f"{check.name.lower()}_fail",
                    title=f"{check.name} authentication failure",
                    points=10,
                    evidence=f"{check.name} result is {check.result}.",
                    source=check.source or "Authentication-Results",
                    details={"result": check.result, "raw": check.raw},
                )
            )
    return findings


def _sender_mismatch_findings(parsed: ParsedEmail) -> list[Finding]:
    from_domain = registrable_domain(domain_of(parsed.from_header))
    reply_domain = registrable_domain(domain_of(parsed.reply_to)) if parsed.reply_to else ""
    return_domain = registrable_domain(domain_of(parsed.return_path)) if parsed.return_path else ""

    findings: list[Finding] = []
    if from_domain and reply_domain and from_domain != reply_domain:
        findings.append(
            Finding(
                code="sender_reply_to_mismatch",
                title="Sender and Reply-To domains unexpectedly differ",
                points=10,
                evidence=(
                    f"From domain `{from_domain}` does not match Reply-To domain `{reply_domain}`."
                ),
                source="From / Reply-To headers",
                details={"from_domain": from_domain, "reply_to_domain": reply_domain},
            )
        )
    elif from_domain and return_domain and from_domain != return_domain and not reply_domain:
        findings.append(
            Finding(
                code="sender_reply_to_mismatch",
                title="Sender and Return-Path domains unexpectedly differ",
                points=10,
                evidence=(
                    f"From domain `{from_domain}` does not match Return-Path domain `{return_domain}`."
                ),
                source="From / Return-Path headers",
                details={"from_domain": from_domain, "return_path_domain": return_domain},
            )
        )
    return findings


def _lookalike_findings(parsed: ParsedEmail) -> list[Finding]:
    from_header = parsed.from_header
    from_domain = domain_of(from_header)
    display = extract_display_name(from_header)
    if not from_domain:
        return []

    brand_hit = _brand_impersonation(display, from_domain)
    lookalike_hit = _domain_lookalike(from_domain)
    hit = brand_hit or lookalike_hit
    if not hit:
        return []

    brand, evidence = hit
    return [
        Finding(
            code="lookalike_sender",
            title="Suspicious lookalike sender domain",
            points=15,
            evidence=evidence,
            source="From header (local lookalike check)",
            details={"brand": brand, "from_domain": from_domain, "display_name": display},
        )
    ]


def _brand_impersonation(display: str, from_domain: str) -> tuple[str, str] | None:
    normalized_display = re.sub(r"[^a-z0-9]+", " ", display.lower()).strip()
    from_reg = registrable_domain(from_domain)
    for brand, domains in KNOWN_BRANDS.items():
        if brand not in normalized_display:
            continue
        allowed = {registrable_domain(d) for d in domains}
        if from_reg not in allowed and not any(from_domain.endswith("." + d) or from_domain == d for d in domains):
            return (
                brand,
                (
                    f"Display name `{display}` impersonates `{brand}` while the From "
                    f"domain is `{from_domain}`."
                ),
            )
    return None


def _domain_lookalike(from_domain: str) -> tuple[str, str] | None:
    labels = from_domain.replace("-", "")
    folded = labels.translate(HOMOGLYPHS)
    from_reg = registrable_domain(from_domain)
    sld = from_reg.split(".")[0]

    for brand, domains in KNOWN_BRANDS.items():
        brand_token = brand.replace(" ", "")
        allowed = {registrable_domain(d) for d in domains}
        if from_reg in allowed:
            continue
        for allowed_domain in allowed:
            target_sld = allowed_domain.split(".")[0]
            distance = _levenshtein(sld, target_sld)
            folded_distance = _levenshtein(sld.translate(HOMOGLYPHS), target_sld)
            hyphen_variant = brand_token in from_domain.replace("-", "") and from_reg not in allowed
            if 0 < distance <= 2 or 0 < folded_distance <= 1 or hyphen_variant:
                return (
                    brand,
                    (
                        f"Sender domain `{from_domain}` resembles `{allowed_domain}` "
                        f"(lookalike of `{brand}`)."
                    ),
                )
        if brand_token in folded and from_reg not in allowed:
            return (
                brand,
                f"Sender domain `{from_domain}` contains a lookalike of `{brand}`.",
            )
    return None


def _levenshtein(left: str, right: str) -> int:
    if left == right:
        return 0
    if not left:
        return len(right)
    if not right:
        return len(left)
    previous = list(range(len(right) + 1))
    for i, lch in enumerate(left, start=1):
        current = [i]
        for j, rch in enumerate(right, start=1):
            insert = current[j - 1] + 1
            delete = previous[j] + 1
            replace = previous[j - 1] + (lch != rch)
            current.append(min(insert, delete, replace))
        previous = current
    return previous[-1]
