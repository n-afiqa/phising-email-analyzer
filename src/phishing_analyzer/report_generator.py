"""Render the HTML analysis report."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from phishing_analyzer import AuthCheck, __version__
from phishing_analyzer.parser import ParsedEmail, iter_relevant_headers
from phishing_analyzer.reputation import ReputationResult
from phishing_analyzer.risk_scorer import RiskResult

TEMPLATE_DIR = Path(__file__).resolve().parents[2] / "templates"


def generate_report(
    *,
    parsed: ParsedEmail,
    auth_checks: list[AuthCheck],
    url_records: list[dict],
    risk: RiskResult,
    reputation: ReputationResult,
    output_path: str | Path,
) -> Path:
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = env.get_template("report.html")
    analyzed_at = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    html = template.render(
        version=__version__,
        filename=parsed.filename,
        analyzed_at=analyzed_at,
        parsed=parsed,
        relevant_headers=list(iter_relevant_headers(parsed)),
        auth_checks=auth_checks,
        url_records=url_records,
        risk=risk,
        findings=risk.contributing,
        reputation=reputation,
        limitations=_limitations(parsed, auth_checks, reputation),
    )
    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(html, encoding="utf-8")
    return destination


def _limitations(
    parsed: ParsedEmail,
    auth_checks: list[AuthCheck],
    reputation: ReputationResult,
) -> list[str]:
    notes = [
        "A low score is not proof that a message is safe.",
        "Header authentication results describe the received message; DNS checks inspect current TXT policy and do not re-validate DKIM signatures. SPF uses Return-Path when available; DMARC uses the From domain.",
    ]
    if not reputation.enabled:
        notes.append("Online DNS and VirusTotal checks were not run. Use --offline-checks to disable them.")
    missing = [check.name for check in auth_checks if not check.available]
    if missing:
        notes.append(
            "Unavailable authentication checks: "
            + ", ".join(missing)
            + ". Missing data did not add points."
        )
    if not parsed.urls:
        notes.append("No URLs were extracted from the text or HTML bodies.")
    if reputation.skipped_reason:
        notes.append(reputation.skipped_reason)
    return notes
