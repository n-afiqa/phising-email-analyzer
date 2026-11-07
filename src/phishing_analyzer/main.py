"""CLI, workflow coordination, and error handling."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

from phishing_analyzer import __version__
from phishing_analyzer.header_analyzer import analyze_headers
from phishing_analyzer.parser import parse_eml
from phishing_analyzer.report_generator import generate_report
from phishing_analyzer.reputation import check_reputation
from phishing_analyzer.risk_scorer import score_findings
from phishing_analyzer.url_analyzer import analyze_urls

DEFAULT_REPORT_DIR = Path("reports")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phishing-analyzer",
        description="Analyze a saved .eml file with online DNS checks by default.",
    )
    parser.add_argument("eml_path", help="Path to a single .eml file")
    parser.add_argument(
        "-o",
        "--output",
        help="HTML report path or directory (default: reports/<filename>.html)",
    )
    online_group = parser.add_mutually_exclusive_group()
    online_group.add_argument(
        "--online-checks",
        action="store_true",
        help="Run online checks (the default; may disclose indicators)",
    )
    online_group.add_argument(
        "--offline-checks",
        dest="online_checks",
        action="store_false",
        help="Disable DNS and VirusTotal lookups",
    )
    parser.set_defaults(online_checks=True)
    parser.add_argument(
        "--version",
        action="version",
        version=f"phishing-email-analyzer {__version__}",
    )
    return parser


def resolve_output_path(eml_path: Path, output: str | None) -> Path:
    if not output:
        return DEFAULT_REPORT_DIR / f"{eml_path.stem}.html"
    candidate = Path(output)
    if candidate.exists() and candidate.is_dir():
        return candidate / f"{eml_path.stem}.html"
    if str(output).endswith(("/", "\\")) or candidate.suffix.lower() != ".html":
        return candidate / f"{eml_path.stem}.html"
    return candidate


def analyze_file(
    eml_path: Path,
    output_path: Path,
    *,
    online_checks: bool = True,
    api_key: str | None = None,
) -> Path:
    parsed = parse_eml(eml_path)
    auth_checks, header_findings = analyze_headers(parsed)
    url_records, url_findings = analyze_urls(parsed)
    reputation = check_reputation(
        parsed,
        enabled=online_checks,
        api_key=api_key,
    )
    risk = score_findings(header_findings + url_findings + reputation.findings)
    return generate_report(
        parsed=parsed,
        auth_checks=auth_checks,
        url_records=url_records,
        risk=risk,
        reputation=reputation,
        output_path=output_path,
    )


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    eml_path = Path(args.eml_path)
    output_path = resolve_output_path(eml_path, args.output)
    api_key = None
    if args.online_checks:
        load_dotenv(Path.cwd() / ".env")
        api_key = os.getenv("VIRUSTOTAL_API_KEY")
    try:
        report = analyze_file(
            eml_path,
            output_path,
            online_checks=args.online_checks,
            api_key=api_key,
        )
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"error: unable to read or write files: {exc}", file=sys.stderr)
        return 2

    print(f"Report written to {report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
