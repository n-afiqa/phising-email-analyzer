"""Parse .eml files and extract headers, bodies, and links."""

from __future__ import annotations

import email
import email.policy
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from email.message import EmailMessage, Message
from pathlib import Path

from bs4 import BeautifulSoup

TEXT_URL_RE = re.compile(
    r"""(?xi)
    \b(
        (?:https?|ftp)://[^\s<>"'\)\]]+
        | www\.[^\s<>"'\)\]]+
    )
    """
)


@dataclass
class ExtractedUrl:
    href: str
    display_text: str
    source: str  # html_anchor | text_body | html_bare


@dataclass
class AttachmentInfo:
    filename: str
    content_type: str


@dataclass
class ParsedEmail:
    path: Path
    filename: str
    message: Message
    headers: dict[str, str]
    from_header: str
    to_header: str
    subject: str
    date_header: str
    reply_to: str
    return_path: str
    authentication_results: list[str]
    received_spf: list[str]
    text_body: str
    html_body: str
    urls: list[ExtractedUrl] = field(default_factory=list)
    attachments: list[AttachmentInfo] = field(default_factory=list)


def parse_eml(path: str | Path) -> ParsedEmail:
    eml_path = Path(path)
    if not eml_path.exists():
        raise FileNotFoundError(f"Email file not found: {eml_path}")
    if not eml_path.is_file():
        raise ValueError(f"Path is not a file: {eml_path}")
    if eml_path.stat().st_size == 0:
        raise ValueError(f"Email file is empty: {eml_path}")

    raw = eml_path.read_bytes()
    try:
        message = email.message_from_bytes(raw, policy=email.policy.default)
    except Exception as exc:  # pragma: no cover - extremely malformed bytes
        raise ValueError(f"Unable to parse email: {exc}") from exc

    if not isinstance(message, Message) or not _looks_like_email(message, raw):
        raise ValueError("File could not be parsed as an email message")

    headers = _flatten_headers(message)
    text_body, html_body, attachments = _extract_bodies(message)
    urls = _extract_urls(text_body, html_body)

    return ParsedEmail(
        path=eml_path,
        filename=eml_path.name,
        message=message,
        headers=headers,
        from_header=_header(message, "From"),
        to_header=_header(message, "To"),
        subject=_header(message, "Subject"),
        date_header=_header(message, "Date"),
        reply_to=_header(message, "Reply-To"),
        return_path=_header(message, "Return-Path"),
        authentication_results=_all_headers(message, "Authentication-Results"),
        received_spf=_all_headers(message, "Received-SPF"),
        text_body=text_body,
        html_body=html_body,
        urls=urls,
        attachments=attachments,
    )


def _looks_like_email(message: Message, raw: bytes) -> bool:
    if message.keys():
        return True
    sample = raw[:2048].decode("utf-8", errors="replace")
    return bool(re.search(r"(?im)^(From|To|Subject|Date|Received):", sample))


def _header(message: Message, name: str) -> str:
    value = message.get(name)
    if value is None:
        return ""
    return str(value).strip()


def _all_headers(message: Message, name: str) -> list[str]:
    return [str(value).strip() for value in message.get_all(name, []) if str(value).strip()]


def _flatten_headers(message: Message) -> dict[str, str]:
    grouped: dict[str, list[str]] = {}
    for key, value in message.items():
        grouped.setdefault(key, []).append(str(value).strip())
    return {key: "\n".join(values) for key, values in grouped.items()}


def _extract_bodies(message: Message) -> tuple[str, str, list[AttachmentInfo]]:
    text_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[AttachmentInfo] = []

    if message.is_multipart():
        for part in message.walk():
            if part.is_multipart():
                continue
            _consume_part(part, text_parts, html_parts, attachments)
    else:
        _consume_part(message, text_parts, html_parts, attachments)

    return "\n".join(text_parts).strip(), "\n".join(html_parts).strip(), attachments


def _consume_part(
    part: Message,
    text_parts: list[str],
    html_parts: list[str],
    attachments: list[AttachmentInfo],
) -> None:
    filename = part.get_filename()
    content_type = (part.get_content_type() or "").lower()
    disposition = str(part.get("Content-Disposition") or "").lower()

    if filename or "attachment" in disposition:
        attachments.append(
            AttachmentInfo(
                filename=filename or "unnamed",
                content_type=content_type or "application/octet-stream",
            )
        )
        if content_type not in {"text/plain", "text/html"}:
            return

    payload = _decode_payload(part)
    if not payload:
        return
    if content_type == "text/html":
        html_parts.append(payload)
    elif content_type.startswith("text/"):
        text_parts.append(payload)


def _decode_payload(part: Message) -> str:
    try:
        if isinstance(part, EmailMessage):
            content = part.get_content()
            return content if isinstance(content, str) else ""
    except (KeyError, LookupError, ValueError, AttributeError):
        pass

    payload = part.get_payload(decode=True)
    if payload is None:
        raw = part.get_payload()
        return raw if isinstance(raw, str) else ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except LookupError:
        return payload.decode("utf-8", errors="replace")


def _extract_urls(text_body: str, html_body: str) -> list[ExtractedUrl]:
    found: list[ExtractedUrl] = []
    seen: set[tuple[str, str, str]] = set()

    def add(href: str, display: str, source: str) -> None:
        href = _clean_url(href)
        display = re.sub(r"\s+", " ", display).strip()
        if not href:
            return
        key = (href, display, source)
        if key in seen:
            return
        seen.add(key)
        found.append(ExtractedUrl(href=href, display_text=display, source=source))

    if html_body:
        soup = BeautifulSoup(html_body, "html.parser")
        for anchor in soup.find_all("a", href=True):
            href = str(anchor.get("href") or "")
            text = anchor.get_text(" ", strip=True) or href
            add(href, text, "html_anchor")
        html_text = soup.get_text(" ", strip=True)
        for match in TEXT_URL_RE.findall(html_text):
            add(match, match, "html_bare")

    for match in TEXT_URL_RE.findall(text_body or ""):
        add(match, match, "text_body")

    return found


def _clean_url(value: str) -> str:
    return value.strip().rstrip(".,;)]}>\"'")


def iter_relevant_headers(parsed: ParsedEmail) -> Iterable[tuple[str, str]]:
    preferred = (
        "From",
        "To",
        "Cc",
        "Subject",
        "Date",
        "Reply-To",
        "Return-Path",
        "Message-ID",
        "Authentication-Results",
        "Received-SPF",
        "DKIM-Signature",
        "ARC-Authentication-Results",
    )
    for name in preferred:
        values = _all_headers(parsed.message, name)
        for value in values:
            yield name, value
