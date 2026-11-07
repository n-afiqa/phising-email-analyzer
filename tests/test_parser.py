from __future__ import annotations

from email.message import EmailMessage
from pathlib import Path

import pytest

from phishing_analyzer.parser import parse_eml

FIXTURES = Path(__file__).resolve().parents[1] / "samples"


def test_parse_benign_html_and_matching_link():
    parsed = parse_eml(FIXTURES / "benign.eml")
    assert parsed.subject == "October product notes"
    assert "updates@news.example.com" in parsed.from_header
    assert parsed.html_body
    assert any("news.example.com/october" in url.href for url in parsed.urls)


def test_parse_multipart_extracts_anchor_display_text():
    parsed = parse_eml(FIXTURES / "suspicious.eml")
    assert parsed.text_body
    assert parsed.html_body
    anchors = [url for url in parsed.urls if url.source == "html_anchor"]
    assert any(url.display_text == "https://paypal.com/login" for url in anchors)
    assert any("203.0.113.50" in url.href for url in anchors)


def test_missing_file_raises(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        parse_eml(tmp_path / "missing.eml")


def test_empty_file_raises(tmp_path: Path):
    empty = tmp_path / "empty.eml"
    empty.write_bytes(b"")
    with pytest.raises(ValueError, match="empty"):
        parse_eml(empty)


def test_malformed_non_email_raises(tmp_path: Path):
    junk = tmp_path / "junk.eml"
    junk.write_bytes(b"\x00\x01this is not an email")
    with pytest.raises(ValueError, match="parsed as an email"):
        parse_eml(junk)


def test_incomplete_email_still_parses(incomplete_email):
    parsed = parse_eml(incomplete_email)
    assert parsed.subject == "Incomplete sample"
    assert parsed.authentication_results == []
    assert parsed.urls == []


def test_generated_plain_text_urls(tmp_path: Path):
    message = EmailMessage()
    message["From"] = "a@b.example"
    message["To"] = "c@d.example"
    message["Subject"] = "plain"
    message.set_content("See www.example.com/path and https://safe.example/app")
    path = tmp_path / "plain.eml"
    path.write_bytes(message.as_bytes())
    parsed = parse_eml(path)
    hrefs = [url.href for url in parsed.urls]
    assert any("www.example.com/path" in href for href in hrefs)
    assert any("https://safe.example/app" in href for href in hrefs)
