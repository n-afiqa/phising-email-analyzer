from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

SAMPLES = ROOT / "samples"


@pytest.fixture
def incomplete_email(tmp_path: Path) -> Path:
    email_path = tmp_path / "incomplete.eml"
    email_path.write_text(
        "From: sender@example.org\n"
        "To: recipient@example.net\n"
        "Subject: Incomplete sample\n"
        "\n"
        "No authentication results or URLs.\n",
        encoding="utf-8",
    )
    return email_path
