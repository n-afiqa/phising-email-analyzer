"""Phishing email analyzer."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

__version__ = "1.1.0"


@dataclass
class Finding:
    """A single scored or informational analysis result."""

    code: str
    title: str
    points: int
    evidence: str
    source: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class AuthCheck:
    name: str
    result: str
    raw: str = ""
    source: str = ""
    available: bool = False
