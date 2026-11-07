"""Calculate a capped risk score from unique, evidence-backed findings."""

from __future__ import annotations

from dataclasses import dataclass, field

from phishing_analyzer import Finding

MAX_SCORE = 100

# Only award a finding type once even if several related signals exist.
DEDUPE_GROUPS = {
    "spf_fail": "auth_spf",
    "dkim_fail": "auth_dkim",
    "dmarc_fail": "auth_dmarc",
    "link_mismatch": "link_mismatch",
    "suspicious_url_pattern": "suspicious_url_pattern",
    "lookalike_sender": "lookalike_sender",
    "sender_reply_to_mismatch": "sender_reply_to_mismatch",
    "vt_malicious_url": "vt_malicious_url",
    "vt_malicious_sender_domain": "vt_malicious_sender_domain",
}

CATEGORIES = (
    (19, "Low"),
    (49, "Medium"),
    (74, "High"),
    (100, "Critical"),
)


@dataclass
class RiskResult:
    score: int
    category: str
    findings: list[Finding] = field(default_factory=list)
    dropped: list[Finding] = field(default_factory=list)

    @property
    def contributing(self) -> list[Finding]:
        return [item for item in self.findings if item.points > 0]


def score_findings(findings: list[Finding]) -> RiskResult:
    awarded: list[Finding] = []
    dropped: list[Finding] = []
    seen_groups: set[str] = set()
    total = 0

    for finding in findings:
        if finding.points <= 0:
            awarded.append(finding)
            continue
        group = DEDUPE_GROUPS.get(finding.code, finding.code)
        if group in seen_groups:
            dropped.append(finding)
            continue
        seen_groups.add(group)
        awarded.append(finding)
        total += finding.points

    total = min(total, MAX_SCORE)
    return RiskResult(
        score=total,
        category=category_for(total),
        findings=awarded,
        dropped=dropped,
    )


def category_for(score: int) -> str:
    for upper, label in CATEGORIES:
        if score <= upper:
            return label
    return "Critical"
