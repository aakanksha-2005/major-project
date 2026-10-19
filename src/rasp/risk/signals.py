"""Deterministic prompt-injection and risk indicators (spec §3.E, §3.F, §11).

DEFENSE IN DEPTH ONLY. String matching is incomplete by design and is
documented as such (docs/LIMITATIONS.md). These signals are recorded in the
audit trail and returned as security flags — they NEVER override hard
authorization rules, and authorization is enforced even if detection misses.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field

from rasp.schemas.common import TrustCategory

# Known-pattern indicators for common direct/indirect injection attempts.
# Keep patterns specific to reduce false positives on legitimate coursework.
INJECTION_PATTERNS: list[tuple[str, str]] = [
    (
        "ignore_previous_instructions",
        r"ignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+instructions",
    ),
    (
        "disregard_system_policy",
        r"disregard\s+(?:the\s+)?(?:system|previous|safety)\s+(?:policy|prompt|instructions)",
    ),
    ("role_override", r"you\s+are\s+now\s+(?:a|an|the)\b"),
    ("developer_or_admin_mode", r"(?:developer|admin|god|sudo)\s+mode"),
    (
        "reveal_system_prompt",
        r"(?:reveal|show|print|repeat)\s+(?:your\s+)?(?:hidden\s+)?system\s+prompt",
    ),
    (
        "policy_tampering",
        r"(?:disable|bypass|override|turn\s+off)\s+(?:the\s+)?(?:policy|security|permissions?|approval)",
    ),
    (
        "fake_authorization",
        r"(?:i|the\s+user|admin(?:istrator)?)\s+(?:hereby\s+)?(?:approves?|authorizes?|grants?)\b",
    ),
    ("credential_request", r"(?:api\s*key|access\s+token|private\s+key|password)\s*(?:=|:)\s*\S+"),
]

_COMPILED: list[tuple[str, re.Pattern[str]]] = [
    (flag, re.compile(pattern, re.IGNORECASE)) for flag, pattern in INJECTION_PATTERNS
]


class RiskAssessment(BaseModel):
    """Supplementary signal only — never a substitute for authorization."""

    model_config = ConfigDict(extra="forbid")

    flags: list[str] = Field(default_factory=list)
    score: int = 0  # 0..len(flags); advisory only
    source: TrustCategory


def scan_text(text: str, source: TrustCategory) -> RiskAssessment:
    """Return matched indicator flags for a piece of content."""
    flags = [flag for flag, pattern in _COMPILED if pattern.search(text)]
    return RiskAssessment(flags=flags, score=min(len(flags), 5), source=source)


def scan_messages(messages: list[tuple[TrustCategory, str]]) -> RiskAssessment:
    """Aggregate flags across (category, text) pairs."""
    all_flags: list[str] = []
    for category, text in messages:
        all_flags.extend(scan_text(text, category).flags)
    # De-duplicate while preserving order.
    seen: dict[str, None] = {}
    for flag in all_flags:
        seen.setdefault(flag)
    return RiskAssessment(
        flags=list(seen),
        score=min(len(seen), 5),
        source=TrustCategory.USER,
    )
