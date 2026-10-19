"""Output disclosure screening and redaction (spec §3.J, §11).

DEFENSE IN DEPTH ONLY. Pattern-based redaction cannot catch every sensitive
value; its limits are documented in docs/LIMITATIONS.md. It does not make
output safe by itself — it reduces accidental disclosure of well-known
secret shapes.
"""

from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

# Well-known secret shapes. Conservative patterns; documented as incomplete.
SECRET_PATTERNS: list[tuple[str, str]] = [
    ("private_key_block", r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    ("openai_style_key", r"\bsk-[A-Za-z0-9_\-]{16,}"),
    ("github_token", r"\bgh[pousr]_[A-Za-z0-9]{20,}"),
    ("password_assignment", r"(?i)\bpassword\s*[:=]\s*['\"]?\S{3,}"),
    ("aws_access_key", r"\bAKIA[0-9A-Z]{16}\b"),
]

_COMPILED: list[tuple[str, re.Pattern[str]]] = [
    (flag, re.compile(pattern)) for flag, pattern in SECRET_PATTERNS
]

REDACTION_TOKEN = "[REDACTED]"


class ScreeningResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: str
    flagged: bool = False
    redaction_count: int = 0
    flags: list[str] = Field(default_factory=list)


def screen_text(text: str) -> ScreeningResult:
    """Return text with known secret shapes redacted, plus flag metadata."""
    if not text:
        return ScreeningResult(text=text)
    out = text
    flags: list[str] = []
    count = 0
    for flag, pattern in _COMPILED:
        out, n = pattern.subn(REDACTION_TOKEN, out)
        if n:
            flags.append(flag)
            count += n
    return ScreeningResult(text=out, flagged=bool(flags), redaction_count=count, flags=flags)


def truncate_items(items: list[Any], max_items: int | None) -> tuple[list[Any], int]:
    """Enforce a policy output-item cap; returns (possibly truncated list, dropped)."""
    if max_items is None or len(items) <= max_items:
        return items, 0
    return items[:max_items], len(items) - max_items


def screen_output_payload(payload: Any) -> Any:
    """Best-effort redaction over string values inside a JSON-like payload."""
    if isinstance(payload, str):
        return screen_text(payload).text
    if isinstance(payload, list):
        return [screen_output_payload(item) for item in payload]
    if isinstance(payload, dict):
        return {key: screen_output_payload(value) for key, value in payload.items()}
    return payload
