"""Audit recording service (spec §3.I).

Milestone 1 uses an in-memory, bounded buffer behind a small service
interface. PostgreSQL-backed persistence arrives in Milestone 2 without
changing call sites.

Privacy properties:
- events carry identifiers, decisions, and digests — never prompt content,
  tool arguments, tool outputs, credentials, or private records;
- principal identifiers are salted and truncated (pseudonymized) unless
  explicitly configured otherwise.
"""

from __future__ import annotations

import hashlib
import threading
from collections import deque
from collections.abc import Iterable

from rasp.schemas.audit import AuditEvent
from rasp.settings import Settings


def pseudonymize(principal_id: str, salt: str) -> str:
    """Salted, truncated pseudonym. Not a production key-management solution."""
    digest = hashlib.sha256(f"{salt}:{principal_id}".encode()).hexdigest()
    return f"pid_{digest[:16]}"


class AuditService:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._events: deque[AuditEvent] = deque(maxlen=settings.audit_buffer_size)
        self._lock = threading.Lock()

    def principal_ref(self, principal_id: str) -> str:
        if self._settings.store_principal_ids:
            return principal_id
        return pseudonymize(principal_id, self._settings.audit_pseudonym_salt)

    def record(self, event: AuditEvent) -> AuditEvent:
        with self._lock:
            self._events.append(event)
        return event

    def query(
        self,
        *,
        request_id: str | None = None,
        principal_refs: Iterable[str] | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[AuditEvent]:
        allowed_refs = set(principal_refs) if principal_refs is not None else None
        with self._lock:
            snapshot = list(self._events)
        matched = [
            event
            for event in snapshot
            if (request_id is None or event.request_id == request_id)
            and (allowed_refs is None or event.principal_ref in allowed_refs)
        ]
        # Newest first for review workflows.
        matched.reverse()
        return matched[offset : offset + limit]

    def count(self) -> int:
        with self._lock:
            return len(self._events)
