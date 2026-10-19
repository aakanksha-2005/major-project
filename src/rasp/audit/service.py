"""Audit recording service (spec §3.I).

Milestone 2: the service is a facade over a pluggable `AuditStore`
backend — in-memory (explicitly configured, documented M1 test/demo
strategy) or PostgreSQL (the default target persistence layer).

Privacy properties (unchanged):
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
from typing import Protocol

from rasp.schemas.audit import AuditEvent
from rasp.settings import Settings


def pseudonymize(principal_id: str, salt: str) -> str:
    """Salted, truncated pseudonym. Not a production key-management solution."""
    digest = hashlib.sha256(f"{salt}:{principal_id}".encode()).hexdigest()
    return f"pid_{digest[:16]}"


class AuditStore(Protocol):
    """Backend contract. Implementations may raise on persistence failure;
    callers decide fail-closed vs. documented read-only fallback."""

    async def record(self, event: AuditEvent) -> AuditEvent: ...

    async def query(
        self,
        *,
        request_id: str | None = None,
        principal_refs: Iterable[str] | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[AuditEvent]: ...

    async def count(self) -> int: ...


class InMemoryAuditStore:
    """Bounded, thread-safe buffer. NOT durable — restarts lose events."""

    def __init__(self, buffer_size: int = 5000) -> None:
        self._events: deque[AuditEvent] = deque(maxlen=buffer_size)
        self._lock = threading.Lock()

    async def record(self, event: AuditEvent) -> AuditEvent:
        with self._lock:
            self._events.append(event)
        return event

    async def query(
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

    async def count(self) -> int:
        with self._lock:
            return len(self._events)


class AuditService:
    """Facade: pseudonymization policy + backend delegation.

    Constructor stays `AuditService(settings)` (in-memory backend) so the
    Milestone 1 unit suite keeps working; the container passes a
    PostgreSQL-backed store when `RASP_PERSISTENCE=postgres`.
    """

    def __init__(self, settings: Settings, store: AuditStore | None = None) -> None:
        self._settings = settings
        self._store: AuditStore = store or InMemoryAuditStore(settings.audit_buffer_size)

    @property
    def store(self) -> AuditStore:
        return self._store

    def principal_ref(self, principal_id: str) -> str:
        if self._settings.store_principal_ids:
            return principal_id
        return pseudonymize(principal_id, self._settings.audit_pseudonym_salt)

    async def record(self, event: AuditEvent) -> AuditEvent:
        return await self._store.record(event)

    async def query(
        self,
        *,
        request_id: str | None = None,
        principal_refs: Iterable[str] | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[AuditEvent]:
        return await self._store.query(
            request_id=request_id,
            principal_refs=principal_refs,
            limit=limit,
            offset=offset,
        )

    async def count(self) -> int:
        return await self._store.count()
