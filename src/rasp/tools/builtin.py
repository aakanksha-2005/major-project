"""Synthetic demonstration tools (spec §8, §9).

Every tool here is harmless and synthetic — no network, no shell, no SQL,
no filesystem access. EXECUTION_LOG provides test instrumentation proving
whether a tool implementation was ever reached (for "denied actions never
reach the tool implementation" tests).

Registered tools:
  system_status         read-only demo (plain ALLOW)
  document_search       read-only demo (ALLOW_WITH_CONSTRAINTS)
  application_preview   read-only demo (medium risk)
  publish_announcement  mutating, enabled, REQUIRES APPROVAL (pending demo)
  application_submit    mutating, DISABLED (negative tests)
  record_delete         mutating, critical, DISABLED (negative tests)
"""

from __future__ import annotations

import time
from typing import Any

# Test instrumentation: appended by mutating handlers on every real call.
# Adversarial tests assert this stays empty when actions are denied.
EXECUTION_LOG: list[str] = []

# Synthetic, clearly-labelled educational-style documents. No real records.
SYNTHETIC_DOCUMENTS: list[dict[str, Any]] = [
    {
        "doc_id": "syn-doc-001",
        "title": "Binary search primer",
        "body": "Binary search repeatedly halves a sorted search space, running in O(log n) time.",
        "classification": "synthetic",
    },
    {
        "doc_id": "syn-doc-002",
        "title": "TCP handshake overview",
        "body": "A TCP connection starts with SYN, SYN-ACK, then ACK.",
        "classification": "synthetic",
    },
    {
        "doc_id": "syn-doc-003",
        "title": "SQL index notes",
        "body": "An index speeds reads but slows writes and costs storage.",
        "classification": "synthetic",
    },
    {
        "doc_id": "syn-doc-004",
        "title": "Linked list operations",
        "body": "Insertion at the head of a linked list is O(1) when the "
        "head pointer is available.",
        "classification": "synthetic",
    },
    {
        "doc_id": "syn-doc-005",
        "title": "Operating system scheduling",
        "body": "Round-robin scheduling gives each process a fixed time slice.",
        "classification": "synthetic",
    },
    {
        "doc_id": "syn-doc-006",
        "title": "CAP theorem summary",
        "body": "Under a network partition a distributed system trades "
        "consistency for availability or vice versa.",
        "classification": "synthetic",
    },
]


def system_status() -> dict[str, Any]:
    """Read-only synthetic status lookup."""
    return {
        "status": "ok",
        "version": "0.1.0",
        "components": {"policy_engine": "ok", "executor": "ok", "audit": "ok"},
        "data_classification": "synthetic",
    }


def document_search(query: str, max_results: int = 5) -> dict[str, Any]:
    """Read-only search over the local synthetic document collection."""
    needle = query.strip().lower()
    matches = [
        doc
        for doc in SYNTHETIC_DOCUMENTS
        if needle and (needle in doc["title"].lower() or needle in doc["body"].lower())
    ]
    return {
        "query": query,
        "total_matches": len(matches),
        "documents": matches[: max(0, int(max_results))],
        "data_classification": "synthetic",
    }


def application_preview(application_id: str) -> dict[str, Any]:
    """Read-only preview of a synthetic application record."""
    EXECUTION_LOG.append(f"application_preview:{application_id}")
    return {
        "application_id": application_id,
        "status": "draft",
        "applicant": "synthetic-applicant-001",
        "amount": 0,
        "data_classification": "synthetic",
    }


def publish_announcement(title: str, body: str) -> dict[str, Any]:
    """Mutating demo tool — policy requires human approval before execution."""
    EXECUTION_LOG.append(f"publish_announcement:{title}")
    return {"queued": True, "announcement_id": "syn-ann-001", "title": title, "body": body}


def application_submit(application_id: str) -> dict[str, Any]:
    """Mutating demo tool — DISABLED by policy (negative tests only)."""
    EXECUTION_LOG.append(f"application_submit:{application_id}")
    return {"submitted": True, "application_id": application_id}


def record_delete(record_id: str) -> dict[str, Any]:
    """Mutating critical demo tool — DISABLED by policy (negative tests only)."""
    EXECUTION_LOG.append(f"record_delete:{record_id}")
    return {"deleted": 1, "record_id": record_id}


def slow_echo(delay_seconds: float, echo: str) -> dict[str, Any]:
    """Test-support tool: demonstrates timeout enforcement. Sleeps, then echoes."""
    EXECUTION_LOG.append("slow_echo")
    time.sleep(delay_seconds)
    return {"echo": echo}
