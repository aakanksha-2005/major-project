"""Application wiring: builds the component graph from validated settings.

Startup fails closed: invalid or contradictory policy configuration raises
PolicyConfigError and the application refuses to start (spec §7, rule 11).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from rasp.approvals.store import ApprovalStore
from rasp.audit.service import AuditService
from rasp.executor.executor import ControlledExecutor
from rasp.gateway.lifecycle import ChatOrchestrator
from rasp.models.base import ModelAdapter
from rasp.models.local import LocalOpenAICompatibleAdapter, OllamaModelAdapter
from rasp.models.mock import MockModelAdapter
from rasp.persistence.db import Database
from rasp.persistence.repositories import (
    PolicyRepository,
    PostgresApprovalStore,
    PostgresAuditStore,
)
from rasp.pilot.readiness import PilotReadiness, validate_pilot_readiness
from rasp.policy.config import (
    PolicyConfig,
    load_policy_file,
    validate_policy_registry_consistency,
)
from rasp.policy.engine import PolicyEngine
from rasp.schemas.tool import RiskLevel, ToolDefinition
from rasp.settings import Settings
from rasp.tools.builtin import (
    application_preview,
    application_submit,
    document_search,
    publish_announcement,
    record_delete,
    system_status,
)
from rasp.tools.registry import ToolRegistry


@dataclass(frozen=True)
class Container:
    settings: Settings
    registry: ToolRegistry
    policy_config: PolicyConfig
    engine: PolicyEngine
    approvals: ApprovalStore
    audit: AuditService
    model: ModelAdapter
    executor: ControlledExecutor
    orchestrator: ChatOrchestrator
    # Milestone 6 pilot readiness (mode + acknowledgements); always present.
    pilot: PilotReadiness
    # Database is None for the explicitly configured in-memory mode.
    db: Database | None = None
    policy_repository: PolicyRepository | None = None

    async def close(self) -> None:
        """Dispose pooled connections (used by tests and shutdown)."""
        if self.db is not None:
            await self.db.dispose()


def resolve_policy_path(settings: Settings) -> Path:
    """Locate the policy file: explicit/env path first, then repo-root default."""
    candidate = Path(settings.policy_path)
    if candidate.is_file():
        return candidate
    if not candidate.is_absolute():
        # src/rasp/container.py -> parents[2] == repository root
        repo_relative = Path(__file__).resolve().parents[2] / candidate
        if repo_relative.is_file():
            return repo_relative
    return candidate  # let load_policy_file raise a clear error


def builtin_tool_definitions() -> list[ToolDefinition]:
    """Trusted registrations for the synthetic demonstration tools."""
    return [
        ToolDefinition(
            tool_id="system_status",
            version="1.0.0",
            description="Read-only synthetic system status lookup.",
            input_schema={
                "type": "object",
                "properties": {},
                "additionalProperties": False,
            },
            output_schema={
                "type": "object",
                "properties": {"status": {"type": "string"}},
                "required": ["status"],
            },
            permission="system:status",
            risk=RiskLevel.LOW,
            read_only=True,
            requires_approval=False,
            timeout_seconds=5.0,
            handler=system_status,
        ),
        ToolDefinition(
            tool_id="document_search",
            version="1.0.0",
            description="Search the local synthetic document collection (read-only).",
            input_schema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "minLength": 1, "maxLength": 200},
                    "max_results": {"type": "integer", "minimum": 1, "maximum": 100},
                },
                "required": ["query"],
                "additionalProperties": False,
            },
            output_schema={
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "total_matches": {"type": "integer"},
                    "documents": {"type": "array"},
                },
                "required": ["query", "total_matches", "documents"],
            },
            permission="documents:read",
            risk=RiskLevel.LOW,
            read_only=True,
            requires_approval=False,
            timeout_seconds=5.0,
            handler=document_search,
        ),
        ToolDefinition(
            tool_id="application_preview",
            version="1.0.0",
            description="Read-only preview of a synthetic application record.",
            input_schema={
                "type": "object",
                "properties": {
                    "application_id": {"type": "string", "minLength": 1, "maxLength": 64}
                },
                "required": ["application_id"],
                "additionalProperties": False,
            },
            output_schema={
                "type": "object",
                "properties": {"application_id": {"type": "string"}},
                "required": ["application_id"],
            },
            permission="applications:preview",
            risk=RiskLevel.MEDIUM,
            read_only=True,
            requires_approval=False,
            timeout_seconds=5.0,
            handler=application_preview,
        ),
        ToolDefinition(
            tool_id="publish_announcement",
            version="1.0.0",
            description="Queue a synthetic announcement (mutating; needs approval).",
            input_schema={
                "type": "object",
                "properties": {
                    "title": {"type": "string", "minLength": 1, "maxLength": 200},
                    "body": {"type": "string", "minLength": 1, "maxLength": 2000},
                },
                "required": ["title", "body"],
                "additionalProperties": False,
            },
            output_schema={
                "type": "object",
                "properties": {"queued": {"type": "boolean"}},
                "required": ["queued"],
            },
            permission="announcements:publish",
            risk=RiskLevel.HIGH,
            read_only=False,
            requires_approval=True,
            timeout_seconds=5.0,
            handler=publish_announcement,
        ),
        ToolDefinition(
            tool_id="application_submit",
            version="1.0.0",
            description="Submit a synthetic application (mutating; disabled by policy).",
            input_schema={
                "type": "object",
                "properties": {
                    "application_id": {"type": "string", "minLength": 1, "maxLength": 64}
                },
                "required": ["application_id"],
                "additionalProperties": False,
            },
            output_schema={
                "type": "object",
                "properties": {"submitted": {"type": "boolean"}},
                "required": ["submitted"],
            },
            permission="applications:submit",
            risk=RiskLevel.HIGH,
            read_only=False,
            requires_approval=True,
            timeout_seconds=5.0,
            handler=application_submit,
        ),
        ToolDefinition(
            tool_id="record_delete",
            version="1.0.0",
            description="Delete a synthetic record (mutating; disabled by policy).",
            input_schema={
                "type": "object",
                "properties": {"record_id": {"type": "string", "minLength": 1, "maxLength": 64}},
                "required": ["record_id"],
                "additionalProperties": False,
            },
            output_schema={
                "type": "object",
                "properties": {"deleted": {"type": "integer"}},
                "required": ["deleted"],
            },
            permission="records:delete",
            risk=RiskLevel.CRITICAL,
            read_only=False,
            requires_approval=True,
            timeout_seconds=5.0,
            handler=record_delete,
        ),
    ]


def build_model_adapter(settings: Settings) -> ModelAdapter:
    """Build the configured model adapter.

    ``mock`` (M1) is deterministic and offline. ``local`` / ``ollama`` (M4)
    target a locally hosted runtime and require no cloud credentials. Any
    unknown provider refuses startup instead of silently falling back.
    """
    provider = settings.model_provider
    if provider == "mock":
        return MockModelAdapter()
    if provider == "local":
        return LocalOpenAICompatibleAdapter(
            base_url=settings.local_model_base_url,
            model_name=settings.local_model_name,
            api_key=settings.local_model_api_key,
            timeout_seconds=settings.local_model_timeout_seconds,
            max_output_chars=settings.local_model_max_output_chars,
        )
    if provider == "ollama":
        return OllamaModelAdapter(
            base_url=settings.local_model_base_url,
            model_name=settings.local_model_name,
            api_key=settings.local_model_api_key,
            timeout_seconds=settings.local_model_timeout_seconds,
            max_output_chars=settings.local_model_max_output_chars,
        )
    raise ValueError(
        f"model provider '{provider}' is not implemented; "
        "expected 'mock', 'local', or 'ollama' (no silent fallback)"
    )


def build_persistence(
    settings: Settings, policy_config: PolicyConfig
) -> tuple[
    AuditService,
    ApprovalStore,
    Database | None,
    PolicyRepository | None,
]:
    """Wire the configured persistence backend.

    - `postgres` (default): PostgreSQL stores; database errors surface from
      store calls and the executor fails closed for sensitive actions.
    - `in_memory`: explicit opt-out for demos and the documented M1 test
      strategy (no database involved).
    - Any other value refuses startup (no silent fallback).
    """
    if settings.persistence == "in_memory":
        audit = AuditService(settings)
        approvals = ApprovalStore(ttl_seconds=settings.approval_ttl_seconds)
        return audit, approvals, None, None
    if settings.persistence == "postgres":
        db = Database(settings)
        policy_repo = PolicyRepository(db, policy_config)
        audit = AuditService(settings, store=PostgresAuditStore(db, policy_repo))
        approvals = ApprovalStore(
            ttl_seconds=settings.approval_ttl_seconds,
            backend=PostgresApprovalStore(db, policy_repo),
        )
        return audit, approvals, db, policy_repo
    raise ValueError(
        f"unknown persistence mode '{settings.persistence}'; "
        "expected 'postgres' or 'in_memory' (no silent fallback)"
    )


def build_container(settings: Settings) -> Container:
    policy_path = resolve_policy_path(settings)
    policy_config = load_policy_file(policy_path)

    # M6: refuse startup when pilot mode is unknown or its acknowledgements are
    # incomplete. This does not weaken any enforcement — it gates a *mode*.
    pilot = validate_pilot_readiness(settings)

    registry = ToolRegistry()
    for definition in builtin_tool_definitions():
        registry.register(definition)

    # Refuse startup on contradictory security settings.
    validate_policy_registry_consistency(policy_config, registry.list())

    engine = PolicyEngine(policy_config, registry)
    audit, approvals, db, policy_repo = build_persistence(settings, policy_config)
    model = build_model_adapter(settings)
    executor = ControlledExecutor(
        registry=registry, engine=engine, approvals=approvals, audit=audit
    )
    orchestrator = ChatOrchestrator(settings=settings, model=model, executor=executor, audit=audit)
    return Container(
        settings=settings,
        registry=registry,
        policy_config=policy_config,
        engine=engine,
        approvals=approvals,
        audit=audit,
        model=model,
        executor=executor,
        orchestrator=orchestrator,
        pilot=pilot,
        db=db,
        policy_repository=policy_repo,
    )
