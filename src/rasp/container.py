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
from rasp.models.mock import MockModelAdapter
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
    """Only the mock provider is implemented (Milestone 1).

    Unknown providers refuse startup instead of silently falling back.
    """
    if settings.model_provider == "mock":
        return MockModelAdapter()
    raise ValueError(
        f"model provider '{settings.model_provider}' is not implemented yet; "
        "only 'mock' is available in Milestone 1 (local adapter planned for M4)"
    )


def build_container(settings: Settings) -> Container:
    policy_path = resolve_policy_path(settings)
    policy_config = load_policy_file(policy_path)

    registry = ToolRegistry()
    for definition in builtin_tool_definitions():
        registry.register(definition)

    # Refuse startup on contradictory security settings.
    validate_policy_registry_consistency(policy_config, registry.list())

    engine = PolicyEngine(policy_config, registry)
    approvals = ApprovalStore(ttl_seconds=settings.approval_ttl_seconds)
    audit = AuditService(settings)
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
    )
