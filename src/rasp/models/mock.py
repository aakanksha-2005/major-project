"""Deterministic mock model adapter (Milestone 1).

No credentials, no network, no randomness: identical input sequences
produce identical outputs. Supports predefined scenarios for demos and
tests, plus simple keyword routing for interactive use.

The mock never claims authority — every tool call it emits is still
proposed into the RASP enforcement pipeline like any real model output.
"""

from __future__ import annotations

import json
from typing import Any

from rasp.models.base import ModelAdapter
from rasp.schemas.model import (
    FinishReason,
    ModelMessage,
    ModelOptions,
    ModelResponse,
    ProviderCapabilities,
    ProviderHealth,
    ToolProposal,
    TrustCategory,
)

# Deterministic default arguments for scenario-driven tool proposals.
DEFAULT_ARGS: dict[str, dict[str, Any]] = {
    "system_status": {},
    "document_search": {"query": "binary search", "max_results": 3},
    "application_preview": {"application_id": "syn-app-001"},
    "publish_announcement": {
        "title": "Synthetic lab reminder",
        "body": "Synthetic announcement used for demonstration.",
    },
    "application_submit": {"application_id": "syn-app-001"},
    "record_delete": {"record_id": "syn-rec-001"},
}

# Deliberately invalid argument sets (schema-violating) for negative tests.
INVALID_ARGS: dict[str, dict[str, Any]] = {
    "document_search": {"max_results": "three"},  # missing query, wrong type
    "application_preview": {"application_id": 42},  # wrong type
}

# Arguments that violate policy argument caps (schema-valid but over the cap).
OVERSIZED_ARGS: dict[str, dict[str, Any]] = {
    "document_search": {"query": "index", "max_results": 50},
}

SCENARIOS = {
    "text": None,  # handled specially
    "call_system_status": ("system_status", {}),
    "call_document_search": ("document_search", DEFAULT_ARGS["document_search"]),
    "call_application_preview": ("application_preview", DEFAULT_ARGS["application_preview"]),
    "call_publish_announcement": ("publish_announcement", DEFAULT_ARGS["publish_announcement"]),
    "call_record_delete": ("record_delete", DEFAULT_ARGS["record_delete"]),
    "call_application_submit": ("application_submit", DEFAULT_ARGS["application_submit"]),
    "call_unknown_tool": ("exfiltrate_credentials", {}),
    "call_invalid_args": ("document_search", INVALID_ARGS["document_search"]),
    "call_oversized_args": ("document_search", OVERSIZED_ARGS["document_search"]),
}

_DENIED_TEXT = "The requested action was not permitted by the runtime security layer."
_PENDING_TEXT = "The requested action requires human approval before it can run."


class MockModelAdapter(ModelAdapter):
    model_id = "mock-deterministic-v1"

    async def generate(
        self,
        messages: list[ModelMessage],
        options: ModelOptions | None = None,
    ) -> ModelResponse:
        options = options or ModelOptions()

        if options.scenario:
            return self._from_scenario(options.scenario, messages)

        if not messages:
            return self._text("No input received.")

        last = messages[-1]
        if last.role == "tool":
            return self._summarize_tool_result(last)
        if last.role in ("system", "assistant"):
            # Deterministic acknowledgement; no tool proposal.
            return self._text("Mock model ready. Send a request to continue.")
        return self._route_user_message(last.content)

    async def health_check(self) -> ProviderHealth:
        return ProviderHealth(ok=True, provider="mock", detail="deterministic mock")

    def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(
            provider="mock",
            supports_tool_calls=True,
            deterministic=True,
            requires_credentials=False,
        )

    # --- deterministic helpers -------------------------------------------------

    def _text(self, text: str) -> ModelResponse:
        return ModelResponse(
            model_id=self.model_id,
            text=text,
            tool_calls=[],
            finish_reason=FinishReason.STOP,
        )

    def _tool_call(self, tool_id: str, arguments: dict[str, Any]) -> ModelResponse:
        return ModelResponse(
            model_id=self.model_id,
            text=None,
            tool_calls=[ToolProposal(tool_id=tool_id, arguments=arguments)],
            finish_reason=FinishReason.TOOL_CALL,
        )

    def _from_scenario(self, scenario: str, messages: list[ModelMessage]) -> ModelResponse:
        if scenario == "text":
            return self._text("Deterministic mock response for scenario 'text'.")
        if scenario in SCENARIOS and SCENARIOS[scenario] is not None:
            tool_id, arguments = SCENARIOS[scenario]  # type: ignore[misc]
            return self._tool_call(tool_id, dict(arguments))
        # Unknown scenario: deterministic text fallback (never a tool call).
        return self._text(f"Unknown scenario '{scenario}'; returning text response.")

    def _route_user_message(self, content: str) -> ModelResponse:
        """Keyword routing so interactive demos exercise real tool paths."""
        lowered = content.lower()
        if "delete" in lowered:
            return self._tool_call("record_delete", {"record_id": "syn-rec-001"})
        if "submit application" in lowered:
            return self._tool_call("application_submit", {"application_id": "syn-app-001"})
        if "publish" in lowered or "announce" in lowered:
            return self._tool_call("publish_announcement", DEFAULT_ARGS["publish_announcement"])
        if "status" in lowered:
            return self._tool_call("system_status", {})
        if "search" in lowered:
            query = content.lower().split("search", 1)[1].strip(" :-\"'") or "binary search"
            return self._tool_call("document_search", {"query": query[:80], "max_results": 3})
        # Plain educational-style reply (deterministic template).
        snippet = " ".join(content.split())[:200]
        return self._text(
            f"Deterministic mock reply to: {snippet}. "
            "Set RASP_MODEL_PROVIDER=local to use a real local model."
        )

    def _summarize_tool_result(self, message: ModelMessage) -> ModelResponse:
        content = message.content
        if '"denied"' in content or '"blocked"' in content:
            return self._text(_DENIED_TEXT)
        if '"pending_approval"' in content:
            return self._text(_PENDING_TEXT)
        summary = " ".join(content.split())[:300]
        tool_label = message.tool_id or "tool"
        return self._text(f"Tool '{tool_label}' returned: {summary}")


def encode_tool_result_content(status: str, payload: dict[str, Any]) -> str:
    """Canonical, size-bounded content for tool-result messages."""
    body = {"status": status, **payload}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)[:4000]


def build_system_policy_message(text: str) -> ModelMessage:
    """Trusted, application-authored system policy message."""
    return ModelMessage(role="system", content=text, source=TrustCategory.SYSTEM_POLICY)
