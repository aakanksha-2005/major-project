"""Local LLM adapters (Milestone 4).

Provider-neutral contract is unchanged: every adapter implements
``ModelAdapter`` and returns an *untrusted proposal*. Nothing here decides
authorization; enforcement stays in the executor.

Two local, credential-free-by-default adapters are provided:

- :class:`LocalOpenAICompatibleAdapter` (provider id ``local``) talks to any
  server exposing the OpenAI ``POST {base_url}/chat/completions`` API
  (Ollama, LM Studio, llama.cpp ``--server``, vLLM, text-generation-webui, …).
- :class:`OllamaModelAdapter` (provider id ``ollama``) talks to Ollama's
  native ``POST {base_url}/api/chat`` endpoint.

Failure policy (fail closed): any transport error, non-2xx status, malformed
JSON, or schema violation raises :class:`ModelAdapterError`. The adapter never
invents a tool call and never treats a model error as "no action required by
policy" — the orchestrator turns the error into a safe error response.

No prompts, arguments, outputs, endpoints, or credentials are ever logged.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx

from rasp.models.base import ModelAdapter, ModelAdapterError
from rasp.schemas.model import (
    FinishReason,
    ModelMessage,
    ModelOptions,
    ModelResponse,
    ProviderCapabilities,
    ProviderHealth,
    ToolProposal,
)

logger = logging.getLogger("rasp.models")

# Only these role strings are ever sent upstream. Untrusted content stays in
# the `content` field and can never alter roles or inject tool calls.
_ALLOWED_ROLES = frozenset({"system", "user", "assistant", "tool"})


def _messages_to_openai(messages: list[ModelMessage]) -> list[dict[str, Any]]:
    """Translate trusted ModelMessage objects into OpenAI chat messages.

    Tool-result messages become ``role: "tool"`` messages; because RASP's
    tool-result content is a self-describing JSON document, it is passed
    through verbatim as the ``content`` value.
    """
    out: list[dict[str, Any]] = []
    for message in messages:
        role = message.role if message.role in _ALLOWED_ROLES else "user"
        out.append({"role": role, "content": message.content})
    return out


def _parse_tool_arguments(raw: Any) -> dict[str, Any]:
    """Best-effort parse of OpenAI ``function.arguments`` (a JSON *string*).

    A model may return malformed JSON, a JSON array, or a non-object. Any of
    those become an empty argument set here; schema validation downstream
    still rejects them. We never raise from parsing because a bad proposal is
    a normal (and deny-able) event, not a transport failure.
    """
    if isinstance(raw, dict):
        return raw
    if raw is None:
        return {}
    if isinstance(raw, str):
        text = raw.strip()
        if not text:
            return {}
        try:
            parsed = json.loads(text)
        except (ValueError, TypeError):
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def _tool_calls_from_openai(raw_calls: Any) -> list[ToolProposal]:
    proposals: list[ToolProposal] = []
    if not isinstance(raw_calls, list):
        return proposals
    for entry in raw_calls:
        if not isinstance(entry, dict):
            continue
        function = entry.get("function")
        if not isinstance(function, dict):
            continue
        name = function.get("name")
        if not isinstance(name, str) or not name.strip():
            continue
        proposals.append(
            ToolProposal(
                tool_id=name.strip(),
                arguments=_parse_tool_arguments(function.get("arguments")),
            )
        )
    return proposals


class LocalOpenAICompatibleAdapter(ModelAdapter):
    """Adapter for locally hosted, OpenAI-compatible chat-completions servers."""

    def __init__(
        self,
        *,
        base_url: str,
        model_name: str,
        api_key: str | None = None,
        timeout_seconds: float = 30.0,
        max_output_chars: int = 4000,
        transport: httpx.AsyncBaseTransport | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        normalized = base_url.strip().rstrip("/")
        if not normalized:
            raise ValueError("local model base_url must not be empty")
        self._base_url = normalized
        # OpenAI-compatible servers expose the API under `/v1`. Accept either
        # the server root (http://host:port) or an explicit `/v1` suffix so a
        # single RASP_LOCAL_MODEL_BASE_URL works for both OpenAI-compatible
        # and Ollama-native adapters.
        self._openai_base = normalized if normalized.endswith("/v1") else f"{normalized}/v1"
        self._model_name = model_name
        self._api_key = api_key or None
        self._timeout = timeout_seconds
        self._max_output_chars = max_output_chars
        # The client may be injected for tests (httpx.MockTransport). When it
        # is, the adapter does NOT own its lifecycle.
        self._client = client
        self._transport = transport
        self._owns_client = client is None
        self.model_id = f"local:{model_name}"

    def _headers(self) -> dict[str, str]:
        headers = {"content-type": "application/json"}
        if self._api_key:
            # Local servers usually ignore this; it exists for a future
            # authenticated gateway. The value is never logged.
            headers["authorization"] = f"Bearer {self._api_key}"
        return headers

    async def _post(
        self, path: str, payload: dict[str, Any], base: str | None = None
    ) -> dict[str, Any]:
        url = f"{base or self._openai_base}{path}"
        try:
            if self._client is not None:
                response = await self._client.post(
                    url, json=payload, headers=self._headers(), timeout=self._timeout
                )
            else:
                async with httpx.AsyncClient(
                    transport=self._transport, timeout=self._timeout
                ) as client:
                    response = await client.post(url, json=payload, headers=self._headers())
        except httpx.HTTPError as exc:  # transport-level failure
            raise ModelAdapterError(f"local model request failed ({type(exc).__name__})") from exc

        if response.status_code >= 400:
            # Status only — response bodies can echo prompts and are never logged.
            raise ModelAdapterError(f"local model returned HTTP {response.status_code}")
        try:
            data = response.json()
        except ValueError as exc:
            raise ModelAdapterError("local model returned malformed JSON") from exc
        if not isinstance(data, dict):
            raise ModelAdapterError("local model returned an unexpected payload shape")
        return data

    async def generate(
        self,
        messages: list[ModelMessage],
        options: ModelOptions | None = None,
    ) -> ModelResponse:
        options = options or ModelOptions()
        payload: dict[str, Any] = {
            "model": self._model_name,
            "messages": _messages_to_openai(messages),
            "stream": False,
        }
        data = await self._post("/chat/completions", payload)
        return self._parse_response(data, options)

    def _parse_response(self, data: dict[str, Any], options: ModelOptions) -> ModelResponse:
        choices = data.get("choices")
        if not isinstance(choices, list) or not choices:
            raise ModelAdapterError("local model response contained no choices")
        first = choices[0]
        if not isinstance(first, dict):
            raise ModelAdapterError("local model choice was not an object")
        message = first.get("message")
        if not isinstance(message, dict):
            raise ModelAdapterError("local model response contained no message")

        proposals = _tool_calls_from_openai(message.get("tool_calls"))
        raw_text = message.get("content")
        text = raw_text if isinstance(raw_text, str) and raw_text.strip() else None

        if proposals:
            return ModelResponse(
                model_id=self.model_id,
                text=None,
                tool_calls=proposals,
                finish_reason=FinishReason.TOOL_CALL,
            )
        if text is None:
            # A degenerate response with neither text nor tools: surface it as
            # an empty stop rather than fabricating content.
            return ModelResponse(
                model_id=self.model_id,
                text="",
                tool_calls=[],
                finish_reason=FinishReason.STOP,
            )
        limit = min(options.max_output_chars, self._max_output_chars)
        return ModelResponse(
            model_id=self.model_id,
            text=text[:limit],
            tool_calls=[],
            finish_reason=FinishReason.STOP,
        )

    async def health_check(self) -> ProviderHealth:
        try:
            async with httpx.AsyncClient(
                transport=self._transport, timeout=min(self._timeout, 5.0)
            ) as client:
                response = await client.get(f"{self._openai_base}/models", headers=self._headers())
        except httpx.HTTPError as exc:
            return ProviderHealth(
                ok=False,
                provider="local",
                detail=f"unreachable ({type(exc).__name__})",
            )
        if response.status_code >= 400:
            return ProviderHealth(ok=False, provider="local", detail=f"HTTP {response.status_code}")
        return ProviderHealth(ok=True, provider="local", detail="reachable")

    async def aclose(self) -> None:
        if self._owns_client and self._client is not None:  # pragma: no cover - defensive
            await self._client.aclose()

    def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(
            provider="local",
            supports_tool_calls=True,
            deterministic=False,
            requires_credentials=False,
        )


class OllamaModelAdapter(LocalOpenAICompatibleAdapter):
    """Adapter for Ollama's native ``POST /api/chat`` endpoint.

    Reuses the transport, timeout, and fail-closed behavior of the
    OpenAI-compatible adapter but speaks Ollama's message/tool-call schema.
    """

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.model_id = f"ollama:{self._model_name}"

    async def generate(
        self,
        messages: list[ModelMessage],
        options: ModelOptions | None = None,
    ) -> ModelResponse:
        options = options or ModelOptions()
        payload: dict[str, Any] = {
            "model": self._model_name,
            "messages": [
                {"role": m.role if m.role in _ALLOWED_ROLES else "user", "content": m.content}
                for m in messages
            ],
            "stream": False,
        }
        data = await self._post("/api/chat", payload, base=self._base_url)
        return self._parse_ollama_response(data, options)

    def _parse_ollama_response(self, data: dict[str, Any], options: ModelOptions) -> ModelResponse:
        message = data.get("message")
        if not isinstance(message, dict):
            raise ModelAdapterError("ollama response contained no message")

        # Ollama returns tool calls with an object (not a JSON string) for
        # `arguments`, but may also return the OpenAI-shaped string.
        proposals = _tool_calls_from_openai(message.get("tool_calls"))
        raw_text = message.get("content")
        text = raw_text if isinstance(raw_text, str) and raw_text.strip() else None

        if proposals:
            return ModelResponse(
                model_id=self.model_id,
                text=None,
                tool_calls=proposals,
                finish_reason=FinishReason.TOOL_CALL,
            )
        if text is None:
            return ModelResponse(
                model_id=self.model_id,
                text="",
                tool_calls=[],
                finish_reason=FinishReason.STOP,
            )
        limit = min(options.max_output_chars, self._max_output_chars)
        return ModelResponse(
            model_id=self.model_id,
            text=text[:limit],
            tool_calls=[],
            finish_reason=FinishReason.STOP,
        )

    async def health_check(self) -> ProviderHealth:
        try:
            async with httpx.AsyncClient(
                transport=self._transport, timeout=min(self._timeout, 5.0)
            ) as client:
                response = await client.get(f"{self._base_url}/api/tags")
        except httpx.HTTPError as exc:
            return ProviderHealth(
                ok=False,
                provider="ollama",
                detail=f"unreachable ({type(exc).__name__})",
            )
        if response.status_code >= 400:
            return ProviderHealth(
                ok=False, provider="ollama", detail=f"HTTP {response.status_code}"
            )
        return ProviderHealth(ok=True, provider="ollama", detail="reachable")

    def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(
            provider="ollama",
            supports_tool_calls=True,
            deterministic=False,
            requires_credentials=False,
        )
