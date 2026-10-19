"""Provider-neutral model adapter interface (spec §3.B, §6.1)."""

from __future__ import annotations

from abc import ABC, abstractmethod

from rasp.schemas.model import (
    ModelMessage,
    ModelOptions,
    ModelResponse,
    ProviderCapabilities,
    ProviderHealth,
)


class ModelAdapterError(Exception):
    """Model adapter failed in a controlled, categorized way."""


class ModelAdapter(ABC):
    """A replaceable model provider.

    The response it returns is an untrusted proposal; enforcement happens
    outside the adapter.
    """

    model_id: str

    @abstractmethod
    async def generate(
        self,
        messages: list[ModelMessage],
        options: ModelOptions | None = None,
    ) -> ModelResponse:
        raise NotImplementedError

    @abstractmethod
    async def health_check(self) -> ProviderHealth:
        raise NotImplementedError

    @abstractmethod
    def capabilities(self) -> ProviderCapabilities:
        raise NotImplementedError
