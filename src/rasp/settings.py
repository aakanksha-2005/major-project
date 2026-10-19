"""Application settings.

All values are overridable through RASP_-prefixed environment variables
(see .env.example). Security-relevant defaults fail closed.
"""

from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="RASP_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "RASP"
    environment: str = "development"

    # Policy configuration is validated at startup; invalid/contradictory
    # security settings must prevent the application from starting.
    policy_path: str = "config/policies.example.yaml"

    # Only "mock" is implemented for Milestone 1. "local" is planned (M4)
    # and must not be assumed functional.
    model_provider: str = "mock"

    # Loop / size budgets (defense against unbounded tool-call loops).
    max_agent_steps: int = Field(default=3, ge=1, le=16)
    max_request_bytes: int = Field(default=1_000_000, ge=1024)
    default_tool_timeout_seconds: float = Field(default=5.0, gt=0, le=60)
    max_message_chars: int = Field(default=8000, ge=1)

    # Development-only identity mechanism (NOT production authentication).
    dev_auth_enabled: bool = True

    # Audit privacy: store salted pseudonyms instead of raw principal ids.
    store_principal_ids: bool = False
    audit_pseudonym_salt: str = "dev-only-salt-rotate-in-production"
    audit_buffer_size: int = Field(default=5000, ge=16)

    # Approval lifecycle (in-memory for M1; PostgreSQL-backed in later milestones).
    approval_ttl_seconds: int = Field(default=900, ge=30)


def load_settings() -> Settings:
    return Settings()
