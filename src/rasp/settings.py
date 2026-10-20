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

    # Model provider selection. "mock" (M1) is deterministic and needs no
    # network. "local" (M4) talks to an OpenAI-compatible local server;
    # "ollama" (M4) talks to Ollama's native API. Any other value refuses
    # startup (no silent fallback, no cloud providers).
    model_provider: str = "mock"

    # Milestone 4 local adapter. No cloud credentials are used or required:
    # these point at a locally hosted runtime. `local_model_api_key` is
    # optional (some local gateways want a bearer token) and is never logged.
    local_model_base_url: str = "http://127.0.0.1:11434"
    local_model_name: str = "llama3.2"
    local_model_api_key: str | None = None
    local_model_timeout_seconds: float = Field(default=30.0, gt=0, le=300)
    local_model_max_output_chars: int = Field(default=4000, ge=64)

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

    # Milestone 3 structured logging. Unknown level/format refuse startup
    # (no silent fallback). Logs never contain prompts/arguments/outputs.
    log_level: str = "INFO"
    log_format: str = "json"  # Literal["json", "text"]

    # Approval lifecycle: TTL for pending records (both backends).
    approval_ttl_seconds: int = Field(default=900, ge=30)

    # Milestone 6 controlled-pilot gate. "off" (default) changes nothing.
    # "controlled" requires every documented pre-pilot gap to be explicitly
    # acknowledged (see docs/PILOT_READINESS.md); any other value refuses
    # startup. This gate records human acceptance — it does NOT make RASP
    # production-ready, and real authentication remains a hard prerequisite.
    pilot_mode: str = "off"
    pilot_acknowledged_gaps: str = ""

    # Milestone 2 persistence: PostgreSQL is the target store.
    # "postgres" (default) requires a reachable database before sensitive
    # actions execute (fail closed). "in_memory" is an EXPLICIT opt-out for
    # local demos and the M1 test suite — never a silent substitution.
    persistence: str = "postgres"  # Literal["postgres", "in_memory"]
    # Host port 5433 (not 5432): the shipped docker-compose.yml publishes
    # 5433 so RASP never collides with an existing local PostgreSQL.
    database_url: str = "postgresql+asyncpg://rasp:rasp@127.0.0.1:5433/rasp"
    database_pool_size: int = Field(default=5, ge=1, le=30)
    database_pool_timeout: float = Field(default=5.0, gt=0, le=60)
    # Bound every statement so a hung database cannot hang enforcement.
    database_statement_timeout_ms: int = Field(default=5000, ge=100, le=60000)


def load_settings() -> Settings:
    return Settings()
