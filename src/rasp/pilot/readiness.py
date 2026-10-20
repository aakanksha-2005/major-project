"""Controlled-pilot readiness gate (Milestone 6).

RASP is a prototype and is **not** ready for unsupervised use. This module
turns the documented pre-pilot gaps into a machine-checked gate so that
"controlled pilot" mode can never be enabled silently.

Design (documented in docs/PILOT_READINESS.md and docs/GOVERNANCE.md):

- **Opt-in.** The default ``RASP_PILOT_MODE=off`` changes nothing.
- **Fail closed.** An unknown mode refuses startup (same pattern as
  ``RASP_MODEL_PROVIDER`` / ``RASP_PERSISTENCE`` — no silent fallback).
- **Explicit acknowledgement.** Enabling ``controlled`` requires the operator
  to name *every* outstanding gap in ``RASP_PILOT_ACKNOWLEDGED_GAPS``. A
  missing, unknown, or stale acknowledgement refuses startup.
- **No false authority.** Passing this gate does **not** make RASP safe or
  certified. It records that a named human accepted the documented gaps. The
  hard prerequisite (real authentication) is *not* implemented here; it must
  be resolved by the deployment before the gate is even relevant.
"""

from __future__ import annotations

from dataclasses import dataclass

from rasp.settings import Settings

#: Recognized pilot modes. Anything else refuses startup.
PILOT_MODES: tuple[str, ...] = ("off", "controlled")

#: The documented gaps that must be individually acknowledged before a
#: controlled pilot. IDs are stable; see docs/PILOT_READINESS.md.
REQUIRED_ACKNOWLEDGEMENTS: tuple[str, ...] = (
    # Authentication / identity
    "dev_identity_not_production_auth",
    # Data protection
    "synthetic_data_only_until_auth_and_hardening",
    "audit_rows_mutable_by_db_credentials",
    "no_log_signing_or_sink_control",
    # Model behavior
    "no_live_model_safety_evaluation",
    # Operational
    "no_rate_limiting",
    "single_instance_no_ha",
    "manual_db_recovery_runbook",
    # Governance
    "human_oversight_required",
    "no_fairness_or_accessibility_evaluation",
)


class PilotReadinessError(Exception):
    """Raised when pilot mode is requested but the gate is not satisfied."""


@dataclass(frozen=True)
class PilotReadiness:
    mode: str
    enabled: bool
    acknowledged_gaps: tuple[str, ...]


def parse_acknowledgements(raw: str) -> tuple[str, ...]:
    """Parse the comma-separated acknowledgement list (order-insensitive)."""
    items = [item.strip() for item in raw.split(",")]
    return tuple(sorted({item for item in items if item}))


def validate_pilot_readiness(settings: Settings) -> PilotReadiness:
    """Validate pilot configuration. Raises PilotReadinessError to refuse startup.

    - Unknown mode -> refuse (no silent fallback).
    - ``controlled`` -> every documented gap must be acknowledged; unknown or
      missing acknowledgements refuse startup.
    """
    mode = settings.pilot_mode.strip().lower()
    if mode not in PILOT_MODES:
        raise PilotReadinessError(
            f"unknown pilot mode '{settings.pilot_mode}'; "
            f"expected one of {PILOT_MODES} (no silent fallback)"
        )

    acknowledged = parse_acknowledgements(settings.pilot_acknowledged_gaps)
    if mode == "off":
        return PilotReadiness(mode=mode, enabled=False, acknowledged_gaps=acknowledged)

    unknown = sorted(set(acknowledged) - set(REQUIRED_ACKNOWLEDGEMENTS))
    if unknown:
        raise PilotReadinessError(
            "unknown pilot acknowledgement id(s): "
            + ", ".join(unknown)
            + "; see docs/PILOT_READINESS.md for the exact ids"
        )

    missing = sorted(set(REQUIRED_ACKNOWLEDGEMENTS) - set(acknowledged))
    if missing:
        raise PilotReadinessError(
            "controlled pilot mode requires explicitly acknowledging every "
            "documented gap; missing: " + ", ".join(missing)
        )

    return PilotReadiness(mode=mode, enabled=True, acknowledged_gaps=acknowledged)
