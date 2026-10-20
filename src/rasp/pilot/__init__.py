"""Controlled-pilot readiness gate (Milestone 6).

See :mod:`rasp.pilot.readiness` and docs/PILOT_READINESS.md.
"""

from rasp.pilot.readiness import (
    PILOT_MODES,
    REQUIRED_ACKNOWLEDGEMENTS,
    PilotReadiness,
    PilotReadinessError,
    validate_pilot_readiness,
)

__all__ = [
    "PILOT_MODES",
    "REQUIRED_ACKNOWLEDGEMENTS",
    "PilotReadiness",
    "PilotReadinessError",
    "validate_pilot_readiness",
]
