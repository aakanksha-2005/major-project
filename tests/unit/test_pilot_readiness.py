"""Controlled-pilot readiness gate tests (Milestone 6).

The gate is opt-in and fails closed: an unknown mode, an unknown
acknowledgement id, or a missing acknowledgement must all refuse startup.
Passing the gate must not change any enforcement behavior.
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from rasp.container import build_container
from rasp.main import create_app
from rasp.pilot.readiness import (
    REQUIRED_ACKNOWLEDGEMENTS,
    PilotReadinessError,
    parse_acknowledgements,
    validate_pilot_readiness,
)
from rasp.settings import Settings

_ALL_ACKS = ",".join(REQUIRED_ACKNOWLEDGEMENTS)


def _settings(**overrides) -> Settings:
    base = {
        "policy_path": "config/policies.example.yaml",
        "persistence": "in_memory",
    }
    base.update(overrides)
    return Settings(**base)


# --- default mode is off and inert --------------------------------------------


def test_default_mode_is_off():
    readiness = validate_pilot_readiness(_settings())
    assert readiness.mode == "off"
    assert readiness.enabled is False
    assert readiness.acknowledged_gaps == ()


def test_off_mode_ignores_acknowledgements():
    """Gaps listed while pilot is off are recorded but never required."""
    readiness = validate_pilot_readiness(
        _settings(pilot_mode="off", pilot_acknowledged_gaps="dev_identity_not_production_auth")
    )
    assert readiness.enabled is False
    assert readiness.acknowledged_gaps == ("dev_identity_not_production_auth",)


# --- fail closed: unknown mode --------------------------------------------------


def test_unknown_pilot_mode_refuses_startup():
    with pytest.raises(PilotReadinessError, match="unknown pilot mode"):
        validate_pilot_readiness(_settings(pilot_mode="live"))


def test_unknown_pilot_mode_refuses_container_build():
    """The gate is wired into startup, not just importable."""
    with pytest.raises(PilotReadinessError, match="no silent fallback"):
        build_container(_settings(pilot_mode="yolo"))


def test_create_app_refuses_unknown_pilot_mode():
    with pytest.raises(PilotReadinessError):
        create_app(_settings(pilot_mode="production"))


# --- fail closed: incomplete / unknown acknowledgements ------------------------


def test_controlled_without_acknowledgements_refuses():
    with pytest.raises(PilotReadinessError, match="missing"):
        validate_pilot_readiness(_settings(pilot_mode="controlled"))


def test_controlled_with_partial_acknowledgements_refuses():
    partial = ",".join(REQUIRED_ACKNOWLEDGEMENTS[:2])
    with pytest.raises(PilotReadinessError, match="missing"):
        validate_pilot_readiness(
            _settings(pilot_mode="controlled", pilot_acknowledged_gaps=partial)
        )


def test_controlled_with_unknown_acknowledgement_refuses():
    with pytest.raises(PilotReadinessError, match="unknown pilot acknowledgement"):
        validate_pilot_readiness(
            _settings(
                pilot_mode="controlled",
                pilot_acknowledged_gaps=_ALL_ACKS + ",made_up_gap",
            )
        )


def test_controlled_with_all_acknowledgements_is_enabled():
    readiness = validate_pilot_readiness(
        _settings(pilot_mode="controlled", pilot_acknowledged_gaps=_ALL_ACKS)
    )
    assert readiness.enabled is True
    assert set(readiness.acknowledged_gaps) == set(REQUIRED_ACKNOWLEDGEMENTS)


def test_acknowledgements_are_order_and_whitespace_insensitive():
    shuffled = ", ".join(reversed(REQUIRED_ACKNOWLEDGEMENTS))
    spaced = " , ".join(reversed(REQUIRED_ACKNOWLEDGEMENTS))
    a = validate_pilot_readiness(
        _settings(pilot_mode="controlled", pilot_acknowledged_gaps=shuffled)
    )
    b = validate_pilot_readiness(_settings(pilot_mode="controlled", pilot_acknowledged_gaps=spaced))
    assert a.acknowledged_gaps == b.acknowledged_gaps == tuple(sorted(REQUIRED_ACKNOWLEDGEMENTS))


def test_parse_acknowledgements_drops_blanks_and_duplicates():
    assert parse_acknowledgements("a,,b,a, ") == ("a", "b")


def test_mode_is_case_insensitive():
    readiness = validate_pilot_readiness(
        _settings(pilot_mode="CONTROLLED", pilot_acknowledged_gaps=_ALL_ACKS)
    )
    assert readiness.enabled is True


# --- passing the gate does not change enforcement, and is surfaced --------------


async def test_controlled_pilot_still_enforces_denies():
    """Enabling pilot mode never grants authority: a disabled tool stays denied."""
    app = create_app(_settings(pilot_mode="controlled", pilot_acknowledged_gaps=_ALL_ACKS))
    container = app.state.container
    assert container.pilot.enabled is True

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/v1/tools/execute",
            json={"tool_id": "record_delete", "arguments": {"record_id": "r1"}},
            headers={
                "X-Dev-Principal": "pilot-user",
                "X-Dev-Permissions": "records:delete",
            },
        )
    # Policy disables record_delete regardless of the caller's claims.
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "tool_disabled"
    await container.close()


async def test_controlled_pilot_health_reveals_no_configuration():
    """Pilot mode must not leak configuration through the health endpoint."""
    app = create_app(_settings(pilot_mode="controlled", pilot_acknowledged_gaps=_ALL_ACKS))
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/v1/health")
    body = response.json()
    assert response.status_code == 200
    assert "controlled" not in str(body)
    await app.state.container.close()
