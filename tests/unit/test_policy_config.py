"""Policy configuration validation tests (spec §11: policy tests)."""

from __future__ import annotations

import textwrap

import pytest

from rasp.container import builtin_tool_definitions
from rasp.policy.config import (
    PolicyConfig,
    PolicyConfigError,
    load_policy_file,
    validate_policy_registry_consistency,
)

VALID_YAML = textwrap.dedent(
    """
    version: "9.9"
    defaults:
      unknown_tool: deny
      authorization_failure: deny
      policy_error: deny
      sensitive_action_without_approval: deny
    tools:
      system_status:
        enabled: true
        risk: low
        permission: system:status
        requires_approval: false
    """
)


def _load(tmp_path, content: str) -> PolicyConfig:
    path = tmp_path / "policy.yaml"
    path.write_text(textwrap.dedent(content), encoding="utf-8")
    return load_policy_file(path)


def test_example_policy_file_loads():
    config = load_policy_file("config/policies.example.yaml")
    assert config.version == "1.0"
    assert config.defaults.unknown_tool == "deny"
    assert "record_delete" in config.tools


def test_missing_file_refuses_startup(tmp_path):
    with pytest.raises(PolicyConfigError):
        load_policy_file(tmp_path / "absent.yaml")


def test_invalid_yaml_refuses_startup(tmp_path):
    path = tmp_path / "policy.yaml"
    path.write_text("version: [unclosed", encoding="utf-8")
    with pytest.raises(PolicyConfigError):
        load_policy_file(path)


def test_defaults_cannot_be_weakened(tmp_path):
    """Fail-closed invariant: default-deny categories are hard-wired."""
    bad = VALID_YAML.replace("unknown_tool: deny", "unknown_tool: allow")
    with pytest.raises(PolicyConfigError):
        _load(tmp_path, bad)


def test_policy_error_default_cannot_be_overridden(tmp_path):
    bad = VALID_YAML.replace("policy_error: deny", "policy_error: allow")
    with pytest.raises(PolicyConfigError):
        _load(tmp_path, bad)


def test_critical_enabled_tool_requires_approval(tmp_path):
    """Contradictory settings: enabled critical tool without approval refuses startup."""
    content = textwrap.dedent(
        """
        version: "9.9"
        tools:
          record_delete:
            enabled: true
            risk: critical
            permission: records:delete
            requires_approval: false
        """
    )
    with pytest.raises(PolicyConfigError):
        _load(tmp_path, content)


def test_registry_policy_mismatch_refuses_startup():
    config = load_policy_file("config/policies.example.yaml")
    # Tamper with one entry to create a contradiction with the registry.
    tampered = config.model_copy(deep=True)
    tampered.tools["record_delete"].permission = "records:anything"
    with pytest.raises(PolicyConfigError):
        validate_policy_registry_consistency(tampered, builtin_tool_definitions())


def test_registered_tool_without_policy_entry_refuses_startup():
    config = load_policy_file("config/policies.example.yaml")
    tampered = config.model_copy(deep=True)
    del tampered.tools["system_status"]
    with pytest.raises(PolicyConfigError):
        validate_policy_registry_consistency(tampered, builtin_tool_definitions())


def test_valid_config_passes_consistency_check():
    config = load_policy_file("config/policies.example.yaml")
    validate_policy_registry_consistency(config, builtin_tool_definitions())
