from typing import Any

import pytest

from app.models.playbook import Playbook
from app.services.playbook_execution.engine import (
    PlaybookExecutionEngine,
)
from app.services.playbook_execution.handlers import (
    BlockSourceHandler,
    CollectContextHandler,
    CreateIncidentHandler,
    PlaybookActionHandler,
    PlaybookActionRegistry,
)


# ============================================================
# Helpers
# ============================================================


def build_playbook(
    *,
    definition: dict[str, Any] | None = None,
    enabled: bool = True,
) -> Playbook:
    """Build an in-memory playbook for engine tests."""

    return Playbook(
        name="test-playbook",
        description="Playbook engine test",
        playbook_type="RESPONSE",
        version=1,
        enabled=enabled,
        definition=(
            definition
            if definition is not None
            else {
                "actions": [],
            }
        ),
        created_by_user_id=1,
    )


# ============================================================
# Engine initialization / registry
# ============================================================


def test_engine_registers_default_handlers() -> None:
    """The engine should register all built-in action handlers."""

    engine = PlaybookExecutionEngine()

    assert engine.supported_actions() == [
        "BLOCK_SOURCE",
        "COLLECT_CONTEXT",
        "CREATE_INCIDENT",
    ]


def test_engine_returns_registered_handler() -> None:
    """The registry should resolve a registered action handler."""

    engine = PlaybookExecutionEngine()

    handler = engine.registry.get("BLOCK_SOURCE")

    assert isinstance(handler, BlockSourceHandler)


def test_registry_returns_none_for_unknown_handler() -> None:
    """Unknown action types should not resolve to a handler."""

    registry = PlaybookActionRegistry(
        [
            CollectContextHandler(),
            BlockSourceHandler(),
            CreateIncidentHandler(),
        ]
    )

    assert registry.get("UNKNOWN_ACTION") is None


def test_registry_supported_actions_are_sorted() -> None:
    """Supported action types should be returned deterministically."""

    registry = PlaybookActionRegistry(
        [
            CreateIncidentHandler(),
            BlockSourceHandler(),
            CollectContextHandler(),
        ]
    )

    assert registry.supported_actions() == [
        "BLOCK_SOURCE",
        "COLLECT_CONTEXT",
        "CREATE_INCIDENT",
    ]


# ============================================================
# Playbook definition validation
# ============================================================


def test_get_actions_accepts_valid_definition() -> None:
    """A valid playbook definition should be normalized correctly."""

    definition = {
        "actions": [
            {
                "type": "COLLECT_CONTEXT",
            },
            {
                "type": "BLOCK_SOURCE",
                "parameters": {
                    "target": "192.168.1.10",
                },
            },
        ]
    }

    actions = PlaybookExecutionEngine.get_actions(
        definition
    )

    assert actions == [
        {
            "type": "COLLECT_CONTEXT",
            "parameters": {},
        },
        {
            "type": "BLOCK_SOURCE",
            "parameters": {
                "target": "192.168.1.10",
            },
        },
    ]


def test_get_actions_rejects_non_object_definition() -> None:
    """The playbook definition must be a dictionary."""

    with pytest.raises(
        ValueError,
        match="Playbook definition must be an object",
    ):
        PlaybookExecutionEngine.get_actions(
            []
        )


def test_get_actions_rejects_missing_actions() -> None:
    """A playbook definition must contain an actions list."""

    with pytest.raises(
        ValueError,
        match="must contain an 'actions' list",
    ):
        PlaybookExecutionEngine.get_actions(
            {}
        )


def test_get_actions_rejects_non_list_actions() -> None:
    """The actions field must be a list."""

    with pytest.raises(
        ValueError,
        match="must contain an 'actions' list",
    ):
        PlaybookExecutionEngine.get_actions(
            {
                "actions": {},
            }
        )


def test_get_actions_accepts_empty_action_list() -> None:
    """An empty action list is valid."""

    actions = PlaybookExecutionEngine.get_actions(
        {
            "actions": [],
        }
    )

    assert actions == []


def test_get_actions_rejects_non_object_action() -> None:
    """Every action must be an object."""

    with pytest.raises(
        ValueError,
        match="action at index 0 must be an object",
    ):
        PlaybookExecutionEngine.get_actions(
            {
                "actions": [
                    "COLLECT_CONTEXT",
                ],
            }
        )


def test_get_actions_rejects_missing_action_type() -> None:
    """Every action must contain a string type."""

    with pytest.raises(
        ValueError,
        match="must contain a string 'type'",
    ):
        PlaybookExecutionEngine.get_actions(
            {
                "actions": [
                    {},
                ],
            }
        )


def test_get_actions_rejects_non_string_action_type() -> None:
    """Action type must be a string."""

    with pytest.raises(
        ValueError,
        match="must contain a string 'type'",
    ):
        PlaybookExecutionEngine.get_actions(
            {
                "actions": [
                    {
                        "type": 123,
                    },
                ],
            }
        )


def test_get_actions_rejects_empty_action_type() -> None:
    """An action type cannot be empty or whitespace."""

    with pytest.raises(
        ValueError,
        match="has an empty action type",
    ):
        PlaybookExecutionEngine.get_actions(
            {
                "actions": [
                    {
                        "type": "   ",
                    },
                ],
            }
        )


def test_get_actions_defaults_missing_parameters_to_empty_dict() -> None:
    """Actions without parameters should receive an empty dictionary."""

    actions = PlaybookExecutionEngine.get_actions(
        {
            "actions": [
                {
                    "type": "COLLECT_CONTEXT",
                },
            ],
        }
    )

    assert actions == [
        {
            "type": "COLLECT_CONTEXT",
            "parameters": {},
        },
    ]


def test_get_actions_rejects_non_object_parameters() -> None:
    """Action parameters must be dictionaries."""

    with pytest.raises(
        ValueError,
        match="must be an object",
    ):
        PlaybookExecutionEngine.get_actions(
            {
                "actions": [
                    {
                        "type": "COLLECT_CONTEXT",
                        "parameters": [],
                    },
                ],
            }
        )


# ============================================================
# Engine action dispatch validation
# ============================================================


def test_execute_action_rejects_non_string_action_type() -> None:
    """Action type must be a string before registry dispatch."""

    engine = PlaybookExecutionEngine()

    with pytest.raises(
        ValueError,
        match="action type must be a string",
    ):
        engine.execute_action(
            action_type=123,  # type: ignore[arg-type]
            parameters={},
            context={},
        )


def test_execute_action_rejects_empty_action_type() -> None:
    """Whitespace-only action types must be rejected."""

    engine = PlaybookExecutionEngine()

    with pytest.raises(
        ValueError,
        match="action type cannot be empty",
    ):
        engine.execute_action(
            action_type="   ",
            parameters={},
            context={},
        )


def test_execute_action_rejects_non_object_parameters() -> None:
    """Action parameters must be dictionaries."""

    engine = PlaybookExecutionEngine()

    with pytest.raises(
        ValueError,
        match="parameters must be an object",
    ):
        engine.execute_action(
            action_type="COLLECT_CONTEXT",
            parameters=[],  # type: ignore[arg-type]
            context={},
        )


def test_execute_action_rejects_non_object_context() -> None:
    """Execution context must be a dictionary."""

    engine = PlaybookExecutionEngine()

    with pytest.raises(
        ValueError,
        match="context must be an object",
    ):
        engine.execute_action(
            action_type="COLLECT_CONTEXT",
            parameters={},
            context=[],  # type: ignore[arg-type]
        )


def test_execute_action_rejects_unsupported_action() -> None:
    """Unsupported actions should fail explicitly."""

    engine = PlaybookExecutionEngine()

    with pytest.raises(
        ValueError,
        match="Unsupported playbook action type: UNKNOWN_ACTION",
    ):
        engine.execute_action(
            action_type="UNKNOWN_ACTION",
            parameters={},
            context={},
        )


# ============================================================
# COLLECT_CONTEXT
# ============================================================


def test_collect_context_returns_execution_context() -> None:
    """COLLECT_CONTEXT should return a copy of the execution context."""

    engine = PlaybookExecutionEngine()

    context = {
        "alert_id": 100,
        "source_ip": "192.168.1.10",
        "severity": "HIGH",
    }

    result = engine.execute_action(
        action_type="COLLECT_CONTEXT",
        parameters={},
        context=context,
    )

    assert result["action"] == "COLLECT_CONTEXT"
    assert result["status"] == "SUCCESS"
    assert result["data"]["source"] == "execution"
    assert result["data"]["context"] == context

    assert result["data"]["context"] is not context


def test_collect_context_accepts_custom_source() -> None:
    """COLLECT_CONTEXT should preserve a custom source parameter."""

    engine = PlaybookExecutionEngine()

    result = engine.execute_action(
        action_type="COLLECT_CONTEXT",
        parameters={
            "source": "alert",
        },
        context={
            "alert_id": 101,
        },
    )

    assert result["data"]["source"] == "alert"
    assert result["data"]["context"] == {
        "alert_id": 101,
    }


# ============================================================
# BLOCK_SOURCE
# ============================================================


def test_block_source_accepts_valid_target() -> None:
    """BLOCK_SOURCE should accept a valid target."""

    engine = PlaybookExecutionEngine()

    result = engine.execute_action(
        action_type="BLOCK_SOURCE",
        parameters={
            "target": "192.168.1.10",
        },
        context={},
    )

    assert result["action"] == "BLOCK_SOURCE"
    assert result["status"] == "SUCCESS"
    assert result["data"]["target"] == "192.168.1.10"


def test_block_source_strips_target_whitespace() -> None:
    """BLOCK_SOURCE should normalize target whitespace."""

    engine = PlaybookExecutionEngine()

    result = engine.execute_action(
        action_type="BLOCK_SOURCE",
        parameters={
            "target": "  192.168.1.10  ",
        },
        context={},
    )

    assert result["data"]["target"] == "192.168.1.10"


@pytest.mark.parametrize(
    "parameters",
    [
        {},
        {
            "target": "",
        },
        {
            "target": "   ",
        },
        {
            "target": 123,
        },
        {
            "target": None,
        },
    ],
)
def test_block_source_rejects_invalid_target(
    parameters: dict[str, Any],
) -> None:
    """BLOCK_SOURCE requires a non-empty string target."""

    engine = PlaybookExecutionEngine()

    with pytest.raises(
        ValueError,
        match="BLOCK_SOURCE requires a non-empty 'target'",
    ):
        engine.execute_action(
            action_type="BLOCK_SOURCE",
            parameters=parameters,
            context={},
        )


# ============================================================
# CREATE_INCIDENT
# ============================================================


def test_create_incident_uses_default_severity() -> None:
    """CREATE_INCIDENT should default severity to MEDIUM."""

    engine = PlaybookExecutionEngine()

    result = engine.execute_action(
        action_type="CREATE_INCIDENT",
        parameters={},
        context={},
    )

    assert result["action"] == "CREATE_INCIDENT"
    assert result["status"] == "SUCCESS"
    assert result["data"]["severity"] == "MEDIUM"


def test_create_incident_normalizes_severity() -> None:
    """CREATE_INCIDENT should normalize severity."""

    engine = PlaybookExecutionEngine()

    result = engine.execute_action(
        action_type="CREATE_INCIDENT",
        parameters={
            "severity": "  high  ",
        },
        context={},
    )

    assert result["data"]["severity"] == "HIGH"


@pytest.mark.parametrize(
    "severity",
    [
        "",
        "   ",
    ],
)
def test_create_incident_rejects_empty_severity(
    severity: str,
) -> None:
    """CREATE_INCIDENT should reject empty severity."""

    engine = PlaybookExecutionEngine()

    with pytest.raises(
        ValueError,
        match="cannot be empty",
    ):
        engine.execute_action(
            action_type="CREATE_INCIDENT",
            parameters={
                "severity": severity,
            },
            context={},
        )


def test_create_incident_rejects_non_string_severity() -> None:
    """CREATE_INCIDENT severity must be a string."""

    engine = PlaybookExecutionEngine()

    with pytest.raises(
        ValueError,
        match="'severity' must be a string",
    ):
        engine.execute_action(
            action_type="CREATE_INCIDENT",
            parameters={
                "severity": 500,
            },
            context={},
        )


# ============================================================
# Full engine execution
# ============================================================


def test_execute_runs_actions_sequentially() -> None:
    """The engine should execute actions in definition order."""

    engine = PlaybookExecutionEngine()

    playbook = build_playbook(
        definition={
            "actions": [
                {
                    "type": "COLLECT_CONTEXT",
                    "parameters": {
                        "source": "alert",
                    },
                },
                {
                    "type": "BLOCK_SOURCE",
                    "parameters": {
                        "target": "10.0.0.50",
                    },
                },
                {
                    "type": "CREATE_INCIDENT",
                    "parameters": {
                        "severity": "HIGH",
                    },
                },
            ],
        }
    )

    context = {
        "alert_id": 500,
        "source_ip": "10.0.0.50",
    }

    results = engine.execute(
        playbook=playbook,
        context=context,
    )

    assert len(results) == 3

    assert results[0]["index"] == 0
    assert results[0]["type"] == "COLLECT_CONTEXT"
    assert results[0]["status"] == "SUCCESS"

    assert results[1]["index"] == 1
    assert results[1]["type"] == "BLOCK_SOURCE"
    assert results[1]["status"] == "SUCCESS"

    assert results[2]["index"] == 2
    assert results[2]["type"] == "CREATE_INCIDENT"
    assert results[2]["status"] == "SUCCESS"


def test_execute_supports_empty_action_list() -> None:
    """A playbook with no actions should complete with no results."""

    engine = PlaybookExecutionEngine()

    playbook = build_playbook(
        definition={
            "actions": [],
        }
    )

    results = engine.execute(
        playbook=playbook,
        context={},
    )

    assert results == []


def test_execute_rejects_disabled_playbook() -> None:
    """Disabled playbooks must not execute."""

    engine = PlaybookExecutionEngine()

    playbook = build_playbook(
        enabled=False,
        definition={
            "actions": [
                {
                    "type": "COLLECT_CONTEXT",
                },
            ],
        },
    )

    with pytest.raises(
        ValueError,
        match="Playbook 'test-playbook' is disabled",
    ):
        engine.execute(
            playbook=playbook,
            context={},
        )


def test_execute_preserves_context_across_actions() -> None:
    """The execution context should remain available to actions."""

    engine = PlaybookExecutionEngine()

    playbook = build_playbook(
        definition={
            "actions": [
                {
                    "type": "COLLECT_CONTEXT",
                },
            ],
        }
    )

    context = {
        "incident_id": 42,
        "hostname": "server-01",
    }

    results = engine.execute(
        playbook=playbook,
        context=context,
    )

    assert results[0]["result"]["data"]["context"] == context


# ============================================================
# Custom handler registration
# ============================================================


class CustomTestHandler(PlaybookActionHandler):
    """Test-only custom action handler."""

    action_type = "TEST_ACTION"

    def execute(
        self,
        *,
        parameters: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "action": self.action_type,
            "status": "SUCCESS",
            "data": {
                "parameters": parameters,
                "context": context,
            },
        }


def test_engine_accepts_custom_handlers() -> None:
    """The engine should support dependency-injected handlers."""

    engine = PlaybookExecutionEngine(
        handlers=[
            CustomTestHandler(),
        ]
    )

    assert engine.supported_actions() == [
        "TEST_ACTION",
    ]

    result = engine.execute_action(
        action_type="TEST_ACTION",
        parameters={
            "value": "test",
        },
        context={
            "request_id": "abc123",
        },
    )

    assert result == {
        "action": "TEST_ACTION",
        "status": "SUCCESS",
        "data": {
            "parameters": {
                "value": "test",
            },
            "context": {
                "request_id": "abc123",
            },
        },
    }