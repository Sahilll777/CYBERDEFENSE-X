from typing import Any
from uuid import uuid4

import pytest
from sqlalchemy.orm import Session

from app.models.playbook import Playbook
from app.models.playbook_execution import PlaybookExecution
from app.models.playbook_execution_action import (
    PlaybookExecutionAction,
)
from app.models.user import User
from app.repositories.playbook.playbook_repository import (
    PlaybookRepository,
)
from app.services.playbook_execution.service import (
    PlaybookExecutionService,
)


# ============================================================
# Helpers
# ============================================================


def create_test_user(
    db_session: Session,
) -> User:
    """Create a real persisted user for foreign-key relationships."""

    unique_id = uuid4().hex[:12]

    user = User(
        username=f"playbook_test_user_{unique_id}",
        email=f"playbook_test_{unique_id}@example.com",
        password_hash="test-password-hash",
        full_name="Playbook Test User",
        is_active=True,
        is_superuser=False,
    )

    db_session.add(user)
    db_session.flush()
    db_session.refresh(user)

    return user


def build_playbook(
    db_session: Session,
    *,
    definition: dict[str, Any] | None = None,
    enabled: bool = True,
    created_by_user_id: int | None = None,
    name: str | None = None,
) -> Playbook:
    """
    Create and persist a valid playbook.

    The created_by_user_id is always backed by a real User record.
    """

    if created_by_user_id is None:
        user = create_test_user(db_session)
        created_by_user_id = user.id

    playbook_name = (
        name
        if name is not None
        else f"service-test-playbook-{uuid4().hex[:12]}"
    )

    repository = PlaybookRepository(
        db_session
    )

    playbook = repository.create(
        name=playbook_name,
        description="Playbook execution service test",
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
        created_by_user_id=created_by_user_id,
    )

    db_session.flush()
    db_session.refresh(playbook)

    return playbook


# ============================================================
# Fixtures
# ============================================================


@pytest.fixture
def playbook(
    db_session: Session,
) -> Playbook:
    """Provide a persisted enabled playbook."""

    return build_playbook(
        db_session,
    )


@pytest.fixture
def disabled_playbook(
    db_session: Session,
) -> Playbook:
    """Provide a persisted disabled playbook."""

    return build_playbook(
        db_session,
        enabled=False,
    )


# ============================================================
# Service initialization
# ============================================================


def test_service_initializes(
    db_session: Session,
) -> None:
    """The service should initialize all dependencies."""

    service = PlaybookExecutionService(
        db_session
    )

    assert service.db is db_session
    assert service.repository is not None
    assert service.action_repository is not None
    assert service.playbook_repository is not None
    assert service.engine is not None


# ============================================================
# CREATE EXECUTION
# ============================================================


def test_create_execution_creates_pending_execution(
    db_session: Session,
    playbook: Playbook,
) -> None:
    """A valid playbook should create a PENDING execution."""

    service = PlaybookExecutionService(
        db_session
    )

    execution = service.create_execution(
        playbook_id=playbook.id,
        triggered_by_user_id=playbook.created_by_user_id,
    )

    db_session.flush()
    db_session.refresh(execution)

    assert execution.id is not None
    assert execution.playbook_id == playbook.id
    assert execution.incident_id is None
    assert execution.alert_id is None
    assert (
        execution.triggered_by_user_id
        == playbook.created_by_user_id
    )
    assert execution.status == "PENDING"
    assert execution.started_at is None
    assert execution.completed_at is None
    assert execution.error_message is None


def test_create_execution_accepts_null_optional_relationships(
    db_session: Session,
    playbook: Playbook,
) -> None:
    """Incident and alert relationships may be omitted."""

    service = PlaybookExecutionService(
        db_session
    )

    execution = service.create_execution(
        playbook_id=playbook.id,
    )

    db_session.flush()

    assert execution.playbook_id == playbook.id
    assert execution.incident_id is None
    assert execution.alert_id is None


def test_create_execution_rejects_missing_playbook(
    db_session: Session,
) -> None:
    """A nonexistent playbook must be rejected."""

    service = PlaybookExecutionService(
        db_session
    )

    with pytest.raises(
        ValueError,
        match="Playbook 999999 not found",
    ):
        service.create_execution(
            playbook_id=999999,
        )


def test_create_execution_rejects_disabled_playbook(
    db_session: Session,
    disabled_playbook: Playbook,
) -> None:
    """Disabled playbooks must not create executions."""

    service = PlaybookExecutionService(
        db_session
    )

    with pytest.raises(
        ValueError,
        match="is disabled",
    ):
        service.create_execution(
            playbook_id=disabled_playbook.id,
        )


# ============================================================
# GET EXECUTION
# ============================================================


def test_get_execution_returns_existing_execution(
    db_session: Session,
    playbook: Playbook,
) -> None:
    """An existing execution should be returned."""

    service = PlaybookExecutionService(
        db_session
    )

    execution = service.create_execution(
        playbook_id=playbook.id,
    )

    db_session.flush()

    result = service.get_execution(
        execution.id
    )

    assert result is not None
    assert result.id == execution.id
    assert result.playbook_id == playbook.id


def test_get_execution_returns_none_for_missing_execution(
    db_session: Session,
) -> None:
    """A nonexistent execution should return None."""

    service = PlaybookExecutionService(
        db_session
    )

    result = service.get_execution(
        999999
    )

    assert result is None


# ============================================================
# LIST EXECUTIONS
# ============================================================


def test_list_executions_returns_created_executions(
    db_session: Session,
    playbook: Playbook,
) -> None:
    """Created executions should be returned."""

    service = PlaybookExecutionService(
        db_session
    )

    first = service.create_execution(
        playbook_id=playbook.id,
    )

    db_session.flush()

    second = service.create_execution(
        playbook_id=playbook.id,
    )

    db_session.flush()

    results = service.list_executions(
        playbook_id=playbook.id,
    )

    result_ids = {
        item.id
        for item in results
    }

    assert first.id in result_ids
    assert second.id in result_ids


def test_list_executions_supports_status_filter(
    db_session: Session,
    playbook: Playbook,
) -> None:
    """Execution status filtering should work."""

    service = PlaybookExecutionService(
        db_session
    )

    execution = service.create_execution(
        playbook_id=playbook.id,
    )

    db_session.flush()

    service.start_execution(
        execution.id
    )

    db_session.flush()

    running_results = service.list_executions(
        playbook_id=playbook.id,
        status="RUNNING",
    )

    assert any(
        item.id == execution.id
        for item in running_results
    )


# ============================================================
# ACTION LOOKUPS
# ============================================================


def test_list_action_executions_returns_actions(
    db_session: Session,
    playbook: Playbook,
) -> None:
    """Actions should be returned in action-index order."""

    service = PlaybookExecutionService(
        db_session
    )

    execution = service.create_execution(
        playbook_id=playbook.id,
    )

    db_session.flush()

    first_action = service.action_repository.create(
        execution_id=execution.id,
        action_index=0,
        action_type="COLLECT_CONTEXT",
        parameters={},
    )

    second_action = service.action_repository.create(
        execution_id=execution.id,
        action_index=1,
        action_type="BLOCK_SOURCE",
        parameters={
            "target": "192.168.1.10",
        },
    )

    db_session.flush()

    results = service.list_action_executions(
        execution.id
    )

    assert len(results) == 2
    assert results[0].id == first_action.id
    assert results[1].id == second_action.id
    assert results[0].action_index == 0
    assert results[1].action_index == 1


def test_get_action_execution_returns_matching_action(
    db_session: Session,
    playbook: Playbook,
) -> None:
    """An action belonging to the execution should be returned."""

    service = PlaybookExecutionService(
        db_session
    )

    execution = service.create_execution(
        playbook_id=playbook.id,
    )

    db_session.flush()

    action = service.action_repository.create(
        execution_id=execution.id,
        action_index=0,
        action_type="COLLECT_CONTEXT",
        parameters={},
    )

    db_session.flush()

    result = service.get_action_execution(
        execution_id=execution.id,
        action_id=action.id,
    )

    assert result is not None
    assert result.id == action.id
    assert result.execution_id == execution.id


def test_get_action_execution_returns_none_for_missing_action(
    db_session: Session,
    playbook: Playbook,
) -> None:
    """A missing action should return None."""

    service = PlaybookExecutionService(
        db_session
    )

    execution = service.create_execution(
        playbook_id=playbook.id,
    )

    db_session.flush()

    result = service.get_action_execution(
        execution_id=execution.id,
        action_id=999999,
    )

    assert result is None


def test_get_action_execution_prevents_cross_execution_access(
    db_session: Session,
) -> None:
    """Actions from another execution must not be exposed."""

    first_playbook = build_playbook(
        db_session
    )

    second_playbook = build_playbook(
        db_session
    )

    service = PlaybookExecutionService(
        db_session
    )

    first_execution = service.create_execution(
        playbook_id=first_playbook.id,
    )

    second_execution = service.create_execution(
        playbook_id=second_playbook.id,
    )

    db_session.flush()

    action = service.action_repository.create(
        execution_id=first_execution.id,
        action_index=0,
        action_type="COLLECT_CONTEXT",
        parameters={},
    )

    db_session.flush()

    result = service.get_action_execution(
        execution_id=second_execution.id,
        action_id=action.id,
    )

    assert result is None


# ============================================================
# START EXECUTION
# ============================================================


def test_start_execution_moves_pending_to_running(
    db_session: Session,
    playbook: Playbook,
) -> None:
    """PENDING should transition to RUNNING."""

    service = PlaybookExecutionService(
        db_session
    )

    execution = service.create_execution(
        playbook_id=playbook.id,
    )

    db_session.flush()

    result = service.start_execution(
        execution.id
    )

    db_session.flush()

    assert result.status == "RUNNING"
    assert result.started_at is not None
    assert result.completed_at is None


def test_start_execution_rejects_missing_execution(
    db_session: Session,
) -> None:
    """Starting a missing execution should fail."""

    service = PlaybookExecutionService(
        db_session
    )

    with pytest.raises(
        ValueError,
        match="Playbook execution 999999 not found",
    ):
        service.start_execution(
            999999
        )


def test_start_execution_rejects_invalid_transition(
    db_session: Session,
    playbook: Playbook,
) -> None:
    """A completed execution cannot be started again."""

    service = PlaybookExecutionService(
        db_session
    )

    execution = service.create_execution(
        playbook_id=playbook.id,
    )

    db_session.flush()

    service.start_execution(
        execution.id
    )

    db_session.flush()

    service.complete_execution(
        execution.id
    )

    db_session.flush()

    with pytest.raises(
        ValueError,
        match="Invalid playbook execution status transition",
    ):
        service.start_execution(
            execution.id
        )


# ============================================================
# EXECUTE EXECUTION
# ============================================================


def test_execute_execution_requires_running_state(
    db_session: Session,
    playbook: Playbook,
) -> None:
    """Execution must be RUNNING before actions can execute."""

    service = PlaybookExecutionService(
        db_session
    )

    execution = service.create_execution(
        playbook_id=playbook.id,
    )

    db_session.flush()

    with pytest.raises(
        ValueError,
        match="expected RUNNING, got PENDING",
    ):
        service.execute_execution(
            execution.id
        )


def test_execute_execution_persists_action_results(
    db_session: Session,
) -> None:
    """Successful actions should be persisted."""

    playbook = build_playbook(
        db_session,
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
        },
    )

    service = PlaybookExecutionService(
        db_session
    )

    execution = service.create_execution(
        playbook_id=playbook.id,
    )

    db_session.flush()

    service.start_execution(
        execution.id
    )

    db_session.flush()

    results = service.execute_execution(
        execution.id,
        context={
            "alert_id": 500,
            "source_ip": "10.0.0.50",
        },
    )

    db_session.flush()

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

    actions = service.list_action_executions(
        execution.id
    )

    assert len(actions) == 3

    assert all(
        action.status == "COMPLETED"
        for action in actions
    )

    assert all(
        action.result is not None
        for action in actions
    )


def test_execute_execution_preserves_context(
    db_session: Session,
) -> None:
    """Execution context should be passed to handlers."""

    playbook = build_playbook(
        db_session,
        definition={
            "actions": [
                {
                    "type": "COLLECT_CONTEXT",
                },
            ],
        },
    )

    service = PlaybookExecutionService(
        db_session
    )

    execution = service.create_execution(
        playbook_id=playbook.id,
    )

    db_session.flush()

    service.start_execution(
        execution.id
    )

    db_session.flush()

    context = {
        "incident_id": 42,
        "hostname": "server-01",
    }

    results = service.execute_execution(
        execution.id,
        context=context,
    )

    assert (
        results[0]["result"]["data"]["context"]
        == context
    )


def test_execute_execution_supports_empty_action_list(
    db_session: Session,
) -> None:
    """An empty action list should execute successfully."""

    playbook = build_playbook(
        db_session,
        definition={
            "actions": [],
        },
    )

    service = PlaybookExecutionService(
        db_session
    )

    execution = service.create_execution(
        playbook_id=playbook.id,
    )

    db_session.flush()

    service.start_execution(
        execution.id
    )

    db_session.flush()

    results = service.execute_execution(
        execution.id
    )

    assert results == []

    actions = service.list_action_executions(
        execution.id
    )

    assert actions == []


def test_execute_execution_persists_failed_action(
    db_session: Session,
) -> None:
    """Failed actions should be persisted as FAILED."""

    playbook = build_playbook(
        db_session,
        definition={
            "actions": [
                {
                    "type": "BLOCK_SOURCE",
                    "parameters": {},
                },
            ],
        },
    )

    service = PlaybookExecutionService(
        db_session
    )

    execution = service.create_execution(
        playbook_id=playbook.id,
    )

    db_session.flush()

    service.start_execution(
        execution.id
    )

    db_session.flush()

    with pytest.raises(
        ValueError,
        match="BLOCK_SOURCE requires a non-empty 'target'",
    ):
        service.execute_execution(
            execution.id
        )

    db_session.flush()

    actions = service.list_action_executions(
        execution.id
    )

    assert len(actions) == 1

    action = actions[0]

    assert action.status == "FAILED"
    assert action.error_message is not None
    assert (
        "BLOCK_SOURCE requires a non-empty 'target'"
        in action.error_message
    )
    assert action.started_at is not None
    assert action.completed_at is not None


def test_execute_execution_stops_after_failed_action(
    db_session: Session,
) -> None:
    """Execution should stop when an action fails."""

    playbook = build_playbook(
        db_session,
        definition={
            "actions": [
                {
                    "type": "BLOCK_SOURCE",
                    "parameters": {},
                },
                {
                    "type": "COLLECT_CONTEXT",
                },
            ],
        },
    )

    service = PlaybookExecutionService(
        db_session
    )

    execution = service.create_execution(
        playbook_id=playbook.id,
    )

    db_session.flush()

    service.start_execution(
        execution.id
    )

    db_session.flush()

    with pytest.raises(
        ValueError,
        match="BLOCK_SOURCE requires a non-empty 'target'",
    ):
        service.execute_execution(
            execution.id
        )

    db_session.flush()

    actions = service.list_action_executions(
        execution.id
    )

    assert len(actions) == 1
    assert actions[0].action_type == "BLOCK_SOURCE"
    assert actions[0].status == "FAILED"


# ============================================================
# COMPLETE EXECUTION
# ============================================================


def test_complete_execution_moves_running_to_completed(
    db_session: Session,
    playbook: Playbook,
) -> None:
    """RUNNING should transition to COMPLETED."""

    service = PlaybookExecutionService(
        db_session
    )

    execution = service.create_execution(
        playbook_id=playbook.id,
    )

    db_session.flush()

    service.start_execution(
        execution.id
    )

    db_session.flush()

    result = service.complete_execution(
        execution.id
    )

    db_session.flush()

    assert result.status == "COMPLETED"
    assert result.started_at is not None
    assert result.completed_at is not None
    assert (
        result.completed_at
        >= result.started_at
    )


def test_complete_execution_rejects_pending_execution(
    db_session: Session,
    playbook: Playbook,
) -> None:
    """PENDING cannot transition directly to COMPLETED."""

    service = PlaybookExecutionService(
        db_session
    )

    execution = service.create_execution(
        playbook_id=playbook.id,
    )

    db_session.flush()

    with pytest.raises(
        ValueError,
        match="Invalid playbook execution status transition",
    ):
        service.complete_execution(
            execution.id
        )


def test_complete_execution_rejects_missing_execution(
    db_session: Session,
) -> None:
    """Completing a missing execution should fail."""

    service = PlaybookExecutionService(
        db_session
    )

    with pytest.raises(
        ValueError,
        match="Playbook execution 999999 not found",
    ):
        service.complete_execution(
            999999
        )


# ============================================================
# FAIL EXECUTION
# ============================================================


def test_fail_execution_moves_running_to_failed(
    db_session: Session,
    playbook: Playbook,
) -> None:
    """RUNNING should transition to FAILED."""

    service = PlaybookExecutionService(
        db_session
    )

    execution = service.create_execution(
        playbook_id=playbook.id,
    )

    db_session.flush()

    service.start_execution(
        execution.id
    )

    db_session.flush()

    result = service.fail_execution(
        execution.id,
        error_message="Action failed.",
    )

    db_session.flush()

    assert result.status == "FAILED"
    assert result.started_at is not None
    assert result.completed_at is not None
    assert result.error_message == "Action failed."


def test_fail_execution_strips_error_message(
    db_session: Session,
    playbook: Playbook,
) -> None:
    """Failure messages should be stripped."""

    service = PlaybookExecutionService(
        db_session
    )

    execution = service.create_execution(
        playbook_id=playbook.id,
    )

    db_session.flush()

    service.start_execution(
        execution.id
    )

    db_session.flush()

    result = service.fail_execution(
        execution.id,
        error_message="   Action failed.   ",
    )

    assert result.error_message == "Action failed."


@pytest.mark.parametrize(
    "error_message",
    [
        "",
        "   ",
    ],
)
def test_fail_execution_rejects_empty_error_message(
    db_session: Session,
    playbook: Playbook,
    error_message: str,
) -> None:
    """Failure messages cannot be empty."""

    service = PlaybookExecutionService(
        db_session
    )

    execution = service.create_execution(
        playbook_id=playbook.id,
    )

    db_session.flush()

    service.start_execution(
        execution.id
    )

    db_session.flush()

    with pytest.raises(
        ValueError,
        match="error_message cannot be empty",
    ):
        service.fail_execution(
            execution.id,
            error_message=error_message,
        )


def test_fail_execution_rejects_pending_execution(
    db_session: Session,
    playbook: Playbook,
) -> None:
    """PENDING cannot transition directly to FAILED."""

    service = PlaybookExecutionService(
        db_session
    )

    execution = service.create_execution(
        playbook_id=playbook.id,
    )

    db_session.flush()

    with pytest.raises(
        ValueError,
        match="Invalid playbook execution status transition",
    ):
        service.fail_execution(
            execution.id,
            error_message="Failure.",
        )


def test_fail_execution_rejects_missing_execution(
    db_session: Session,
) -> None:
    """Failing a missing execution should fail."""

    service = PlaybookExecutionService(
        db_session
    )

    with pytest.raises(
        ValueError,
        match="Playbook execution 999999 not found",
    ):
        service.fail_execution(
            999999,
            error_message="Failure.",
        )


# ============================================================
# FULL RUN
# ============================================================


def test_run_execution_completes_successfully(
    db_session: Session,
) -> None:
    """run_execution should complete a successful lifecycle."""

    playbook = build_playbook(
        db_session,
        definition={
            "actions": [
                {
                    "type": "COLLECT_CONTEXT",
                },
                {
                    "type": "BLOCK_SOURCE",
                    "parameters": {
                        "target": "192.168.1.20",
                    },
                },
            ],
        },
    )

    service = PlaybookExecutionService(
        db_session
    )

    execution = service.create_execution(
        playbook_id=playbook.id,
    )

    db_session.flush()

    result = service.run_execution(
        execution.id,
        context={
            "source_ip": "192.168.1.20",
        },
    )

    db_session.flush()

    assert result.status == "COMPLETED"
    assert result.started_at is not None
    assert result.completed_at is not None
    assert result.error_message is None

    actions = service.list_action_executions(
        result.id
    )

    assert len(actions) == 2

    assert all(
        action.status == "COMPLETED"
        for action in actions
    )


def test_run_execution_fails_when_action_fails(
    db_session: Session,
) -> None:
    """run_execution should mark execution FAILED on error."""

    playbook = build_playbook(
        db_session,
        definition={
            "actions": [
                {
                    "type": "BLOCK_SOURCE",
                    "parameters": {},
                },
            ],
        },
    )

    service = PlaybookExecutionService(
        db_session
    )

    execution = service.create_execution(
        playbook_id=playbook.id,
    )

    db_session.flush()

    with pytest.raises(
        ValueError,
        match="BLOCK_SOURCE requires a non-empty 'target'",
    ):
        service.run_execution(
            execution.id
        )

    db_session.flush()
    db_session.refresh(execution)

    assert execution.status == "FAILED"
    assert execution.started_at is not None
    assert execution.completed_at is not None
    assert execution.error_message is not None

    actions = service.list_action_executions(
        execution.id
    )

    assert len(actions) == 1
    assert actions[0].status == "FAILED"


def test_run_execution_with_empty_actions_completes(
    db_session: Session,
) -> None:
    """An empty playbook should complete successfully."""

    playbook = build_playbook(
        db_session,
        definition={
            "actions": [],
        },
    )

    service = PlaybookExecutionService(
        db_session
    )

    execution = service.create_execution(
        playbook_id=playbook.id,
    )

    db_session.flush()

    result = service.run_execution(
        execution.id
    )

    db_session.flush()

    assert result.status == "COMPLETED"
    assert result.started_at is not None
    assert result.completed_at is not None

    assert (
        service.list_action_executions(
            result.id
        )
        == []
    )


def test_run_execution_rejects_missing_execution(
    db_session: Session,
) -> None:
    """run_execution should reject missing executions."""

    service = PlaybookExecutionService(
        db_session
    )

    with pytest.raises(
        ValueError,
        match="Playbook execution 999999 not found",
    ):
        service.run_execution(
            999999
        )


# ============================================================
# INVALID PLAYBOOK DEFINITIONS
# ============================================================


def test_run_execution_rejects_invalid_definition(
    db_session: Session,
) -> None:
    """Invalid definitions should fail the execution."""

    playbook = build_playbook(
        db_session,
        definition={
            "invalid": "definition",
        },
    )

    service = PlaybookExecutionService(
        db_session
    )

    execution = service.create_execution(
        playbook_id=playbook.id,
    )

    db_session.flush()

    with pytest.raises(
        ValueError,
        match="must contain an 'actions' list",
    ):
        service.run_execution(
            execution.id
        )

    db_session.flush()
    db_session.refresh(execution)

    assert execution.status == "FAILED"
    assert execution.error_message is not None


def test_run_execution_rejects_unsupported_action(
    db_session: Session,
) -> None:
    """Unsupported actions should fail the execution."""

    playbook = build_playbook(
        db_session,
        definition={
            "actions": [
                {
                    "type": "UNKNOWN_ACTION",
                },
            ],
        },
    )

    service = PlaybookExecutionService(
        db_session
    )

    execution = service.create_execution(
        playbook_id=playbook.id,
    )

    db_session.flush()

    with pytest.raises(
        ValueError,
        match="Unsupported playbook action type: UNKNOWN_ACTION",
    ):
        service.run_execution(
            execution.id
        )

    db_session.flush()
    db_session.refresh(execution)

    assert execution.status == "FAILED"
    assert execution.error_message is not None


# ============================================================
# ACTION PERSISTENCE
# ============================================================


def test_execute_execution_persists_action_parameters(
    db_session: Session,
) -> None:
    """Action parameters should be persisted."""

    playbook = build_playbook(
        db_session,
        definition={
            "actions": [
                {
                    "type": "BLOCK_SOURCE",
                    "parameters": {
                        "target": "10.10.10.10",
                    },
                },
            ],
        },
    )

    service = PlaybookExecutionService(
        db_session
    )

    execution = service.create_execution(
        playbook_id=playbook.id,
    )

    db_session.flush()

    service.start_execution(
        execution.id
    )

    db_session.flush()

    service.execute_execution(
        execution.id
    )

    db_session.flush()

    actions = service.list_action_executions(
        execution.id
    )

    assert len(actions) == 1

    assert actions[0].parameters == {
        "target": "10.10.10.10",
    }


def test_execute_execution_assigns_sequential_indexes(
    db_session: Session,
) -> None:
    """Action indexes should follow definition order."""

    playbook = build_playbook(
        db_session,
        definition={
            "actions": [
                {
                    "type": "COLLECT_CONTEXT",
                },
                {
                    "type": "BLOCK_SOURCE",
                    "parameters": {
                        "target": "10.0.0.1",
                    },
                },
                {
                    "type": "CREATE_INCIDENT",
                    "parameters": {
                        "severity": "LOW",
                    },
                },
            ],
        },
    )

    service = PlaybookExecutionService(
        db_session
    )

    execution = service.create_execution(
        playbook_id=playbook.id,
    )

    db_session.flush()

    service.start_execution(
        execution.id
    )

    db_session.flush()

    service.execute_execution(
        execution.id
    )

    db_session.flush()

    actions = service.list_action_executions(
        execution.id
    )

    assert [
        action.action_index
        for action in actions
    ] == [0, 1, 2]


def test_completed_actions_have_timestamps(
    db_session: Session,
) -> None:
    """Completed actions should have timestamps."""

    playbook = build_playbook(
        db_session,
        definition={
            "actions": [
                {
                    "type": "COLLECT_CONTEXT",
                },
            ],
        },
    )

    service = PlaybookExecutionService(
        db_session
    )

    execution = service.create_execution(
        playbook_id=playbook.id,
    )

    db_session.flush()

    service.start_execution(
        execution.id
    )

    db_session.flush()

    service.execute_execution(
        execution.id
    )

    db_session.flush()

    actions = service.list_action_executions(
        execution.id
    )

    action = actions[0]

    assert action.status == "COMPLETED"
    assert action.started_at is not None
    assert action.completed_at is not None
    assert (
        action.completed_at
        >= action.started_at
    )


def test_failed_actions_have_error_without_result(
    db_session: Session,
) -> None:
    """Failed actions should contain an error and no result."""

    playbook = build_playbook(
        db_session,
        definition={
            "actions": [
                {
                    "type": "BLOCK_SOURCE",
                    "parameters": {},
                },
            ],
        },
    )

    service = PlaybookExecutionService(
        db_session
    )

    execution = service.create_execution(
        playbook_id=playbook.id,
    )

    db_session.flush()

    service.start_execution(
        execution.id
    )

    db_session.flush()

    with pytest.raises(ValueError):
        service.execute_execution(
            execution.id
        )

    db_session.flush()

    actions = service.list_action_executions(
        execution.id
    )

    action = actions[0]

    assert action.status == "FAILED"
    assert action.result is None
    assert action.error_message is not None


# ============================================================
# STATUS TRANSITIONS
# ============================================================


@pytest.mark.parametrize(
    "current_status,target_status",
    [
        ("PENDING", "COMPLETED"),
        ("PENDING", "FAILED"),
        ("RUNNING", "RUNNING"),
        ("COMPLETED", "RUNNING"),
        ("COMPLETED", "COMPLETED"),
        ("COMPLETED", "FAILED"),
        ("FAILED", "RUNNING"),
        ("FAILED", "COMPLETED"),
        ("FAILED", "FAILED"),
    ],
)
def test_invalid_transitions_are_rejected(
    db_session: Session,
    current_status: str,
    target_status: str,
) -> None:
    """Invalid lifecycle transitions must be rejected."""

    service = PlaybookExecutionService(
        db_session
    )

    with pytest.raises(
        ValueError,
        match="Invalid playbook execution status transition",
    ):
        service._validate_transition(
            current_status=current_status,
            target_status=target_status,
        )


@pytest.mark.parametrize(
    "current_status,target_status",
    [
        ("PENDING", "RUNNING"),
        ("RUNNING", "COMPLETED"),
        ("RUNNING", "FAILED"),
    ],
)
def test_valid_transitions_are_accepted(
    db_session: Session,
    current_status: str,
    target_status: str,
) -> None:
    """Valid lifecycle transitions should be accepted."""

    service = PlaybookExecutionService(
        db_session
    )

    service._validate_transition(
        current_status=current_status,
        target_status=target_status,
    )


# ============================================================
# TERMINAL STATES
# ============================================================


def test_completed_execution_cannot_be_failed(
    db_session: Session,
    playbook: Playbook,
) -> None:
    """COMPLETED is a terminal state."""

    service = PlaybookExecutionService(
        db_session
    )

    execution = service.create_execution(
        playbook_id=playbook.id,
    )

    db_session.flush()

    service.start_execution(
        execution.id
    )

    db_session.flush()

    service.complete_execution(
        execution.id
    )

    db_session.flush()

    with pytest.raises(
        ValueError,
        match="Invalid playbook execution status transition",
    ):
        service.fail_execution(
            execution.id,
            error_message="Late failure.",
        )


def test_failed_execution_cannot_be_completed(
    db_session: Session,
    playbook: Playbook,
) -> None:
    """FAILED is a terminal state."""

    service = PlaybookExecutionService(
        db_session
    )

    execution = service.create_execution(
        playbook_id=playbook.id,
    )

    db_session.flush()

    service.start_execution(
        execution.id
    )

    db_session.flush()

    service.fail_execution(
        execution.id,
        error_message="Execution failed.",
    )

    db_session.flush()

    with pytest.raises(
        ValueError,
        match="Invalid playbook execution status transition",
    ):
        service.complete_execution(
            execution.id
        )


# ============================================================
# FULL MANUAL LIFECYCLE
# ============================================================


def test_full_manual_success_lifecycle(
    db_session: Session,
) -> None:
    """
    Validate:

        PENDING
            |
            v
        RUNNING
            |
            v
        COMPLETED
    """

    playbook = build_playbook(
        db_session,
        definition={
            "actions": [
                {
                    "type": "COLLECT_CONTEXT",
                },
            ],
        },
    )

    service = PlaybookExecutionService(
        db_session
    )

    execution = service.create_execution(
        playbook_id=playbook.id,
    )

    db_session.flush()

    assert execution.status == "PENDING"

    service.start_execution(
        execution.id
    )

    db_session.flush()
    db_session.refresh(execution)

    assert execution.status == "RUNNING"

    results = service.execute_execution(
        execution.id,
        context={
            "request_id": "manual-test",
        },
    )

    db_session.flush()

    assert len(results) == 1

    service.complete_execution(
        execution.id
    )

    db_session.flush()
    db_session.refresh(execution)

    assert execution.status == "COMPLETED"
    assert execution.started_at is not None
    assert execution.completed_at is not None
    assert execution.error_message is None


def test_full_manual_failure_lifecycle(
    db_session: Session,
) -> None:
    """
    Validate:

        PENDING
            |
            v
        RUNNING
            |
            v
        FAILED
    """

    playbook = build_playbook(
        db_session,
        definition={
            "actions": [
                {
                    "type": "BLOCK_SOURCE",
                    "parameters": {},
                },
            ],
        },
    )

    service = PlaybookExecutionService(
        db_session
    )

    execution = service.create_execution(
        playbook_id=playbook.id,
    )

    db_session.flush()

    assert execution.status == "PENDING"

    service.start_execution(
        execution.id
    )

    db_session.flush()
    db_session.refresh(execution)

    assert execution.status == "RUNNING"

    with pytest.raises(
        ValueError,
        match="BLOCK_SOURCE requires a non-empty 'target'",
    ):
        service.execute_execution(
            execution.id
        )

    db_session.flush()

    service.fail_execution(
        execution.id,
        error_message=(
            "BLOCK_SOURCE requires a non-empty 'target'"
        ),
    )

    db_session.flush()
    db_session.refresh(execution)

    assert execution.status == "FAILED"
    assert execution.started_at is not None
    assert execution.completed_at is not None
    assert execution.error_message == (
        "BLOCK_SOURCE requires a non-empty 'target'"
    )


# ============================================================
# ENGINE / SERVICE RESULT INTEGRATION
# ============================================================


def test_run_execution_persists_collect_context_result(
    db_session: Session,
) -> None:
    """COLLECT_CONTEXT result should be persisted."""

    playbook = build_playbook(
        db_session,
        definition={
            "actions": [
                {
                    "type": "COLLECT_CONTEXT",
                    "parameters": {
                        "source": "incident",
                    },
                },
            ],
        },
    )

    service = PlaybookExecutionService(
        db_session
    )

    execution = service.create_execution(
        playbook_id=playbook.id,
    )

    db_session.flush()

    result = service.run_execution(
        execution.id,
        context={
            "incident_id": 123,
        },
    )

    db_session.flush()

    actions = service.list_action_executions(
        result.id
    )

    assert len(actions) == 1

    action = actions[0]

    assert action.status == "COMPLETED"
    assert action.result is not None
    assert action.result["action"] == "COLLECT_CONTEXT"
    assert action.result["status"] == "SUCCESS"
    assert (
        action.result["data"]["source"]
        == "incident"
    )
    assert (
        action.result["data"]["context"]
        == {
            "incident_id": 123,
        }
    )


def test_run_execution_persists_block_source_result(
    db_session: Session,
) -> None:
    """BLOCK_SOURCE result should be persisted."""

    playbook = build_playbook(
        db_session,
        definition={
            "actions": [
                {
                    "type": "BLOCK_SOURCE",
                    "parameters": {
                        "target": "172.16.0.10",
                    },
                },
            ],
        },
    )

    service = PlaybookExecutionService(
        db_session
    )

    execution = service.create_execution(
        playbook_id=playbook.id,
    )

    db_session.flush()

    result = service.run_execution(
        execution.id
    )

    db_session.flush()

    actions = service.list_action_executions(
        result.id
    )

    assert len(actions) == 1

    action = actions[0]

    assert action.status == "COMPLETED"
    assert action.result is not None
    assert action.result["action"] == "BLOCK_SOURCE"
    assert (
        action.result["data"]["target"]
        == "172.16.0.10"
    )


def test_run_execution_persists_create_incident_result(
    db_session: Session,
) -> None:
    """CREATE_INCIDENT result should be persisted."""

    playbook = build_playbook(
        db_session,
        definition={
            "actions": [
                {
                    "type": "CREATE_INCIDENT",
                    "parameters": {
                        "severity": "  critical  ",
                    },
                },
            ],
        },
    )

    service = PlaybookExecutionService(
        db_session
    )

    execution = service.create_execution(
        playbook_id=playbook.id,
    )

    db_session.flush()

    result = service.run_execution(
        execution.id
    )

    db_session.flush()

    actions = service.list_action_executions(
        result.id
    )

    assert len(actions) == 1

    action = actions[0]

    assert action.status == "COMPLETED"
    assert action.result is not None
    assert (
        action.result["action"]
        == "CREATE_INCIDENT"
    )
    assert (
        action.result["data"]["severity"]
        == "CRITICAL"
    )


# ============================================================
# MODEL RELATIONSHIP
# ============================================================


def test_execution_actions_relationship_is_populated(
    db_session: Session,
) -> None:
    """PlaybookExecution.actions should contain persisted actions."""

    playbook = build_playbook(
        db_session,
        definition={
            "actions": [
                {
                    "type": "COLLECT_CONTEXT",
                },
                {
                    "type": "BLOCK_SOURCE",
                    "parameters": {
                        "target": "10.0.0.100",
                    },
                },
            ],
        },
    )

    service = PlaybookExecutionService(
        db_session
    )

    execution = service.create_execution(
        playbook_id=playbook.id,
    )

    db_session.flush()

    service.run_execution(
        execution.id
    )

    db_session.flush()
    db_session.refresh(execution)

    assert len(execution.actions) == 2

    assert execution.actions[0].action_index == 0
    assert execution.actions[1].action_index == 1


def test_execution_actions_relationship_is_ordered(
    db_session: Session,
) -> None:
    """Execution actions should follow definition order."""

    playbook = build_playbook(
        db_session,
        definition={
            "actions": [
                {
                    "type": "COLLECT_CONTEXT",
                },
                {
                    "type": "BLOCK_SOURCE",
                    "parameters": {
                        "target": "10.0.0.200",
                    },
                },
                {
                    "type": "CREATE_INCIDENT",
                    "parameters": {
                        "severity": "MEDIUM",
                    },
                },
            ],
        },
    )

    service = PlaybookExecutionService(
        db_session
    )

    execution = service.create_execution(
        playbook_id=playbook.id,
    )

    db_session.flush()

    service.run_execution(
        execution.id
    )

    db_session.flush()
    db_session.refresh(execution)

    assert [
        action.action_index
        for action in execution.actions
    ] == [0, 1, 2]


# ============================================================
# SANITY CHECKS
# ============================================================


def test_execution_model_is_correctly_imported() -> None:
    """Execution model should use the expected table."""

    assert (
        PlaybookExecution.__tablename__
        == "playbook_executions"
    )


def test_action_model_is_correctly_imported() -> None:
    """Action model should use the expected table."""

    assert (
        PlaybookExecutionAction.__tablename__
        == "playbook_execution_actions"
    )