from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.models.playbook_execution import PlaybookExecution
from app.repositories.playbook_execution import (
    PlaybookExecutionRepository,
)


class PlaybookExecutionService:
    """Business logic for playbook execution lifecycle management."""

    ALLOWED_TRANSITIONS = {
        "PENDING": {"RUNNING"},
        "RUNNING": {"COMPLETED", "FAILED"},
        "COMPLETED": set(),
        "FAILED": set(),
    }

    def __init__(self, db: Session) -> None:
        self.db = db
        self.repository = PlaybookExecutionRepository(db)

    def create_execution(
        self,
        *,
        playbook_id: int,
        incident_id: int | None = None,
        alert_id: int | None = None,
        triggered_by_user_id: int | None = None,
    ) -> PlaybookExecution:
        """Create a new execution in the PENDING state."""

        execution = self.repository.create(
            playbook_id=playbook_id,
            incident_id=incident_id,
            alert_id=alert_id,
            triggered_by_user_id=triggered_by_user_id,
            status="PENDING",
        )

        return execution

    def get_execution(
        self,
        execution_id: int,
    ) -> PlaybookExecution | None:
        """Return an execution by ID."""

        return self.repository.get_by_id(execution_id)

    def list_executions(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        playbook_id: int | None = None,
        incident_id: int | None = None,
        alert_id: int | None = None,
        triggered_by_user_id: int | None = None,
        status: str | None = None,
    ) -> list[PlaybookExecution]:
        """Return executions with optional filters."""

        return self.repository.list(
            limit=limit,
            offset=offset,
            playbook_id=playbook_id,
            incident_id=incident_id,
            alert_id=alert_id,
            triggered_by_user_id=triggered_by_user_id,
            status=status,
        )

    def start_execution(
        self,
        execution_id: int,
    ) -> PlaybookExecution:
        """Move an execution from PENDING to RUNNING."""

        execution = self._get_required_execution(execution_id)

        self._validate_transition(
            current_status=execution.status,
            target_status="RUNNING",
        )

        started_at = datetime.now(timezone.utc)

        return self.repository.mark_running(
            execution,
            started_at=started_at,
        )

    def complete_execution(
        self,
        execution_id: int,
    ) -> PlaybookExecution:
        """Move an execution from RUNNING to COMPLETED."""

        execution = self._get_required_execution(execution_id)

        self._validate_transition(
            current_status=execution.status,
            target_status="COMPLETED",
        )

        completed_at = datetime.now(timezone.utc)

        return self.repository.mark_completed(
            execution,
            completed_at=completed_at,
        )

    def fail_execution(
        self,
        execution_id: int,
        *,
        error_message: str,
    ) -> PlaybookExecution:
        """Move an execution from RUNNING to FAILED."""

        if not error_message.strip():
            raise ValueError(
                "error_message cannot be empty."
            )

        execution = self._get_required_execution(execution_id)

        self._validate_transition(
            current_status=execution.status,
            target_status="FAILED",
        )

        completed_at = datetime.now(timezone.utc)

        return self.repository.mark_failed(
            execution,
            completed_at=completed_at,
            error_message=error_message.strip(),
        )

    def _get_required_execution(
        self,
        execution_id: int,
    ) -> PlaybookExecution:
        """Return an execution or raise a not-found error."""

        execution = self.repository.get_by_id(execution_id)

        if execution is None:
            raise ValueError(
                f"Playbook execution {execution_id} not found."
            )

        return execution

    def _validate_transition(
        self,
        *,
        current_status: str,
        target_status: str,
    ) -> None:
        """Validate a playbook execution state transition."""

        allowed_targets = self.ALLOWED_TRANSITIONS.get(
            current_status,
            set(),
        )

        if target_status not in allowed_targets:
            raise ValueError(
                "Invalid playbook execution status transition: "
                f"{current_status} -> {target_status}."
            )