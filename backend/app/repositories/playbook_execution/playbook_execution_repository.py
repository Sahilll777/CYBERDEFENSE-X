from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.playbook_execution import PlaybookExecution


class PlaybookExecutionRepository:
    """Data-access repository for playbook executions."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def create(
        self,
        *,
        playbook_id: int,
        incident_id: int | None = None,
        alert_id: int | None = None,
        triggered_by_user_id: int | None = None,
        status: str = "PENDING",
    ) -> PlaybookExecution:
        """Create a new playbook execution record."""

        execution = PlaybookExecution(
            playbook_id=playbook_id,
            incident_id=incident_id,
            alert_id=alert_id,
            triggered_by_user_id=triggered_by_user_id,
            status=status,
        )

        self.db.add(execution)
        self.db.flush()

        return execution

    def get_by_id(
        self,
        execution_id: int,
    ) -> PlaybookExecution | None:
        """Return an execution by ID."""

        statement = select(PlaybookExecution).where(
            PlaybookExecution.id == execution_id,
        )

        return self.db.scalar(statement)

    def list(
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
        """Return playbook executions with optional filters."""

        statement = select(PlaybookExecution)

        if playbook_id is not None:
            statement = statement.where(
                PlaybookExecution.playbook_id == playbook_id,
            )

        if incident_id is not None:
            statement = statement.where(
                PlaybookExecution.incident_id == incident_id,
            )

        if alert_id is not None:
            statement = statement.where(
                PlaybookExecution.alert_id == alert_id,
            )

        if triggered_by_user_id is not None:
            statement = statement.where(
                PlaybookExecution.triggered_by_user_id
                == triggered_by_user_id,
            )

        if status is not None:
            statement = statement.where(
                PlaybookExecution.status == status,
            )

        statement = statement.order_by(
            PlaybookExecution.created_at.desc(),
            PlaybookExecution.id.desc(),
        )

        statement = statement.limit(limit).offset(offset)

        return list(self.db.scalars(statement).all())

    def update(
        self,
        execution: PlaybookExecution,
        *,
        status: str | None = None,
        started_at: datetime | None = None,
        completed_at: datetime | None = None,
        error_message: str | None = None,
    ) -> PlaybookExecution:
        """Update execution fields."""

        if status is not None:
            execution.status = status

        if started_at is not None:
            execution.started_at = started_at

        if completed_at is not None:
            execution.completed_at = completed_at

        if error_message is not None:
            execution.error_message = error_message

        self.db.flush()

        return execution

    def mark_running(
        self,
        execution: PlaybookExecution,
        *,
        started_at: datetime,
    ) -> PlaybookExecution:
        """Mark an execution as running."""

        return self.update(
            execution,
            status="RUNNING",
            started_at=started_at,
        )

    def mark_completed(
        self,
        execution: PlaybookExecution,
        *,
        completed_at: datetime,
    ) -> PlaybookExecution:
        """Mark an execution as completed."""

        return self.update(
            execution,
            status="COMPLETED",
            completed_at=completed_at,
        )

    def mark_failed(
        self,
        execution: PlaybookExecution,
        *,
        completed_at: datetime,
        error_message: str,
    ) -> PlaybookExecution:
        """Mark an execution as failed."""

        return self.update(
            execution,
            status="FAILED",
            completed_at=completed_at,
            error_message=error_message,
        )