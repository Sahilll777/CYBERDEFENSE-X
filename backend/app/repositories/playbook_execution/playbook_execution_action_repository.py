from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.playbook_execution_action import (
    PlaybookExecutionAction,
)


class PlaybookExecutionActionRepository:
    """Data-access repository for individual playbook execution actions."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def create(
        self,
        *,
        execution_id: int,
        action_index: int,
        action_type: str,
        parameters: dict[str, Any] | None = None,
        status: str = "PENDING",
        started_at: datetime | None = None,
    ) -> PlaybookExecutionAction:
        """Create a persisted action execution record."""

        action = PlaybookExecutionAction(
            execution_id=execution_id,
            action_index=action_index,
            action_type=action_type,
            status=status,
            parameters=parameters or {},
            started_at=started_at,
        )

        self.db.add(action)
        self.db.flush()

        return action

    def get_by_id(
        self,
        action_id: int,
    ) -> PlaybookExecutionAction | None:
        """Return an action execution by ID."""

        statement = select(
            PlaybookExecutionAction
        ).where(
            PlaybookExecutionAction.id == action_id,
        )

        return self.db.scalar(statement)

    def list_by_execution_id(
        self,
        execution_id: int,
    ) -> list[PlaybookExecutionAction]:
        """Return all action executions for an execution."""

        statement = (
            select(PlaybookExecutionAction)
            .where(
                PlaybookExecutionAction.execution_id
                == execution_id,
            )
            .order_by(
                PlaybookExecutionAction.action_index.asc(),
            )
        )

        return list(
            self.db.scalars(statement).all()
        )

    def update(
        self,
        action: PlaybookExecutionAction,
        *,
        status: str | None = None,
        result: dict[str, Any] | None = None,
        error_message: str | None = None,
        started_at: datetime | None = None,
        completed_at: datetime | None = None,
    ) -> PlaybookExecutionAction:
        """Update mutable action execution fields."""

        if status is not None:
            action.status = status

        if result is not None:
            action.result = result

        if error_message is not None:
            action.error_message = error_message

        if started_at is not None:
            action.started_at = started_at

        if completed_at is not None:
            action.completed_at = completed_at

        self.db.flush()

        return action

    def mark_running(
        self,
        action: PlaybookExecutionAction,
        *,
        started_at: datetime,
    ) -> PlaybookExecutionAction:
        """Mark an action as running."""

        return self.update(
            action,
            status="RUNNING",
            started_at=started_at,
        )

    def mark_completed(
        self,
        action: PlaybookExecutionAction,
        *,
        completed_at: datetime,
        result: dict[str, Any],
    ) -> PlaybookExecutionAction:
        """Mark an action as successfully completed."""

        return self.update(
            action,
            status="COMPLETED",
            completed_at=completed_at,
            result=result,
        )

    def mark_failed(
        self,
        action: PlaybookExecutionAction,
        *,
        completed_at: datetime,
        error_message: str,
    ) -> PlaybookExecutionAction:
        """Mark an action as failed."""

        return self.update(
            action,
            status="FAILED",
            completed_at=completed_at,
            error_message=error_message,
        )