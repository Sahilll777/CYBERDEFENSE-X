from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class PlaybookExecutionStatus(str, Enum):
    """Supported playbook execution lifecycle states."""

    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class PlaybookExecutionCreate(BaseModel):
    """Request payload for creating a playbook execution."""

    playbook_id: int = Field(
        ge=1,
    )

    incident_id: int | None = Field(
        default=None,
        ge=1,
    )

    alert_id: int | None = Field(
        default=None,
        ge=1,
    )


class PlaybookExecutionFail(BaseModel):
    """Request payload for failing a playbook execution."""

    error_message: str = Field(
        min_length=1,
        max_length=5000,
    )


class PlaybookExecutionResponse(BaseModel):
    """Public API representation of a playbook execution."""

    model_config = ConfigDict(
        from_attributes=True,
    )

    id: int
    playbook_id: int
    incident_id: int | None
    alert_id: int | None
    triggered_by_user_id: int | None
    status: PlaybookExecutionStatus
    started_at: datetime | None
    completed_at: datetime | None
    error_message: str | None
    created_at: datetime
    updated_at: datetime