from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class AlertStatus(str, Enum):
    """Supported alert lifecycle states."""

    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"


class AlertResponse(BaseModel):
    """Public API representation of a security alert."""

    model_config = ConfigDict(
        from_attributes=True,
    )

    id: int
    detection_match_id: int
    security_event_id: int
    detection_rule_id: int
    severity: str
    status: AlertStatus
    title: str
    description: str
    assigned_to_user_id: int | None
    opened_at: datetime
    acknowledged_at: datetime | None
    resolved_at: datetime | None
    closed_at: datetime | None
    created_at: datetime
    updated_at: datetime


class AlertUpdate(BaseModel):
    """Fields that can be updated on an alert."""

    status: AlertStatus | None = None

    assigned_to_user_id: int | None = Field(
        default=None,
        ge=1,
    )