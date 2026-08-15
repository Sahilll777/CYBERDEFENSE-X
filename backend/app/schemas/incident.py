from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class IncidentStatus(str, Enum):
    """Supported incident lifecycle states."""

    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"


class IncidentPriority(str, Enum):
    """Supported incident priority levels."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class IncidentCreate(BaseModel):
    """Request payload for creating a security incident."""

    title: str = Field(
        min_length=1,
        max_length=255,
    )

    description: str = Field(
        min_length=1,
        max_length=10000,
    )

    severity: str = Field(
        min_length=1,
        max_length=20,
    )

    priority: IncidentPriority = IncidentPriority.MEDIUM

    assigned_to_user_id: int | None = Field(
        default=None,
        ge=1,
    )


class IncidentUpdate(BaseModel):
    """Request payload for partially updating a security incident."""

    title: str | None = Field(
        default=None,
        min_length=1,
        max_length=255,
    )

    description: str | None = Field(
        default=None,
        min_length=1,
        max_length=10000,
    )

    severity: str | None = Field(
        default=None,
        min_length=1,
        max_length=20,
    )

    priority: IncidentPriority | None = None

    status: IncidentStatus | None = None

    assigned_to_user_id: int | None = Field(
        default=None,
        ge=1,
    )

    resolution_summary: str | None = Field(
        default=None,
        max_length=10000,
    )


class IncidentResponse(BaseModel):
    """Public API representation of a security incident."""

    model_config = ConfigDict(
        from_attributes=True,
    )

    id: int
    title: str
    description: str
    severity: str
    priority: IncidentPriority
    status: IncidentStatus
    assigned_to_user_id: int | None
    created_by_user_id: int
    opened_at: datetime
    investigating_at: datetime | None
    contained_at: datetime | None
    resolved_at: datetime | None
    closed_at: datetime | None
    resolution_summary: str | None
    created_at: datetime
    updated_at: datetime