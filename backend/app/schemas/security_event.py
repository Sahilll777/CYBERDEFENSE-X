from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class SecurityEventSeverity(str, Enum):
    """Supported security-event severity levels."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class SecurityEventCreate(BaseModel):
    """Request payload for creating a security event."""

    event_type: str = Field(
        min_length=1,
        max_length=100,
    )

    severity: SecurityEventSeverity

    source: str = Field(
        min_length=1,
        max_length=100,
    )

    source_ip: str | None = Field(
        default=None,
        max_length=45,
    )

    destination_ip: str | None = Field(
        default=None,
        max_length=45,
    )

    username: str | None = Field(
        default=None,
        max_length=255,
    )

    hostname: str | None = Field(
        default=None,
        max_length=255,
    )

    message: str = Field(
        min_length=1,
        max_length=10000,
    )

    event_timestamp: datetime

    metadata: dict[str, Any] = Field(
        default_factory=dict,
    )


class SecurityEventResponse(BaseModel):
    """Public API representation of a security event."""

    model_config = ConfigDict(
        from_attributes=True,
        populate_by_name=True,
    )

    id: int

    event_type: str

    severity: SecurityEventSeverity

    source: str

    source_ip: str | None

    destination_ip: str | None

    username: str | None

    hostname: str | None

    message: str

    event_timestamp: datetime

    metadata: dict[str, Any] = Field(
        validation_alias="event_metadata",
    )

    created_at: datetime