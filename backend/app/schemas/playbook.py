from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class PlaybookType(str, Enum):
    """Supported playbook execution categories."""

    RESPONSE = "RESPONSE"
    CONTAINMENT = "CONTAINMENT"
    INVESTIGATION = "INVESTIGATION"
    REMEDIATION = "REMEDIATION"


class PlaybookCreate(BaseModel):
    """Request payload for creating a playbook."""

    name: str = Field(
        min_length=1,
        max_length=150,
    )

    description: str | None = Field(
        default=None,
        max_length=5000,
    )

    playbook_type: PlaybookType

    version: int = Field(
        default=1,
        ge=1,
    )

    enabled: bool = True

    definition: dict[str, Any] = Field(
        default_factory=dict,
    )


class PlaybookUpdate(BaseModel):
    """Request payload for updating a playbook."""

    name: str | None = Field(
        default=None,
        min_length=1,
        max_length=150,
    )

    description: str | None = Field(
        default=None,
        max_length=5000,
    )

    playbook_type: PlaybookType | None = None

    version: int | None = Field(
        default=None,
        ge=1,
    )

    enabled: bool | None = None

    definition: dict[str, Any] | None = None


class PlaybookResponse(BaseModel):
    """Public API representation of a playbook."""

    model_config = ConfigDict(
        from_attributes=True,
    )

    id: int
    name: str
    description: str | None
    playbook_type: PlaybookType
    version: int
    enabled: bool
    definition: dict[str, Any]
    created_by_user_id: int
    created_at: datetime
    updated_at: datetime