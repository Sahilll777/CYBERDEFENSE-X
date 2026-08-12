from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class DetectionRuleCreate(BaseModel):
    """Request payload for creating a detection rule."""

    name: str = Field(
        min_length=1,
        max_length=150,
    )

    description: str | None = Field(
        default=None,
        max_length=5000,
    )

    rule_type: str = Field(
        min_length=1,
        max_length=100,
    )

    severity: str = Field(
        min_length=1,
        max_length=20,
    )

    conditions: dict[str, Any] = Field(
        default_factory=dict,
    )

    enabled: bool = True


class DetectionRuleUpdate(BaseModel):
    """Request payload for partially updating a detection rule."""

    name: str | None = Field(
        default=None,
        min_length=1,
        max_length=150,
    )

    description: str | None = Field(
        default=None,
        max_length=5000,
    )

    rule_type: str | None = Field(
        default=None,
        min_length=1,
        max_length=100,
    )

    severity: str | None = Field(
        default=None,
        min_length=1,
        max_length=20,
    )

    conditions: dict[str, Any] | None = None

    enabled: bool | None = None


class DetectionRuleResponse(BaseModel):
    """Public API representation of a detection rule."""

    model_config = ConfigDict(
        from_attributes=True,
    )

    id: int
    name: str
    description: str | None
    rule_type: str
    severity: str
    conditions: dict[str, Any]
    enabled: bool
    created_by_user_id: int
    created_at: datetime
    updated_at: datetime