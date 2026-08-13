
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict


class DetectionMatchStatus(str, Enum):
    """Supported detection-match lifecycle states."""

    NEW = "NEW"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"


class DetectionMatchStatusUpdate(BaseModel):
    """Request payload for updating a detection-match status."""

    status: DetectionMatchStatus


class DetectionMatchResponse(BaseModel):
    """Public API representation of a detection match."""

    model_config = ConfigDict(
        from_attributes=True,
    )

    id: int
    security_event_id: int
    detection_rule_id: int
    severity: str
    status: DetectionMatchStatus
    matched_at: datetime
    metadata: dict[str, Any]
    created_at: datetime
