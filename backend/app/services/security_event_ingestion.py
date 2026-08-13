from __future__ import annotations

from dataclasses import dataclass

from app.models.security_event import SecurityEvent
from app.services.detection.detection_engine import DetectionEngineResult


@dataclass(frozen=True)
class SecurityEventIngestionResult:
    """Result of ingesting and evaluating one security event."""

    event: SecurityEvent
    detection_result: DetectionEngineResult