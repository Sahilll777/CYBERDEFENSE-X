from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.incident import Incident
from app.models.security_event import SecurityEvent


@dataclass(frozen=True)
class CorrelationCandidate:
    """An active incident and one of its prior alert events."""

    incident: Incident
    security_event: SecurityEvent


class AlertCorrelationRepository:
    """Read-model queries used by incident correlation."""

    ACTIVE_INCIDENT_STATUSES = ("OPEN", "INVESTIGATING", "CONTAINED")

    def __init__(self, db: Session):
        self.db = db

    def get_security_event_for_alert(self, *, alert: Alert) -> SecurityEvent | None:
        """Return the event that produced ``alert``."""
        return self.db.scalar(
            select(SecurityEvent).where(SecurityEvent.id == alert.security_event_id)
        )

    def find_active_candidates(
        self,
        *,
        detection_rule_id: int,
        window_start: datetime,
        window_end: datetime,
    ) -> list[CorrelationCandidate]:
        """Return prior alert events for active incidents in the time window."""
        statement = (
            select(Incident, SecurityEvent)
            .join(Alert, Alert.incident_id == Incident.id)
            .join(SecurityEvent, SecurityEvent.id == Alert.security_event_id)
            .where(
                Alert.detection_rule_id == detection_rule_id,
                Incident.status.in_(self.ACTIVE_INCIDENT_STATUSES),
                SecurityEvent.event_timestamp >= window_start,
                SecurityEvent.event_timestamp <= window_end,
            )
            .order_by(
                SecurityEvent.event_timestamp.desc(),
                Incident.id.desc(),
                Alert.id.desc(),
            )
        )
        return [
            CorrelationCandidate(incident=incident, security_event=security_event)
            for incident, security_event in self.db.execute(statement).all()
        ]
