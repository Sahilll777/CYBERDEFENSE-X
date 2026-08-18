from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.incident import Incident
from app.models.security_event import SecurityEvent
from app.repositories.alert.correlation_repository import AlertCorrelationRepository, CorrelationCandidate
from app.repositories.alert_repository import AlertRepository
from app.repositories.user_repository import UserRepository
from app.services.incident.service import IncidentService


@dataclass(frozen=True)
class IncidentCorrelationResult:
    incident: Incident
    created: bool


class IncidentCorrelationService:
    """Correlate detection alerts with active security incidents."""

    SYSTEM_USERNAME = "system"
    CORRELATION_WINDOW = timedelta(hours=24)

    def __init__(self, db: Session):
        self.alert_repository = AlertRepository(db)
        self.correlation_repository = AlertCorrelationRepository(db)
        self.incident_service = IncidentService(db)
        self.user_repository = UserRepository(db)

    def correlate_alert(self, *, alert: Alert) -> IncidentCorrelationResult:
        """
        Attach an alert to an incident or create one for it.

        A candidate must be active, contain an alert from the same detection
        rule in the prior 24 hours, have the same event type, and share a
        non-empty source IP, destination IP, username, or hostname. Candidate
        ordering is most-recent event, then incident ID, making it stable.

        No commit occurs here: all ingestion records participate in the
        caller's transaction. Reprocessing an attached alert is a no-op.
        """
        if alert.incident_id is not None:
            incident = self.incident_service.get_incident(incident_id=alert.incident_id)
            if incident is None:
                raise RuntimeError("Alert references an incident that no longer exists.")
            return IncidentCorrelationResult(incident=incident, created=False)

        event = self.correlation_repository.get_security_event_for_alert(alert=alert)
        if event is None:
            raise ValueError(f"Security event not found for alert: {alert.id}.")

        candidate = self._select_candidate(
            event=event,
            candidates=self.correlation_repository.find_active_candidates(
                detection_rule_id=alert.detection_rule_id,
                window_start=event.event_timestamp - self.CORRELATION_WINDOW,
                window_end=event.event_timestamp,
            ),
        )
        if candidate is not None:
            self.alert_repository.attach_to_incident(alert, incident_id=candidate.id)
            return IncidentCorrelationResult(incident=candidate, created=False)

        system_user = self.user_repository.get_by_username(self.SYSTEM_USERNAME)
        if system_user is None:
            raise RuntimeError("System automation user is missing; run database migrations.")

        incident = self.incident_service.create_incident(
            title=self._incident_title(alert),
            description=f"Automatically created from alert {alert.id}: {alert.description}",
            severity=alert.severity,
            created_by_user_id=system_user.id,
            opened_at=event.event_timestamp,
        )
        self.alert_repository.attach_to_incident(alert, incident_id=incident.id)
        return IncidentCorrelationResult(incident=incident, created=True)

    @classmethod
    def _select_candidate(cls, *, event: SecurityEvent, candidates: list[CorrelationCandidate]) -> Incident | None:
        examined_incident_ids: set[int] = set()
        for candidate in candidates:
            if candidate.incident.id in examined_incident_ids:
                continue
            examined_incident_ids.add(candidate.incident.id)
            if candidate.security_event.event_type == event.event_type and cls._shares_entity_identifier(event, candidate.security_event):
                return candidate.incident
        return None

    @staticmethod
    def _shares_entity_identifier(left: SecurityEvent, right: SecurityEvent) -> bool:
        return any(
            left_value is not None and left_value != "" and left_value == right_value
            for left_value, right_value in (
                (left.source_ip, right.source_ip),
                (left.destination_ip, right.destination_ip),
                (left.username, right.username),
                (left.hostname, right.hostname),
            )
        )

    @staticmethod
    def _incident_title(alert: Alert) -> str:
        return f"Automated incident: {alert.title}"[:255]
