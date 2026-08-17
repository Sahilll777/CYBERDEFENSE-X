from datetime import datetime

from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.repositories.alert_repository import AlertRepository
from app.repositories.incident.incident_repository import (
    IncidentRepository,
)


class AlertService:
    """Business logic for security alert management."""

    VALID_TRANSITIONS = {
        "OPEN": {"ACKNOWLEDGED"},
        "ACKNOWLEDGED": {"RESOLVED"},
        "RESOLVED": {"CLOSED"},
        "CLOSED": set(),
    }

    def __init__(self, db: Session):
        self.alert_repository = AlertRepository(db)
        self.incident_repository = IncidentRepository(db)

    def create_alert(
        self,
        *,
        detection_match_id: int,
        security_event_id: int,
        detection_rule_id: int,
        severity: str,
        title: str,
        description: str,
        status: str = "OPEN",
        assigned_to_user_id: int | None = None,
        incident_id: int | None = None,
        opened_at: datetime | None = None,
    ) -> Alert:
        """
        Create an alert for a detection match.

        A detection match can have only one alert. If an alert already
        exists for the detection match, return the existing alert.

        If incident_id is provided, the referenced incident must exist.
        """

        existing_alert = (
            self.alert_repository.get_by_detection_match_id(
                detection_match_id
            )
        )

        if existing_alert is not None:
            return existing_alert

        if incident_id is not None:
            incident = self.incident_repository.get_by_id(
                incident_id
            )

            if incident is None:
                raise ValueError(
                    f"Incident not found: {incident_id}."
                )

        return self.alert_repository.create(
            detection_match_id=detection_match_id,
            security_event_id=security_event_id,
            detection_rule_id=detection_rule_id,
            severity=severity,
            title=title,
            description=description,
            status=status,
            assigned_to_user_id=assigned_to_user_id,
            incident_id=incident_id,
            opened_at=opened_at,
        )

    def get_alert(
        self,
        *,
        alert_id: int,
    ) -> Alert | None:
        """Retrieve an alert by ID."""

        return self.alert_repository.get_by_id(
            alert_id
        )

    def get_alert_by_detection_match(
        self,
        *,
        detection_match_id: int,
    ) -> Alert | None:
        """Retrieve the alert associated with a detection match."""

        return self.alert_repository.get_by_detection_match_id(
            detection_match_id
        )

    def list_alerts(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        severity: str | None = None,
        status: str | None = None,
        assigned_to_user_id: int | None = None,
        security_event_id: int | None = None,
        detection_rule_id: int | None = None,
        incident_id: int | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> list[Alert]:
        """Retrieve alerts using repository filters."""

        return self.alert_repository.list_alerts(
            limit=limit,
            offset=offset,
            severity=severity,
            status=status,
            assigned_to_user_id=assigned_to_user_id,
            security_event_id=security_event_id,
            detection_rule_id=detection_rule_id,
            incident_id=incident_id,
            start_time=start_time,
            end_time=end_time,
        )

    def get_alerts_for_incident(
        self,
        *,
        incident_id: int,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Alert]:
        """
        Retrieve alerts associated with a specific incident.

        The incident must exist before its alerts are queried.
        """

        incident = self.incident_repository.get_by_id(
            incident_id
        )

        if incident is None:
            raise ValueError(
                f"Incident not found: {incident_id}."
            )

        return self.alert_repository.get_by_incident_id(
            incident_id,
            limit=limit,
            offset=offset,
        )

    def attach_alert_to_incident(
        self,
        *,
        alert_id: int,
        incident_id: int,
    ) -> Alert | None:
        """
        Associate an existing alert with an existing incident.

        Both entities must exist before the relationship is created.
        """

        alert = self.alert_repository.get_by_id(
            alert_id
        )

        if alert is None:
            return None

        incident = self.incident_repository.get_by_id(
            incident_id
        )

        if incident is None:
            raise ValueError(
                f"Incident not found: {incident_id}."
            )

        return self.alert_repository.attach_to_incident(
            alert,
            incident_id=incident_id,
        )

    def detach_alert_from_incident(
        self,
        *,
        alert_id: int,
    ) -> Alert | None:
        """
        Remove an alert's association with its incident.

        The alert itself is preserved.
        """

        alert = self.alert_repository.get_by_id(
            alert_id
        )

        if alert is None:
            return None

        return self.alert_repository.detach_from_incident(
            alert
        )

    def update_alert(
        self,
        *,
        alert_id: int,
        status: str | None = None,
        assigned_to_user_id: int | None = None,
    ) -> Alert | None:
        """Update the supported fields of an alert."""

        alert = self.alert_repository.get_by_id(
            alert_id
        )

        if alert is None:
            return None

        if status is not None:
            self._validate_status_transition(
                current_status=alert.status,
                new_status=status,
            )

        return self.alert_repository.update(
            alert,
            status=status,
            assigned_to_user_id=assigned_to_user_id,
        )

    @classmethod
    def _validate_status_transition(
        cls,
        *,
        current_status: str,
        new_status: str,
    ) -> None:
        """Validate an alert lifecycle transition."""

        if current_status == new_status:
            return

        allowed_statuses = cls.VALID_TRANSITIONS.get(
            current_status,
            set(),
        )

        if new_status not in allowed_statuses:
            raise ValueError(
                "Invalid alert status transition: "
                f"{current_status} -> {new_status}."
            )