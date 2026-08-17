from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.alert import Alert


class AlertRepository:
    """Database access operations for Alert entities."""

    def __init__(self, db: Session):
        self.db = db

    def create(
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
        """Create and persist a security alert."""

        alert = Alert(
            detection_match_id=detection_match_id,
            security_event_id=security_event_id,
            detection_rule_id=detection_rule_id,
            severity=severity,
            status=status,
            title=title,
            description=description,
            assigned_to_user_id=assigned_to_user_id,
            incident_id=incident_id,
            opened_at=opened_at,
        )

        self.db.add(alert)
        self.db.flush()
        self.db.refresh(alert)

        return alert

    def get_by_id(
        self,
        alert_id: int,
    ) -> Alert | None:
        """Return an alert by its primary key."""

        statement = select(Alert).where(
            Alert.id == alert_id
        )

        return self.db.scalar(statement)

    def get_by_detection_match_id(
        self,
        detection_match_id: int,
    ) -> Alert | None:
        """Return the alert associated with a detection match."""

        statement = select(Alert).where(
            Alert.detection_match_id == detection_match_id
        )

        return self.db.scalar(statement)

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
        """Return alerts with optional filters."""

        statement = select(Alert)

        if severity is not None:
            statement = statement.where(
                Alert.severity == severity
            )

        if status is not None:
            statement = statement.where(
                Alert.status == status
            )

        if assigned_to_user_id is not None:
            statement = statement.where(
                Alert.assigned_to_user_id == assigned_to_user_id
            )

        if security_event_id is not None:
            statement = statement.where(
                Alert.security_event_id == security_event_id
            )

        if detection_rule_id is not None:
            statement = statement.where(
                Alert.detection_rule_id == detection_rule_id
            )

        if incident_id is not None:
            statement = statement.where(
                Alert.incident_id == incident_id
            )

        if start_time is not None:
            statement = statement.where(
                Alert.opened_at >= start_time
            )

        if end_time is not None:
            statement = statement.where(
                Alert.opened_at <= end_time
            )

        statement = (
            statement
            .order_by(
                Alert.opened_at.desc(),
                Alert.id.desc(),
            )
            .offset(offset)
            .limit(limit)
        )

        return list(
            self.db.scalars(statement).all()
        )

    def get_by_incident_id(
        self,
        incident_id: int,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Alert]:
        """Return alerts associated with a specific incident."""

        statement = (
            select(Alert)
            .where(
                Alert.incident_id == incident_id
            )
            .order_by(
                Alert.opened_at.desc(),
                Alert.id.desc(),
            )
            .offset(offset)
            .limit(limit)
        )

        return list(
            self.db.scalars(statement).all()
        )

    def update(
        self,
        alert: Alert,
        *,
        status: str | None = None,
        assigned_to_user_id: int | None = None,
        incident_id: int | None = None,
    ) -> Alert:
        """
        Update supported alert fields.

        Lifecycle timestamps are recorded when an alert transitions into
        ACKNOWLEDGED, RESOLVED, or CLOSED.

        Existing lifecycle timestamps are preserved and are never
        overwritten by repeated updates.
        """

        if status is not None:
            now = datetime.now(timezone.utc)

            if status != alert.status:
                if (
                    status == "ACKNOWLEDGED"
                    and alert.acknowledged_at is None
                ):
                    alert.acknowledged_at = now

                elif (
                    status == "RESOLVED"
                    and alert.resolved_at is None
                ):
                    alert.resolved_at = now

                elif (
                    status == "CLOSED"
                    and alert.closed_at is None
                ):
                    alert.closed_at = now

            alert.status = status

        if assigned_to_user_id is not None:
            alert.assigned_to_user_id = assigned_to_user_id

        if incident_id is not None:
            alert.incident_id = incident_id

        self.db.add(alert)
        self.db.flush()
        self.db.refresh(alert)

        return alert

    def attach_to_incident(
        self,
        alert: Alert,
        *,
        incident_id: int,
    ) -> Alert:
        """Associate an existing alert with an incident."""

        alert.incident_id = incident_id

        self.db.add(alert)
        self.db.flush()
        self.db.refresh(alert)

        return alert

    def detach_from_incident(
        self,
        alert: Alert,
    ) -> Alert:
        """Remove the alert's association with an incident."""

        alert.incident_id = None

        self.db.add(alert)
        self.db.flush()
        self.db.refresh(alert)

        return alert