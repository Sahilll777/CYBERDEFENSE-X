from __future__ import annotations

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.incident import Incident


class IncidentRepository:
    """Database access operations for Incident entities."""

    def __init__(self, db: Session):
        self.db = db

    def create(
        self,
        *,
        title: str,
        description: str,
        severity: str,
        priority: str = "MEDIUM",
        status: str = "OPEN",
        assigned_to_user_id: int | None = None,
        created_by_user_id: int,
        opened_at: datetime | None = None,
    ) -> Incident:
        """Create and persist a security incident."""

        incident = Incident(
            title=title,
            description=description,
            severity=severity,
            priority=priority,
            status=status,
            assigned_to_user_id=assigned_to_user_id,
            created_by_user_id=created_by_user_id,
            opened_at=opened_at,
        )

        self.db.add(incident)
        self.db.flush()
        self.db.refresh(incident)

        return incident

    def get_by_id(
        self,
        incident_id: int,
    ) -> Incident | None:
        """Return an incident by its primary key."""

        statement = select(Incident).where(
            Incident.id == incident_id
        )

        return self.db.scalar(statement)

    def list_incidents(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        severity: str | None = None,
        priority: str | None = None,
        status: str | None = None,
        assigned_to_user_id: int | None = None,
        created_by_user_id: int | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> list[Incident]:
        """Return incidents with optional filters."""

        statement = select(Incident)

        if severity is not None:
            statement = statement.where(
                Incident.severity == severity
            )

        if priority is not None:
            statement = statement.where(
                Incident.priority == priority
            )

        if status is not None:
            statement = statement.where(
                Incident.status == status
            )

        if assigned_to_user_id is not None:
            statement = statement.where(
                Incident.assigned_to_user_id
                == assigned_to_user_id
            )

        if created_by_user_id is not None:
            statement = statement.where(
                Incident.created_by_user_id
                == created_by_user_id
            )

        if start_time is not None:
            statement = statement.where(
                Incident.opened_at >= start_time
            )

        if end_time is not None:
            statement = statement.where(
                Incident.opened_at <= end_time
            )

        statement = (
            statement
            .order_by(
                Incident.opened_at.desc(),
                Incident.id.desc(),
            )
            .offset(offset)
            .limit(limit)
        )

        return list(
            self.db.scalars(statement).all()
        )

    def get_by_assigned_user(
        self,
        *,
        assigned_to_user_id: int,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Incident]:
        """Return incidents assigned to a specific user."""

        statement = (
            select(Incident)
            .where(
                Incident.assigned_to_user_id
                == assigned_to_user_id
            )
            .order_by(
                Incident.opened_at.desc(),
                Incident.id.desc(),
            )
            .offset(offset)
            .limit(limit)
        )

        return list(
            self.db.scalars(statement).all()
        )

    def update(
        self,
        incident: Incident,
        *,
        title: str | None = None,
        description: str | None = None,
        severity: str | None = None,
        priority: str | None = None,
        status: str | None = None,
        assigned_to_user_id: int | None = None,
        investigating_at: datetime | None = None,
        contained_at: datetime | None = None,
        resolved_at: datetime | None = None,
        closed_at: datetime | None = None,
        resolution_summary: str | None = None,
    ) -> Incident:
        """Update supported incident fields."""

        if title is not None:
            incident.title = title

        if description is not None:
            incident.description = description

        if severity is not None:
            incident.severity = severity

        if priority is not None:
            incident.priority = priority

        if status is not None:
            incident.status = status

        if assigned_to_user_id is not None:
            incident.assigned_to_user_id = assigned_to_user_id

        if investigating_at is not None:
            incident.investigating_at = investigating_at

        if contained_at is not None:
            incident.contained_at = contained_at

        if resolved_at is not None:
            incident.resolved_at = resolved_at

        if closed_at is not None:
            incident.closed_at = closed_at

        if resolution_summary is not None:
            incident.resolution_summary = resolution_summary

        self.db.add(incident)
        self.db.flush()
        self.db.refresh(incident)

        return incident