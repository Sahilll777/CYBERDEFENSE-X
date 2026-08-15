from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.models.incident import Incident
from app.repositories.incident.incident_repository import (
    IncidentRepository,
)


class IncidentService:
    """Business logic for security incident management."""

    VALID_TRANSITIONS = {
        "OPEN": {"INVESTIGATING"},
        "INVESTIGATING": {"CONTAINED"},
        "CONTAINED": {"RESOLVED"},
        "RESOLVED": {"CLOSED"},
        "CLOSED": set(),
    }

    def __init__(self, db: Session):
        self.incident_repository = IncidentRepository(db)

    def create_incident(
        self,
        *,
        title: str,
        description: str,
        severity: str,
        priority: str = "MEDIUM",
        assigned_to_user_id: int | None = None,
        created_by_user_id: int,
        opened_at: datetime | None = None,
    ) -> Incident:
        """Create a new security incident."""

        return self.incident_repository.create(
            title=title,
            description=description,
            severity=severity,
            priority=priority,
            status="OPEN",
            assigned_to_user_id=assigned_to_user_id,
            created_by_user_id=created_by_user_id,
            opened_at=opened_at,
        )

    def get_incident(
        self,
        *,
        incident_id: int,
    ) -> Incident | None:
        """Retrieve an incident by ID."""

        return self.incident_repository.get_by_id(
            incident_id
        )

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
        """Retrieve incidents using repository filters."""

        return self.incident_repository.list_incidents(
            limit=limit,
            offset=offset,
            severity=severity,
            priority=priority,
            status=status,
            assigned_to_user_id=assigned_to_user_id,
            created_by_user_id=created_by_user_id,
            start_time=start_time,
            end_time=end_time,
        )

    def get_incidents_by_assigned_user(
        self,
        *,
        assigned_to_user_id: int,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Incident]:
        """Retrieve incidents assigned to a specific user."""

        return self.incident_repository.get_by_assigned_user(
            assigned_to_user_id=assigned_to_user_id,
            limit=limit,
            offset=offset,
        )

    def update_incident(
        self,
        *,
        incident_id: int,
        title: str | None = None,
        description: str | None = None,
        severity: str | None = None,
        priority: str | None = None,
        status: str | None = None,
        assigned_to_user_id: int | None = None,
        resolution_summary: str | None = None,
    ) -> Incident | None:
        """
        Update an incident while enforcing its lifecycle.

        Lifecycle:

            OPEN
              ↓
            INVESTIGATING
              ↓
            CONTAINED
              ↓
            RESOLVED
              ↓
            CLOSED
        """

        incident = self.incident_repository.get_by_id(
            incident_id
        )

        if incident is None:
            return None

        now = datetime.now(timezone.utc)

        investigating_at = None
        contained_at = None
        resolved_at = None
        closed_at = None

        if status is not None:
            self._validate_status_transition(
                current_status=incident.status,
                new_status=status,
            )

            if status != incident.status:
                if (
                    status == "INVESTIGATING"
                    and incident.investigating_at is None
                ):
                    investigating_at = now

                elif (
                    status == "CONTAINED"
                    and incident.contained_at is None
                ):
                    contained_at = now

                elif (
                    status == "RESOLVED"
                    and incident.resolved_at is None
                ):
                    resolved_at = now

                elif (
                    status == "CLOSED"
                    and incident.closed_at is None
                ):
                    closed_at = now

        return self.incident_repository.update(
            incident,
            title=title,
            description=description,
            severity=severity,
            priority=priority,
            status=status,
            assigned_to_user_id=assigned_to_user_id,
            investigating_at=investigating_at,
            contained_at=contained_at,
            resolved_at=resolved_at,
            closed_at=closed_at,
            resolution_summary=resolution_summary,
        )

    @classmethod
    def _validate_status_transition(
        cls,
        *,
        current_status: str,
        new_status: str,
    ) -> None:
        """Validate an incident lifecycle transition."""

        if current_status == new_status:
            return

        allowed_statuses = cls.VALID_TRANSITIONS.get(
            current_status,
            set(),
        )

        if new_status not in allowed_statuses:
            raise ValueError(
                "Invalid incident status transition: "
                f"{current_status} -> {new_status}."
            )