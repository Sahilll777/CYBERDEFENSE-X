from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.detection_match import DetectionMatch


class DetectionMatchRepository:
    """Database access operations for DetectionMatch entities."""

    def __init__(self, db: Session):
        self.db = db

    def create(
        self,
        *,
        security_event_id: int,
        detection_rule_id: int,
        severity: str,
        status: str = "NEW",
        matched_at: datetime | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> DetectionMatch:
        """Create and persist a detection match."""

        match = DetectionMatch(
    security_event_id=security_event_id,
    detection_rule_id=detection_rule_id,
    severity=severity,
    status=status,
    matched_at=matched_at,
    match_metadata=metadata or {},
)

        self.db.add(match)
        self.db.flush()
        self.db.refresh(match)

        return match

    def get_by_id(
        self,
        match_id: int,
    ) -> DetectionMatch | None:
        """Return a detection match by its primary key."""

        statement = select(DetectionMatch).where(
            DetectionMatch.id == match_id
        )

        return self.db.scalar(statement)

    def get_by_event_and_rule(
        self,
        *,
        security_event_id: int,
        detection_rule_id: int,
    ) -> DetectionMatch | None:
        """Return a detection match for a specific event/rule pair."""

        statement = select(DetectionMatch).where(
            DetectionMatch.security_event_id == security_event_id,
            DetectionMatch.detection_rule_id == detection_rule_id,
        )

        return self.db.scalar(statement)

    def list_matches(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        security_event_id: int | None = None,
        detection_rule_id: int | None = None,
        severity: str | None = None,
        status: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> list[DetectionMatch]:
        """Return detection matches with optional filters."""

        statement = select(DetectionMatch)

        if security_event_id is not None:
            statement = statement.where(
                DetectionMatch.security_event_id == security_event_id
            )

        if detection_rule_id is not None:
            statement = statement.where(
                DetectionMatch.detection_rule_id == detection_rule_id
            )

        if severity is not None:
            statement = statement.where(
                DetectionMatch.severity == severity
            )

        if status is not None:
            statement = statement.where(
                DetectionMatch.status == status
            )

        if start_time is not None:
            statement = statement.where(
                DetectionMatch.matched_at >= start_time
            )

        if end_time is not None:
            statement = statement.where(
                DetectionMatch.matched_at <= end_time
            )

        statement = (
            statement
            .order_by(
                DetectionMatch.matched_at.desc(),
                DetectionMatch.id.desc(),
            )
            .offset(offset)
            .limit(limit)
        )

        return list(self.db.scalars(statement).all())

    def update_status(
        self,
        match: DetectionMatch,
        *,
        status: str,
    ) -> DetectionMatch:
        """Update the status of a detection match."""

        match.status = status

        self.db.add(match)
        self.db.flush()
        self.db.refresh(match)

        return match