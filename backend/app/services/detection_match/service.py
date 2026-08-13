
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from app.models.detection_match import DetectionMatch
from app.repositories.detection_match_repository import (
    DetectionMatchRepository,
)


class DetectionMatchService:
    """Business logic for detection match management."""

    def __init__(self, db: Session):
        self.detection_match_repository = DetectionMatchRepository(db)

    def create_match(
        self,
        *,
        security_event_id: int,
        detection_rule_id: int,
        severity: str,
        status: str = "NEW",
        matched_at: datetime | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> DetectionMatch:
        """Create a detection match."""

        existing_match = (
            self.detection_match_repository.get_by_event_and_rule(
                security_event_id=security_event_id,
                detection_rule_id=detection_rule_id,
            )
        )

        if existing_match is not None:
            return existing_match

        return self.detection_match_repository.create(
            security_event_id=security_event_id,
            detection_rule_id=detection_rule_id,
            severity=severity,
            status=status,
            matched_at=matched_at,
            metadata=metadata,
        )

    def get_match(
        self,
        *,
        match_id: int,
    ) -> DetectionMatch | None:
        """Retrieve a detection match by ID."""

        return self.detection_match_repository.get_by_id(
            match_id
        )

    def get_match_by_event_and_rule(
        self,
        *,
        security_event_id: int,
        detection_rule_id: int,
    ) -> DetectionMatch | None:
        """Retrieve a detection match for an event/rule pair."""

        return self.detection_match_repository.get_by_event_and_rule(
            security_event_id=security_event_id,
            detection_rule_id=detection_rule_id,
        )

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
        """Retrieve detection matches using repository filters."""

        return self.detection_match_repository.list_matches(
            limit=limit,
            offset=offset,
            security_event_id=security_event_id,
            detection_rule_id=detection_rule_id,
            severity=severity,
            status=status,
            start_time=start_time,
            end_time=end_time,
        )

    def update_status(
        self,
        *,
        match_id: int,
        status: str,
    ) -> DetectionMatch | None:
        """Update the status of a detection match."""

        match = self.detection_match_repository.get_by_id(
            match_id
        )

        if match is None:
            return None

        return self.detection_match_repository.update_status(
            match,
            status=status,
        )
