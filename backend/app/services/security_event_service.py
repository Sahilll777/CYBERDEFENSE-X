from datetime import datetime

from sqlalchemy.orm import Session

from app.models.security_event import SecurityEvent
from app.repositories.security_event_repository import (
    SecurityEventRepository,
)
from app.schemas.security_event import SecurityEventCreate


class SecurityEventService:
    """Business logic for security event ingestion and retrieval."""

    def __init__(self, db: Session):
        self.security_event_repository = SecurityEventRepository(db)

    def create_event(
        self,
        *,
        event: SecurityEventCreate,
    ) -> SecurityEvent:
        """Create a security event from a validated API payload."""

        return self.security_event_repository.create(
            event_type=event.event_type,
            severity=event.severity.value,
            source=event.source,
            source_ip=event.source_ip,
            destination_ip=event.destination_ip,
            username=event.username,
            hostname=event.hostname,
            message=event.message,
            event_timestamp=event.event_timestamp,
            metadata=event.metadata,
        )

    def get_event(
        self,
        *,
        event_id: int,
    ) -> SecurityEvent | None:
        """Retrieve a security event by ID."""

        return self.security_event_repository.get_by_id(
            event_id
        )

    def list_events(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        severity: str | None = None,
        event_type: str | None = None,
        source: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> list[SecurityEvent]:
        """Retrieve security events using repository filters."""

        return self.security_event_repository.list_events(
            limit=limit,
            offset=offset,
            severity=severity,
            event_type=event_type,
            source=source,
            start_time=start_time,
            end_time=end_time,
        )

    def search_events(
        self,
        *,
        query: str,
        limit: int = 100,
        offset: int = 0,
        severity: str | None = None,
        event_type: str | None = None,
        source: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> tuple[list[SecurityEvent], int]:
        """
        Search security events using free-text and structured filters.
        """

        return self.security_event_repository.search_events(
            query=query,
            limit=limit,
            offset=offset,
            severity=severity,
            event_type=event_type,
            source=source,
            start_time=start_time,
            end_time=end_time,
        )