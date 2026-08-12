from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.security_event import SecurityEvent


class SecurityEventRepository:
    """Database access operations for SecurityEvent entities."""

    def __init__(self, db: Session):
        self.db = db

    def get_by_id(self, event_id: int) -> SecurityEvent | None:
        """Return a security event by its primary key."""

        statement = select(SecurityEvent).where(
            SecurityEvent.id == event_id
        )

        return self.db.scalar(statement)

    def create(
        self,
        *,
        event_type: str,
        severity: str,
        source: str,
        message: str,
        event_timestamp: datetime,
        source_ip: str | None = None,
        destination_ip: str | None = None,
        username: str | None = None,
        hostname: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> SecurityEvent:
        """Create and persist a security event."""

        event = SecurityEvent(
            event_type=event_type,
            severity=severity,
            source=source,
            source_ip=source_ip,
            destination_ip=destination_ip,
            username=username,
            hostname=hostname,
            message=message,
            event_timestamp=event_timestamp,
            event_metadata=metadata or {},
        )

        self.db.add(event)
        self.db.flush()
        self.db.refresh(event)

        return event

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
        """Return security events with optional filters."""

        statement = select(SecurityEvent)

        if severity is not None:
            statement = statement.where(
                SecurityEvent.severity == severity
            )

        if event_type is not None:
            statement = statement.where(
                SecurityEvent.event_type == event_type
            )

        if source is not None:
            statement = statement.where(
                SecurityEvent.source == source
            )

        if start_time is not None:
            statement = statement.where(
                SecurityEvent.event_timestamp >= start_time
            )

        if end_time is not None:
            statement = statement.where(
                SecurityEvent.event_timestamp <= end_time
            )

        statement = (
            statement
            .order_by(SecurityEvent.event_timestamp.desc())
            .offset(offset)
            .limit(limit)
        )

        return list(self.db.scalars(statement).all())