from datetime import datetime, timezone

from sqlalchemy import delete

from app.core.database import SessionLocal
from app.models.security_event import SecurityEvent
from app.schemas.security_event import SecurityEventCreate
from app.services.security_event_service import SecurityEventService


def test_create_security_event_through_service():
    db = SessionLocal()

    try:
        service = SecurityEventService(db)

        event_payload = SecurityEventCreate(
            event_type="BRUTE_FORCE_DETECTED",
            severity="CRITICAL",
            source="authentication-service",
            source_ip="10.10.10.20",
            username="admin",
            hostname="auth-server-01",
            message="Multiple failed authentication attempts detected.",
            event_timestamp=datetime(
                2026,
                8,
                12,
                12,
                0,
                tzinfo=timezone.utc,
            ),
            metadata={
                "attempt_count": 10,
                "window_seconds": 60,
            },
        )

        event = service.create_event(
            event=event_payload,
        )

        db.commit()

        assert event.id is not None
        assert event.event_type == "BRUTE_FORCE_DETECTED"
        assert event.severity == "CRITICAL"
        assert event.source == "authentication-service"
        assert event.source_ip == "10.10.10.20"
        assert event.username == "admin"
        assert event.hostname == "auth-server-01"
        assert event.metadata["attempt_count"] == 10

    finally:
        db.rollback()

        db.execute(
            delete(SecurityEvent).where(
                SecurityEvent.event_type == "BRUTE_FORCE_DETECTED",
                SecurityEvent.source == "authentication-service",
                SecurityEvent.username == "admin",
            )
        )

        db.commit()
        db.close()


def test_get_security_event_through_service():
    db = SessionLocal()

    try:
        service = SecurityEventService(db)

        created_event = service.create_event(
            event=SecurityEventCreate(
                event_type="MALWARE_DETECTED",
                severity="CRITICAL",
                source="endpoint-agent",
                message="Malware detected.",
                event_timestamp=datetime.now(timezone.utc),
            )
        )

        db.commit()

        event = service.get_event(
            event_id=created_event.id,
        )

        assert event is not None
        assert event.id == created_event.id
        assert event.event_type == "MALWARE_DETECTED"

    finally:
        db.rollback()

        db.execute(
            delete(SecurityEvent).where(
                SecurityEvent.event_type == "MALWARE_DETECTED",
                SecurityEvent.source == "endpoint-agent",
            )
        )

        db.commit()
        db.close()


def test_get_unknown_security_event_returns_none():
    db = SessionLocal()

    try:
        service = SecurityEventService(db)

        event = service.get_event(
            event_id=999999999,
        )

        assert event is None

    finally:
        db.close()


def test_list_security_events_through_service():
    db = SessionLocal()

    try:
        service = SecurityEventService(db)

        service.create_event(
            event=SecurityEventCreate(
                event_type="SUSPICIOUS_LOGIN",
                severity="HIGH",
                source="auth-service-test",
                message="Suspicious login detected.",
                event_timestamp=datetime(
                    2026,
                    8,
                    12,
                    10,
                    0,
                    tzinfo=timezone.utc,
                ),
            )
        )

        service.create_event(
            event=SecurityEventCreate(
                event_type="NORMAL_LOGIN",
                severity="LOW",
                source="auth-service-test",
                message="Normal login detected.",
                event_timestamp=datetime(
                    2026,
                    8,
                    12,
                    11,
                    0,
                    tzinfo=timezone.utc,
                ),
            )
        )

        db.commit()

        events = service.list_events(
            severity="HIGH",
            source="auth-service-test",
        )

        assert len(events) >= 1
        assert all(
            event.severity == "HIGH"
            for event in events
        )

    finally:
        db.rollback()

        db.execute(
            delete(SecurityEvent).where(
                SecurityEvent.source == "auth-service-test"
            )
        )

        db.commit()
        db.close()


def test_list_security_events_supports_time_range():
    db = SessionLocal()

    try:
        service = SecurityEventService(db)

        service.create_event(
            event=SecurityEventCreate(
                event_type="TIME_RANGE_EVENT",
                severity="MEDIUM",
                source="service-test",
                message="Event inside time range.",
                event_timestamp=datetime(
                    2026,
                    8,
                    12,
                    10,
                    0,
                    tzinfo=timezone.utc,
                ),
            )
        )

        db.commit()

        events = service.list_events(
            start_time=datetime(
                2026,
                8,
                12,
                9,
                0,
                tzinfo=timezone.utc,
            ),
            end_time=datetime(
                2026,
                8,
                12,
                11,
                0,
                tzinfo=timezone.utc,
            ),
        )

        matching_events = [
            event
            for event in events
            if event.event_type == "TIME_RANGE_EVENT"
        ]

        assert len(matching_events) == 1

    finally:
        db.rollback()

        db.execute(
            delete(SecurityEvent).where(
                SecurityEvent.event_type == "TIME_RANGE_EVENT"
            )
        )

        db.commit()
        db.close()