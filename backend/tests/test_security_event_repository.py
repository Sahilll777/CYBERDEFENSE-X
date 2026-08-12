from datetime import datetime, timezone

from sqlalchemy import delete, select

from app.core.database import SessionLocal
from app.models.security_event import SecurityEvent
from app.repositories.security_event_repository import SecurityEventRepository


def test_create_security_event():
    db = SessionLocal()

    try:
        repository = SecurityEventRepository(db)

        event = repository.create(
            event_type="LOGIN_FAILED",
            severity="HIGH",
            source="linux-server",
            source_ip="192.168.1.10",
            username="admin",
            hostname="server-01",
            message="Failed SSH login attempt.",
            event_timestamp=datetime(
                2026,
                8,
                12,
                10,
                30,
                tzinfo=timezone.utc,
            ),
            metadata={
                "attempt_count": 5,
                "authentication_method": "ssh",
            },
        )

        db.commit()

        stored_event = db.scalar(
            select(SecurityEvent).where(
                SecurityEvent.id == event.id
            )
        )

        assert stored_event is not None
        assert stored_event.event_type == "LOGIN_FAILED"
        assert stored_event.severity == "HIGH"
        assert stored_event.source == "linux-server"
        assert stored_event.source_ip == "192.168.1.10"
        assert stored_event.username == "admin"
        assert stored_event.hostname == "server-01"
        assert stored_event.message == "Failed SSH login attempt."
        assert stored_event.metadata["attempt_count"] == 5

    finally:
        db.rollback()

        db.execute(
            delete(SecurityEvent).where(
                SecurityEvent.event_type == "LOGIN_FAILED",
                SecurityEvent.source == "linux-server",
                SecurityEvent.username == "admin",
            )
        )

        db.commit()
        db.close()


def test_get_security_event_by_id():
    db = SessionLocal()

    try:
        repository = SecurityEventRepository(db)

        event = repository.create(
            event_type="MALWARE_DETECTED",
            severity="CRITICAL",
            source="endpoint-agent",
            message="Malware detected.",
            event_timestamp=datetime.now(timezone.utc),
        )

        db.commit()

        stored_event = repository.get_by_id(event.id)

        assert stored_event is not None
        assert stored_event.id == event.id
        assert stored_event.event_type == "MALWARE_DETECTED"

    finally:
        db.rollback()

        db.execute(
            delete(SecurityEvent).where(
                SecurityEvent.event_type == "MALWARE_DETECTED"
            )
        )

        db.commit()
        db.close()


def test_get_security_event_by_id_returns_none_for_unknown_id():
    db = SessionLocal()

    try:
        repository = SecurityEventRepository(db)

        event = repository.get_by_id(999999999)

        assert event is None

    finally:
        db.close()


def test_list_security_events_supports_filters():
    db = SessionLocal()

    try:
        repository = SecurityEventRepository(db)

        repository.create(
            event_type="LOGIN_FAILED",
            severity="HIGH",
            source="ssh-server",
            message="Failed login.",
            event_timestamp=datetime(
                2026,
                8,
                12,
                10,
                0,
                tzinfo=timezone.utc,
            ),
        )

        repository.create(
            event_type="LOGIN_SUCCESS",
            severity="LOW",
            source="ssh-server",
            message="Successful login.",
            event_timestamp=datetime(
                2026,
                8,
                12,
                11,
                0,
                tzinfo=timezone.utc,
            ),
        )

        db.commit()

        events = repository.list_events(
            severity="HIGH",
            source="ssh-server",
        )

        assert len(events) >= 1
        assert all(event.severity == "HIGH" for event in events)
        assert all(event.source == "ssh-server" for event in events)

    finally:
        db.rollback()

        db.execute(
            delete(SecurityEvent).where(
                SecurityEvent.source == "ssh-server"
            )
        )

        db.commit()
        db.close()


def test_list_security_events_returns_newest_first():
    db = SessionLocal()

    try:
        repository = SecurityEventRepository(db)

        older_event = repository.create(
            event_type="TEST_OLDER_EVENT",
            severity="LOW",
            source="repository-test",
            message="Older event.",
            event_timestamp=datetime(
                2026,
                8,
                12,
                9,
                0,
                tzinfo=timezone.utc,
            ),
        )

        newer_event = repository.create(
            event_type="TEST_NEWER_EVENT",
            severity="LOW",
            source="repository-test",
            message="Newer event.",
            event_timestamp=datetime(
                2026,
                8,
                12,
                12,
                0,
                tzinfo=timezone.utc,
            ),
        )

        db.commit()

        events = repository.list_events(
            source="repository-test",
        )

        assert events[0].id == newer_event.id
        assert events[1].id == older_event.id

    finally:
        db.rollback()

        db.execute(
            delete(SecurityEvent).where(
                SecurityEvent.source == "repository-test"
            )
        )

        db.commit()
        db.close()