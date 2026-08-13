from datetime import datetime, timezone

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.models.detection_rule import DetectionRule
from app.models.security_event import SecurityEvent
from app.models.user import User
from app.repositories.detection_rule_repository import (
    DetectionRuleRepository,
)
from app.repositories.security_event_repository import (
    SecurityEventRepository,
)
from app.security.password import hash_password


def _cleanup_test_data(db: Session) -> None:
    """
    Remove database records created by integration tests.

    Integration tests intentionally commit their transactions because
    the application itself commits database changes. Therefore, a
    normal session rollback cannot provide test isolation.

    This cleanup targets only records created by integration tests and
    does not remove seeded production roles or permissions.
    """

    # ---------------------------------------------------------
    # Detection Match test data
    # ---------------------------------------------------------
    db.execute(
        text(
            """
            DELETE FROM detection_matches
            WHERE security_event_id IN (
                SELECT id
                FROM security_events
                WHERE source LIKE 'detection-match-%'
            )
            OR detection_rule_id IN (
                SELECT id
                FROM detection_rules
                WHERE name LIKE 'detection-match-%'
            )
            """
        )
    )

    # ---------------------------------------------------------
    # Detection Rule test data
    # ---------------------------------------------------------
    db.execute(
        text(
            """
            DELETE FROM detection_rules
            WHERE name LIKE 'api-%'
            OR name LIKE 'test-%'
            OR name LIKE 'detection-match-%'
            """
        )
    )

    # ---------------------------------------------------------
    # Security Event API test data
    # ---------------------------------------------------------
    db.execute(
        text(
            """
            DELETE FROM security_events
            WHERE source = 'security-event-api-test'
            OR source LIKE 'detection-match-%'
            """
        )
    )

    # ---------------------------------------------------------
    # Remove RBAC test role-permission mappings
    # ---------------------------------------------------------
    db.execute(
        text(
            """
            DELETE FROM role_permissions
            WHERE role_id IN (
                SELECT id
                FROM roles
                WHERE name LIKE 'TEST_ROLE_%'
            )
            """
        )
    )

    # ---------------------------------------------------------
    # Remove RBAC test user-role mappings
    # ---------------------------------------------------------
    db.execute(
        text(
            """
            DELETE FROM user_roles
            WHERE user_id IN (
                SELECT id
                FROM users
                WHERE username LIKE 'rbac_%'
            )
            OR role_id IN (
                SELECT id
                FROM roles
                WHERE name LIKE 'TEST_ROLE_%'
            )
            """
        )
    )

    # ---------------------------------------------------------
    # Remove Security Event API test user-role mappings
    # ---------------------------------------------------------
    db.execute(
        text(
            """
            DELETE FROM user_roles
            WHERE user_id IN (
                SELECT id
                FROM users
                WHERE username LIKE 'event_api_%'
            )
            OR role_id IN (
                SELECT id
                FROM roles
                WHERE name LIKE 'TEST_ROLE_event_api_%'
            )
            """
        )
    )

    # ---------------------------------------------------------
    # Remove Detection Rule test users
    # ---------------------------------------------------------
    db.execute(
        text(
            """
            DELETE FROM users
            WHERE username LIKE 'detection_rule_%'
            """
        )
    )

    # ---------------------------------------------------------
    # Remove Detection Match test users
    # ---------------------------------------------------------
    db.execute(
        text(
            """
            DELETE FROM users
            WHERE username LIKE 'detection-match-%'
            """
        )
    )

    # ---------------------------------------------------------
    # Remove Detection Rule API test users
    # ---------------------------------------------------------
    db.execute(
        text(
            """
            DELETE FROM users
            WHERE username LIKE 'api_%'
            """
        )
    )

    # ---------------------------------------------------------
    # Remove RBAC test roles
    # ---------------------------------------------------------
    db.execute(
        text(
            """
            DELETE FROM roles
            WHERE name LIKE 'TEST_ROLE_%'
            """
        )
    )

    # ---------------------------------------------------------
    # Remove RBAC test users
    # ---------------------------------------------------------
    db.execute(
        text(
            """
            DELETE FROM users
            WHERE username LIKE 'rbac_%'
            """
        )
    )

    # ---------------------------------------------------------
    # Remove Security Event API test users
    # ---------------------------------------------------------
    db.execute(
        text(
            """
            DELETE FROM users
            WHERE username LIKE 'event_api_%'
            """
        )
    )

    db.commit()


@pytest.fixture
def db_session() -> Session:
    """
    Provide a PostgreSQL session for database-backed tests.

    Integration tests commit their changes, so the fixture performs
    explicit cleanup before and after each test to guarantee
    repeatability.
    """

    db = SessionLocal()

    try:
        # Remove leftovers from previous interrupted/failed test runs.
        _cleanup_test_data(db)

        yield db

    finally:
        try:
            db.rollback()
            _cleanup_test_data(db)
        finally:
            db.close()


@pytest.fixture
def security_event(db_session: Session) -> SecurityEvent:
    """
    Create a security event for DetectionMatch repository tests.
    """

    repository = SecurityEventRepository(db_session)

    event = repository.create(
        event_type="LOGIN_FAILED",
        severity="HIGH",
        source="detection-match-primary",
        source_ip="192.168.1.10",
        destination_ip="192.168.1.100",
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

    db_session.commit()
    db_session.refresh(event)

    return event


@pytest.fixture
def another_security_event(db_session: Session) -> SecurityEvent:
    """
    Create a second security event for multi-record tests.
    """

    repository = SecurityEventRepository(db_session)

    event = repository.create(
        event_type="MALWARE_DETECTED",
        severity="CRITICAL",
        source="detection-match-secondary",
        source_ip="10.0.0.20",
        hostname="endpoint-02",
        message="Malware detected on endpoint.",
        event_timestamp=datetime(
            2026,
            8,
            12,
            11,
            30,
            tzinfo=timezone.utc,
        ),
        metadata={
            "malware_family": "test-malware",
        },
    )

    db_session.commit()
    db_session.refresh(event)

    return event


@pytest.fixture
def detection_rule(db_session: Session) -> DetectionRule:
    """
    Create a detection rule for DetectionMatch repository tests.
    """

    user = User(
        username="detection-match-user",
        email="detection-match-user@example.com",
        password_hash=hash_password("StrongPassword123!"),
        is_active=True,
        is_superuser=False,
    )

    db_session.add(user)
    db_session.flush()
    db_session.refresh(user)

    repository = DetectionRuleRepository(db_session)

    rule = repository.create(
        name="detection-match-primary-rule",
        description="Detection match repository test rule",
        rule_type="BRUTE_FORCE",
        severity="HIGH",
        conditions={
            "event_type": "LOGIN_FAILED",
            "threshold": 5,
        },
        enabled=True,
        created_by_user_id=user.id,
    )

    db_session.commit()
    db_session.refresh(rule)

    return rule


@pytest.fixture
def another_detection_rule(db_session: Session) -> DetectionRule:
    """
    Create a second detection rule for multi-record tests.
    """

    user = User(
        username="detection-match-user-secondary",
        email="detection-match-user-secondary@example.com",
        password_hash=hash_password("StrongPassword123!"),
        is_active=True,
        is_superuser=False,
    )

    db_session.add(user)
    db_session.flush()
    db_session.refresh(user)

    repository = DetectionRuleRepository(db_session)

    rule = repository.create(
        name="detection-match-secondary-rule",
        description="Second detection match repository test rule",
        rule_type="MALWARE",
        severity="LOW",
        conditions={
            "event_type": "MALWARE_DETECTED",
        },
        enabled=True,
        created_by_user_id=user.id,
    )

    db_session.commit()
    db_session.refresh(rule)

    return rule