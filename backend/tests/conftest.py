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
    Remove database records created by integration/API tests.

    Integration tests intentionally commit their transactions because
    the application itself commits database changes. Therefore, normal
    session rollback cannot provide test isolation.

    Cleanup is dependency-aware and removes child records before parent
    records.

    IMPORTANT:
    This function only targets records created by tests. Seeded
    production roles, permissions, and unrelated application data are
    preserved.
    """

    # =========================================================
    # ALERT TEST DATA
    # =========================================================
    #
    # Alerts depend on:
    #   - detection_matches
    #   - security_events
    #   - detection_rules
    #   - incidents
    #
    # Delete alerts first.
    #
    db.execute(
        text(
            """
            DELETE FROM alerts
            WHERE title LIKE 'alert-api-%'
            OR detection_match_id IN (
                SELECT dm.id
                FROM detection_matches AS dm
                JOIN security_events AS se
                    ON se.id = dm.security_event_id
                WHERE se.source LIKE 'detection-match-%'
                   OR se.source LIKE 'detection-match-integration-%'
            )
            OR detection_rule_id IN (
                SELECT id
                FROM detection_rules
                WHERE name LIKE 'alert-api-%'
                   OR name LIKE 'detection-match-%'
                   OR name LIKE 'detection-match-integration-%'
                   OR name = 'SSH Brute Force Test'
            )
            """
        )
    )

    # =========================================================
    # ALERT API TEST INCIDENTS
    # =========================================================
    #
    # Incident.created_by_user_id uses ON DELETE RESTRICT.
    #
    # Therefore, Alert API test incidents MUST be deleted before
    # Alert API test users.
    #
    # These incidents are created by users whose usernames start
    # with:
    #
    #     alert-api-
    #
    db.execute(
        text(
            """
            DELETE FROM incidents
            WHERE created_by_user_id IN (
                SELECT id
                FROM users
                WHERE username LIKE 'alert-api-%'
            )
            OR title LIKE 'alert-api-%'
            """
        )
    )

    # =========================================================
    # DETECTION MATCH TEST DATA
    # =========================================================
    #
    # DetectionMatch depends on security_events and detection_rules.
    #
    db.execute(
        text(
            """
            DELETE FROM detection_matches
            WHERE security_event_id IN (
                SELECT id
                FROM security_events
                WHERE source LIKE 'detection-match-%'
                   OR source LIKE 'detection-match-integration-%'
            )
            OR detection_rule_id IN (
                SELECT id
                FROM detection_rules
                WHERE name LIKE 'detection-match-%'
                   OR name LIKE 'detection-match-integration-%'
                   OR name = 'SSH Brute Force Test'
            )
            """
        )
    )

    # =========================================================
    # SECURITY EVENT TEST DATA
    # =========================================================
    db.execute(
        text(
            """
            DELETE FROM security_events
            WHERE source = 'security-event-api-test'
            OR source LIKE 'detection-match-%'
            OR source LIKE 'detection-match-integration-%'
            """
        )
    )

    # =========================================================
    # DETECTION RULE TEST DATA
    # =========================================================
    db.execute(
        text(
            """
            DELETE FROM detection_rules
            WHERE name LIKE 'api-%'
            OR name LIKE 'test-%'
            OR name LIKE 'detection-match-%'
            OR name LIKE 'detection-match-integration-%'
            OR name = 'SSH Brute Force Test'
            """
        )
    )

    # =========================================================
    # ALERT API TEST USER-ROLE MAPPINGS
    # =========================================================
    #
    # Alert API users have usernames:
    #
    #     alert-api-*
    #
    # Their roles are TEST_ROLE_*.
    #
    db.execute(
        text(
            """
            DELETE FROM user_roles
            WHERE user_id IN (
                SELECT id
                FROM users
                WHERE username LIKE 'alert-api-%'
            )
            OR role_id IN (
                SELECT id
                FROM roles
                WHERE name LIKE 'TEST_ROLE_%'
            )
            """
        )
    )

    # =========================================================
    # DETECTION / SECURITY EVENT TEST USER-ROLE MAPPINGS
    # =========================================================
    db.execute(
        text(
            """
            DELETE FROM user_roles
            WHERE user_id IN (
                SELECT id
                FROM users
                WHERE username LIKE 'detection-match-%'
            )
            OR user_id IN (
                SELECT id
                FROM users
                WHERE username LIKE 'detection-match-integration-%'
            )
            """
        )
    )

    # =========================================================
    # RBAC TEST ROLE-PERMISSION MAPPINGS
    # =========================================================
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

    # =========================================================
    # RBAC TEST USER-ROLE MAPPINGS
    # =========================================================
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

    # =========================================================
    # SECURITY EVENT API TEST USER-ROLE MAPPINGS
    # =========================================================
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

    # =========================================================
    # DETECTION RULE API TEST USERS
    # =========================================================
    db.execute(
        text(
            """
            DELETE FROM users
            WHERE username LIKE 'detection_rule_%'
            """
        )
    )

    # =========================================================
    # DETECTION MATCH TEST USERS
    # =========================================================
    db.execute(
        text(
            """
            DELETE FROM users
            WHERE username LIKE 'detection-match-%'
            OR username LIKE 'detection-match-integration-%'
            """
        )
    )

    # =========================================================
    # ALERT API TEST USERS
    # =========================================================
    #
    # At this point:
    #
    #   - alert-api incidents are deleted
    #   - user_roles mappings are deleted
    #   - alerts are deleted
    #
    # Therefore the RESTRICT foreign key on
    # incidents.created_by_user_id no longer blocks deletion.
    #
    db.execute(
        text(
            """
            DELETE FROM users
            WHERE username LIKE 'alert-api-%'
            """
        )
    )

    # =========================================================
    # GENERAL API TEST USERS
    # =========================================================
    db.execute(
        text(
            """
            DELETE FROM users
            WHERE username LIKE 'api_%'
            """
        )
    )

    # =========================================================
    # RBAC TEST ROLES
    # =========================================================
    db.execute(
        text(
            """
            DELETE FROM roles
            WHERE name LIKE 'TEST_ROLE_%'
            """
        )
    )

    # =========================================================
    # RBAC TEST USERS
    # =========================================================
    db.execute(
        text(
            """
            DELETE FROM users
            WHERE username LIKE 'rbac_%'
            """
        )
    )

    # =========================================================
    # SECURITY EVENT API TEST USERS
    # =========================================================
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
def security_event(
    db_session: Session,
) -> SecurityEvent:
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
def another_security_event(
    db_session: Session,
) -> SecurityEvent:
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
def detection_rule(
    db_session: Session,
) -> DetectionRule:
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
def another_detection_rule(
    db_session: Session,
) -> DetectionRule:
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