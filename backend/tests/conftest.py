import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.database import SessionLocal


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
    # Security Event API test data
    # ---------------------------------------------------------
    db.execute(
        text(
            """
            DELETE FROM security_events
            WHERE source = 'security-event-api-test'
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