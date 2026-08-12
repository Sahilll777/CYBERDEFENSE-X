import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.database import SessionLocal


def _cleanup_rbac_test_data(db: Session) -> None:
    """
    Remove database records created by RBAC API integration tests.

    RBAC API tests intentionally commit their transactions because the
    application itself commits database changes. Therefore, a normal
    session rollback cannot provide test isolation.

    This cleanup targets only records created by the RBAC tests and does
    not remove seeded production roles or permissions.
    """

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

    db.execute(
        text(
            """
            DELETE FROM roles
            WHERE name LIKE 'TEST_ROLE_%'
            """
        )
    )

    db.execute(
        text(
            """
            DELETE FROM users
            WHERE username LIKE 'rbac_%'
            """
        )
    )

    db.commit()


@pytest.fixture
def db_session() -> Session:
    """
    Provide a PostgreSQL session for database-backed tests.

    RBAC integration tests commit their changes, so the fixture performs
    explicit cleanup before and after each test to guarantee repeatability.
    """

    db = SessionLocal()

    try:
        # Remove leftovers from previous interrupted/failed test runs.
        _cleanup_rbac_test_data(db)

        yield db

    finally:
        try:
            db.rollback()
            _cleanup_rbac_test_data(db)
        finally:
            db.close()