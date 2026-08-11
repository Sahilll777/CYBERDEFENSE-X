from sqlalchemy import select

from app.core.database import SessionLocal
from app.models.user import User
from app.services.auth_service import AuthService


def test_register_user_creates_user_with_hashed_password():
    db = SessionLocal()

    try:
        service = AuthService(db)

        user = service.register_user(
            username="test_security_user",
            email="test_security_user@example.com",
            password="TestPassword123!",
            full_name="Security Test User",
        )

        db.commit()

        stored_user = db.scalar(
            select(User).where(User.id == user.id)
        )

        assert stored_user is not None
        assert stored_user.username == "test_security_user"
        assert stored_user.email == "test_security_user@example.com"
        assert stored_user.full_name == "Security Test User"
        assert stored_user.password_hash != "TestPassword123!"
        assert stored_user.password_hash.startswith("$argon2")

    finally:
        db.rollback()

        db.execute(
            User.__table__.delete().where(
                User.username == "test_security_user"
            )
        )

        db.commit()
        db.close()


def test_duplicate_username_is_rejected():
    db = SessionLocal()

    try:
        service = AuthService(db)

        service.register_user(
            username="duplicate_security_user",
            email="duplicate1@example.com",
            password="TestPassword123!",
        )

        db.commit()

        try:
            service.register_user(
                username="duplicate_security_user",
                email="duplicate2@example.com",
                password="TestPassword123!",
            )

            assert False, "Expected duplicate username to be rejected."

        except ValueError as exc:
            assert str(exc) == "Username already exists."

    finally:
        db.rollback()

        db.execute(
            User.__table__.delete().where(
                User.username == "duplicate_security_user"
            )
        )

        db.commit()
        db.close()


def test_duplicate_email_is_rejected():
    db = SessionLocal()

    try:
        service = AuthService(db)

        service.register_user(
            username="email_security_user_1",
            email="duplicate-email@example.com",
            password="TestPassword123!",
        )

        db.commit()

        try:
            service.register_user(
                username="email_security_user_2",
                email="duplicate-email@example.com",
                password="TestPassword123!",
            )

            assert False, "Expected duplicate email to be rejected."

        except ValueError as exc:
            assert str(exc) == "Email already exists."

    finally:
        db.rollback()

        db.execute(
            User.__table__.delete().where(
                User.email == "duplicate-email@example.com"
            )
        )

        db.commit()
        db.close()