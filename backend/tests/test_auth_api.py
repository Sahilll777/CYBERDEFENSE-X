from uuid import uuid4

from fastapi.testclient import TestClient

from app.core.database import SessionLocal
from app.main import app
from app.models.user import User


client = TestClient(app)


def cleanup_user(username: str) -> None:
    db = SessionLocal()

    try:
        user = (
            db.query(User)
            .filter(User.username == username)
            .first()
        )

        if user is not None:
            db.delete(user)
            db.commit()

    finally:
        db.close()


def test_register_user_successfully():
    unique_id = uuid4().hex[:8]

    username = f"api_user_{unique_id}"
    email = f"api_user_{unique_id}@example.com"

    try:
        response = client.post(
            "/api/v1/auth/register",
            json={
                "username": username,
                "email": email,
                "password": "StrongPassword123!",
                "full_name": "API Test User",
            },
        )

        assert response.status_code == 201

        data = response.json()

        assert data["username"] == username
        assert data["email"] == email
        assert data["full_name"] == "API Test User"
        assert data["is_active"] is True
        assert data["is_superuser"] is False

        assert "password" not in data
        assert "password_hash" not in data

    finally:
        cleanup_user(username)


def test_register_duplicate_username_returns_conflict():
    unique_id = uuid4().hex[:8]

    username = f"duplicate_{unique_id}"

    try:
        first_response = client.post(
            "/api/v1/auth/register",
            json={
                "username": username,
                "email": f"first_{unique_id}@example.com",
                "password": "StrongPassword123!",
            },
        )

        assert first_response.status_code == 201

        second_response = client.post(
            "/api/v1/auth/register",
            json={
                "username": username,
                "email": f"second_{unique_id}@example.com",
                "password": "StrongPassword123!",
            },
        )

        assert second_response.status_code == 409
        assert second_response.json()["detail"] == "Username already exists."

    finally:
        cleanup_user(username)


def test_register_duplicate_email_returns_conflict():
    unique_id = uuid4().hex[:8]

    email = f"duplicate_email_{unique_id}@example.com"

    username_one = f"email_user_one_{unique_id}"
    username_two = f"email_user_two_{unique_id}"

    try:
        first_response = client.post(
            "/api/v1/auth/register",
            json={
                "username": username_one,
                "email": email,
                "password": "StrongPassword123!",
            },
        )

        assert first_response.status_code == 201

        second_response = client.post(
            "/api/v1/auth/register",
            json={
                "username": username_two,
                "email": email,
                "password": "StrongPassword123!",
            },
        )

        assert second_response.status_code == 409
        assert second_response.json()["detail"] == "Email already exists."

    finally:
        cleanup_user(username_one)
        cleanup_user(username_two)


def test_register_rejects_short_password():
    unique_id = uuid4().hex[:8]

    response = client.post(
        "/api/v1/auth/register",
        json={
            "username": f"short_password_{unique_id}",
            "email": f"short_{unique_id}@example.com",
            "password": "short",
        },
    )

    assert response.status_code == 422