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


def test_login_returns_access_token():
    unique_id = uuid4().hex[:8]

    username = f"login_user_{unique_id}"
    email = f"login_{unique_id}@example.com"

    try:
        register_response = client.post(
            "/api/v1/auth/register",
            json={
                "username": username,
                "email": email,
                "password": "StrongPassword123!",
                "full_name": "Login Test User",
            },
        )

        assert register_response.status_code == 201

        login_response = client.post(
            "/api/v1/auth/login",
            json={
                "username": username,
                "password": "StrongPassword123!",
            },
        )

        assert login_response.status_code == 200

        data = login_response.json()

        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert len(data["access_token"]) > 20

    finally:
        cleanup_user(username)


def test_login_rejects_wrong_password():
    unique_id = uuid4().hex[:8]

    username = f"wrong_password_{unique_id}"
    email = f"wrong_{unique_id}@example.com"

    try:
        register_response = client.post(
            "/api/v1/auth/register",
            json={
                "username": username,
                "email": email,
                "password": "StrongPassword123!",
            },
        )

        assert register_response.status_code == 201

        login_response = client.post(
            "/api/v1/auth/login",
            json={
                "username": username,
                "password": "WrongPassword123!",
            },
        )

        assert login_response.status_code == 401
        assert login_response.json()["detail"] == "Invalid username or password."

    finally:
        cleanup_user(username)


def test_login_rejects_unknown_username():
    response = client.post(
        "/api/v1/auth/login",
        json={
            "username": "definitely_nonexistent_user",
            "password": "StrongPassword123!",
        },
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid username or password."