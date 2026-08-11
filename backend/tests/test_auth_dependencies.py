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


def test_me_requires_authentication():
    response = client.get("/api/v1/auth/me")

    assert response.status_code == 401
    assert response.json()["detail"] == (
        "Could not validate authentication credentials."
    )


def test_me_returns_authenticated_user():
    unique_id = uuid4().hex[:8]

    username = f"me_user_{unique_id}"
    email = f"me_{unique_id}@example.com"

    try:
        register_response = client.post(
            "/api/v1/auth/register",
            json={
                "username": username,
                "email": email,
                "password": "StrongPassword123!",
                "full_name": "Authenticated User",
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

        token = login_response.json()["access_token"]

        me_response = client.get(
            "/api/v1/auth/me",
            headers={
                "Authorization": f"Bearer {token}",
            },
        )

        assert me_response.status_code == 200

        data = me_response.json()

        assert data["username"] == username
        assert data["email"] == email
        assert data["full_name"] == "Authenticated User"
        assert data["is_active"] is True
        assert data["is_superuser"] is False

        assert "password" not in data
        assert "password_hash" not in data

    finally:
        cleanup_user(username)


def test_me_rejects_invalid_token():
    response = client.get(
        "/api/v1/auth/me",
        headers={
            "Authorization": "Bearer invalid.jwt.token",
        },
    )

    assert response.status_code == 401