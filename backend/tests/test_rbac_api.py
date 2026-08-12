from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.main import app
from app.models.permission import Permission
from app.models.role import Role
from app.models.user import User
from app.security.jwt import create_access_token
from app.security.password import hash_password


client = TestClient(app)


def create_test_user(
    db: Session,
    *,
    username: str,
    email: str,
    permissions: list[str],
    is_superuser: bool = False,
) -> User:
    user = User(
        username=username,
        email=email,
        password_hash=hash_password("StrongPassword123!"),
        is_active=True,
        is_superuser=is_superuser,
    )

    roles = []

    for index, permission_name in enumerate(permissions):
        permission = (
            db.query(Permission)
            .filter(Permission.name == permission_name)
            .first()
        )

        if permission is None:
            permission = Permission(
                name=permission_name,
                description=f"Test permission: {permission_name}",
            )
            db.add(permission)
            db.flush()

        role = Role(
            name=f"TEST_ROLE_{username}_{index}",
            description="Test role",
        )

        role.permissions.append(permission)

        db.add(role)
        db.flush()

        roles.append(role)

    user.roles = roles

    db.add(user)
    db.commit()
    db.refresh(user)

    return user


def get_authorization_header(user: User) -> dict[str, str]:
    token = create_access_token(str(user.id))

    return {
        "Authorization": f"Bearer {token}",
    }


def test_rbac_endpoint_requires_authentication():
    response = client.get("/api/v1/rbac/test")

    assert response.status_code == 401


def test_rbac_endpoint_rejects_invalid_token():
    response = client.get(
        "/api/v1/rbac/test",
        headers={
            "Authorization": "Bearer invalid-token",
        },
    )

    assert response.status_code == 401


def test_user_with_required_permission_is_authorized(
    db_session: Session,
):
    user = create_test_user(
        db_session,
        username="rbac_allowed",
        email="rbac_allowed@example.com",
        permissions=["events.read"],
    )

    response = client.get(
        "/api/v1/rbac/test",
        headers=get_authorization_header(user),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "authorized"
    assert data["username"] == "rbac_allowed"
    assert data["permission"] == "events.read"


def test_user_without_required_permission_is_forbidden(
    db_session: Session,
):
    user = create_test_user(
        db_session,
        username="rbac_forbidden",
        email="rbac_forbidden@example.com",
        permissions=["incidents.read"],
    )

    response = client.get(
        "/api/v1/rbac/test",
        headers=get_authorization_header(user),
    )

    assert response.status_code == 403

    data = response.json()

    assert data["detail"] == "Permission required: events.read"


def test_superuser_can_access_rbac_endpoint(
    db_session: Session,
):
    user = create_test_user(
        db_session,
        username="rbac_superuser",
        email="rbac_superuser@example.com",
        permissions=[],
        is_superuser=True,
    )

    response = client.get(
        "/api/v1/rbac/test",
        headers=get_authorization_header(user),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "authorized"
    assert data["username"] == "rbac_superuser"