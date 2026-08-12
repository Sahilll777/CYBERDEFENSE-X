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
    """Create a database user with the requested permissions."""

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
            description="Detection rule API test role",
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


def authorization_header(user: User) -> dict[str, str]:
    """Return a Bearer authorization header for a test user."""

    token = create_access_token(str(user.id))

    return {
        "Authorization": f"Bearer {token}",
    }


def create_rule_payload(
    *,
    name: str = "API Test Detection Rule",
) -> dict:
    """Return a valid detection-rule API payload."""

    return {
        "name": name,
        "description": "Detect repeated failed logins",
        "rule_type": "BRUTE_FORCE",
        "severity": "HIGH",
        "conditions": {
            "event_type": "LOGIN_FAILED",
            "threshold": 5,
        },
        "enabled": True,
    }


def test_create_detection_rule_requires_authentication():
    response = client.post(
        "/api/v1/detection-rules",
        json=create_rule_payload(),
    )

    assert response.status_code == 401


def test_create_detection_rule_rejects_invalid_token():
    response = client.post(
        "/api/v1/detection-rules",
        json=create_rule_payload(),
        headers={
            "Authorization": "Bearer invalid-token",
        },
    )

    assert response.status_code == 401


def test_create_detection_rule_requires_create_permission(
    db_session: Session,
):
    user = create_test_user(
        db_session,
        username="api_create_forbidden",
        email="api_create_forbidden@example.com",
        permissions=["detection_rules.read"],
    )

    response = client.post(
        "/api/v1/detection-rules",
        json=create_rule_payload(
            name="api-create-forbidden-rule",
        ),
        headers=authorization_header(user),
    )

    assert response.status_code == 403
    assert (
        response.json()["detail"]
        == "Permission required: detection_rules.create"
    )


def test_create_detection_rule_successfully(
    db_session: Session,
):
    user = create_test_user(
        db_session,
        username="api_create_success",
        email="api_create_success@example.com",
        permissions=["detection_rules.create"],
    )

    response = client.post(
        "/api/v1/detection-rules",
        json=create_rule_payload(
            name="api-create-success-rule",
        ),
        headers=authorization_header(user),
    )

    assert response.status_code == 201

    data = response.json()

    assert data["id"] is not None
    assert data["name"] == "api-create-success-rule"
    assert data["description"] == "Detect repeated failed logins"
    assert data["rule_type"] == "BRUTE_FORCE"
    assert data["severity"] == "HIGH"
    assert data["conditions"] == {
        "event_type": "LOGIN_FAILED",
        "threshold": 5,
    }
    assert data["enabled"] is True
    assert data["created_by_user_id"] == user.id


def test_create_detection_rule_rejects_duplicate_name(
    db_session: Session,
):
    user = create_test_user(
        db_session,
        username="api_create_duplicate",
        email="api_create_duplicate@example.com",
        permissions=["detection_rules.create"],
    )

    first_response = client.post(
        "/api/v1/detection-rules",
        json=create_rule_payload(
            name="api-duplicate-rule",
        ),
        headers=authorization_header(user),
    )

    assert first_response.status_code == 201

    second_response = client.post(
        "/api/v1/detection-rules",
        json=create_rule_payload(
            name="api-duplicate-rule",
        ),
        headers=authorization_header(user),
    )

    assert second_response.status_code == 409
    assert (
        second_response.json()["detail"]
        == "Detection rule name already exists."
    )


def test_create_detection_rule_rejects_invalid_payload(
    db_session: Session,
):
    user = create_test_user(
        db_session,
        username="api_create_invalid",
        email="api_create_invalid@example.com",
        permissions=["detection_rules.create"],
    )

    response = client.post(
        "/api/v1/detection-rules",
        json={
            "name": "",
            "rule_type": "BRUTE_FORCE",
            "severity": "HIGH",
            "conditions": {},
        },
        headers=authorization_header(user),
    )

    assert response.status_code == 422


def test_list_detection_rules_requires_authentication():
    response = client.get(
        "/api/v1/detection-rules",
    )

    assert response.status_code == 401


def test_list_detection_rules_requires_read_permission(
    db_session: Session,
):
    user = create_test_user(
        db_session,
        username="api_list_forbidden",
        email="api_list_forbidden@example.com",
        permissions=["detection_rules.create"],
    )

    response = client.get(
        "/api/v1/detection-rules",
        headers=authorization_header(user),
    )

    assert response.status_code == 403
    assert (
        response.json()["detail"]
        == "Permission required: detection_rules.read"
    )


def test_list_detection_rules_successfully(
    db_session: Session,
):
    user = create_test_user(
        db_session,
        username="api_list_success",
        email="api_list_success@example.com",
        permissions=["detection_rules.read"],
    )

    response = client.get(
        "/api/v1/detection-rules",
        headers=authorization_header(user),
    )

    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_list_detection_rules_supports_filters(
    db_session: Session,
):
    user = create_test_user(
        db_session,
        username="api_list_filters",
        email="api_list_filters@example.com",
        permissions=[
            "detection_rules.create",
            "detection_rules.read",
        ],
    )

    create_response = client.post(
        "/api/v1/detection-rules",
        json=create_rule_payload(
            name="api-filter-brute-force",
        ),
        headers=authorization_header(user),
    )

    assert create_response.status_code == 201

    malware_payload = {
        "name": "api-filter-malware",
        "description": "Detect malware",
        "rule_type": "MALWARE",
        "severity": "CRITICAL",
        "conditions": {
            "event_type": "MALWARE_DETECTED",
        },
        "enabled": False,
    }

    malware_response = client.post(
        "/api/v1/detection-rules",
        json=malware_payload,
        headers=authorization_header(user),
    )

    assert malware_response.status_code == 201

    brute_force_response = client.get(
        "/api/v1/detection-rules",
        params={
            "rule_type": "BRUTE_FORCE",
        },
        headers=authorization_header(user),
    )

    assert brute_force_response.status_code == 200

    brute_force_rules = brute_force_response.json()

    assert len(brute_force_rules) == 1
    assert brute_force_rules[0]["name"] == "api-filter-brute-force"

    critical_response = client.get(
        "/api/v1/detection-rules",
        params={
            "severity": "CRITICAL",
        },
        headers=authorization_header(user),
    )

    assert critical_response.status_code == 200

    critical_rules = critical_response.json()

    assert len(critical_rules) == 1
    assert critical_rules[0]["name"] == "api-filter-malware"

    disabled_response = client.get(
        "/api/v1/detection-rules",
        params={
            "enabled": "false",
        },
        headers=authorization_header(user),
    )

    assert disabled_response.status_code == 200

    disabled_rules = disabled_response.json()

    assert len(disabled_rules) == 1
    assert disabled_rules[0]["name"] == "api-filter-malware"


def test_get_detection_rule_requires_read_permission(
    db_session: Session,
):
    user = create_test_user(
        db_session,
        username="api_get_forbidden",
        email="api_get_forbidden@example.com",
        permissions=["detection_rules.create"],
    )

    response = client.get(
        "/api/v1/detection-rules/999999999",
        headers=authorization_header(user),
    )

    assert response.status_code == 403
    assert (
        response.json()["detail"]
        == "Permission required: detection_rules.read"
    )


def test_get_detection_rule_returns_not_found(
    db_session: Session,
):
    user = create_test_user(
        db_session,
        username="api_get_unknown",
        email="api_get_unknown@example.com",
        permissions=["detection_rules.read"],
    )

    response = client.get(
        "/api/v1/detection-rules/999999999",
        headers=authorization_header(user),
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Detection rule not found."


def test_get_detection_rule_successfully(
    db_session: Session,
):
    user = create_test_user(
        db_session,
        username="api_get_success",
        email="api_get_success@example.com",
        permissions=[
            "detection_rules.create",
            "detection_rules.read",
        ],
    )

    create_response = client.post(
        "/api/v1/detection-rules",
        json=create_rule_payload(
            name="api-get-success-rule",
        ),
        headers=authorization_header(user),
    )

    assert create_response.status_code == 201

    rule_id = create_response.json()["id"]

    response = client.get(
        f"/api/v1/detection-rules/{rule_id}",
        headers=authorization_header(user),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == rule_id
    assert data["name"] == "api-get-success-rule"


def test_update_detection_rule_requires_update_permission(
    db_session: Session,
):
    user = create_test_user(
        db_session,
        username="api_update_forbidden",
        email="api_update_forbidden@example.com",
        permissions=["detection_rules.read"],
    )

    response = client.patch(
        "/api/v1/detection-rules/999999999",
        json={
            "enabled": False,
        },
        headers=authorization_header(user),
    )

    assert response.status_code == 403
    assert (
        response.json()["detail"]
        == "Permission required: detection_rules.update"
    )


def test_update_detection_rule_successfully(
    db_session: Session,
):
    user = create_test_user(
        db_session,
        username="api_update_success",
        email="api_update_success@example.com",
        permissions=[
            "detection_rules.create",
            "detection_rules.update",
        ],
    )

    create_response = client.post(
        "/api/v1/detection-rules",
        json=create_rule_payload(
            name="api-update-rule",
        ),
        headers=authorization_header(user),
    )

    assert create_response.status_code == 201

    rule_id = create_response.json()["id"]

    response = client.patch(
        f"/api/v1/detection-rules/{rule_id}",
        json={
            "name": "api-updated-rule",
            "severity": "CRITICAL",
            "enabled": False,
        },
        headers=authorization_header(user),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == rule_id
    assert data["name"] == "api-updated-rule"
    assert data["severity"] == "CRITICAL"
    assert data["enabled"] is False
    assert data["rule_type"] == "BRUTE_FORCE"


def test_update_detection_rule_returns_not_found(
    db_session: Session,
):
    user = create_test_user(
        db_session,
        username="api_update_unknown",
        email="api_update_unknown@example.com",
        permissions=["detection_rules.update"],
    )

    response = client.patch(
        "/api/v1/detection-rules/999999999",
        json={
            "enabled": False,
        },
        headers=authorization_header(user),
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Detection rule not found."


def test_delete_detection_rule_requires_delete_permission(
    db_session: Session,
):
    user = create_test_user(
        db_session,
        username="api_delete_forbidden",
        email="api_delete_forbidden@example.com",
        permissions=["detection_rules.read"],
    )

    response = client.delete(
        "/api/v1/detection-rules/999999999",
        headers=authorization_header(user),
    )

    assert response.status_code == 403
    assert (
        response.json()["detail"]
        == "Permission required: detection_rules.delete"
    )


def test_delete_detection_rule_successfully(
    db_session: Session,
):
    user = create_test_user(
        db_session,
        username="api_delete_success",
        email="api_delete_success@example.com",
        permissions=[
            "detection_rules.create",
            "detection_rules.delete",
            "detection_rules.read",
        ],
    )

    create_response = client.post(
        "/api/v1/detection-rules",
        json=create_rule_payload(
            name="api-delete-rule",
        ),
        headers=authorization_header(user),
    )

    assert create_response.status_code == 201

    rule_id = create_response.json()["id"]

    response = client.delete(
        f"/api/v1/detection-rules/{rule_id}",
        headers=authorization_header(user),
    )

    assert response.status_code == 204
    assert response.content == b""

    get_response = client.get(
        f"/api/v1/detection-rules/{rule_id}",
        headers=authorization_header(user),
    )

    assert get_response.status_code == 404


def test_delete_detection_rule_returns_not_found(
    db_session: Session,
):
    user = create_test_user(
        db_session,
        username="api_delete_unknown",
        email="api_delete_unknown@example.com",
        permissions=["detection_rules.delete"],
    )

    response = client.delete(
        "/api/v1/detection-rules/999999999",
        headers=authorization_header(user),
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Detection rule not found."


def test_superuser_can_access_detection_rule_endpoints(
    db_session: Session,
):
    user = create_test_user(
        db_session,
        username="api_detection_superuser",
        email="api_detection_superuser@example.com",
        permissions=[],
        is_superuser=True,
    )

    create_response = client.post(
        "/api/v1/detection-rules",
        json=create_rule_payload(
            name="api-superuser-rule",
        ),
        headers=authorization_header(user),
    )

    assert create_response.status_code == 201

    rule_id = create_response.json()["id"]

    get_response = client.get(
        f"/api/v1/detection-rules/{rule_id}",
        headers=authorization_header(user),
    )

    assert get_response.status_code == 200

    update_response = client.patch(
        f"/api/v1/detection-rules/{rule_id}",
        json={
            "enabled": False,
        },
        headers=authorization_header(user),
    )

    assert update_response.status_code == 200

    delete_response = client.delete(
        f"/api/v1/detection-rules/{rule_id}",
        headers=authorization_header(user),
    )

    assert delete_response.status_code == 204