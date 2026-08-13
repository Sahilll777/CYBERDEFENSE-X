from datetime import datetime, timezone

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.main import app
from app.models.detection_match import DetectionMatch
from app.models.permission import Permission
from app.models.role import Role
from app.models.user import User
from app.repositories.detection_match_repository import (
    DetectionMatchRepository,
)
from app.repositories.detection_rule_repository import (
    DetectionRuleRepository,
)
from app.repositories.security_event_repository import (
    SecurityEventRepository,
)
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
            description="Detection match API test role",
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


def create_detection_match(
    db: Session,
    *,
    security_event_id: int,
    detection_rule_id: int,
    severity: str = "HIGH",
    status: str = "NEW",
) -> DetectionMatch:
    """Create a detection match directly for API tests."""

    repository = DetectionMatchRepository(db)

    match = repository.create(
        security_event_id=security_event_id,
        detection_rule_id=detection_rule_id,
        severity=severity,
        status=status,
        matched_at=datetime(
            2026,
            8,
            12,
            12,
            0,
            tzinfo=timezone.utc,
        ),
        metadata={
            "matched_condition": "event_type",
            "test": True,
        },
    )

    db.commit()
    db.refresh(match)

    return match


def test_list_detection_matches_requires_authentication():
    response = client.get(
        "/api/v1/detection-matches",
    )

    assert response.status_code == 401


def test_list_detection_matches_rejects_invalid_token():
    response = client.get(
        "/api/v1/detection-matches",
        headers={
            "Authorization": "Bearer invalid-token",
        },
    )

    assert response.status_code == 401


def test_list_detection_matches_requires_read_permission(
    db_session: Session,
):
    user = create_test_user(
        db_session,
        username="detection-match-list-forbidden",
        email="detection-match-list-forbidden@example.com",
        permissions=["detection_matches.update"],
    )

    response = client.get(
        "/api/v1/detection-matches",
        headers=authorization_header(user),
    )

    assert response.status_code == 403
    assert (
        response.json()["detail"]
        == "Permission required: detection_matches.read"
    )


def test_list_detection_matches_successfully(
    db_session: Session,
    security_event,
    detection_rule,
):
    user = create_test_user(
        db_session,
        username="detection-match-list-success",
        email="detection-match-list-success@example.com",
        permissions=["detection_matches.read"],
    )

    match = create_detection_match(
        db_session,
        security_event_id=security_event.id,
        detection_rule_id=detection_rule.id,
    )

    response = client.get(
        "/api/v1/detection-matches",
        headers=authorization_header(user),
    )

    assert response.status_code == 200

    data = response.json()

    assert isinstance(data, list)
    assert any(
        item["id"] == match.id
        for item in data
    )


def test_list_detection_matches_supports_filters(
    db_session: Session,
    security_event,
    another_security_event,
    detection_rule,
    another_detection_rule,
):
    user = create_test_user(
        db_session,
        username="detection-match-list-filters",
        email="detection-match-list-filters@example.com",
        permissions=["detection_matches.read"],
    )

    high_match = create_detection_match(
        db_session,
        security_event_id=security_event.id,
        detection_rule_id=detection_rule.id,
        severity="HIGH",
        status="NEW",
    )

    low_match = create_detection_match(
        db_session,
        security_event_id=another_security_event.id,
        detection_rule_id=another_detection_rule.id,
        severity="LOW",
        status="ACKNOWLEDGED",
    )

    severity_response = client.get(
        "/api/v1/detection-matches",
        params={
            "severity": "HIGH",
        },
        headers=authorization_header(user),
    )

    assert severity_response.status_code == 200

    severity_matches = severity_response.json()

    assert len(severity_matches) == 1
    assert severity_matches[0]["id"] == high_match.id

    status_response = client.get(
        "/api/v1/detection-matches",
        params={
            "status": "ACKNOWLEDGED",
        },
        headers=authorization_header(user),
    )

    assert status_response.status_code == 200

    status_matches = status_response.json()

    assert len(status_matches) == 1
    assert status_matches[0]["id"] == low_match.id


def test_list_detection_matches_supports_event_and_rule_filters(
    db_session: Session,
    security_event,
    detection_rule,
):
    user = create_test_user(
        db_session,
        username="detection-match-specific-filters",
        email="detection-match-specific-filters@example.com",
        permissions=["detection_matches.read"],
    )

    match = create_detection_match(
        db_session,
        security_event_id=security_event.id,
        detection_rule_id=detection_rule.id,
    )

    response = client.get(
        "/api/v1/detection-matches",
        params={
            "security_event_id": security_event.id,
            "detection_rule_id": detection_rule.id,
        },
        headers=authorization_header(user),
    )

    assert response.status_code == 200

    data = response.json()

    assert len(data) == 1
    assert data[0]["id"] == match.id


def test_get_detection_match_requires_authentication(
    db_session: Session,
    security_event,
    detection_rule,
):
    match = create_detection_match(
        db_session,
        security_event_id=security_event.id,
        detection_rule_id=detection_rule.id,
    )

    response = client.get(
        f"/api/v1/detection-matches/{match.id}",
    )

    assert response.status_code == 401


def test_get_detection_match_requires_read_permission(
    db_session: Session,
    security_event,
    detection_rule,
):
    user = create_test_user(
        db_session,
        username="detection-match-get-forbidden",
        email="detection-match-get-forbidden@example.com",
        permissions=["detection_matches.update"],
    )

    match = create_detection_match(
        db_session,
        security_event_id=security_event.id,
        detection_rule_id=detection_rule.id,
    )

    response = client.get(
        f"/api/v1/detection-matches/{match.id}",
        headers=authorization_header(user),
    )

    assert response.status_code == 403
    assert (
        response.json()["detail"]
        == "Permission required: detection_matches.read"
    )


def test_get_detection_match_returns_not_found(
    db_session: Session,
):
    user = create_test_user(
        db_session,
        username="detection-match-get-unknown",
        email="detection-match-get-unknown@example.com",
        permissions=["detection_matches.read"],
    )

    response = client.get(
        "/api/v1/detection-matches/999999999",
        headers=authorization_header(user),
    )

    assert response.status_code == 404
    assert (
        response.json()["detail"]
        == "Detection match not found."
    )


def test_get_detection_match_successfully(
    db_session: Session,
    security_event,
    detection_rule,
):
    user = create_test_user(
        db_session,
        username="detection-match-get-success",
        email="detection-match-get-success@example.com",
        permissions=["detection_matches.read"],
    )

    match = create_detection_match(
        db_session,
        security_event_id=security_event.id,
        detection_rule_id=detection_rule.id,
        severity="CRITICAL",
    )

    response = client.get(
        f"/api/v1/detection-matches/{match.id}",
        headers=authorization_header(user),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == match.id
    assert data["security_event_id"] == security_event.id
    assert data["detection_rule_id"] == detection_rule.id
    assert data["severity"] == "CRITICAL"
    assert data["status"] == "NEW"
    assert data["metadata"]["test"] is True


def test_update_detection_match_requires_update_permission(
    db_session: Session,
    security_event,
    detection_rule,
):
    user = create_test_user(
        db_session,
        username="detection-match-update-forbidden",
        email="detection-match-update-forbidden@example.com",
        permissions=["detection_matches.read"],
    )

    match = create_detection_match(
        db_session,
        security_event_id=security_event.id,
        detection_rule_id=detection_rule.id,
    )

    response = client.patch(
        f"/api/v1/detection-matches/{match.id}/status",
        json={
            "status": "ACKNOWLEDGED",
        },
        headers=authorization_header(user),
    )

    assert response.status_code == 403
    assert (
        response.json()["detail"]
        == "Permission required: detection_matches.update"
    )


def test_update_detection_match_successfully(
    db_session: Session,
    security_event,
    detection_rule,
):
    user = create_test_user(
        db_session,
        username="detection-match-update-success",
        email="detection-match-update-success@example.com",
        permissions=["detection_matches.update"],
    )

    match = create_detection_match(
        db_session,
        security_event_id=security_event.id,
        detection_rule_id=detection_rule.id,
    )

    response = client.patch(
        f"/api/v1/detection-matches/{match.id}/status",
        json={
            "status": "ACKNOWLEDGED",
        },
        headers=authorization_header(user),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == match.id
    assert data["status"] == "ACKNOWLEDGED"


def test_update_detection_match_returns_not_found(
    db_session: Session,
):
    user = create_test_user(
        db_session,
        username="detection-match-update-unknown",
        email="detection-match-update-unknown@example.com",
        permissions=["detection_matches.update"],
    )

    response = client.patch(
        "/api/v1/detection-matches/999999999/status",
        json={
            "status": "RESOLVED",
        },
        headers=authorization_header(user),
    )

    assert response.status_code == 404
    assert (
        response.json()["detail"]
        == "Detection match not found."
    )


def test_update_detection_match_rejects_invalid_status(
    db_session: Session,
    security_event,
    detection_rule,
):
    user = create_test_user(
        db_session,
        username="detection-match-invalid-status",
        email="detection-match-invalid-status@example.com",
        permissions=["detection_matches.update"],
    )

    match = create_detection_match(
        db_session,
        security_event_id=security_event.id,
        detection_rule_id=detection_rule.id,
    )

    response = client.patch(
        f"/api/v1/detection-matches/{match.id}/status",
        json={
            "status": "INVALID_STATUS",
        },
        headers=authorization_header(user),
    )

    assert response.status_code == 422


def test_superuser_can_access_detection_match_endpoints(
    db_session: Session,
    security_event,
    detection_rule,
):
    user = create_test_user(
        db_session,
        username="detection-match-superuser",
        email="detection-match-superuser@example.com",
        permissions=[],
        is_superuser=True,
    )

    match = create_detection_match(
        db_session,
        security_event_id=security_event.id,
        detection_rule_id=detection_rule.id,
    )

    get_response = client.get(
        f"/api/v1/detection-matches/{match.id}",
        headers=authorization_header(user),
    )

    assert get_response.status_code == 200

    update_response = client.patch(
        f"/api/v1/detection-matches/{match.id}/status",
        json={
            "status": "RESOLVED",
        },
        headers=authorization_header(user),
    )

    assert update_response.status_code == 200
    assert update_response.json()["status"] == "RESOLVED"