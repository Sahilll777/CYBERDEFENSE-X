from datetime import datetime, timezone

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.main import app
from app.models.alert import Alert
from app.models.detection_match import DetectionMatch
from app.models.detection_rule import DetectionRule
from app.models.incident import Incident
from app.models.permission import Permission
from app.models.role import Role
from app.models.user import User
from app.repositories.alert_repository import AlertRepository
from app.repositories.detection_match_repository import (
    DetectionMatchRepository,
)
from app.repositories.incident.incident_repository import (
    IncidentRepository,
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
            description="Alert API test role",
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


def authorization_header(
    user: User,
) -> dict[str, str]:
    """Return a Bearer authorization header."""

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
    """Create a detection match for Alert API tests."""

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


def create_alert(
    db: Session,
    *,
    detection_match_id: int,
    security_event_id: int,
    detection_rule_id: int,
    severity: str = "HIGH",
    title: str = "alert-api-primary-alert",
    status: str = "OPEN",
    incident_id: int | None = None,
    assigned_to_user_id: int | None = None,
) -> Alert:
    """Create an alert directly for API tests."""

    repository = AlertRepository(db)

    alert = repository.create(
        detection_match_id=detection_match_id,
        security_event_id=security_event_id,
        detection_rule_id=detection_rule_id,
        severity=severity,
        title=title,
        description="Alert API integration test alert.",
        status=status,
        assigned_to_user_id=assigned_to_user_id,
        incident_id=incident_id,
        opened_at=datetime(
            2026,
            8,
            12,
            12,
            30,
            tzinfo=timezone.utc,
        ),
    )

    db.commit()
    db.refresh(alert)

    return alert


def create_incident(
    db: Session,
    *,
    created_by_user_id: int,
    title: str = "alert-api-primary-incident",
    severity: str = "HIGH",
    priority: str = "HIGH",
    status: str = "OPEN",
) -> Incident:
    """Create an incident for Alert API tests."""

    repository = IncidentRepository(db)

    incident = repository.create(
        title=title,
        description="Alert API integration test incident.",
        severity=severity,
        priority=priority,
        status=status,
        created_by_user_id=created_by_user_id,
        opened_at=datetime(
            2026,
            8,
            12,
            13,
            0,
            tzinfo=timezone.utc,
        ),
    )

    db.commit()
    db.refresh(incident)

    return incident


def create_alert_test_data(
    db: Session,
    security_event,
    detection_rule,
    *,
    title: str = "alert-api-primary-alert",
) -> Alert:
    """Create the DetectionMatch -> Alert test dependency chain."""

    match = create_detection_match(
        db,
        security_event_id=security_event.id,
        detection_rule_id=detection_rule.id,
    )

    return create_alert(
        db,
        detection_match_id=match.id,
        security_event_id=security_event.id,
        detection_rule_id=detection_rule.id,
        title=title,
    )


# ============================================================
# Authentication
# ============================================================


def test_list_alerts_requires_authentication():
    response = client.get(
        "/api/v1/alerts",
    )

    assert response.status_code == 401


def test_list_alerts_rejects_invalid_token():
    response = client.get(
        "/api/v1/alerts",
        headers={
            "Authorization": "Bearer invalid-token",
        },
    )

    assert response.status_code == 401


def test_get_alert_requires_authentication():
    response = client.get(
        "/api/v1/alerts/999999999",
    )

    assert response.status_code == 401


# ============================================================
# RBAC
# ============================================================


def test_list_alerts_requires_read_permission(
    db_session: Session,
):
    user = create_test_user(
        db_session,
        username="alert-api-list-forbidden",
        email="alert-api-list-forbidden@example.com",
        permissions=["alerts.update"],
    )

    response = client.get(
        "/api/v1/alerts",
        headers=authorization_header(user),
    )

    assert response.status_code == 403
    assert (
        response.json()["detail"]
        == "Permission required: alerts.read"
    )


def test_get_alert_requires_read_permission(
    db_session: Session,
):
    user = create_test_user(
        db_session,
        username="alert-api-get-forbidden",
        email="alert-api-get-forbidden@example.com",
        permissions=["alerts.update"],
    )

    response = client.get(
        "/api/v1/alerts/999999999",
        headers=authorization_header(user),
    )

    assert response.status_code == 403
    assert (
        response.json()["detail"]
        == "Permission required: alerts.read"
    )


def test_attach_alert_requires_update_permission(
    db_session: Session,
):
    user = create_test_user(
        db_session,
        username="alert-api-attach-forbidden",
        email="alert-api-attach-forbidden@example.com",
        permissions=["alerts.read"],
    )

    response = client.post(
        "/api/v1/alerts/999999999/incident",
        json={
            "incident_id": 1,
        },
        headers=authorization_header(user),
    )

    assert response.status_code == 403
    assert (
        response.json()["detail"]
        == "Permission required: alerts.update"
    )


def test_detach_alert_requires_update_permission(
    db_session: Session,
):
    user = create_test_user(
        db_session,
        username="alert-api-detach-forbidden",
        email="alert-api-detach-forbidden@example.com",
        permissions=["alerts.read"],
    )

    response = client.delete(
        "/api/v1/alerts/999999999/incident",
        headers=authorization_header(user),
    )

    assert response.status_code == 403
    assert (
        response.json()["detail"]
        == "Permission required: alerts.update"
    )


def test_assign_alert_requires_assign_permission(
    db_session: Session,
):
    user = create_test_user(
        db_session,
        username="alert-api-assign-forbidden",
        email="alert-api-assign-forbidden@example.com",
        permissions=["alerts.update"],
    )

    response = client.patch(
        "/api/v1/alerts/999999999/assignment",
        json={
            "assigned_to_user_id": user.id,
        },
        headers=authorization_header(user),
    )

    assert response.status_code == 403
    assert (
        response.json()["detail"]
        == "Permission required: alerts.assign"
    )


# ============================================================
# List / Get
# ============================================================


def test_list_alerts_successfully(
    db_session: Session,
    security_event,
    detection_rule,
):
    user = create_test_user(
        db_session,
        username="alert-api-list-success",
        email="alert-api-list-success@example.com",
        permissions=["alerts.read"],
    )

    alert = create_alert_test_data(
        db_session,
        security_event,
        detection_rule,
        title="alert-api-list-success-alert",
    )

    response = client.get(
        "/api/v1/alerts",
        headers=authorization_header(user),
    )

    assert response.status_code == 200

    data = response.json()

    assert isinstance(data, list)
    assert any(
        item["id"] == alert.id
        for item in data
    )


def test_get_alert_successfully(
    db_session: Session,
    security_event,
    detection_rule,
):
    user = create_test_user(
        db_session,
        username="alert-api-get-success",
        email="alert-api-get-success@example.com",
        permissions=["alerts.read"],
    )

    alert = create_alert_test_data(
        db_session,
        security_event,
        detection_rule,
        title="alert-api-get-success-alert",
    )

    response = client.get(
        f"/api/v1/alerts/{alert.id}",
        headers=authorization_header(user),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == alert.id
    assert data["detection_match_id"] == alert.detection_match_id
    assert data["security_event_id"] == security_event.id
    assert data["detection_rule_id"] == detection_rule.id
    assert data["severity"] == "HIGH"
    assert data["status"] == "OPEN"
    assert data["incident_id"] is None


def test_get_alert_returns_not_found(
    db_session: Session,
):
    user = create_test_user(
        db_session,
        username="alert-api-get-unknown",
        email="alert-api-get-unknown@example.com",
        permissions=["alerts.read"],
    )

    response = client.get(
        "/api/v1/alerts/999999999",
        headers=authorization_header(user),
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Alert not found."


def test_list_alerts_supports_filters(
    db_session: Session,
    security_event,
    another_security_event,
    detection_rule,
    another_detection_rule,
):
    user = create_test_user(
        db_session,
        username="alert-api-filters",
        email="alert-api-filters@example.com",
        permissions=["alerts.read"],
    )

    high_alert = create_alert_test_data(
        db_session,
        security_event,
        detection_rule,
        title="alert-api-filter-high",
    )

    low_match = create_detection_match(
        db_session,
        security_event_id=another_security_event.id,
        detection_rule_id=another_detection_rule.id,
        severity="LOW",
        status="NEW",
    )

    low_alert = create_alert(
        db_session,
        detection_match_id=low_match.id,
        security_event_id=another_security_event.id,
        detection_rule_id=another_detection_rule.id,
        severity="LOW",
        title="alert-api-filter-low",
    )

    severity_response = client.get(
        "/api/v1/alerts",
        params={
            "severity": "HIGH",
        },
        headers=authorization_header(user),
    )

    assert severity_response.status_code == 200

    severity_data = severity_response.json()

    assert len(severity_data) == 1
    assert severity_data[0]["id"] == high_alert.id

    event_response = client.get(
        "/api/v1/alerts",
        params={
            "security_event_id": another_security_event.id,
        },
        headers=authorization_header(user),
    )

    assert event_response.status_code == 200

    event_data = event_response.json()

    assert len(event_data) == 1
    assert event_data[0]["id"] == low_alert.id


# ============================================================
# Alert lifecycle
# ============================================================


def test_update_alert_successfully(
    db_session: Session,
    security_event,
    detection_rule,
):
    user = create_test_user(
        db_session,
        username="alert-api-update-success",
        email="alert-api-update-success@example.com",
        permissions=["alerts.update"],
    )

    alert = create_alert_test_data(
        db_session,
        security_event,
        detection_rule,
        title="alert-api-update-success-alert",
    )

    response = client.patch(
        f"/api/v1/alerts/{alert.id}",
        json={
            "status": "ACKNOWLEDGED",
        },
        headers=authorization_header(user),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == alert.id
    assert data["status"] == "ACKNOWLEDGED"
    assert data["acknowledged_at"] is not None


def test_update_alert_rejects_invalid_transition(
    db_session: Session,
    security_event,
    detection_rule,
):
    user = create_test_user(
        db_session,
        username="alert-api-invalid-transition",
        email="alert-api-invalid-transition@example.com",
        permissions=["alerts.update"],
    )

    alert = create_alert_test_data(
        db_session,
        security_event,
        detection_rule,
        title="alert-api-invalid-transition-alert",
    )

    response = client.patch(
        f"/api/v1/alerts/{alert.id}",
        json={
            "status": "CLOSED",
        },
        headers=authorization_header(user),
    )

    assert response.status_code == 409
    assert (
        response.json()["detail"]
        == "Invalid alert status transition: OPEN -> CLOSED."
    )


def test_update_alert_returns_not_found(
    db_session: Session,
):
    user = create_test_user(
        db_session,
        username="alert-api-update-unknown",
        email="alert-api-update-unknown@example.com",
        permissions=["alerts.update"],
    )

    response = client.patch(
        "/api/v1/alerts/999999999",
        json={
            "status": "ACKNOWLEDGED",
        },
        headers=authorization_header(user),
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Alert not found."


# ============================================================
# Alert assignment
# ============================================================


def test_assign_alert_successfully(
    db_session: Session,
    security_event,
    detection_rule,
):
    user = create_test_user(
        db_session,
        username="alert-api-assign-success",
        email="alert-api-assign-success@example.com",
        permissions=["alerts.assign"],
    )

    alert = create_alert_test_data(
        db_session,
        security_event,
        detection_rule,
        title="alert-api-assign-success-alert",
    )

    response = client.patch(
        f"/api/v1/alerts/{alert.id}/assignment",
        json={
            "assigned_to_user_id": user.id,
        },
        headers=authorization_header(user),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == alert.id
    assert data["assigned_to_user_id"] == user.id


def test_assign_alert_requires_user_id(
    db_session: Session,
):
    user = create_test_user(
        db_session,
        username="alert-api-assign-missing",
        email="alert-api-assign-missing@example.com",
        permissions=["alerts.assign"],
    )

    response = client.patch(
        "/api/v1/alerts/999999999/assignment",
        json={},
        headers=authorization_header(user),
    )

    assert response.status_code == 422


def test_update_alert_rejects_assignment_without_assign_permission(
    db_session: Session,
):
    user = create_test_user(
        db_session,
        username="alert-api-assignment-forbidden",
        email="alert-api-assignment-forbidden@example.com",
        permissions=["alerts.update"],
    )

    response = client.patch(
        "/api/v1/alerts/999999999",
        json={
            "assigned_to_user_id": user.id,
        },
        headers=authorization_header(user),
    )

    assert response.status_code == 403
    assert (
        response.json()["detail"]
        == (
            "Alert assignment requires the "
            "alerts.assign permission."
        )
    )


# ============================================================
# Incident correlation
# ============================================================


def test_attach_alert_to_incident_successfully(
    db_session: Session,
    security_event,
    detection_rule,
):
    user = create_test_user(
        db_session,
        username="alert-api-attach-success",
        email="alert-api-attach-success@example.com",
        permissions=["alerts.update"],
    )

    alert = create_alert_test_data(
        db_session,
        security_event,
        detection_rule,
        title="alert-api-attach-success-alert",
    )

    incident = create_incident(
        db_session,
        created_by_user_id=user.id,
        title="alert-api-attach-success-incident",
    )

    response = client.post(
        f"/api/v1/alerts/{alert.id}/incident",
        json={
            "incident_id": incident.id,
        },
        headers=authorization_header(user),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == alert.id
    assert data["incident_id"] == incident.id


def test_attach_alert_to_nonexistent_incident_returns_not_found(
    db_session: Session,
    security_event,
    detection_rule,
):
    user = create_test_user(
        db_session,
        username="alert-api-attach-unknown-incident",
        email="alert-api-attach-unknown-incident@example.com",
        permissions=["alerts.update"],
    )

    alert = create_alert_test_data(
        db_session,
        security_event,
        detection_rule,
        title="alert-api-attach-unknown-incident-alert",
    )

    response = client.post(
        f"/api/v1/alerts/{alert.id}/incident",
        json={
            "incident_id": 999999999,
        },
        headers=authorization_header(user),
    )

    assert response.status_code == 404
    assert (
        response.json()["detail"]
        == "Incident not found: 999999999."
    )


def test_attach_nonexistent_alert_returns_not_found(
    db_session: Session,
):
    user = create_test_user(
        db_session,
        username="alert-api-attach-unknown-alert",
        email="alert-api-attach-unknown-alert@example.com",
        permissions=["alerts.update"],
    )

    incident = create_incident(
        db_session,
        created_by_user_id=user.id,
        title="alert-api-attach-unknown-alert-incident",
    )

    response = client.post(
        "/api/v1/alerts/999999999/incident",
        json={
            "incident_id": incident.id,
        },
        headers=authorization_header(user),
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Alert not found."


def test_attach_alert_rejects_invalid_incident_id(
    db_session: Session,
):
    user = create_test_user(
        db_session,
        username="alert-api-attach-invalid-id",
        email="alert-api-attach-invalid-id@example.com",
        permissions=["alerts.update"],
    )

    response = client.post(
        "/api/v1/alerts/999999999/incident",
        json={
            "incident_id": 0,
        },
        headers=authorization_header(user),
    )

    assert response.status_code == 422


def test_get_alert_incident_successfully(
    db_session: Session,
    security_event,
    detection_rule,
):
    user = create_test_user(
        db_session,
        username="alert-api-get-incident",
        email="alert-api-get-incident@example.com",
        permissions=["alerts.read"],
    )

    alert = create_alert_test_data(
        db_session,
        security_event,
        detection_rule,
        title="alert-api-get-incident-alert",
    )

    incident = create_incident(
        db_session,
        created_by_user_id=user.id,
        title="alert-api-get-incident-incident",
    )

    alert.incident_id = incident.id
    db_session.add(alert)
    db_session.commit()
    db_session.refresh(alert)

    response = client.get(
        f"/api/v1/alerts/{alert.id}/incident",
        headers=authorization_header(user),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == alert.id
    assert data["incident_id"] == incident.id


def test_get_alert_incident_returns_not_found_for_unknown_alert(
    db_session: Session,
):
    user = create_test_user(
        db_session,
        username="alert-api-get-incident-unknown",
        email="alert-api-get-incident-unknown@example.com",
        permissions=["alerts.read"],
    )

    response = client.get(
        "/api/v1/alerts/999999999/incident",
        headers=authorization_header(user),
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Alert not found."


def test_get_alerts_for_incident_successfully(
    db_session: Session,
    security_event,
    detection_rule,
    another_security_event,
    another_detection_rule,
):
    user = create_test_user(
        db_session,
        username="alert-api-by-incident",
        email="alert-api-by-incident@example.com",
        permissions=["alerts.read"],
    )

    incident = create_incident(
        db_session,
        created_by_user_id=user.id,
        title="alert-api-by-incident-incident",
    )

    first_alert = create_alert_test_data(
        db_session,
        security_event,
        detection_rule,
        title="alert-api-by-incident-first",
    )

    second_match = create_detection_match(
        db_session,
        security_event_id=another_security_event.id,
        detection_rule_id=another_detection_rule.id,
    )

    second_alert = create_alert(
        db_session,
        detection_match_id=second_match.id,
        security_event_id=another_security_event.id,
        detection_rule_id=another_detection_rule.id,
        severity="CRITICAL",
        title="alert-api-by-incident-second",
    )

    first_alert.incident_id = incident.id
    second_alert.incident_id = incident.id

    db_session.add(first_alert)
    db_session.add(second_alert)
    db_session.commit()

    response = client.get(
        f"/api/v1/alerts/by-incident/{incident.id}",
        headers=authorization_header(user),
    )

    assert response.status_code == 200

    data = response.json()

    returned_ids = {
        item["id"]
        for item in data
    }

    assert returned_ids == {
        first_alert.id,
        second_alert.id,
    }


def test_get_alerts_for_nonexistent_incident_returns_not_found(
    db_session: Session,
):
    user = create_test_user(
        db_session,
        username="alert-api-by-incident-unknown",
        email="alert-api-by-incident-unknown@example.com",
        permissions=["alerts.read"],
    )

    response = client.get(
        "/api/v1/alerts/by-incident/999999999",
        headers=authorization_header(user),
    )

    assert response.status_code == 404
    assert (
        response.json()["detail"]
        == "Incident not found: 999999999."
    )


def test_list_alerts_supports_incident_filter(
    db_session: Session,
    security_event,
    detection_rule,
    another_security_event,
    another_detection_rule,
):
    user = create_test_user(
        db_session,
        username="alert-api-incident-filter",
        email="alert-api-incident-filter@example.com",
        permissions=["alerts.read"],
    )

    incident = create_incident(
        db_session,
        created_by_user_id=user.id,
        title="alert-api-incident-filter-incident",
    )

    first_alert = create_alert_test_data(
        db_session,
        security_event,
        detection_rule,
        title="alert-api-incident-filter-first",
    )

    second_match = create_detection_match(
        db_session,
        security_event_id=another_security_event.id,
        detection_rule_id=another_detection_rule.id,
    )

    second_alert = create_alert(
        db_session,
        detection_match_id=second_match.id,
        security_event_id=another_security_event.id,
        detection_rule_id=another_detection_rule.id,
        severity="LOW",
        title="alert-api-incident-filter-second",
    )

    first_alert.incident_id = incident.id

    db_session.add(first_alert)
    db_session.add(second_alert)
    db_session.commit()

    response = client.get(
        "/api/v1/alerts",
        params={
            "incident_id": incident.id,
        },
        headers=authorization_header(user),
    )

    assert response.status_code == 200

    data = response.json()

    assert len(data) == 1
    assert data[0]["id"] == first_alert.id
    assert data[0]["incident_id"] == incident.id


def test_detach_alert_from_incident_successfully(
    db_session: Session,
    security_event,
    detection_rule,
):
    user = create_test_user(
        db_session,
        username="alert-api-detach-success",
        email="alert-api-detach-success@example.com",
        permissions=["alerts.update"],
    )

    incident = create_incident(
        db_session,
        created_by_user_id=user.id,
        title="alert-api-detach-success-incident",
    )

    alert = create_alert_test_data(
        db_session,
        security_event,
        detection_rule,
        title="alert-api-detach-success-alert",
    )

    alert.incident_id = incident.id

    db_session.add(alert)
    db_session.commit()
    db_session.refresh(alert)

    response = client.delete(
        f"/api/v1/alerts/{alert.id}/incident",
        headers=authorization_header(user),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == alert.id
    assert data["incident_id"] is None


def test_detach_nonexistent_alert_returns_not_found(
    db_session: Session,
):
    user = create_test_user(
        db_session,
        username="alert-api-detach-unknown",
        email="alert-api-detach-unknown@example.com",
        permissions=["alerts.update"],
    )

    response = client.delete(
        "/api/v1/alerts/999999999/incident",
        headers=authorization_header(user),
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Alert not found."


# ============================================================
# Superuser
# ============================================================


def test_superuser_can_access_alert_endpoints(
    db_session: Session,
    security_event,
    detection_rule,
):
    user = create_test_user(
        db_session,
        username="alert-api-superuser",
        email="alert-api-superuser@example.com",
        permissions=[],
        is_superuser=True,
    )

    alert = create_alert_test_data(
        db_session,
        security_event,
        detection_rule,
        title="alert-api-superuser-alert",
    )

    incident = create_incident(
        db_session,
        created_by_user_id=user.id,
        title="alert-api-superuser-incident",
    )

    get_response = client.get(
        f"/api/v1/alerts/{alert.id}",
        headers=authorization_header(user),
    )

    assert get_response.status_code == 200

    attach_response = client.post(
        f"/api/v1/alerts/{alert.id}/incident",
        json={
            "incident_id": incident.id,
        },
        headers=authorization_header(user),
    )

    assert attach_response.status_code == 200
    assert attach_response.json()["incident_id"] == incident.id

    incident_response = client.get(
        f"/api/v1/alerts/by-incident/{incident.id}",
        headers=authorization_header(user),
    )

    assert incident_response.status_code == 200

    assert any(
        item["id"] == alert.id
        for item in incident_response.json()
    )

    detach_response = client.delete(
        f"/api/v1/alerts/{alert.id}/incident",
        headers=authorization_header(user),
    )

    assert detach_response.status_code == 200
    assert detach_response.json()["incident_id"] is None
