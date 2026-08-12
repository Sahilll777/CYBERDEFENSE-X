from datetime import datetime, timedelta, timezone
from uuid import uuid4

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
    """
    Create a test user with the requested RBAC permissions.
    """

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
            description="Security Event API test role",
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
    """Create a Bearer authorization header for a test user."""

    token = create_access_token(str(user.id))

    return {
        "Authorization": f"Bearer {token}",
    }


def test_create_event_requires_authentication():
    response = client.post(
        "/api/v1/events",
        json={
            "event_type": "LOGIN_FAILED",
            "severity": "HIGH",
            "source": "security-event-api-test",
            "message": "Failed login attempt",
            "event_timestamp": "2026-08-12T10:30:00Z",
        },
    )

    assert response.status_code == 401


def test_create_event_rejects_invalid_token():
    response = client.post(
        "/api/v1/events",
        headers={
            "Authorization": "Bearer invalid-token",
        },
        json={
            "event_type": "LOGIN_FAILED",
            "severity": "HIGH",
            "source": "security-event-api-test",
            "message": "Failed login attempt",
            "event_timestamp": "2026-08-12T10:30:00Z",
        },
    )

    assert response.status_code == 401


def test_create_event_requires_events_create_permission(
    db_session: Session,
):
    unique_id = uuid4().hex[:8]

    user = create_test_user(
        db_session,
        username=f"event_api_reader_{unique_id}",
        email=f"event_api_reader_{unique_id}@example.com",
        permissions=["events.read"],
    )

    response = client.post(
        "/api/v1/events",
        headers=get_authorization_header(user),
        json={
            "event_type": "LOGIN_FAILED",
            "severity": "HIGH",
            "source": "security-event-api-test",
            "message": "Failed login attempt",
            "event_timestamp": "2026-08-12T10:30:00Z",
        },
    )

    assert response.status_code == 403

    data = response.json()

    assert data["detail"] == "Permission required: events.create"


def test_create_security_event_successfully(
    db_session: Session,
):
    unique_id = uuid4().hex[:8]

    user = create_test_user(
        db_session,
        username=f"event_api_creator_{unique_id}",
        email=f"event_api_creator_{unique_id}@example.com",
        permissions=["events.create"],
    )

    response = client.post(
        "/api/v1/events",
        headers=get_authorization_header(user),
        json={
            "event_type": "LOGIN_FAILED",
            "severity": "HIGH",
            "source": "security-event-api-test",
            "source_ip": "192.168.1.10",
            "destination_ip": "10.0.0.5",
            "username": "administrator",
            "hostname": "server-01",
            "message": "Failed login attempt detected.",
            "event_timestamp": "2026-08-12T10:30:00Z",
            "metadata": {
                "attempt_count": 5,
                "authentication_method": "password",
            },
        },
    )

    assert response.status_code == 201

    data = response.json()

    assert data["id"] > 0
    assert data["event_type"] == "LOGIN_FAILED"
    assert data["severity"] == "HIGH"
    assert data["source"] == "security-event-api-test"
    assert data["source_ip"] == "192.168.1.10"
    assert data["destination_ip"] == "10.0.0.5"
    assert data["username"] == "administrator"
    assert data["hostname"] == "server-01"
    assert data["message"] == "Failed login attempt detected."
    assert data["metadata"]["attempt_count"] == 5
    assert data["metadata"]["authentication_method"] == "password"
    assert "created_at" in data


def test_create_security_event_rejects_invalid_payload(
    db_session: Session,
):
    unique_id = uuid4().hex[:8]

    user = create_test_user(
        db_session,
        username=f"event_api_validator_{unique_id}",
        email=f"event_api_validator_{unique_id}@example.com",
        permissions=["events.create"],
    )

    response = client.post(
        "/api/v1/events",
        headers=get_authorization_header(user),
        json={
            "event_type": "",
            "severity": "INVALID",
            "source": "",
            "message": "",
            "event_timestamp": "not-a-timestamp",
        },
    )

    assert response.status_code == 422


def test_get_security_event_requires_authentication():
    response = client.get("/api/v1/events/1")

    assert response.status_code == 401


def test_get_security_event_requires_events_read_permission(
    db_session: Session,
):
    unique_id = uuid4().hex[:8]

    user = create_test_user(
        db_session,
        username=f"event_api_creator_only_{unique_id}",
        email=f"event_api_creator_only_{unique_id}@example.com",
        permissions=["events.create"],
    )

    response = client.get(
        "/api/v1/events/1",
        headers=get_authorization_header(user),
    )

    assert response.status_code == 403

    data = response.json()

    assert data["detail"] == "Permission required: events.read"


def test_get_security_event_returns_not_found_for_unknown_event(
    db_session: Session,
):
    unique_id = uuid4().hex[:8]

    user = create_test_user(
        db_session,
        username=f"event_api_reader_{unique_id}",
        email=f"event_api_reader_{unique_id}@example.com",
        permissions=["events.read"],
    )

    response = client.get(
        "/api/v1/events/999999999",
        headers=get_authorization_header(user),
    )

    assert response.status_code == 404

    data = response.json()

    assert data["detail"] == "Security event not found."


def test_get_security_event_successfully(
    db_session: Session,
):
    creator_id = uuid4().hex[:8]
    reader_id = uuid4().hex[:8]

    creator = create_test_user(
        db_session,
        username=f"event_api_creator_{creator_id}",
        email=f"event_api_creator_{creator_id}@example.com",
        permissions=["events.create"],
    )

    reader = create_test_user(
        db_session,
        username=f"event_api_reader_{reader_id}",
        email=f"event_api_reader_{reader_id}@example.com",
        permissions=["events.read"],
    )

    create_response = client.post(
        "/api/v1/events",
        headers=get_authorization_header(creator),
        json={
            "event_type": "MALWARE_DETECTED",
            "severity": "CRITICAL",
            "source": "security-event-api-test",
            "source_ip": "10.10.10.10",
            "hostname": "endpoint-01",
            "message": "Malware detected on endpoint.",
            "event_timestamp": "2026-08-12T11:00:00Z",
        },
    )

    assert create_response.status_code == 201

    event_id = create_response.json()["id"]

    response = client.get(
        f"/api/v1/events/{event_id}",
        headers=get_authorization_header(reader),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == event_id
    assert data["event_type"] == "MALWARE_DETECTED"
    assert data["severity"] == "CRITICAL"
    assert data["source"] == "security-event-api-test"
    assert data["message"] == "Malware detected on endpoint."


def test_list_security_events_requires_authentication():
    response = client.get("/api/v1/events")

    assert response.status_code == 401


def test_list_security_events_requires_events_read_permission(
    db_session: Session,
):
    unique_id = uuid4().hex[:8]

    user = create_test_user(
        db_session,
        username=f"event_api_creator_{unique_id}",
        email=f"event_api_creator_{unique_id}@example.com",
        permissions=["events.create"],
    )

    response = client.get(
        "/api/v1/events",
        headers=get_authorization_header(user),
    )

    assert response.status_code == 403

    data = response.json()

    assert data["detail"] == "Permission required: events.read"


def test_list_security_events_successfully(
    db_session: Session,
):
    unique_id = uuid4().hex[:8]

    user = create_test_user(
        db_session,
        username=f"event_api_reader_{unique_id}",
        email=f"event_api_reader_{unique_id}@example.com",
        permissions=["events.read"],
    )

    for index in range(3):
        response = client.post(
            "/api/v1/events",
            headers=get_authorization_header(
                create_test_user(
                    db_session,
                    username=f"event_api_creator_{unique_id}_{index}",
                    email=f"event_api_creator_{unique_id}_{index}@example.com",
                    permissions=["events.create"],
                )
            ),
            json={
                "event_type": f"TEST_EVENT_{index}",
                "severity": "HIGH",
                "source": "security-event-api-test",
                "message": f"Test security event {index}",
                "event_timestamp": (
                    f"2026-08-12T1{index}:00:00Z"
                ),
            },
        )

        assert response.status_code == 201

    response = client.get(
        "/api/v1/events",
        headers=get_authorization_header(user),
        params={
            "source": "security-event-api-test",
            "limit": 100,
            "offset": 0,
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert isinstance(data, list)
    assert len(data) >= 3

    event_types = {
        event["event_type"]
        for event in data
    }

    assert {
        "TEST_EVENT_0",
        "TEST_EVENT_1",
        "TEST_EVENT_2",
    }.issubset(event_types)


def test_list_security_events_supports_filters(
    db_session: Session,
):
    unique_id = uuid4().hex[:8]

    creator = create_test_user(
        db_session,
        username=f"event_api_creator_{unique_id}",
        email=f"event_api_creator_{unique_id}@example.com",
        permissions=["events.create"],
    )

    reader = create_test_user(
        db_session,
        username=f"event_api_reader_{unique_id}",
        email=f"event_api_reader_{unique_id}@example.com",
        permissions=["events.read"],
    )

    events = [
        {
            "event_type": "LOGIN_FAILED",
            "severity": "HIGH",
            "message": "Failed login attempt.",
            "event_timestamp": "2026-08-12T08:00:00Z",
        },
        {
            "event_type": "MALWARE_DETECTED",
            "severity": "CRITICAL",
            "message": "Malware detected.",
            "event_timestamp": "2026-08-12T09:00:00Z",
        },
        {
            "event_type": "LOGIN_SUCCESS",
            "severity": "LOW",
            "message": "Successful login.",
            "event_timestamp": "2026-08-12T10:00:00Z",
        },
    ]

    for event in events:
        response = client.post(
            "/api/v1/events",
            headers=get_authorization_header(creator),
            json={
                **event,
                "source": "security-event-api-test",
            },
        )

        assert response.status_code == 201

    severity_response = client.get(
        "/api/v1/events",
        headers=get_authorization_header(reader),
        params={
            "source": "security-event-api-test",
            "severity": "CRITICAL",
        },
    )

    assert severity_response.status_code == 200

    severity_data = severity_response.json()

    assert len(severity_data) >= 1
    assert all(
        event["severity"] == "CRITICAL"
        for event in severity_data
    )

    event_type_response = client.get(
        "/api/v1/events",
        headers=get_authorization_header(reader),
        params={
            "source": "security-event-api-test",
            "event_type": "LOGIN_FAILED",
        },
    )

    assert event_type_response.status_code == 200

    event_type_data = event_type_response.json()

    assert len(event_type_data) >= 1
    assert all(
        event["event_type"] == "LOGIN_FAILED"
        for event in event_type_data
    )


def test_list_security_events_supports_time_range(
    db_session: Session,
):
    unique_id = uuid4().hex[:8]

    creator = create_test_user(
        db_session,
        username=f"event_api_creator_{unique_id}",
        email=f"event_api_creator_{unique_id}@example.com",
        permissions=["events.create"],
    )

    reader = create_test_user(
        db_session,
        username=f"event_api_reader_{unique_id}",
        email=f"event_api_reader_{unique_id}@example.com",
        permissions=["events.read"],
    )

    response = client.post(
        "/api/v1/events",
        headers=get_authorization_header(creator),
        json={
            "event_type": "TIME_RANGE_TEST",
            "severity": "MEDIUM",
            "source": "security-event-api-test",
            "message": "Time range test event.",
            "event_timestamp": "2026-08-12T12:00:00Z",
        },
    )

    assert response.status_code == 201

    start_time = datetime(
        2026,
        8,
        12,
        11,
        59,
        tzinfo=timezone.utc,
    )

    end_time = datetime(
        2026,
        8,
        12,
        12,
        1,
        tzinfo=timezone.utc,
    )

    response = client.get(
        "/api/v1/events",
        headers=get_authorization_header(reader),
        params={
            "source": "security-event-api-test",
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert any(
        event["event_type"] == "TIME_RANGE_TEST"
        for event in data
    )


def test_list_security_events_supports_pagination(
    db_session: Session,
):
    unique_id = uuid4().hex[:8]

    creator = create_test_user(
        db_session,
        username=f"event_api_creator_{unique_id}",
        email=f"event_api_creator_{unique_id}@example.com",
        permissions=["events.create"],
    )

    reader = create_test_user(
        db_session,
        username=f"event_api_reader_{unique_id}",
        email=f"event_api_reader_{unique_id}@example.com",
        permissions=["events.read"],
    )

    for index in range(5):
        response = client.post(
            "/api/v1/events",
            headers=get_authorization_header(creator),
            json={
                "event_type": f"PAGINATION_TEST_{index}",
                "severity": "LOW",
                "source": "security-event-api-test",
                "message": f"Pagination event {index}.",
                "event_timestamp": (
                    f"2026-08-12T1{5 + index}:00:00Z"
                ),
            },
        )

        assert response.status_code == 201

    response = client.get(
        "/api/v1/events",
        headers=get_authorization_header(reader),
        params={
            "source": "security-event-api-test",
            "limit": 2,
            "offset": 0,
        },
    )

    assert response.status_code == 200

    first_page = response.json()

    assert len(first_page) == 2

    response = client.get(
        "/api/v1/events",
        headers=get_authorization_header(reader),
        params={
            "source": "security-event-api-test",
            "limit": 2,
            "offset": 2,
        },
    )

    assert response.status_code == 200

    second_page = response.json()

    assert len(second_page) == 2

    first_ids = {
        event["id"]
        for event in first_page
    }

    second_ids = {
        event["id"]
        for event in second_page
    }

    assert first_ids.isdisjoint(second_ids)