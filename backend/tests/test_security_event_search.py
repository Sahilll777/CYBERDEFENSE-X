from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from app.core.database import SessionLocal
from app.models.permission import Permission
from app.models.role import Role
from app.models.user import User
from app.security.jwt import create_access_token
from app.security.password import hash_password


client = TestClient(
    __import__("app.main", fromlist=["app"]).app
)


def create_search_test_user(
    *,
    username: str,
    email: str,
    permissions: list[str],
) -> User:
    """Create a user with the requested permissions for search API tests."""

    db = SessionLocal()

    try:
        user = User(
            username=username,
            email=email,
            password_hash=hash_password("StrongPassword123!"),
            is_active=True,
            is_superuser=False,
        )

        roles = []

        for index, permission_name in enumerate(permissions):
            permission = (
                db.query(Permission)
                .filter(
                    Permission.name == permission_name
                )
                .first()
            )

            if permission is None:
                permission = Permission(
                    name=permission_name,
                    description=(
                        "Search test permission: "
                        f"{permission_name}"
                    ),
                )

                db.add(permission)
                db.flush()

            role = Role(
                name=(
                    f"SEARCH_TEST_ROLE_"
                    f"{username}_"
                    f"{index}"
                ),
                description="Security event search test role",
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

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()


def cleanup_search_test_data() -> None:
    """
    Remove all records created by the security-event search tests.

    Search tests intentionally commit their transactions, so explicit
    cleanup is required for test isolation.
    """

    db = SessionLocal()

    try:
        # ---------------------------------------------------------
        # Remove search-test role/permission mappings.
        # ---------------------------------------------------------
        db.execute(
            __import__(
                "sqlalchemy",
                fromlist=["text"],
            ).text(
                """
                DELETE FROM role_permissions
                WHERE role_id IN (
                    SELECT id
                    FROM roles
                    WHERE name LIKE 'SEARCH_TEST_ROLE_%'
                )
                """
            )
        )

        # ---------------------------------------------------------
        # Remove search-test user/role mappings.
        # ---------------------------------------------------------
        db.execute(
            __import__(
                "sqlalchemy",
                fromlist=["text"],
            ).text(
                """
                DELETE FROM user_roles
                WHERE user_id IN (
                    SELECT id
                    FROM users
                    WHERE username LIKE 'search_%'
                )
                OR role_id IN (
                    SELECT id
                    FROM roles
                    WHERE name LIKE 'SEARCH_TEST_ROLE_%'
                )
                """
            )
        )

        # ---------------------------------------------------------
        # Remove search-test roles.
        # ---------------------------------------------------------
        db.execute(
            __import__(
                "sqlalchemy",
                fromlist=["text"],
            ).text(
                """
                DELETE FROM roles
                WHERE name LIKE 'SEARCH_TEST_ROLE_%'
                """
            )
        )

        # ---------------------------------------------------------
        # Remove search-test users.
        # ---------------------------------------------------------
        db.execute(
            __import__(
                "sqlalchemy",
                fromlist=["text"],
            ).text(
                """
                DELETE FROM users
                WHERE username LIKE 'search_%'
                """
            )
        )

        # ---------------------------------------------------------
        # Remove search-test security events.
        # ---------------------------------------------------------
        db.execute(
            __import__(
                "sqlalchemy",
                fromlist=["text"],
            ).text(
                """
                DELETE FROM security_events
                WHERE source = 'search-test'
                """
            )
        )

        db.commit()

    finally:
        db.close()


def authorization_header(
    user: User,
) -> dict[str, str]:
    """Create an Authorization header for a test user."""

    token = create_access_token(str(user.id))

    return {
        "Authorization": f"Bearer {token}",
    }


def create_search_test_events() -> None:
    """
    Create the controlled dataset used by search API tests.

    All records use source='search-test' so that tests remain isolated
    from unrelated security events already present in the database.
    """

    db = SessionLocal()

    now = datetime.now(timezone.utc)

    try:
        db.execute(
            __import__(
                "sqlalchemy",
                fromlist=["text"],
            ).text(
                """
                INSERT INTO security_events (
                    event_type,
                    severity,
                    source,
                    source_ip,
                    destination_ip,
                    username,
                    hostname,
                    message,
                    event_timestamp,
                    metadata
                )
                VALUES
                (
                    'LOGIN_FAILED',
                    'HIGH',
                    'search-test',
                    '10.10.10.10',
                    '10.10.10.20',
                    'alice',
                    'web-server-01',
                    'Failed login attempt for alice',
                    :timestamp_1,
                    '{"test": "search"}'
                ),
                (
                    'LOGIN_SUCCESS',
                    'LOW',
                    'search-test',
                    '10.10.10.11',
                    '10.10.10.21',
                    'bob',
                    'web-server-02',
                    'Successful login for bob',
                    :timestamp_2,
                    '{"test": "search"}'
                ),
                (
                    'MALWARE_DETECTED',
                    'CRITICAL',
                    'search-test',
                    '10.10.10.12',
                    '10.10.10.22',
                    'charlie',
                    'endpoint-01',
                    'Malware detected on endpoint',
                    :timestamp_3,
                    '{"test": "search"}'
                ),
                (
                    'LOGIN_FAILED',
                    'MEDIUM',
                    'search-test',
                    '10.10.10.13',
                    '10.10.10.23',
                    'alice',
                    'web-server-03',
                    'Another failed login attempt',
                    :timestamp_4,
                    '{"test": "search"}'
                )
                """
            ),
            {
                "timestamp_1": now - timedelta(minutes=10),
                "timestamp_2": now - timedelta(minutes=7),
                "timestamp_3": now - timedelta(minutes=4),
                "timestamp_4": now - timedelta(minutes=1),
            },
        )

        db.commit()

    finally:
        db.close()


def test_search_endpoint_requires_authentication():
    response = client.get(
        "/api/v1/events/search",
        params={"q": "login"},
    )

    assert response.status_code == 401


def test_search_endpoint_rejects_invalid_token():
    response = client.get(
        "/api/v1/events/search",
        params={"q": "login"},
        headers={
            "Authorization": "Bearer invalid-token",
        },
    )

    assert response.status_code == 401


def test_search_endpoint_requires_events_read_permission():
    cleanup_search_test_data()

    user = create_search_test_user(
        username="search_no_permission",
        email="search_no_permission@example.com",
        permissions=[],
    )

    try:
        response = client.get(
            "/api/v1/events/search",
            params={
                "q": "login",
            },
            headers=authorization_header(user),
        )

        assert response.status_code == 403
        assert (
            response.json()["detail"]
            == "Permission required: events.read"
        )

    finally:
        cleanup_search_test_data()


def test_search_security_events_by_message():
    cleanup_search_test_data()
    create_search_test_events()

    user = create_search_test_user(
        username="search_message",
        email="search_message@example.com",
        permissions=["events.read"],
    )

    try:
        response = client.get(
            "/api/v1/events/search",
            params={
                "q": "failed login",
                "source": "search-test",
            },
            headers=authorization_header(user),
        )

        assert response.status_code == 200

        data = response.json()

        assert data["total"] == 2
        assert len(data["items"]) == 2

        assert all(
            "failed login" in item["message"].lower()
            for item in data["items"]
        )

    finally:
        cleanup_search_test_data()


def test_search_security_events_is_case_insensitive():
    cleanup_search_test_data()
    create_search_test_events()

    user = create_search_test_user(
        username="search_case",
        email="search_case@example.com",
        permissions=["events.read"],
    )

    try:
        response = client.get(
            "/api/v1/events/search",
            params={
                "q": "MALWARE",
                "source": "search-test",
            },
            headers=authorization_header(user),
        )

        assert response.status_code == 200

        data = response.json()

        assert data["total"] == 1
        assert (
            data["items"][0]["event_type"]
            == "MALWARE_DETECTED"
        )

    finally:
        cleanup_search_test_data()


def test_search_security_events_across_multiple_fields():
    cleanup_search_test_data()
    create_search_test_events()

    user = create_search_test_user(
        username="search_fields",
        email="search_fields@example.com",
        permissions=["events.read"],
    )

    try:
        response = client.get(
            "/api/v1/events/search",
            params={
                "q": "web-server-01",
                "source": "search-test",
            },
            headers=authorization_header(user),
        )

        assert response.status_code == 200
        assert response.json()["total"] == 1

        response = client.get(
            "/api/v1/events/search",
            params={
                "q": "10.10.10.12",
                "source": "search-test",
            },
            headers=authorization_header(user),
        )

        assert response.status_code == 200
        assert response.json()["total"] == 1

        response = client.get(
            "/api/v1/events/search",
            params={
                "q": "alice",
                "source": "search-test",
            },
            headers=authorization_header(user),
        )

        assert response.status_code == 200
        assert response.json()["total"] == 2

    finally:
        cleanup_search_test_data()


def test_search_security_events_supports_severity_filter():
    cleanup_search_test_data()
    create_search_test_events()

    user = create_search_test_user(
        username="search_severity",
        email="search_severity@example.com",
        permissions=["events.read"],
    )

    try:
        response = client.get(
            "/api/v1/events/search",
            params={
                "q": "login",
                "severity": "HIGH",
                "source": "search-test",
            },
            headers=authorization_header(user),
        )

        assert response.status_code == 200

        data = response.json()

        assert data["total"] == 1
        assert len(data["items"]) == 1
        assert data["items"][0]["severity"] == "HIGH"

    finally:
        cleanup_search_test_data()


def test_search_security_events_supports_event_type_filter():
    cleanup_search_test_data()
    create_search_test_events()

    user = create_search_test_user(
        username="search_event_type",
        email="search_event_type@example.com",
        permissions=["events.read"],
    )

    try:
        response = client.get(
            "/api/v1/events/search",
            params={
                "q": "login",
                "event_type": "LOGIN_FAILED",
                "source": "search-test",
            },
            headers=authorization_header(user),
        )

        assert response.status_code == 200

        data = response.json()

        assert data["total"] == 2

        assert all(
            item["event_type"] == "LOGIN_FAILED"
            for item in data["items"]
        )

    finally:
        cleanup_search_test_data()


def test_search_security_events_supports_source_filter():
    cleanup_search_test_data()
    create_search_test_events()

    user = create_search_test_user(
        username="search_source",
        email="search_source@example.com",
        permissions=["events.read"],
    )

    try:
        response = client.get(
            "/api/v1/events/search",
            params={
                "q": "login",
                "source": "search-test",
            },
            headers=authorization_header(user),
        )

        assert response.status_code == 200
        assert response.json()["total"] == 3

    finally:
        cleanup_search_test_data()


def test_search_security_events_supports_time_range():
    cleanup_search_test_data()
    create_search_test_events()

    user = create_search_test_user(
        username="search_time",
        email="search_time@example.com",
        permissions=["events.read"],
    )

    now = datetime.now(timezone.utc)

    start_time = (
        now - timedelta(minutes=8)
    ).isoformat()

    end_time = (
        now - timedelta(minutes=6)
    ).isoformat()

    try:
        response = client.get(
            "/api/v1/events/search",
            params={
                "q": "login",
                "source": "search-test",
                "start_time": start_time,
                "end_time": end_time,
            },
            headers=authorization_header(user),
        )

        assert response.status_code == 200

        data = response.json()

        assert data["total"] == 1
        assert data["items"][0]["username"] == "bob"

    finally:
        cleanup_search_test_data()


def test_search_security_events_supports_pagination():
    cleanup_search_test_data()
    create_search_test_events()

    user = create_search_test_user(
        username="search_pagination",
        email="search_pagination@example.com",
        permissions=["events.read"],
    )

    try:
        response = client.get(
            "/api/v1/events/search",
            params={
                "q": "login",
                "source": "search-test",
                "limit": 1,
                "offset": 0,
            },
            headers=authorization_header(user),
        )

        assert response.status_code == 200

        first_page = response.json()

        assert first_page["total"] == 3
        assert len(first_page["items"]) == 1

        response = client.get(
            "/api/v1/events/search",
            params={
                "q": "login",
                "source": "search-test",
                "limit": 1,
                "offset": 1,
            },
            headers=authorization_header(user),
        )

        assert response.status_code == 200

        second_page = response.json()

        assert second_page["total"] == 3
        assert len(second_page["items"]) == 1

        assert (
            first_page["items"][0]["id"]
            != second_page["items"][0]["id"]
        )

    finally:
        cleanup_search_test_data()


def test_search_security_events_returns_newest_first():
    cleanup_search_test_data()
    create_search_test_events()

    user = create_search_test_user(
        username="search_order",
        email="search_order@example.com",
        permissions=["events.read"],
    )

    try:
        response = client.get(
            "/api/v1/events/search",
            params={
                "q": "login",
                "source": "search-test",
            },
            headers=authorization_header(user),
        )

        assert response.status_code == 200

        items = response.json()["items"]

        timestamps = [
            datetime.fromisoformat(
                item["event_timestamp"]
            )
            for item in items
        ]

        assert timestamps == sorted(
            timestamps,
            reverse=True,
        )

    finally:
        cleanup_search_test_data()


def test_search_security_events_returns_empty_result_when_nothing_matches():
    cleanup_search_test_data()
    create_search_test_events()

    user = create_search_test_user(
        username="search_empty",
        email="search_empty@example.com",
        permissions=["events.read"],
    )

    try:
        response = client.get(
            "/api/v1/events/search",
            params={
                "q": "this-does-not-exist",
                "source": "search-test",
            },
            headers=authorization_header(user),
        )

        assert response.status_code == 200

        data = response.json()

        assert data["total"] == 0
        assert data["items"] == []

    finally:
        cleanup_search_test_data()