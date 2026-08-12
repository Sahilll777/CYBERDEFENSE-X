from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.security.authorization import require_permission


def create_user(
    *,
    permissions: list[str] | None = None,
    is_superuser: bool = False,
):
    permissions = permissions or []

    role = SimpleNamespace(
        permissions=[
            SimpleNamespace(name=permission)
            for permission in permissions
        ]
    )

    return SimpleNamespace(
        is_superuser=is_superuser,
        roles=[role],
    )


def test_user_with_required_permission_is_allowed():
    user = create_user(
        permissions=["incidents.read"],
    )

    dependency = require_permission("incidents.read")

    result = dependency(current_user=user)

    assert result is user


def test_user_without_required_permission_is_rejected():
    user = create_user(
        permissions=["events.read"],
    )

    dependency = require_permission("incidents.read")

    with pytest.raises(HTTPException) as exc_info:
        dependency(current_user=user)

    assert exc_info.value.status_code == 403
    assert exc_info.value.detail == "Permission required: incidents.read"


def test_user_with_multiple_roles_can_use_permission():
    role_one = SimpleNamespace(
        permissions=[
            SimpleNamespace(name="events.read"),
        ]
    )

    role_two = SimpleNamespace(
        permissions=[
            SimpleNamespace(name="incidents.read"),
        ]
    )

    user = SimpleNamespace(
        is_superuser=False,
        roles=[role_one, role_two],
    )

    dependency = require_permission("incidents.read")

    result = dependency(current_user=user)

    assert result is user


def test_superuser_bypasses_permission_check():
    user = create_user(
        permissions=[],
        is_superuser=True,
    )

    dependency = require_permission("system.admin")

    result = dependency(current_user=user)

    assert result is user