from collections.abc import Callable
from typing import Any

from fastapi import Depends, HTTPException, status

from app.models.user import User
from app.security.dependencies import get_current_user


def require_permission(permission_name: str) -> Callable[..., Any]:
    """
    Create a FastAPI dependency that requires the authenticated user
    to have the specified permission.
    """

    def permission_dependency(
        current_user: User = Depends(get_current_user),
    ) -> User:
        """
        Verify that the authenticated user has the required permission.
        """

        if current_user.is_superuser:
            return current_user

        user_permissions = {
            permission.name
            for role in current_user.roles
            for permission in role.permissions
        }

        if permission_name not in user_permissions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission required: {permission_name}",
            )

        return current_user

    return permission_dependency


def require_any_permission(
    *permission_names: str,
) -> Callable[..., Any]:
    """
    Create a FastAPI dependency that requires the authenticated user
    to have at least one of the specified permissions.
    """

    def permission_dependency(
        current_user: User = Depends(get_current_user),
    ) -> User:
        """
        Verify that the authenticated user has at least one required
        permission.
        """

        if current_user.is_superuser:
            return current_user

        user_permissions = {
            permission.name
            for role in current_user.roles
            for permission in role.permissions
        }

        if not user_permissions.intersection(permission_names):
            required_permissions = ", ".join(permission_names)

            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission required: {required_permissions}",
            )

        return current_user

    return permission_dependency
