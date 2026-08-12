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