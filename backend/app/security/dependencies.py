from typing import Annotated, Callable

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.user import User
from app.repositories.user_repository import UserRepository
from app.security.jwt import decode_access_token


bearer_scheme = HTTPBearer(
    auto_error=False,
)


def get_current_user(
    credentials: Annotated[
        HTTPAuthorizationCredentials | None,
        Depends(bearer_scheme),
    ],
    db: Annotated[Session, Depends(get_db)],
) -> User:
    """Resolve the authenticated user from a JWT access token."""

    unauthorized_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate authentication credentials.",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if credentials is None:
        raise unauthorized_exception

    try:
        payload = decode_access_token(credentials.credentials)

    except Exception as exc:
        raise unauthorized_exception from exc

    user_id = payload.get("sub")

    if user_id is None:
        raise unauthorized_exception

    try:
        user_id = int(user_id)

    except (TypeError, ValueError) as exc:
        raise unauthorized_exception from exc

    repository = UserRepository(db)

    user = repository.get_by_id(user_id)

    if user is None:
        raise unauthorized_exception

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive.",
        )

    return user


def require_permission(permission_name: str) -> Callable:
    """
    Create a FastAPI dependency that requires a specific permission.

    Example:

        Depends(require_permission("alerts.read"))
    """

    def permission_dependency(
        current_user: Annotated[
            User,
            Depends(get_current_user),
        ],
    ) -> User:
        """Verify that the authenticated user has the required permission."""

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