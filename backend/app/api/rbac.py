from fastapi import APIRouter, Depends

from app.models.user import User
from app.security.authorization import require_permission


router = APIRouter(
    prefix="/api/v1/rbac",
    tags=["RBAC"],
)


@router.get("/test")
def rbac_test(
    current_user: User = Depends(
        require_permission("events.read")
    ),
) -> dict[str, str]:
    """
    Test endpoint protected by the events.read permission.
    """

    return {
        "status": "authorized",
        "username": current_user.username,
        "permission": "events.read",
    }