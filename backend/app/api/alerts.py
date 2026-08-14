from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.user import User
from app.schemas.alert import (
    AlertResponse,
    AlertStatus,
    AlertUpdate,
)
from app.security.authorization import require_permission
from app.services.alert.service import AlertService


router = APIRouter(
    prefix="/api/v1/alerts",
    tags=["Alerts"],
)


@router.get(
    "",
    response_model=list[AlertResponse],
)
def list_alerts(
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_permission("alerts.read")
    ),
    limit: int = Query(
        default=100,
        ge=1,
        le=500,
    ),
    offset: int = Query(
        default=0,
        ge=0,
    ),
    severity: str | None = Query(
        default=None,
        max_length=20,
    ),
    status_filter: AlertStatus | None = Query(
        default=None,
        alias="status",
    ),
    assigned_to_user_id: int | None = Query(
        default=None,
        ge=1,
    ),
    security_event_id: int | None = Query(
        default=None,
        ge=1,
    ),
    detection_rule_id: int | None = Query(
        default=None,
        ge=1,
    ),
    start_time: datetime | None = None,
    end_time: datetime | None = None,
) -> list[AlertResponse]:
    """Return security alerts with optional filters."""

    service = AlertService(db)

    return service.list_alerts(
        limit=limit,
        offset=offset,
        severity=severity,
        status=(
            status_filter.value
            if status_filter is not None
            else None
        ),
        assigned_to_user_id=assigned_to_user_id,
        security_event_id=security_event_id,
        detection_rule_id=detection_rule_id,
        start_time=start_time,
        end_time=end_time,
    )


@router.get(
    "/{alert_id}",
    response_model=AlertResponse,
)
def get_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_permission("alerts.read")
    ),
) -> AlertResponse:
    """Return a security alert by ID."""

    service = AlertService(db)

    alert = service.get_alert(
        alert_id=alert_id,
    )

    if alert is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found.",
        )

    return alert


@router.patch(
    "/{alert_id}",
    response_model=AlertResponse,
)
def update_alert(
    alert_id: int,
    updates: AlertUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_permission("alerts.update")
    ),
) -> AlertResponse:
    """Update the lifecycle status of a security alert."""

    if updates.assigned_to_user_id is not None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Alert assignment requires the "
                "alerts.assign permission."
            ),
        )

    service = AlertService(db)

    try:
        updated_alert = service.update_alert(
            alert_id=alert_id,
            status=(
                updates.status.value
                if updates.status is not None
                else None
            ),
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc

    if updated_alert is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found.",
        )

    db.commit()
    db.refresh(updated_alert)

    return updated_alert


@router.patch(
    "/{alert_id}/assignment",
    response_model=AlertResponse,
)
def assign_alert(
    alert_id: int,
    updates: AlertUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_permission("alerts.assign")
    ),
) -> AlertResponse:
    """Assign a security alert to a user."""

    if updates.assigned_to_user_id is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="assigned_to_user_id is required.",
        )

    service = AlertService(db)

    updated_alert = service.update_alert(
        alert_id=alert_id,
        assigned_to_user_id=updates.assigned_to_user_id,
    )

    if updated_alert is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found.",
        )

    db.commit()
    db.refresh(updated_alert)

    return updated_alert