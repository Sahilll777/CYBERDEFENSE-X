
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.user import User
from app.schemas.detection_match import (
    DetectionMatchResponse,
    DetectionMatchStatus,
    DetectionMatchStatusUpdate,
)
from app.security.authorization import require_permission
from app.services.detection_match.service import DetectionMatchService


router = APIRouter(
    prefix="/api/v1/detection-matches",
    tags=["Detection Matches"],
)


@router.get(
    "",
    response_model=list[DetectionMatchResponse],
)
def list_detection_matches(
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_permission("detection_matches.read")
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
    security_event_id: int | None = Query(
        default=None,
        ge=1,
    ),
    detection_rule_id: int | None = Query(
        default=None,
        ge=1,
    ),
    severity: str | None = Query(
        default=None,
        max_length=20,
    ),
    status: DetectionMatchStatus | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
) -> list[DetectionMatchResponse]:
    """Return detection matches with optional filters."""

    service = DetectionMatchService(db)

    return service.list_matches(
        limit=limit,
        offset=offset,
        security_event_id=security_event_id,
        detection_rule_id=detection_rule_id,
        severity=severity,
        status=status.value if status is not None else None,
        start_time=start_time,
        end_time=end_time,
    )


@router.get(
    "/{match_id}",
    response_model=DetectionMatchResponse,
)
def get_detection_match(
    match_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_permission("detection_matches.read")
    ),
) -> DetectionMatchResponse:
    """Return a detection match by ID."""

    service = DetectionMatchService(db)

    match = service.get_match(
        match_id=match_id,
    )

    if match is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Detection match not found.",
        )

    return match


@router.patch(
    "/{match_id}/status",
    response_model=DetectionMatchResponse,
)
def update_detection_match_status(
    match_id: int,
    payload: DetectionMatchStatusUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_permission("detection_matches.update")
    ),
) -> DetectionMatchResponse:
    """Update the lifecycle status of a detection match."""

    service = DetectionMatchService(db)

    updated_match = service.update_status(
        match_id=match_id,
        status=payload.status.value,
    )

    if updated_match is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Detection match not found.",
        )

    db.commit()
    db.refresh(updated_match)

    return updated_match
