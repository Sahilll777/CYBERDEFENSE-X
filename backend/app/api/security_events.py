from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.user import User
from app.schemas.security_event import (
    SecurityEventCreate,
    SecurityEventResponse,
    SecurityEventSearchResponse,
)
from app.security.authorization import require_permission
from app.services.security_event_service import SecurityEventService


router = APIRouter(
    prefix="/api/v1/events",
    tags=["Security Events"],
)


@router.post(
    "",
    response_model=SecurityEventResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_security_event(
    event: SecurityEventCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_permission("events.create")
    ),
) -> SecurityEventResponse:
    """Create and evaluate a new security event."""

    service = SecurityEventService(db)

    ingestion_result = service.create_event_with_detection(
        event=event,
    )

    created_event = ingestion_result.event

    db.commit()
    db.refresh(created_event)

    return created_event


@router.get(
    "",
    response_model=list[SecurityEventResponse],
)
def list_security_events(
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_permission("events.read")
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
    event_type: str | None = Query(
        default=None,
        max_length=100,
    ),
    source: str | None = Query(
        default=None,
        max_length=100,
    ),
    start_time: datetime | None = None,
    end_time: datetime | None = None,
) -> list[SecurityEventResponse]:
    """Return security events with optional filters."""

    service = SecurityEventService(db)

    return service.list_events(
        limit=limit,
        offset=offset,
        severity=severity,
        event_type=event_type,
        source=source,
        start_time=start_time,
        end_time=end_time,
    )


@router.get(
    "/search",
    response_model=SecurityEventSearchResponse,
)
def search_security_events(
    q: str = Query(
        min_length=1,
        max_length=500,
    ),
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_permission("events.read")
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
    event_type: str | None = Query(
        default=None,
        max_length=100,
    ),
    source: str | None = Query(
        default=None,
        max_length=100,
    ),
    start_time: datetime | None = None,
    end_time: datetime | None = None,
) -> SecurityEventSearchResponse:
    """Search security events using free-text and structured filters."""

    service = SecurityEventService(db)

    events, total = service.search_events(
        query=q,
        limit=limit,
        offset=offset,
        severity=severity,
        event_type=event_type,
        source=source,
        start_time=start_time,
        end_time=end_time,
    )

    return SecurityEventSearchResponse(
        items=events,
        total=total,
    )


@router.get(
    "/{event_id}",
    response_model=SecurityEventResponse,
)
def get_security_event(
    event_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_permission("events.read")
    ),
) -> SecurityEventResponse:
    """Return a security event by ID."""

    service = SecurityEventService(db)

    event = service.get_event(
        event_id=event_id,
    )

    if event is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Security event not found.",
        )

    return event