from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.user import User
from app.schemas.incident import (
    IncidentCreate,
    IncidentPriority,
    IncidentResponse,
    IncidentStatus,
    IncidentUpdate,
)
from app.security.authorization import require_permission
from app.services.incident.service import IncidentService


router = APIRouter(
    prefix="/api/v1/incidents",
    tags=["Incidents"],
)


@router.post(
    "",
    response_model=IncidentResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_incident(
    incident: IncidentCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_permission("incidents.create")
    ),
) -> IncidentResponse:
    """Create a new security incident."""

    service = IncidentService(db)

    created_incident = service.create_incident(
        title=incident.title,
        description=incident.description,
        severity=incident.severity,
        priority=incident.priority.value,
        assigned_to_user_id=incident.assigned_to_user_id,
        created_by_user_id=current_user.id,
    )

    db.commit()
    db.refresh(created_incident)

    return created_incident


@router.get(
    "",
    response_model=list[IncidentResponse],
)
def list_incidents(
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_permission("incidents.read")
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
    priority: IncidentPriority | None = Query(
        default=None,
    ),
    status_filter: IncidentStatus | None = Query(
        default=None,
        alias="status",
    ),
    assigned_to_user_id: int | None = Query(
        default=None,
        ge=1,
    ),
    created_by_user_id: int | None = Query(
        default=None,
        ge=1,
    ),
) -> list[IncidentResponse]:
    """Return security incidents with optional filters."""

    service = IncidentService(db)

    return service.list_incidents(
        limit=limit,
        offset=offset,
        severity=severity,
        priority=(
            priority.value
            if priority is not None
            else None
        ),
        status=(
            status_filter.value
            if status_filter is not None
            else None
        ),
        assigned_to_user_id=assigned_to_user_id,
        created_by_user_id=created_by_user_id,
    )


@router.get(
    "/{incident_id}",
    response_model=IncidentResponse,
)
def get_incident(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_permission("incidents.read")
    ),
) -> IncidentResponse:
    """Return a security incident by ID."""

    service = IncidentService(db)

    incident = service.get_incident(
        incident_id=incident_id,
    )

    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found.",
        )

    return incident


@router.patch(
    "/{incident_id}",
    response_model=IncidentResponse,
)
def update_incident(
    incident_id: int,
    updates: IncidentUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_permission("incidents.update")
    ),
) -> IncidentResponse:
    """Update a security incident."""

    if updates.assigned_to_user_id is not None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Incident assignment requires the "
                "incidents.assign permission."
            ),
        )

    if updates.status == IncidentStatus.CLOSED:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Incident closure requires the "
                "incidents.close permission."
            ),
        )

    service = IncidentService(db)

    try:
        updated_incident = service.update_incident(
            incident_id=incident_id,
            title=updates.title,
            description=updates.description,
            severity=updates.severity,
            priority=(
                updates.priority.value
                if updates.priority is not None
                else None
            ),
            status=(
                updates.status.value
                if updates.status is not None
                else None
            ),
            resolution_summary=updates.resolution_summary,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc

    if updated_incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found.",
        )

    db.commit()
    db.refresh(updated_incident)

    return updated_incident


@router.patch(
    "/{incident_id}/assignment",
    response_model=IncidentResponse,
)
def assign_incident(
    incident_id: int,
    updates: IncidentUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_permission("incidents.assign")
    ),
) -> IncidentResponse:
    """Assign a security incident to a user."""

    if updates.assigned_to_user_id is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="assigned_to_user_id is required.",
        )

    service = IncidentService(db)

    updated_incident = service.update_incident(
        incident_id=incident_id,
        assigned_to_user_id=updates.assigned_to_user_id,
    )

    if updated_incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found.",
        )

    db.commit()
    db.refresh(updated_incident)

    return updated_incident


@router.patch(
    "/{incident_id}/close",
    response_model=IncidentResponse,
)
def close_incident(
    incident_id: int,
    updates: IncidentUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_permission("incidents.close")
    ),
) -> IncidentResponse:
    """Close a resolved security incident."""

    if updates.status != IncidentStatus.CLOSED:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="status must be CLOSED.",
        )

    service = IncidentService(db)

    try:
        updated_incident = service.update_incident(
            incident_id=incident_id,
            status=IncidentStatus.CLOSED.value,
            resolution_summary=updates.resolution_summary,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc

    if updated_incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found.",
        )

    db.commit()
    db.refresh(updated_incident)

    return updated_incident
