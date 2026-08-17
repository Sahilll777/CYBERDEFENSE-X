from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.user import User
from app.schemas.playbook_execution import (
    PlaybookExecutionCreate,
    PlaybookExecutionFail,
    PlaybookExecutionResponse,
    PlaybookExecutionStatus,
)
from app.security.authorization import require_permission
from app.services.playbook_execution.service import (
    PlaybookExecutionService,
)


router = APIRouter(
    prefix="/api/v1/playbook-executions",
    tags=["Playbook Executions"],
)


@router.post(
    "",
    response_model=PlaybookExecutionResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_execution(
    payload: PlaybookExecutionCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_permission("playbooks.execute")
    ),
) -> PlaybookExecutionResponse:
    """Create a new playbook execution."""

    service = PlaybookExecutionService(db)

    try:
        execution = service.create_execution(
            playbook_id=payload.playbook_id,
            incident_id=payload.incident_id,
            alert_id=payload.alert_id,
            triggered_by_user_id=current_user.id,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc

    db.commit()
    db.refresh(execution)

    return execution


@router.get(
    "",
    response_model=list[PlaybookExecutionResponse],
)
def list_executions(
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_permission("playbooks.read")
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
    playbook_id: int | None = Query(
        default=None,
        ge=1,
    ),
    incident_id: int | None = Query(
        default=None,
        ge=1,
    ),
    alert_id: int | None = Query(
        default=None,
        ge=1,
    ),
    triggered_by_user_id: int | None = Query(
        default=None,
        ge=1,
    ),
    execution_status: PlaybookExecutionStatus | None = Query(
        default=None,
        alias="status",
    ),
) -> list[PlaybookExecutionResponse]:
    """Return playbook executions with optional filters."""

    service = PlaybookExecutionService(db)

    return service.list_executions(
        limit=limit,
        offset=offset,
        playbook_id=playbook_id,
        incident_id=incident_id,
        alert_id=alert_id,
        triggered_by_user_id=triggered_by_user_id,
        status=(
            execution_status.value
            if execution_status is not None
            else None
        ),
    )


@router.get(
    "/{execution_id}",
    response_model=PlaybookExecutionResponse,
)
def get_execution(
    execution_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_permission("playbooks.read")
    ),
) -> PlaybookExecutionResponse:
    """Return a playbook execution by ID."""

    service = PlaybookExecutionService(db)

    execution = service.get_execution(
        execution_id=execution_id,
    )

    if execution is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Playbook execution not found.",
        )

    return execution


@router.post(
    "/{execution_id}/start",
    response_model=PlaybookExecutionResponse,
)
def start_execution(
    execution_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_permission("playbooks.execute")
    ),
) -> PlaybookExecutionResponse:
    """Start a pending playbook execution."""

    service = PlaybookExecutionService(db)

    try:
        execution = service.start_execution(
            execution_id,
        )
    except ValueError as exc:
        message = str(exc)

        if "not found" in message.lower():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=message,
            ) from exc

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=message,
        ) from exc

    db.commit()
    db.refresh(execution)

    return execution


@router.post(
    "/{execution_id}/complete",
    response_model=PlaybookExecutionResponse,
)
def complete_execution(
    execution_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_permission("playbooks.execute")
    ),
) -> PlaybookExecutionResponse:
    """Complete a running playbook execution."""

    service = PlaybookExecutionService(db)

    try:
        execution = service.complete_execution(
            execution_id,
        )
    except ValueError as exc:
        message = str(exc)

        if "not found" in message.lower():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=message,
            ) from exc

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=message,
        ) from exc

    db.commit()
    db.refresh(execution)

    return execution


@router.post(
    "/{execution_id}/fail",
    response_model=PlaybookExecutionResponse,
)
def fail_execution(
    execution_id: int,
    payload: PlaybookExecutionFail,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_permission("playbooks.execute")
    ),
) -> PlaybookExecutionResponse:
    """Mark a running playbook execution as failed."""

    service = PlaybookExecutionService(db)

    try:
        execution = service.fail_execution(
            execution_id,
            error_message=payload.error_message,
        )
    except ValueError as exc:
        message = str(exc)

        if "not found" in message.lower():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=message,
            ) from exc

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=message,
        ) from exc

    db.commit()
    db.refresh(execution)

    return execution