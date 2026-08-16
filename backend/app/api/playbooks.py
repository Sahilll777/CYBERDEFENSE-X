from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.user import User
from app.schemas.playbook import (
    PlaybookCreate,
    PlaybookResponse,
    PlaybookType,
    PlaybookUpdate,
)
from app.security.authorization import require_permission
from app.services.playbook.service import PlaybookService


router = APIRouter(
    prefix="/api/v1/playbooks",
    tags=["Playbooks"],
)


@router.post(
    "",
    response_model=PlaybookResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_playbook(
    playbook: PlaybookCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_permission("playbooks.execute")
    ),
) -> PlaybookResponse:
    """Create a new security playbook."""

    service = PlaybookService(db)

    try:
        created_playbook = service.create_playbook(
            name=playbook.name,
            description=playbook.description,
            playbook_type=playbook.playbook_type.value,
            version=playbook.version,
            enabled=playbook.enabled,
            definition=playbook.definition,
            created_by_user_id=current_user.id,
        )

        db.commit()
        db.refresh(created_playbook)

        return created_playbook

    except ValueError as exc:
        db.rollback()

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc

    except IntegrityError as exc:
        db.rollback()

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Playbook name already exists.",
        ) from exc


@router.get(
    "",
    response_model=list[PlaybookResponse],
)
def list_playbooks(
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
    playbook_type: PlaybookType | None = Query(
        default=None,
    ),
    enabled: bool | None = Query(
        default=None,
    ),
    created_by_user_id: int | None = Query(
        default=None,
        ge=1,
    ),
) -> list[PlaybookResponse]:
    """Return security playbooks with optional filters."""

    service = PlaybookService(db)

    return service.list_playbooks(
        limit=limit,
        offset=offset,
        playbook_type=(
            playbook_type.value
            if playbook_type is not None
            else None
        ),
        enabled=enabled,
        created_by_user_id=created_by_user_id,
    )


@router.get(
    "/{playbook_id}",
    response_model=PlaybookResponse,
)
def get_playbook(
    playbook_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_permission("playbooks.read")
    ),
) -> PlaybookResponse:
    """Return a security playbook by ID."""

    service = PlaybookService(db)

    playbook = service.get_playbook(
        playbook_id=playbook_id,
    )

    if playbook is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Playbook not found.",
        )

    return playbook


@router.patch(
    "/{playbook_id}",
    response_model=PlaybookResponse,
)
def update_playbook(
    playbook_id: int,
    updates: PlaybookUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_permission("playbooks.execute")
    ),
) -> PlaybookResponse:
    """Update an existing security playbook."""

    service = PlaybookService(db)

    try:
        updated_playbook = service.update_playbook(
            playbook_id=playbook_id,
            name=updates.name,
            description=updates.description,
            playbook_type=(
                updates.playbook_type.value
                if updates.playbook_type is not None
                else None
            ),
            version=updates.version,
            enabled=updates.enabled,
            definition=updates.definition,
        )

        if updated_playbook is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Playbook not found.",
            )

        db.commit()
        db.refresh(updated_playbook)

        return updated_playbook

    except ValueError as exc:
        db.rollback()

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc

    except IntegrityError as exc:
        db.rollback()

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Playbook name already exists.",
        ) from exc


@router.patch(
    "/{playbook_id}/enable",
    response_model=PlaybookResponse,
)
def enable_playbook(
    playbook_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_permission("playbooks.execute")
    ),
) -> PlaybookResponse:
    """Enable a security playbook."""

    service = PlaybookService(db)

    updated_playbook = service.enable_playbook(
        playbook_id=playbook_id,
    )

    if updated_playbook is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Playbook not found.",
        )

    db.commit()
    db.refresh(updated_playbook)

    return updated_playbook


@router.patch(
    "/{playbook_id}/disable",
    response_model=PlaybookResponse,
)
def disable_playbook(
    playbook_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_permission("playbooks.execute")
    ),
) -> PlaybookResponse:
    """Disable a security playbook."""

    service = PlaybookService(db)

    updated_playbook = service.disable_playbook(
        playbook_id=playbook_id,
    )

    if updated_playbook is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Playbook not found.",
        )

    db.commit()
    db.refresh(updated_playbook)

    return updated_playbook