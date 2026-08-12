from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.user import User
from app.schemas.detection_rule import (
    DetectionRuleCreate,
    DetectionRuleResponse,
    DetectionRuleUpdate,
)
from app.security.authorization import require_permission
from app.services.detection_rule_service import DetectionRuleService


router = APIRouter(
    prefix="/api/v1/detection-rules",
    tags=["Detection Rules"],
)


@router.post(
    "",
    response_model=DetectionRuleResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_detection_rule(
    rule: DetectionRuleCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_permission("detection_rules.create")
    ),
) -> DetectionRuleResponse:
    """Create a new detection rule."""

    service = DetectionRuleService(db)

    try:
        created_rule = service.create_rule(
            rule=rule,
            created_by_user_id=current_user.id,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc

    db.commit()
    db.refresh(created_rule)

    return created_rule


@router.get(
    "",
    response_model=list[DetectionRuleResponse],
)
def list_detection_rules(
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_permission("detection_rules.read")
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
    rule_type: str | None = Query(
        default=None,
        max_length=100,
    ),
    severity: str | None = Query(
        default=None,
        max_length=20,
    ),
    enabled: bool | None = None,
    created_by_user_id: int | None = Query(
        default=None,
        ge=1,
    ),
) -> list[DetectionRuleResponse]:
    """Return detection rules with optional filters."""

    service = DetectionRuleService(db)

    return service.list_rules(
        limit=limit,
        offset=offset,
        rule_type=rule_type,
        severity=severity,
        enabled=enabled,
        created_by_user_id=created_by_user_id,
    )


@router.get(
    "/{rule_id}",
    response_model=DetectionRuleResponse,
)
def get_detection_rule(
    rule_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_permission("detection_rules.read")
    ),
) -> DetectionRuleResponse:
    """Return a detection rule by ID."""

    service = DetectionRuleService(db)

    rule = service.get_rule(
        rule_id=rule_id,
    )

    if rule is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Detection rule not found.",
        )

    return rule


@router.patch(
    "/{rule_id}",
    response_model=DetectionRuleResponse,
)
def update_detection_rule(
    rule_id: int,
    updates: DetectionRuleUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_permission("detection_rules.update")
    ),
) -> DetectionRuleResponse:
    """Partially update a detection rule."""

    service = DetectionRuleService(db)

    try:
        updated_rule = service.update_rule(
            rule_id=rule_id,
            updates=updates,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc

    if updated_rule is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Detection rule not found.",
        )

    db.commit()
    db.refresh(updated_rule)

    return updated_rule


@router.delete(
    "/{rule_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_detection_rule(
    rule_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_permission("detection_rules.delete")
    ),
) -> None:
    """Delete a detection rule."""

    service = DetectionRuleService(db)

    deleted = service.delete_rule(
        rule_id=rule_id,
    )

    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Detection rule not found.",
        )

    db.commit()