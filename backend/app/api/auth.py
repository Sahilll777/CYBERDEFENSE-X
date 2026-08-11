from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.schemas.auth import (
    TokenResponse,
    UserLoginRequest,
    UserRegisterRequest,
    UserResponse,
)
from app.security.dependencies import get_current_user
from app.services.auth_service import (
    AuthService,
    AuthenticationError,
    InactiveUserError,
)


router = APIRouter(
    prefix="/api/v1/auth",
    tags=["Authentication"],
)


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
def register(
    payload: UserRegisterRequest,
    db: Session = Depends(get_db),
) -> UserResponse:
    """Register a new CYBERDEFENSE-X user."""

    service = AuthService(db)

    try:
        user = service.register_user(
            username=payload.username,
            email=str(payload.email),
            password=payload.password,
            full_name=payload.full_name,
        )

        db.commit()
        db.refresh(user)

        return UserResponse.model_validate(user)

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
            detail="Username or email already exists.",
        ) from exc


@router.post(
    "/login",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
)
def login(
    payload: UserLoginRequest,
    db: Session = Depends(get_db),
) -> TokenResponse:
    """Authenticate a user and issue a JWT access token."""

    service = AuthService(db)

    try:
        access_token = service.login(
            username=payload.username,
            password=payload.password,
        )

        return TokenResponse(
            access_token=access_token,
            token_type="bearer",
        )

    except AuthenticationError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    except InactiveUserError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        ) from exc


@router.get(
    "/me",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
)
def get_me(
    current_user: Annotated[
        object,
        Depends(get_current_user),
    ],
) -> UserResponse:
    """Return the currently authenticated user."""

    return UserResponse.model_validate(current_user)