from pydantic import BaseModel, ConfigDict, EmailStr, Field


class UserRegisterRequest(BaseModel):
    """Request payload for user registration."""

    username: str = Field(
        min_length=3,
        max_length=50,
        pattern=r"^[a-zA-Z0-9_.-]+$",
    )

    email: EmailStr

    password: str = Field(
        min_length=12,
        max_length=128,
    )

    full_name: str | None = Field(
        default=None,
        max_length=255,
    )


class UserResponse(BaseModel):
    """Safe public representation of an application user."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    email: EmailStr
    full_name: str | None
    is_active: bool
    is_superuser: bool