from sqlalchemy import String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class Role(Base):
    """Security role assigned to one or more users."""

    __tablename__ = "roles"

    id: Mapped[int] = mapped_column(
        primary_key=True,
        index=True,
    )

    name: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
        index=True,
    )

    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    users = relationship(
        "User",
        secondary="user_roles",
        back_populates="roles",
    )

    permissions = relationship(
        "Permission",
        secondary="role_permissions",
        back_populates="roles",
    )