from datetime import datetime
from typing import Any

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class PlaybookExecutionAction(Base):
    """Persisted result of an individual playbook execution action."""

    __tablename__ = "playbook_execution_actions"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )

    execution_id: Mapped[int] = mapped_column(
        ForeignKey(
            "playbook_executions.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    action_index: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    action_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
    )

    status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        index=True,
    )

    parameters: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default="{}",
    )

    result: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB,
        nullable=True,
    )

    error_message: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        index=True,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    execution = relationship(
        "PlaybookExecution",
        foreign_keys=[execution_id],
        back_populates="actions",
    )

    __table_args__ = (
        Index(
            "ix_playbook_execution_actions_execution_index",
            "execution_id",
            "action_index",
            unique=True,
        ),
        Index(
            "ix_playbook_execution_actions_execution_status",
            "execution_id",
            "status",
        ),
    )
