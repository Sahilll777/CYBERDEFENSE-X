from datetime import datetime

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class PlaybookExecution(Base):
    """Execution record for a security response playbook."""

    __tablename__ = "playbook_executions"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )

    playbook_id: Mapped[int] = mapped_column(
        ForeignKey(
            "playbooks.id",
            ondelete="RESTRICT",
        ),
        nullable=False,
        index=True,
    )

    incident_id: Mapped[int | None] = mapped_column(
        ForeignKey(
            "incidents.id",
            ondelete="SET NULL",
        ),
        nullable=True,
        index=True,
    )

    alert_id: Mapped[int | None] = mapped_column(
        ForeignKey(
            "alerts.id",
            ondelete="SET NULL",
        ),
        nullable=True,
        index=True,
    )

    triggered_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey(
            "users.id",
            ondelete="SET NULL",
        ),
        nullable=True,
        index=True,
    )

    status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="PENDING",
        server_default="PENDING",
        index=True,
    )

    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    error_message: Mapped[str | None] = mapped_column(
        Text,
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

    playbook = relationship(
        "Playbook",
        foreign_keys=[playbook_id],
    )

    incident = relationship(
        "Incident",
        foreign_keys=[incident_id],
    )

    alert = relationship(
        "Alert",
        foreign_keys=[alert_id],
    )

    triggered_by = relationship(
        "User",
        foreign_keys=[triggered_by_user_id],
    )

    actions = relationship(
        "PlaybookExecutionAction",
        foreign_keys="PlaybookExecutionAction.execution_id",
        back_populates="execution",
        cascade="all, delete-orphan",
        order_by="PlaybookExecutionAction.action_index",
    )

    __table_args__ = (
        Index(
            "ix_playbook_executions_status_created_at",
            "status",
            "created_at",
        ),
        Index(
            "ix_playbook_executions_playbook_status",
            "playbook_id",
            "status",
        ),
        Index(
            "ix_playbook_executions_incident_status",
            "incident_id",
            "status",
        ),
    )