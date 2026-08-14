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


class Alert(Base):
    """Actionable security alert generated from a detection match."""

    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )

    detection_match_id: Mapped[int] = mapped_column(
        ForeignKey(
            "detection_matches.id",
            ondelete="RESTRICT",
        ),
        nullable=False,
        unique=True,
        index=True,
    )

    security_event_id: Mapped[int] = mapped_column(
        ForeignKey(
            "security_events.id",
            ondelete="RESTRICT",
        ),
        nullable=False,
        index=True,
    )

    detection_rule_id: Mapped[int] = mapped_column(
        ForeignKey(
            "detection_rules.id",
            ondelete="RESTRICT",
        ),
        nullable=False,
        index=True,
    )

    severity: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        index=True,
    )

    status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="OPEN",
        server_default="OPEN",
        index=True,
    )

    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    assigned_to_user_id: Mapped[int | None] = mapped_column(
        ForeignKey(
            "users.id",
            ondelete="SET NULL",
        ),
        nullable=True,
        index=True,
    )

    opened_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        index=True,
    )

    acknowledged_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    resolved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    closed_at: Mapped[datetime | None] = mapped_column(
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

    detection_match = relationship(
        "DetectionMatch",
        foreign_keys=[detection_match_id],
    )

    security_event = relationship(
        "SecurityEvent",
        foreign_keys=[security_event_id],
    )

    detection_rule = relationship(
        "DetectionRule",
        foreign_keys=[detection_rule_id],
    )

    assigned_to = relationship(
        "User",
        foreign_keys=[assigned_to_user_id],
    )

    __table_args__ = (
        Index(
            "ix_alerts_status_opened_at",
            "status",
            "opened_at",
        ),
        Index(
            "ix_alerts_severity_opened_at",
            "severity",
            "opened_at",
        ),
        Index(
            "ix_alerts_assigned_status",
            "assigned_to_user_id",
            "status",
        ),
    )