from datetime import datetime
from typing import Any

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class DetectionMatch(Base):
    """Detection generated when a security event matches a detection rule."""

    __tablename__ = "detection_matches"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
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
        default="NEW",
        server_default="NEW",
        index=True,
    )

    matched_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        index=True,
    )

    # SQLAlchemy reserves the Python attribute name "metadata".
    # Therefore the Python ORM attribute is match_metadata while
    # the actual PostgreSQL column remains named "metadata".
    match_metadata: Mapped[dict[str, Any]] = mapped_column(
        "metadata",
        JSONB,
        nullable=False,
        default=dict,
        server_default="{}",
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        index=True,
    )

    security_event = relationship(
        "SecurityEvent",
        foreign_keys=[security_event_id],
    )

    detection_rule = relationship(
        "DetectionRule",
        foreign_keys=[detection_rule_id],
    )

    __table_args__ = (
        UniqueConstraint(
            "security_event_id",
            "detection_rule_id",
            name="uq_detection_matches_event_rule",
        ),
        Index(
            "ix_detection_matches_status_matched_at",
            "status",
            "matched_at",
        ),
        Index(
            "ix_detection_matches_severity_matched_at",
            "severity",
            "matched_at",
        ),
    )


# -------------------------------------------------------------------------
# Compatibility alias
# -------------------------------------------------------------------------
#
# Database column:
#     metadata
#
# SQLAlchemy mapped attribute:
#     match_metadata
#
# Application-level attribute:
#     DetectionMatch.metadata
#
# This alias is defined AFTER the declarative class has been constructed
# so it does not interfere with SQLAlchemy's Declarative API.
#

DetectionMatch.metadata = property(
    lambda self: self.match_metadata,
    lambda self, value: setattr(self, "match_metadata", value),
)