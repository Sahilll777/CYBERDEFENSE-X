from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, Index, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class SecurityEvent(Base):
    """Security event ingested into the CYBERDEFENSE-X platform."""

    __tablename__ = "security_events"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )

    event_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
    )

    severity: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        index=True,
    )

    source: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
    )

    source_ip: Mapped[str | None] = mapped_column(
        String(45),
        nullable=True,
        index=True,
    )

    destination_ip: Mapped[str | None] = mapped_column(
        String(45),
        nullable=True,
        index=True,
    )

    username: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        index=True,
    )

    hostname: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        index=True,
    )

    message: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    event_timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )

    # SQLAlchemy reserves the Python attribute name "metadata".
    # Therefore the Python ORM attribute is event_metadata while
    # the actual PostgreSQL column remains named "metadata".
    event_metadata: Mapped[dict[str, Any]] = mapped_column(
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

    __table_args__ = (
        Index(
            "ix_security_events_type_timestamp",
            "event_type",
            "event_timestamp",
        ),
        Index(
            "ix_security_events_severity_timestamp",
            "severity",
            "event_timestamp",
        ),
        Index(
            "ix_security_events_source_timestamp",
            "source",
            "event_timestamp",
        ),
    )


# -------------------------------------------------------------------------
# Compatibility alias
# -------------------------------------------------------------------------
#
# IMPORTANT:
# This must be defined AFTER the SQLAlchemy declarative class has been
# constructed. Defining it inside SecurityEvent would overwrite the
# inherited SQLAlchemy "metadata" attribute and break table construction.
#
# Database column:
#     metadata
#
# SQLAlchemy mapped attribute:
#     event_metadata
#
# Application-level attribute:
#     event.metadata
#
SecurityEvent.metadata = property(
    lambda self: self.event_metadata,
    lambda self, value: setattr(self, "event_metadata", value),
)