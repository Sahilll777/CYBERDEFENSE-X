"""add alert incident correlation

Revision ID: f13a57a9629d
Revises: 2e36eeea73f3
Create Date: 2026-08-17
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# Revision identifiers, used by Alembic.
revision: str = "f13a57a9629d"
down_revision: Union[str, Sequence[str], None] = "2e36eeea73f3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add incident correlation to security alerts."""

    op.add_column(
        "alerts",
        sa.Column(
            "incident_id",
            sa.Integer(),
            nullable=True,
        ),
    )

    op.create_index(
        "ix_alerts_incident_id",
        "alerts",
        ["incident_id"],
        unique=False,
    )

    op.create_foreign_key(
        "alerts_incident_id_fkey",
        "alerts",
        "incidents",
        ["incident_id"],
        ["id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    """Remove incident correlation from security alerts."""

    op.drop_constraint(
        "alerts_incident_id_fkey",
        "alerts",
        type_="foreignkey",
    )

    op.drop_index(
        "ix_alerts_incident_id",
        table_name="alerts",
    )

    op.drop_column(
        "alerts",
        "incident_id",
    )