"""add events create permission

Revision ID: ae303eb2e01e
Revises: 11263ab84241
Create Date: 2026-08-12
"""

from alembic import op
from sqlalchemy import text


revision = "ae303eb2e01e"
down_revision = "11263ab84241"
branch_labels = None
depends_on = None


PERMISSION_NAME = "events.create"
PERMISSION_DESCRIPTION = "Create security events"


ROLE_NAMES = (
    "SOC_ANALYST",
    "SOC_MANAGER",
    "SECURITY_ADMIN",
)


def upgrade() -> None:
    """Add the events.create permission and assign it to event-ingestion roles."""

    connection = op.get_bind()

    # ---------------------------------------------------------
    # Create permission
    # ---------------------------------------------------------
    connection.execute(
        text(
            """
            INSERT INTO permissions (name, description)
            VALUES (:name, :description)
            ON CONFLICT (name) DO NOTHING
            """
        ),
        {
            "name": PERMISSION_NAME,
            "description": PERMISSION_DESCRIPTION,
        },
    )

    # ---------------------------------------------------------
    # Assign permission to roles
    # ---------------------------------------------------------
    for role_name in ROLE_NAMES:
        connection.execute(
            text(
                """
                INSERT INTO role_permissions (role_id, permission_id)
                SELECT
                    r.id,
                    p.id
                FROM roles r
                CROSS JOIN permissions p
                WHERE r.name = :role_name
                  AND p.name = :permission_name
                ON CONFLICT DO NOTHING
                """
            ),
            {
                "role_name": role_name,
                "permission_name": PERMISSION_NAME,
            },
        )


def downgrade() -> None:
    """Remove the events.create permission and its role mappings."""

    connection = op.get_bind()

    # ---------------------------------------------------------
    # Remove role → permission mappings
    # ---------------------------------------------------------
    for role_name in ROLE_NAMES:
        connection.execute(
            text(
                """
                DELETE FROM role_permissions
                WHERE role_id = (
                    SELECT id
                    FROM roles
                    WHERE name = :role_name
                )
                AND permission_id = (
                    SELECT id
                    FROM permissions
                    WHERE name = :permission_name
                )
                """
            ),
            {
                "role_name": role_name,
                "permission_name": PERMISSION_NAME,
            },
        )

    # ---------------------------------------------------------
    # Remove permission
    # ---------------------------------------------------------
    connection.execute(
        text(
            """
            DELETE FROM permissions
            WHERE name = :permission_name
            """
        ),
        {
            "permission_name": PERMISSION_NAME,
        },
    )