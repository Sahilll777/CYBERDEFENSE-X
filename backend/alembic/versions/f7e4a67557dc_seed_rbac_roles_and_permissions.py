"""seed RBAC roles and permissions

Revision ID: f7e4a67557dc
Revises: 6b1d44e38e04
Create Date: 2026-08-11
"""

from alembic import op
from sqlalchemy import text


revision = "f7e4a67557dc"
down_revision = "6b1d44e38e04"
branch_labels = None
depends_on = None


PERMISSIONS = [
    ("alerts.read", "Read security alerts"),
    ("alerts.update", "Update security alerts"),
    ("incidents.read", "Read security incidents"),
    ("incidents.create", "Create security incidents"),
    ("incidents.update", "Update security incidents"),
    ("incidents.assign", "Assign security incidents"),
    ("incidents.close", "Close security incidents"),
    ("events.read", "Read security events"),
    ("events.search", "Search security events"),
    ("rules.read", "Read detection rules"),
    ("rules.create", "Create detection rules"),
    ("rules.update", "Update detection rules"),
    ("rules.delete", "Delete detection rules"),
    ("playbooks.read", "Read response playbooks"),
    ("playbooks.execute", "Execute response playbooks"),
    ("users.read", "Read users"),
    ("users.manage", "Manage users"),
    ("system.admin", "Perform system administration"),
]


ROLES = [
    ("SOC_ANALYST", "Security Operations Center Analyst"),
    ("SOC_MANAGER", "Security Operations Center Manager"),
    ("SECURITY_ADMIN", "Security Administrator"),
]


ROLE_PERMISSIONS = {
    "SOC_ANALYST": [
        "alerts.read",
        "alerts.update",
        "incidents.read",
        "incidents.create",
        "incidents.update",
        "incidents.assign",
        "events.read",
        "events.search",
        "rules.read",
        "playbooks.read",
        "users.read",
    ],
    "SOC_MANAGER": [
        "alerts.read",
        "alerts.update",
        "incidents.read",
        "incidents.create",
        "incidents.update",
        "incidents.assign",
        "incidents.close",
        "events.read",
        "events.search",
        "rules.read",
        "rules.create",
        "rules.update",
        "playbooks.read",
        "playbooks.execute",
        "users.read",
    ],
    "SECURITY_ADMIN": [
        "alerts.read",
        "alerts.update",
        "incidents.read",
        "incidents.create",
        "incidents.update",
        "incidents.assign",
        "incidents.close",
        "events.read",
        "events.search",
        "rules.read",
        "rules.create",
        "rules.update",
        "rules.delete",
        "playbooks.read",
        "playbooks.execute",
        "users.read",
        "users.manage",
        "system.admin",
    ],
}


def upgrade() -> None:
    """Seed RBAC roles, permissions, and mappings."""

    connection = op.get_bind()

    # ---------------------------------------------------------
    # Permissions
    # ---------------------------------------------------------
    for name, description in PERMISSIONS:
        connection.execute(
            text(
                """
                INSERT INTO permissions (name, description)
                VALUES (:name, :description)
                ON CONFLICT (name) DO NOTHING
                """
            ),
            {
                "name": name,
                "description": description,
            },
        )

    # ---------------------------------------------------------
    # Roles
    # ---------------------------------------------------------
    for name, description in ROLES:
        connection.execute(
            text(
                """
                INSERT INTO roles (name, description)
                VALUES (:name, :description)
                ON CONFLICT (name) DO NOTHING
                """
            ),
            {
                "name": name,
                "description": description,
            },
        )

    # ---------------------------------------------------------
    # Role → Permission mappings
    # ---------------------------------------------------------
    for role_name, permission_names in ROLE_PERMISSIONS.items():
        for permission_name in permission_names:
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
                    "permission_name": permission_name,
                },
            )


def downgrade() -> None:
    """Remove seeded RBAC configuration."""

    connection = op.get_bind()

    for role_name, permission_names in ROLE_PERMISSIONS.items():
        for permission_name in permission_names:
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
                    "permission_name": permission_name,
                },
            )

    for role_name, _ in ROLES:
        connection.execute(
            text(
                """
                DELETE FROM roles
                WHERE name = :role_name
                """
            ),
            {
                "role_name": role_name,
            },
        )

    for permission_name, _ in PERMISSIONS:
        connection.execute(
            text(
                """
                DELETE FROM permissions
                WHERE name = :permission_name
                """
            ),
            {
                "permission_name": permission_name,
            },
        )