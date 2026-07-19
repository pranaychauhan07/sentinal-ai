"""extend case status and add case management columns

Revision ID: 031e35cdb9e7
Revises: 7ae8f470d5e7
Create Date: 2026-07-20 02:00:00.000000

"""
from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '031e35cdb9e7'
down_revision: str | None = '7ae8f470d5e7'
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None

_ORIGINAL_STATUS_VALUES = ('open', 'investigating', 'closed')
_NEW_STATUS_VALUES = ('escalated', 'on_hold', 'contained', 'resolved', 'archived')
_ALL_STATUS_VALUES = _ORIGINAL_STATUS_VALUES + _NEW_STATUS_VALUES


def upgrade() -> None:
    """ADR-0015 point 1: extend `case_status_enum` additively (the original
    three values are never renamed/removed) and add the new ownership/
    priority/risk/label columns to `cases`.

    Dialect branching here is a deliberate, narrow exception to
    `core/db/session.py`'s "callers never branch on dialect" rule for the
    *application engine* layer — PostgreSQL's native enum type requires
    `ALTER TYPE ... ADD VALUE`; SQLite has no native enum (this project's
    `sa.Enum` compiles to a `VARCHAR` + `CHECK` constraint there), so the
    column must be rebuilt via `batch_alter_table`, mirroring
    `7ae8f470d5e7`'s identical dual-dialect handling for the FK-tightening
    migration.
    """
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        for value in _NEW_STATUS_VALUES:
            op.execute(f"ALTER TYPE case_status_enum ADD VALUE IF NOT EXISTS '{value}'")
    else:
        with op.batch_alter_table("cases", schema=None) as batch_op:
            batch_op.alter_column(
                "status",
                existing_type=sa.Enum(*_ORIGINAL_STATUS_VALUES, name="case_status_enum"),
                type_=sa.Enum(*_ALL_STATUS_VALUES, name="case_status_enum"),
                existing_nullable=False,
            )

    with op.batch_alter_table("cases", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column(
                "priority",
                sa.Enum("low", "medium", "high", "critical", name="case_priority_enum"),
                nullable=False,
                server_default="medium",
            )
        )
        batch_op.add_column(sa.Column("risk_score", sa.Float(), nullable=True))
        batch_op.add_column(sa.Column("owner_id", sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column("assignee_id", sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column("labels", sa.Text(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("cases", schema=None) as batch_op:
        batch_op.drop_column("labels")
        batch_op.drop_column("assignee_id")
        batch_op.drop_column("owner_id")
        batch_op.drop_column("risk_score")
        batch_op.drop_column("priority")

    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        # PostgreSQL does not support removing values from an existing enum
        # type via `ALTER TYPE ... DROP VALUE` — reverting this migration on
        # Postgres requires recreating the type from scratch and is
        # intentionally not attempted here. This mirrors the widely-accepted
        # treatment of additive enum values as effectively irreversible;
        # `case_status_enum`'s five new values remain defined (unused) after
        # a downgrade on this dialect.
        pass
    else:
        with op.batch_alter_table("cases", schema=None) as batch_op:
            batch_op.alter_column(
                "status",
                existing_type=sa.Enum(*_ALL_STATUS_VALUES, name="case_status_enum"),
                type_=sa.Enum(*_ORIGINAL_STATUS_VALUES, name="case_status_enum"),
                existing_nullable=False,
            )
