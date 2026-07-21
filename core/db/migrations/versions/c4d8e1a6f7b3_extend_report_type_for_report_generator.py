"""extend report_type_enum for report generator agent

Revision ID: c4d8e1a6f7b3
Revises: b7e4d2f8a1c9
Create Date: 2026-07-21 09:00:00.000000

"""
from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c4d8e1a6f7b3'
down_revision: str | None = 'b7e4d2f8a1c9'
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None

_ORIGINAL_REPORT_TYPE_VALUES = ('module', 'executive')
_NEW_REPORT_TYPE_VALUES = (
    'technical_investigation',
    'incident_response',
    'ioc_summary',
    'mitre_attack',
    'timeline',
    'threat_intelligence',
    'evidence',
)
_ALL_REPORT_TYPE_VALUES = _ORIGINAL_REPORT_TYPE_VALUES + _NEW_REPORT_TYPE_VALUES


def upgrade() -> None:
    """docs/adr/0024 (Report Generator Agent): extend `report_type_enum`
    additively with the task's remaining named report types — the two
    original values are never renamed/removed. Dialect branching mirrors
    `27d5a3474dca`/`b7e4d2f8a1c9`'s identical, already-established pattern."""
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        for value in _NEW_REPORT_TYPE_VALUES:
            op.execute(f"ALTER TYPE report_type_enum ADD VALUE IF NOT EXISTS '{value}'")
    else:
        with op.batch_alter_table("reports", schema=None) as batch_op:
            batch_op.alter_column(
                "report_type",
                existing_type=sa.Enum(*_ORIGINAL_REPORT_TYPE_VALUES, name="report_type_enum"),
                type_=sa.Enum(*_ALL_REPORT_TYPE_VALUES, name="report_type_enum"),
                existing_nullable=False,
            )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        # PostgreSQL does not support removing values from an existing enum
        # type via `ALTER TYPE ... DROP VALUE` — reverting this migration on
        # Postgres requires recreating the type from scratch and is
        # intentionally not attempted here, mirroring `27d5a3474dca`'s
        # identical, already-accepted limitation.
        return
    with op.batch_alter_table("reports", schema=None) as batch_op:
        batch_op.alter_column(
            "report_type",
            existing_type=sa.Enum(*_ALL_REPORT_TYPE_VALUES, name="report_type_enum"),
            type_=sa.Enum(*_ORIGINAL_REPORT_TYPE_VALUES, name="report_type_enum"),
            existing_nullable=False,
        )
