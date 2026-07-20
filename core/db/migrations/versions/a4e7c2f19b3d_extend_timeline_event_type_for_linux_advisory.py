"""extend timeline_event_type_enum for linux_advisory_assessed

Revision ID: a4e7c2f19b3d
Revises: 7f3d9a1b5c2e
Create Date: 2026-07-20 05:00:00.000000

"""
from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a4e7c2f19b3d'
down_revision: str | None = '7f3d9a1b5c2e'
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None

_ORIGINAL_EVENT_TYPE_VALUES = (
    'case_opened', 'evidence_ingested', 'ioc_extracted', 'finding_generated',
    'agent_analysis', 'case_status_changed', 'manual_note', 'case_assigned',
    'vulnerability_assessed', 'linux_security_finding_detected',
)
_NEW_EVENT_TYPE_VALUES = ('linux_advisory_assessed',)
_ALL_EVENT_TYPE_VALUES = _ORIGINAL_EVENT_TYPE_VALUES + _NEW_EVENT_TYPE_VALUES


def upgrade() -> None:
    """docs/adr/0019 (Linux Security Advisor Framework): extend
    `timeline_event_type_enum` additively with `linux_advisory_assessed` —
    the prior ten values are never renamed/removed. Dialect branching
    mirrors `7f3d9a1b5c2e`'s identical, already-established pattern."""
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        for value in _NEW_EVENT_TYPE_VALUES:
            op.execute(f"ALTER TYPE timeline_event_type_enum ADD VALUE IF NOT EXISTS '{value}'")
    else:
        with op.batch_alter_table("timeline_events", schema=None) as batch_op:
            batch_op.alter_column(
                "event_type",
                existing_type=sa.Enum(
                    *_ORIGINAL_EVENT_TYPE_VALUES, name="timeline_event_type_enum"
                ),
                type_=sa.Enum(*_ALL_EVENT_TYPE_VALUES, name="timeline_event_type_enum"),
                existing_nullable=False,
            )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        # PostgreSQL does not support removing values from an existing enum
        # type via `ALTER TYPE ... DROP VALUE` — reverting this migration on
        # Postgres requires recreating the type from scratch and is
        # intentionally not attempted here, mirroring `7f3d9a1b5c2e`'s
        # identical, already-accepted limitation.
        return
    with op.batch_alter_table("timeline_events", schema=None) as batch_op:
        batch_op.alter_column(
            "event_type",
            existing_type=sa.Enum(*_ALL_EVENT_TYPE_VALUES, name="timeline_event_type_enum"),
            type_=sa.Enum(*_ORIGINAL_EVENT_TYPE_VALUES, name="timeline_event_type_enum"),
            existing_nullable=False,
        )
