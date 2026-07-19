"""add case foreign keys to evidence iocs findings

Revision ID: 7ae8f470d5e7
Revises: 6735a0d18bb9
Create Date: 2026-07-20 01:00:48.470618

"""
from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '7ae8f470d5e7'
down_revision: str | None = '6735a0d18bb9'
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    """Tighten `evidence.case_id`, `iocs.case_id`, `findings.case_id` from
    plain UUID columns into real foreign keys against `cases.id`, now that
    `Case` exists (ADR-0011/0012/0013's deferred follow-up, constitution §7
    "Future scalability": additive, never a redesign). `batch_alter_table` is
    required because SQLite cannot `ALTER TABLE ADD CONSTRAINT` in place; it
    rebuilds each table under the hood and is a no-op wrapper on dialects
    that support it directly (e.g. PostgreSQL)."""
    with op.batch_alter_table("evidence", schema=None) as batch_op:
        batch_op.create_foreign_key(
            "fk_evidence_case_id_cases", "cases", ["case_id"], ["id"], ondelete="CASCADE"
        )
    with op.batch_alter_table("iocs", schema=None) as batch_op:
        batch_op.create_foreign_key(
            "fk_iocs_case_id_cases", "cases", ["case_id"], ["id"], ondelete="CASCADE"
        )
    with op.batch_alter_table("findings", schema=None) as batch_op:
        batch_op.create_foreign_key(
            "fk_findings_case_id_cases", "cases", ["case_id"], ["id"], ondelete="CASCADE"
        )


def downgrade() -> None:
    with op.batch_alter_table("findings", schema=None) as batch_op:
        batch_op.drop_constraint("fk_findings_case_id_cases", type_="foreignkey")
    with op.batch_alter_table("iocs", schema=None) as batch_op:
        batch_op.drop_constraint("fk_iocs_case_id_cases", type_="foreignkey")
    with op.batch_alter_table("evidence", schema=None) as batch_op:
        batch_op.drop_constraint("fk_evidence_case_id_cases", type_="foreignkey")
