"""add report generation columns to reports table

Revision ID: d5e9f2b7a8c4
Revises: c4d8e1a6f7b3
Create Date: 2026-07-21 09:05:00.000000

"""
from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd5e9f2b7a8c4'
down_revision: str | None = 'c4d8e1a6f7b3'
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    """docs/adr/0024 (Report Generator Agent): additive columns needed to
    actually persist a `core.reporting.models.GeneratedReport` (this table
    was, until this session, a schema-only placeholder with no writer). The
    table is guaranteed empty in every environment (its own prior docstring:
    "no report is ever generated yet"), so `NOT NULL` needs no server
    default. `ix_reports_case_id` becomes unique, matching blueprint §8's
    literal "1 nullable" `Report` cardinality (mirrors
    `ix_incident_response_plans_case_id`'s identical uniqueness)."""
    with op.batch_alter_table("reports", schema=None) as batch_op:
        batch_op.add_column(sa.Column("title", sa.String(length=500), nullable=False, server_default=""))
        batch_op.add_column(
            sa.Column("report_data_json", sa.Text(), nullable=False, server_default="{}")
        )
        batch_op.add_column(
            sa.Column("overall_confidence", sa.Float(), nullable=False, server_default="0.0")
        )
        batch_op.add_column(
            sa.Column("degraded", sa.Boolean(), nullable=False, server_default=sa.false())
        )
    op.drop_index("ix_reports_case_id", table_name="reports")
    op.create_index("ix_reports_case_id", "reports", ["case_id"], unique=True)
    op.create_index("ix_reports_report_type", "reports", ["report_type"], unique=False)

    with op.batch_alter_table("reports", schema=None) as batch_op:
        batch_op.alter_column("title", server_default=None)
        batch_op.alter_column("report_data_json", server_default=None)
        batch_op.alter_column("overall_confidence", server_default=None)
        batch_op.alter_column("degraded", server_default=None)


def downgrade() -> None:
    op.drop_index("ix_reports_report_type", table_name="reports")
    op.drop_index("ix_reports_case_id", table_name="reports")
    op.create_index("ix_reports_case_id", "reports", ["case_id"], unique=False)
    with op.batch_alter_table("reports", schema=None) as batch_op:
        batch_op.drop_column("degraded")
        batch_op.drop_column("overall_confidence")
        batch_op.drop_column("report_data_json")
        batch_op.drop_column("title")
