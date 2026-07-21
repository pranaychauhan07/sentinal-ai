"""create incident_response_plans table

Revision ID: f3a9c1d7e2b5
Revises: 27d5a3474dca
Create Date: 2026-07-21 08:00:00.000000

"""
from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f3a9c1d7e2b5'
down_revision: str | None = '27d5a3474dca'
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_table('incident_response_plans',
    sa.Column('case_id', sa.Uuid(), nullable=False),
    sa.Column('incident_severity', sa.Enum(
        'info', 'low', 'medium', 'high', 'critical',
        name='incident_response_severity_enum'), nullable=False),
    sa.Column('overall_risk_score', sa.Float(), nullable=False),
    sa.Column('overall_confidence', sa.Float(), nullable=False),
    sa.Column('plan_degraded', sa.Boolean(), nullable=False),
    sa.Column('plan_data_json', sa.Text(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.ForeignKeyConstraint(['case_id'], ['cases.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_incident_response_plans_case_id', 'incident_response_plans', ['case_id'], unique=True)
    op.create_index('ix_incident_response_plans_incident_severity', 'incident_response_plans', ['incident_severity'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_incident_response_plans_incident_severity', table_name='incident_response_plans')
    op.drop_index('ix_incident_response_plans_case_id', table_name='incident_response_plans')
    op.drop_table('incident_response_plans')
