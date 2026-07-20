"""create linux_security_findings table

Revision ID: 9c1e2a7d4b6f
Revises: b2a6f1c3d8e4
Create Date: 2026-07-20 04:00:00.000000

"""
from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '9c1e2a7d4b6f'
down_revision: str | None = 'b2a6f1c3d8e4'
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_table('linux_security_findings',
    sa.Column('case_id', sa.Uuid(), nullable=False),
    sa.Column('evidence_id', sa.Uuid(), nullable=True),
    sa.Column('category', sa.Enum(
        'brute_force', 'compromise_after_brute_force', 'failed_login_spike',
        'root_login', 'new_user', 'user_deletion', 'password_change',
        'sudo_abuse', 'privilege_escalation', 'suspicious_cron',
        'reverse_shell', 'suspicious_service', 'suspicious_process',
        'persistence_mechanism', 'unauthorized_account_activity',
        name='linux_security_finding_category_enum'), nullable=False),
    sa.Column('subject', sa.String(length=255), nullable=False),
    sa.Column('subject_type', sa.String(length=32), nullable=False),
    sa.Column('title', sa.String(length=512), nullable=False),
    sa.Column('description', sa.String(), nullable=False),
    sa.Column('severity', sa.Enum(
        'info', 'low', 'medium', 'high', 'critical',
        name='linux_security_severity_enum'), nullable=False),
    sa.Column('composite_score', sa.Float(), nullable=False),
    sa.Column('occurrence_count', sa.Integer(), nullable=False),
    sa.Column('line_numbers_json', sa.String(), nullable=True),
    sa.Column('extractor_name', sa.String(length=64), nullable=False),
    sa.Column('extractor_version', sa.String(length=32), nullable=False),
    sa.Column('status', sa.Enum(
        'active', 'dismissed', 'false_positive', 'failed',
        name='linux_security_finding_status_enum'), nullable=False),
    sa.Column('metadata_json', sa.String(), nullable=True),
    sa.Column('error_message', sa.String(), nullable=True),
    sa.Column('first_seen_at', sa.DateTime(), nullable=False),
    sa.Column('last_seen_at', sa.DateTime(), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.ForeignKeyConstraint(['case_id'], ['cases.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['evidence_id'], ['evidence.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_linux_security_findings_case_id', 'linux_security_findings', ['case_id'], unique=False)
    op.create_index('ix_linux_security_findings_evidence_id', 'linux_security_findings', ['evidence_id'], unique=False)
    op.create_index('ix_linux_security_findings_category', 'linux_security_findings', ['category'], unique=False)
    op.create_index('ix_linux_security_findings_severity', 'linux_security_findings', ['severity'], unique=False)
    op.create_index('ix_linux_security_findings_status', 'linux_security_findings', ['status'], unique=False)
    op.create_index('ix_linux_security_findings_subject', 'linux_security_findings', ['subject'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_linux_security_findings_subject', table_name='linux_security_findings')
    op.drop_index('ix_linux_security_findings_status', table_name='linux_security_findings')
    op.drop_index('ix_linux_security_findings_severity', table_name='linux_security_findings')
    op.drop_index('ix_linux_security_findings_category', table_name='linux_security_findings')
    op.drop_index('ix_linux_security_findings_evidence_id', table_name='linux_security_findings')
    op.drop_index('ix_linux_security_findings_case_id', table_name='linux_security_findings')
    op.drop_table('linux_security_findings')
