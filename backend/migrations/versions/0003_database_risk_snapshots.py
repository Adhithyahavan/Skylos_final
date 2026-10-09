"""database_risk_snapshots - stored, explainable Database Guardian risk scores

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-09

Adds the table that keeps each database's risk score together with the rule
contributions, reasons and event references that produced it. Existing data is
not touched. Downgrade drops only this table, which this revision created; the
scores can be recomputed from the alerts and login events that remain.
"""
from alembic import op
import sqlalchemy as sa


revision = '0003'
down_revision = '0002'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('database_risk_snapshots',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('database_id', sa.Integer(), nullable=False),
    sa.Column('calculated_at', sa.DateTime(), nullable=False),
    sa.Column('total_score', sa.Integer(), nullable=False),
    sa.Column('severity', sa.String(length=20), nullable=False),
    sa.Column('contributions_json', sa.Text(), nullable=False),
    sa.Column('scoring_version', sa.String(length=10), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('database_risk_snapshots', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_database_risk_snapshots_calculated_at'), ['calculated_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_database_risk_snapshots_database_id'), ['database_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_database_risk_snapshots_id'), ['id'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('database_risk_snapshots', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_database_risk_snapshots_id'))
        batch_op.drop_index(batch_op.f('ix_database_risk_snapshots_database_id'))
        batch_op.drop_index(batch_op.f('ix_database_risk_snapshots_calculated_at'))
    op.drop_table('database_risk_snapshots')
