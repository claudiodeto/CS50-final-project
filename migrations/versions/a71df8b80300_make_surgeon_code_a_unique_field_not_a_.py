"""Make surgeon_code a unique field, not a foreign key

Revision ID: a71df8b80300
Revises: d9daea241ee0
Create Date: 2025-11-02 10:46:43.136116

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a71df8b80300'
down_revision = 'd9daea241ee0'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('surgeon') as batch_op:
        batch_op.add_column(sa.Column('surgeon_code', sa.String(length=20), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    with op.batch_alter_table('surgeon') as batch_op:
        batch_op.drop_column('surgeon_code')

    # ### end Alembic commands ###
