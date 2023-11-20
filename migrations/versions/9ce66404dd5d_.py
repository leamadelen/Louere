"""empty message

Revision ID: 9ce66404dd5d
Revises: 82a53bd1b3f3
Create Date: 2021-10-18 13:16:18.194068

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '9ce66404dd5d'
down_revision = '82a53bd1b3f3'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('post', sa.Column('image', sa.String(length=999), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('post', 'image')
    # ### end Alembic commands ###
