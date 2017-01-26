# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import migrate
import sqlalchemy as sql
from sqlalchemy.engine import reflection

from keystone.common.sql import upgrades


def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine
    inspector = reflection.Inspector.from_engine(migrate_engine)

    user = sql.Table('user', meta, autoload=True)
    local_user = sql.Table('local_user', meta, autoload=True)
    nonlocal_user = sql.Table('nonlocal_user', meta, autoload=True)

    # drop previous fk constraints
    fk_name = _get_fk_name(inspector, 'local_user', 'user_id')
    if fk_name:
        migrate.ForeignKeyConstraint(columns=[local_user.c.user_id],
                                     refcolumns=[user.c.id],
                                     name=fk_name).drop()

    fk_name = _get_fk_name(inspector, 'nonlocal_user', 'user_id')
    if fk_name:
        migrate.ForeignKeyConstraint(columns=[nonlocal_user.c.user_id],
                                     refcolumns=[user.c.id],
                                     name=fk_name).drop()

    # create user unique constraint needed for the new composite fk constraint
    migrate.UniqueConstraint(user.c.id, user.c.domain_id,
                             name='ixu_user_id_domain_id').create()
    # create new composite fk constraints
    migrate.ForeignKeyConstraint(
        columns=[local_user.c.user_id, local_user.c.domain_id],
        refcolumns=[user.c.id, user.c.domain_id],
        onupdate='CASCADE', ondelete='CASCADE').create()
    migrate.ForeignKeyConstraint(
        columns=[nonlocal_user.c.user_id, nonlocal_user.c.domain_id],
        refcolumns=[user.c.id, user.c.domain_id],
        onupdate='CASCADE', ondelete='CASCADE').create()

    # drop triggers
    if upgrades.USE_TRIGGERS:
        if migrate_engine.name == 'postgresql':
            drop_local_user_insert_trigger = (
                'DROP TRIGGER local_user_after_insert_trigger on local_user;')
            drop_local_user_update_trigger = (
                'DROP TRIGGER local_user_after_update_trigger on local_user;')
            drop_nonlocal_user_insert_trigger = (
                'DROP TRIGGER nonlocal_user_after_insert_trigger '
                'on nonlocal_user;')
            drop_nonlocal_user_update_trigger = (
                'DROP TRIGGER nonlocal_user_after_update_trigger '
                'on nonlocal_user;')
        elif migrate_engine.name == 'mysql':
            drop_local_user_insert_trigger = (
                'DROP TRIGGER local_user_after_insert_trigger;')
            drop_local_user_update_trigger = (
                'DROP TRIGGER local_user_after_update_trigger;')
            drop_nonlocal_user_insert_trigger = (
                'DROP TRIGGER nonlocal_user_after_insert_trigger;')
            drop_nonlocal_user_update_trigger = (
                'DROP TRIGGER nonlocal_user_after_update_trigger;')
        else:
            drop_local_user_insert_trigger = (
                'DROP TRIGGER IF EXISTS local_user_after_insert_trigger;')
            drop_local_user_update_trigger = (
                'DROP TRIGGER IF EXISTS local_user_after_update_trigger;')
            drop_nonlocal_user_insert_trigger = (
                'DROP TRIGGER IF EXISTS nonlocal_user_after_insert_trigger;')
            drop_nonlocal_user_update_trigger = (
                'DROP TRIGGER IF EXISTS nonlocal_user_after_update_trigger;')
        migrate_engine.execute(drop_local_user_insert_trigger)
        migrate_engine.execute(drop_local_user_update_trigger)
        migrate_engine.execute(drop_nonlocal_user_insert_trigger)
        migrate_engine.execute(drop_nonlocal_user_update_trigger)


def _get_fk_name(inspector, table, fk_column):
    for fk in inspector.get_foreign_keys(table):
        if fk_column in fk['constrained_columns']:
            return fk['name']
