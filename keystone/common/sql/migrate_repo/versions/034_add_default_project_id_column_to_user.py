# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 OpenStack Foundation
#
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

import json

import sqlalchemy as sql
from sqlalchemy.orm import sessionmaker


def migrate_default_project_from_extra_json(meta, migrate_engine):
    user_table = sql.Table('user', meta, autoload=True)

    user_list = user_table.select().execute()
    session = sessionmaker(bind=migrate_engine)()
    for user in user_list:
        try:
            data = json.loads(user.extra)
            default_project_id = data.pop('default_project_id', None)
            v2_tenant_id = data.pop('tenantId', None)
            alt_v2_tenant_id = data.pop('tenant_id', None)
        except (ValueError, TypeError):
            # NOTE(morganfainberg): Somehow we have non-json data here.  This
            # is a broken user, but it was broken beforehand.  Cleaning it up
            # is not in the scope of this migration.
            continue

        values = {}
        if default_project_id is not None:
            values['default_project_id'] = default_project_id
        elif v2_tenant_id is not None:
            values['default_project_id'] = v2_tenant_id
        elif alt_v2_tenant_id is not None:
            values['default_project_id'] = alt_v2_tenant_id

        if 'default_project_id' in values:
            values['extra'] = json.dumps(data)
            update = user_table.update().where(
                user_table.c.id == user['id']).values(values)
            migrate_engine.execute(update)

    session.commit()
    session.close()


def migrate_default_project_to_extra_json(meta, migrate_engine):
    user_table = sql.Table('user', meta, autoload=True)

    user_list = user_table.select().execute()
    session = sessionmaker(bind=migrate_engine)()
    for user in user_list:
        try:
            data = json.loads(user.extra)
        except (ValueError, TypeError):
            # NOTE(morganfainberg): Somehow we have non-json data here.  This
            # is a broken user, but it was broken beforehand.  Cleaning it up
            # is not in the scope of this migration.
            continue

        # NOTE(morganfainberg): We don't really know what the original 'extra'
        # property was here.  Populate all of the possible variants we may have
        # originally used.
        if user.default_project_id is not None:
            data['default_project_id'] = user.default_project_id
            data['tenantId'] = user.default_project_id
            data['tenant_id'] = user.default_project_id

            values = {'extra': json.dumps(data)}
            update = user_table.update().where(
                user_table.c.id == user.id).values(values)
            migrate_engine.execute(update)
    session.commit()
    session.close()


def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    user_table = sql.Table('user', meta, autoload=True)
    default_project_id = sql.Column('default_project_id', sql.String(64))
    user_table.create_column(default_project_id)
    migrate_default_project_from_extra_json(meta, migrate_engine)


def downgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    migrate_default_project_to_extra_json(meta, migrate_engine)
    user_table = sql.Table('user', meta, autoload=True)
    user_table.drop_column('default_project_id')
