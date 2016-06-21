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

_USER_TABLE_NAME = 'user'
_USER_NAME_COLUMN_NAME = 'name'
_USER_DOMAINID_COLUMN_NAME = 'domain_id'
_USER_PASSWORD_COLUMN_NAME = 'password'


def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    user_table = sql.Table(_USER_TABLE_NAME, meta, autoload=True)

    # NOTE(gnuoy): the `domain_id` unique constraint is not guaranteed to
    # be a fixed name, such as 'ixu_user_name_domain_id`, so we need to
    # search for the correct constraint that only affects
    # user_table.c.domain_id and drop that constraint. (Fix based on
    # morganfainbergs fix in 088_domain_specific_roles.py)
    #
    # This is an idempotent change that reflects the fix to migration
    # 91 if the user name & domain_id unique constraint was not named
    # consistently and someone manually fixed the migrations / db
    # without dropping the old constraint.
    # This is a copy of migration 97 to catch any/all deployments that
    # are close to master. migration 97 will be backported to
    # stable/mitaka.

    to_drop = None
    if migrate_engine.name == 'mysql':
        for index in user_table.indexes:
            if (index.unique and len(index.columns) == 2 and
                    _USER_DOMAINID_COLUMN_NAME in index.columns and
                    _USER_NAME_COLUMN_NAME in index.columns):
                to_drop = index
                break
    else:
        for index in user_table.constraints:
            if (len(index.columns) == 2 and
                    _USER_DOMAINID_COLUMN_NAME in index.columns and
                    _USER_NAME_COLUMN_NAME in index.columns):
                to_drop = index
                break

    # remove domain_id and name unique constraint
    if to_drop is not None:
        migrate.UniqueConstraint(user_table.c.domain_id,
                                 user_table.c.name,
                                 name=to_drop.name).drop()

    # If migration 91 was aborted due to Bug #1572341 then columns may not
    # have been dropped.
    if _USER_DOMAINID_COLUMN_NAME in user_table.c:
        user_table.c.domain_id.drop()
    if _USER_NAME_COLUMN_NAME in user_table.c:
        user_table.c.name.drop()
    if _USER_PASSWORD_COLUMN_NAME in user_table.c:
        user_table.c.password.drop()
