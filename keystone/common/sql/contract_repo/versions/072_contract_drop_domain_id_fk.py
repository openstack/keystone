# Copyright 2019 SUSE LLC
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

# This is a placeholder for Train backports. Do not use this number for new
# Ussuri work. New Ussuri work starts after all the placeholders.

import migrate
import sqlalchemy as sql


def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine
    user = sql.Table('user', meta, autoload=True)
    project = sql.Table('project', meta, autoload=True)

    fk_name = [
        c for c in user.constraints
        if isinstance(c, sql.ForeignKeyConstraint)
        and c.column_keys == ['domain_id']
    ][0].name
    fk_constraint = migrate.ForeignKeyConstraint(
        columns=[user.c.domain_id], refcolumns=[project.c.id])
    fk_constraint.name = fk_name
    fk_constraint.drop()

    identity_provider = sql.Table('identity_provider', meta, autoload=True)
    fk_name = [
        c for c in identity_provider.constraints
        if isinstance(c, sql.ForeignKeyConstraint)
        and c.column_keys == ['domain_id']
    ][0].name
    fk_constraint = migrate.ForeignKeyConstraint(
        columns=[identity_provider.c.domain_id], refcolumns=[project.c.id])
    fk_constraint.name = fk_name
    fk_constraint.drop()
