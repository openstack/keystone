# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 OpenStack LLC
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

import sqlalchemy as sql


def upgrade(migrate_engine):
    # The group_project_metadata table was not updated in terms of its
    # FK to the tenant table when the tenant->project change was made at
    # the 015 migration for sqlite.  This upgrade fixes that.
    # We need to create a fake tenant table so that we can first load
    # the group_project_metadata at all, then do a dance of copying tables
    # to get us to the correct schema.
    meta = sql.MetaData()
    meta.bind = migrate_engine

    if migrate_engine.name != 'sqlite':
        return

    temp_tenant_table = sql.Table(
        'tenant',
        meta,
        sql.Column('id', sql.String(64), primary_key=True))
    temp_tenant_table.create(migrate_engine, checkfirst=True)

    sql.Table('user', meta, autoload=True)
    old_group_metadata_table = sql.Table('group_project_metadata',
                                         meta, autoload=True)

    # OK, we now have the table loaded, create a first
    # temporary table of a different name with the correct FK
    sql.Table('project', meta, autoload=True)
    temp_group_project_metadata_table = sql.Table(
        'temp_group_project_metadata',
        meta,
        sql.Column(
            'group_id',
            sql.String(64),
            primary_key=True),
        sql.Column(
            'project_id',
            sql.String(64),
            sql.ForeignKey('project.id'),
            primary_key=True),
        sql.Column('data', sql.Text()))
    temp_group_project_metadata_table.create(migrate_engine, checkfirst=True)

    # Populate the new temporary table, and then drop the old one
    session = sql.orm.sessionmaker(bind=migrate_engine)()

    for metadata in session.query(old_group_metadata_table):
        q = temp_group_project_metadata_table.insert().values(
            group_id=metadata.group_id,
            project_id=metadata.project_id,
            data=metadata.data)
        session.execute(q)
    session.commit()
    old_group_metadata_table.drop()
    temp_tenant_table.drop()

    # Now do a final table copy to get the table of the right name.
    # Re-init the metadata so that sqlalchemy does not get confused with
    # multiple versions of the same named table.
    meta2 = sql.MetaData()
    meta2.bind = migrate_engine

    sql.Table('project', meta2, autoload=True)
    new_group_project_metadata_table = sql.Table(
        'group_project_metadata',
        meta2,
        sql.Column(
            'group_id',
            sql.String(64),
            primary_key=True),
        sql.Column(
            'project_id',
            sql.String(64),
            sql.ForeignKey('project.id'),
            primary_key=True),
        sql.Column('data', sql.Text()))
    new_group_project_metadata_table.create(migrate_engine, checkfirst=True)

    for metadata in session.query(temp_group_project_metadata_table):
        q = new_group_project_metadata_table.insert().values(
            group_id=metadata.group_id,
            project_id=metadata.project_id,
            data=metadata.data)
        session.execute(q)
    session.commit()

    temp_group_project_metadata_table.drop()


def downgrade(migrate_engine):
    # Put the group_project_metadata table back the way it was in its rather
    # broken state. We don't try and re-write history, since otherwise people
    # get out of step.
    meta = sql.MetaData()
    meta.bind = migrate_engine

    if migrate_engine.name != 'sqlite':
        return

    sql.Table('user', meta, autoload=True)
    sql.Table('project', meta, autoload=True)
    group_metadata_table = sql.Table('group_project_metadata',
                                     meta, autoload=True)

    # We want to create a temp group meta table with the FK
    # set to the wrong place.
    temp_tenant_table = sql.Table(
        'tenant',
        meta,
        sql.Column('id', sql.String(64), primary_key=True))
    temp_tenant_table.create(migrate_engine, checkfirst=True)

    temp_group_project_metadata_table = sql.Table(
        'temp_group_project_metadata',
        meta,
        sql.Column(
            'group_id',
            sql.String(64),
            primary_key=True),
        sql.Column(
            'project_id',
            sql.String(64),
            sql.ForeignKey('tenant.id'),
            primary_key=True),
        sql.Column('data', sql.Text()))
    temp_group_project_metadata_table.create(migrate_engine, checkfirst=True)

    # Now populate the temp table and drop the real one
    session = sql.orm.sessionmaker(bind=migrate_engine)()

    for metadata in session.query(group_metadata_table):
        q = temp_group_project_metadata_table.insert().values(
            group_id=metadata.group_id,
            project_id=metadata.project_id,
            data=metadata.data)
        session.execute(q)

    session.commit()
    group_metadata_table.drop()

    # Now copy again into the correctly named table.  Re-init the metadata
    # so that sqlalchemy does not get confused with multiple versions of the
    # same named table.
    meta2 = sql.MetaData()
    meta2.bind = migrate_engine

    sql.Table('tenant', meta2, autoload=True)
    new_group_project_metadata_table = sql.Table(
        'group_project_metadata',
        meta2,
        sql.Column(
            'group_id',
            sql.String(64),
            primary_key=True),
        sql.Column(
            'project_id',
            sql.String(64),
            sql.ForeignKey('tenant.id'),
            primary_key=True),
        sql.Column('data', sql.Text()))
    new_group_project_metadata_table.create(migrate_engine, checkfirst=True)

    for metadata in session.query(temp_group_project_metadata_table):
        q = new_group_project_metadata_table.insert().values(
            group_id=metadata.group_id,
            project_id=metadata.project_id,
            data=metadata.data)
        session.execute(q)

    session.commit()

    temp_group_project_metadata_table.drop()
    temp_tenant_table.drop()
