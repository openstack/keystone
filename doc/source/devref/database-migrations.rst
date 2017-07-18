..
      Copyright 2011-2012 OpenStack Foundation
      All Rights Reserved.

      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

Database Migrations
===================

Starting with Newton, keystone supports upgrading both with and without
downtime. In order to support this, there are three separate migration
repositories (all under ``keystone/common/sql/``) that match the three phases
of an upgrade (schema expansion, data migration, and schema contraction):

``expand_repo``
    For additive schema modifications and triggers to ensure data is kept in
    sync between the old and new schema until the point when there are no
    keystone instances running old code.

``data_migration_repo``
    To ensure new tables/columns are fully populated with data from the old
    schema.

``contract_repo``
    Run after all old code versions have been upgraded to running the new code,
    so remove any old schema columns/tables that are not used by the new
    version of the code. Drop any triggers added in the expand phase.

All migrations are required to have a migration script in each of these repos,
each with the same version number (which is indicated by the first three digits
of the name of the script, e.g. ``003_add_X_table.py``). If there is no work to
do in a specific phase, then include a no-op migration to simply ``pass`` (in
fact the ``001`` migration in each of these repositories is a no-op migration,
so that can be used as a template).

.. NOTE::

    Since rolling upgrade support was added part way through the Newton cycle,
    some migrations had already been added to the legacy repository
    (``keystone/common/sql/migrate_repo``). This repository is now closed and
    no new migrations should be added (except for backporting of previous
    placeholders).

In order to support rolling upgrades, where two releases of keystone briefly
operate side-by-side using the same database without downtime, each phase of
the migration must adhere to following constraints:

These triggers should be removed in the contract phase. There are further
restrictions as to what can and cannot be included in migration scripts in each
phase:

Expand phase:
    Only additive schema changes are allowed, such as new columns, tables,
    indices, and triggers.

    Data insertion, modification, and removal is not allowed.

    Triggers must be created to keep data in sync between the previous release
    and the next release. Data written by the previous release must be readable
    by both the previous release and the next release. Data written by the next
    release must be readable by both the next release and the previous release.

    In cases it is not possible for triggers to maintain data integrity across
    multiple schemas, writing data should be forbidden using triggers.

Data Migration phase:
    Data is allowed to be inserted, updated, and deleted.

    No schema changes are allowed.

Contract phase:
    Only contractive schema changes are allowed, such as dropping or altering
    columns, tables, indices, and triggers.

    Data insertion, modification, and removal is not allowed.

    Triggers created during the expand phase must be dropped.

For more information on writing individual migration scripts refer to
`SQLAlchemy-migrate`_.

.. _SQLAlchemy-migrate: https://git.openstack.org/cgit/openstack/sqlalchemy-migrate
