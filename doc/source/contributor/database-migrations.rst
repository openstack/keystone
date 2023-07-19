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

.. versionchanged:: 21.0.0 (Yoga)

    The database migration framework was changed from SQLAlchemy-Migrate to
    Alembic in the Yoga release. Previously there were three SQLAlchemy-Migrate
    repos, corresponding to different type of migration operation: the *expand*
    repo, the *data migration* repo, and the *contract* repo. There are now
    only two Alembic branches, the *expand* branch and the *contract* branch,
    and data migration operations have been folded into the former

.. versionchanged:: 24.0.0 (Bobcat)

   Added support for auto-generation of migrations using the
   ``keystone.common.sql.migrations.manage`` script.

Starting with Newton, keystone supports upgrading both with and without
downtime. In order to support this, there are two separate branches (all under
``keystone/common/sql/migrations``): the *expand* and the *contract* branch.

*expand*
    For additive schema modifications and triggers to ensure data is kept in
    sync between the old and new schema until the point when there are no
    keystone instances running old code.

    May also contain data migrations to ensure new tables/columns are fully
    populated with data from the old schema.

*contract*
    Run after all old code versions have been upgraded to running the new code,
    so remove any old schema columns/tables that are not used by the new
    version of the code. Drop any triggers added in the expand phase.

A migration script must belong to one branch. If a migration has both additive
and destruction operations, it must be split into two migrations scripts, one
in each branch.

In order to support rolling upgrades, where two releases of keystone briefly
operate side-by-side using the same database without downtime, each phase of
the migration must adhere to following constraints:

Expand phase:
    Only additive schema changes, such as new columns, tables, indices, and
    triggers, and data insertion are allowed.

    Data modification or removal is not allowed.

    Triggers must be created to keep data in sync between the previous release
    and the next release. Data written by the previous release must be readable
    by both the previous release and the next release. Data written by the next
    release must be readable by both the next release and the previous release.

    In cases it is not possible for triggers to maintain data integrity across
    multiple schemas, writing data should be forbidden using triggers.

Contract phase:
    Only destructive schema changes, such as dropping or altering
    columns, tables, indices, and triggers, or data modification or removal are
    allowed.

    Triggers created during the expand phase must be dropped.

Writing your own migrations
---------------------------

Because Keystone uses the expand-contract pattern for database migrations, it
is not possible to use the standard ``alembic`` CLI tool. Instead, Keystone
provides its own tool which provides a similar UX to the ``alembic`` tool but
which auto-configures alembic (the library) for this pattern.

To create a new *expand* branch migration:

.. code-block:: bash

   $ tox -e venv -- python -m keystone.common.sql.migrations.manage \
       revision --expand -m "My expand migration"

To create a new *contract* branch migration:

.. code-block:: bash

   $ tox -e venv -- python -m keystone.common.sql.migrations.manage \
       revision --contract -m "My contract migration"

To auto-generate an *expand* and/or *contract* branch migration:

.. code-block:: bash

   $ tox -e venv -- python -m keystone.common.sql.migrations.manage \
       revision --autogenerate -m "My auto-generated migration"

.. important::

   Because of discrepancies between the migrations and models which are yet to
   be ironed out, a number of columns are intentionally ignored. You can view
   these by inspecting the ``env.py`` file in
   ``keystone/common/sql/migrations``.

To view the help page:

.. code-block:: bash

   python -m keystone.common.sql.migrations.manage --help

For information on how this tool works, refer to `this blog post`_.
For more information on writing migration scripts in general refer to the
`Alembic`_ documentation.

.. _this blog post: https://that.guru/blog/zero-downtime-upgrades-with-alembic-and-sqlalchemy/
.. _Alembic: https://alembic.sqlalchemy.org/
