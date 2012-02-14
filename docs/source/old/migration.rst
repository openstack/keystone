===================
Database Migrations
===================

Keystone uses SQLAlchemy Migrate (``sqlalchemy-migrate``) to manage
migrations.

Migrations are tracked using a metadata table (``migrate_version``), which
allows keystone to compare the state of your database to the state it
expects, and to move between versions.

.. WARNING::

    Backup your database before applying migrations. Migrations may
    attempt to modify both your schema and data, and could result in data
    loss.

    Always review the behavior of migrations in a staging environment
    before applying them in production.

Getting Started
===============

Your initial approach to migrations should depend on whether you have an
empty database or a schema full of data.

Starting with an empty database
-------------------------------

If you have an empty database for keystone to work with, you can simply
run::

    $ ./bin/keystone-manage database sync

This command will initialize your metadata table, and run through all the
schema & data migrations necessary to bring your database in sync with
keystone. That's it!

Starting with an existing database
----------------------------------

Place an existing database under version control to enable migration
support::

    $ ./bin/keystone-manage database version_control

This command simply creates a ``migrate_version`` table, set at
``version_number`` 0, which indicates that no migrations have been applied.

If you are starting with an existing schema, you can jump to a specific
schema version without performing migrations using the ``database goto``
command. For example, if you're starting from a diablo-compatible
database, set your current database ``version_number`` to ``1`` using::

    $ ./bin/keystone-manage database goto <version_number>

Determine your appropriate database ``version_number`` by referencing the
following table:

    +------------+-------------+
    | Release    | ``version`` |
    +============+=============+
    | pre-diablo | (see below) |
    +------------+-------------+
    | diablo     | 1           |
    +------------+-------------+
    | essex-m1   | 3           |
    +------------+-------------+
    | essex-m2   | 4           |
    +------------+-------------+

From there, you can upgrade normally (see :ref:`upgrading`).

Starting with a pre-diablo database (cactus)
--------------------------------------------

You'll need to manually migrate your database to a diablo-compatible
schema, and continue forward from there (if desired) using migrations.

.. _upgrading:

Upgrading & Downgrading
=======================

.. note::

    Attempting to start keystone with an outdated schema will cause
    keystone to abort, to avoid corrupting your data.

Upgrade to the latest version automatically::

    $ ./bin/keystone-manage database sync

Check your current schema version::

    $ ./bin/keystone-manage database version

Jump to a specific version without performing migrations::

    $ ./bin/keystone-manage database goto <version_number>

Upgrade to a specific version::

    $ ./bin/keystone-manage database upgrade <version_number>

Downgrade to a specific version (will likely result in data loss!)::

    $ ./bin/keystone-manage database downgrade <version_number>

Opting Out of Migrations
========================

If you don't want to use migrations (e.g. if you want to manage your
schema manually), keystone will complain in your logs on startup, but
won't actually stop you from doing so.

It's recommended that you use migrations to get up and running, but if
you want to manage migrations manually after that, simply drop the
``migrate_version`` table::

    DROP TABLE migrate_version;

Useful Links
============

Principles to follow when developing migrations `OpenStack Deployability <http://wiki.openstack.org/OpenstackDeployability>`_
