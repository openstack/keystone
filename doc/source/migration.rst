===================
Database Migrations
===================

Keystone uses SQLAlchemy Migrate (``sqlalchemy-migrate``) to manage migrations.

.. WARNING::

    Backup your database before applying migrations. Migrations may attempt to modify both your schema and data, and could result in data loss.

    Always review the behavior of migrations in a staging environment before applying them in production.

Getting Started
===============

Migrations are tracked using a metadata table. Place an existing database under version control to enable migration support (SQLite in this case)::

    $ python keystone/backends/sqlalchemy/migrate_repo/manage.py version_control --url=sqlite:///bin/keystone.db --repository=keystone/backends/sqlalchemy/migrate_repo/

If you are starting with an existing schema, you can set your database to the current schema version number using a
SQL command. For example, if you're starting from a
diablo-compatible database, set your current database version to ``1``::

    UPDATE migrate_version SET version=1;

Upgrading & Downgrading
=======================

Fresh installs of Keystone will need to run database upgrades, which will build a schema and bootstrap it with any necessary data.

Upgrade::

    $ python keystone/backends/sqlalchemy/migrate_repo/manage.py upgrade --url=sqlite:///bin/keystone.db --repository=keystone/backends/sqlalchemy/migrate_repo/

Downgrade (will likely result in data loss!)::

    $ python keystone/backends/sqlalchemy/migrate_repo/manage.py downgrade 1 --url=sqlite:///bin/keystone.db --repository=keystone/backends/sqlalchemy/migrate_repo/

Useful Links
============

Principles to follow when developing migrations `OpenStack Deployability <http://wiki.openstack.org/OpenstackDeployability>`_
