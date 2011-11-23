================
Using Migrations
================

Keystone uses sqlalchemy-migrate to manage migrations.


Running Migrations
======================

Keep backups of your db. Migrations will modify data and schema. If they fail, you could lose data.


Add your existing database to version control. ::

    $python keystone/backends/sqlalchemy/migrate_repo/manage.py version_control  --url=sqlite:///bin/keystone.db --repository=keystone/backends/sqlalchemy/migrate_repo/


You can set your database to the current schema version number using a
SQL command. For example, to set your current db version to version number 1,
which maps to diablo release, make this call::

    UPDATE migrate_version SET version=1;

Perform Upgrades/Downgrades

Example Upgrade::

    $python keystone/backends/sqlalchemy/migrate_repo/manage.py upgrade  --url=sqlite:///bin/keystone.db --repository=keystone/backends/sqlalchemy/migrate_repo/

Example Downgrade::

    $python keystone/backends/sqlalchemy/migrate_repo/manage.py downgrade 1   --url=sqlite:///bin/keystone.db --repository=keystone/backends/sqlalchemy/migrate_repo/

If you get an error that says: migrate.exceptions.DatabaseNotControlledError: migrate_version
that means your database is not versioned controlled. See 'Add your existing database to version control' above.
