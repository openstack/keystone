================
Using Migrations
================

Keystone uses sqlalchemy-migrate to manage migrations.


Running Migrations
======================

Keep backups of your db.Add your existing database to version control.

Example::

$python keystone/backends/sqlalchemy/migrate_repo/manage.py version_control  --url=sqlite:///bin/keystone.db --repository=keystone/backends/sqlalchemy/migrate_repo/


Set your current db version to appropriate version_number.

Version number 1 maps to diablo release.

Example::
 
UPDATE migrate_version SET version=1; 

Perform Upgrades/Downgrades

Example Upgrade ::

$python keystone/backends/sqlalchemy/migrate_repo/manage.py upgrade  --url=sqlite:///bin/keystone.db --repository=keystone/backends/sqlalchemy/migrate_repo/

Example Downgrade::

$python keystone/backends/sqlalchemy/migrate_repo/manage.py downgrade 1   --url=sqlite:///bin/keystone.db --repository=keystone/backends/sqlalchemy/migrate_repo/

