=============================
Domain-specific configuration
=============================

The Identity service supports domain-specific Identity drivers.
The drivers allow a domain to have its own LDAP or SQL back end.
By default, domain-specific drivers are disabled.

Domain-specific Identity configuration options can be stored in
domain-specific configuration files, or in the Identity SQL
database using API REST calls.

.. note::

   Storing and managing configuration options in an SQL database is
   experimental in Kilo, and added to the Identity service in the
   Liberty release.

Enable drivers for domain-specific configuration files
------------------------------------------------------

To enable domain-specific drivers, set these options in the
``/etc/keystone/keystone.conf`` file:

.. code-block:: ini

   [identity]
   domain_specific_drivers_enabled = True
   domain_config_dir = /etc/keystone/domains

When you enable domain-specific drivers, Identity looks in the
``domain_config_dir`` directory for configuration files that are named as
``keystone.DOMAIN_NAME.conf``. A domain without a domain-specific
configuration file uses options in the primary configuration file.

Enable drivers for storing configuration options in SQL database
----------------------------------------------------------------

To enable domain-specific drivers, set these options in the
``/etc/keystone/keystone.conf`` file:

.. code-block:: ini

   [identity]
   domain_specific_drivers_enabled = True
   domain_configurations_from_database = True

Any domain-specific configuration options specified through the
Identity v3 API will override domain-specific configuration files in the
``/etc/keystone/domains`` directory.

Migrate domain-specific configuration files to the SQL database
---------------------------------------------------------------

You can use the ``keystone-manage`` command to migrate configuration
options in domain-specific configuration files to the SQL database:

.. code-block:: console

   # keystone-manage domain_config_upload --all

To upload options from a specific domain-configuration file, specify the
domain name:

.. code-block:: console

   # keystone-manage domain_config_upload --domain-name DOMAIN_NAME


