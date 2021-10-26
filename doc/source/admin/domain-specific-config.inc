.. -*- rst -*-

.. _domain_specific_configuration:

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

.. _enable_drivers_for_domain:

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

Unlike the file-based method of specifying domain-specific configurations,
options specified via the Identity API will become active without needing to
restart the keystone server. For performance reasons, the current state of
configuration options for a domain are cached in the keystone server, and in
multi-process and multi-threaded keystone configurations, the new
configuration options may not become active until the cache has timed out. The
cache settings for domain config options can be adjusted in the general
keystone configuration file (option ``cache_time`` in the ``domain_config``
group).

.. NOTE::

    It is important to notice that when using either of these methods of
    specifying domain-specific configuration options, the main keystone
    configuration file is still maintained. Only those options that relate
    to the Identity driver for users and groups (i.e. specifying whether the
    driver for this domain is SQL or LDAP, and, if LDAP, the options that
    define that connection) are supported in a domain-specific manner. Further,
    when using the configuration options via the Identity API, the driver
    option must be set to an LDAP driver (attempting to set it to an SQL driver
    will generate an error when it is subsequently used).

For existing installations that already use file-based domain-specific
configurations who wish to migrate to the SQL-based approach, the
``keystone-manage`` command can be used to upload all configuration files to
the SQL database:

.. code-block:: bash

    $ keystone-manage domain_config_upload --all

Once uploaded, these domain-configuration options will be visible via the
Identity API as well as applied to the domain-specific drivers. It is also
possible to upload individual domain-specific configuration files by
specifying the domain name:

.. code-block:: bash

    $ keystone-manage domain_config_upload --domain-name DOMAINA

.. NOTE::

    It is important to notice that by enabling either of the domain-specific
    configuration methods, the operations of listing all users and listing all
    groups are not supported, those calls will need either a domain filter to
    be specified or usage of a domain scoped token.

.. NOTE::

    Keystone does not support moving the contents of a domain (i.e. "its" users
    and groups) from one backend to another, nor group membership across
    backend boundaries.

.. NOTE::

    When using the file-based domain-specific configuration method, to delete a
    domain that uses a domain specific backend, it's necessary to first disable
    it, remove its specific configuration file (i.e. its corresponding
    keystone.<domain_name>.conf) and then restart the Identity server. When
    managing configuration options via the Identity API, the domain can simply
    be disabled and deleted via the Identity API; since any domain-specific
    configuration options will automatically be removed.

.. NOTE::

    Although keystone supports multiple LDAP backends via the above
    domain-specific configuration methods, it currently only supports one SQL
    backend. This could be either the default driver or a single
    domain-specific backend, perhaps for storing service users in a
    predominantly LDAP installation.

.. NOTE::

    Keystone has deprecated the ``keystone-manage domain_config_upload``
    option. The keystone team recommends setting domain config options via the
    API instead.

Due to the need for user and group IDs to be unique across an OpenStack
installation and for keystone to be able to deduce which domain and backend to
use from just a user or group ID, it dynamically builds a persistent identity
mapping table from a public ID to the actual domain, local ID (within that
backend) and entity type. The public ID is automatically generated by keystone
when it first encounters the entity. If the local ID of the entity is from a
backend that does not guarantee to generate UUIDs, a hash algorithm will
generate a public ID for that entity, which is what will be exposed by
keystone.

The use of a hash will ensure that if the public ID needs to be regenerated
then the same public ID will be created. This is useful if you are running
multiple keystones and want to ensure the same ID would be generated whichever
server you hit.

.. NOTE::

    In case of the LDAP backend, the names of users and groups are not hashed.
    As a result, these are length limited to 255 characters. Longer names
    will result in an error.

While keystone will dynamically maintain the identity mapping, including
removing entries when entities are deleted via the keystone, for those entities
in backends that are managed outside of keystone (e.g. a read-only LDAP),
keystone will not know if entities have been deleted and hence will continue to
carry stale identity mappings in its table. While benign, keystone provides an
ability for operators to purge the mapping table of such stale entries using
the keystone-manage command, for example:

.. code-block:: bash

    $ keystone-manage mapping_purge --domain-name DOMAINA --local-id abc@de.com

A typical usage would be for an operator to obtain a list of those entries in
an external backend that had been deleted out-of-band to keystone, and then
call keystone-manage to purge those entries by specifying the domain and
local-id. The type of the entity (i.e. user or group) may also be specified if
this is needed to uniquely identify the mapping.

Since public IDs can be regenerated **with the correct generator
implementation**, if the details of those entries that have been deleted are
not available, then it is safe to simply bulk purge identity mappings
periodically, for example:

.. code-block:: bash

    $ keystone-manage mapping_purge --domain-name DOMAINA

will purge all the mappings for DOMAINA. The entire mapping table can be purged
with the following command:

.. code-block:: bash

    $ keystone-manage mapping_purge --all

Generating public IDs in the first run may take a while, and most probably
first API requests to fetch user list will fail by timeout. To prevent this,
``mapping_populate`` command should be executed. It should be executed right after
LDAP has been configured or after ``mapping_purge``.

.. code-block:: bash

    $ keystone-manage mapping_populate --domain DOMAINA

Public ID Generators
--------------------

Keystone supports a customizable public ID generator and it is specified in the
``[identity_mapping]`` section of the configuration file. Keystone provides a
sha256 generator as default, which produces regenerable public IDs. The
generator algorithm for public IDs is a balance between key size (i.e. the
length of the public ID), the probability of collision and, in some
circumstances, the security of the public ID. The maximum length of public ID
supported by keystone is 64 characters, and the default generator (sha256) uses
this full capability. Since the public ID is what is exposed externally by
keystone and potentially stored in external systems, some installations may
wish to make use of other generator algorithms that have a different trade-off
of attributes. A different generator can be installed by configuring the
following property:

* ``generator`` - identity mapping generator. Defaults to ``sha256``
  (implemented by :class:`keystone.identity.id_generators.sha256.Generator`)

.. WARNING::

    Changing the generator may cause all existing public IDs to be become
    invalid, so typically the generator selection should be considered
    immutable for a given installation.

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
