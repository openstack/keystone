..
      Copyright 2011-2012 OpenStack, LLC
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

====================
Configuring Keystone
====================

.. toctree::
   :maxdepth: 1

   man/keystone-manage
   man/keystone-all

Once Keystone is installed, it is configured via a primary configuration file
(``etc/keystone.conf``), possibly a separate logging configuration file, and
initializing data into keystone using the command line client.

Starting and Stopping Keystone
==============================

Start Keystone services using the command::

    $ keystone-all

Invoking this command starts up two ``wsgi.Server`` instances, ``admin`` (the
administration API) and ``main`` (the primary/public API interface). Both
services are configured by ``keystone.conf`` as run in a single process.

Stop the process using ``Control-C``.

.. NOTE::

    If you have not already configured Keystone, it may not start as expected.

Configuration Files
===================

The keystone configuration file is an ``ini`` file based on Paste_, a
common system used to configure python WSGI based applications. In addition to
the paste configuration entries, general and driver-specific configuration
values are organized into the following sections:

* ``[DEFAULT]`` - general configuration
* ``[sql]`` - optional storage backend configuration
* ``[ec2]`` - Amazon EC2 authentication driver configuration
* ``[s3]`` - Amazon S3 authentication driver configuration.
* ``[identity]`` - identity system driver configuration
* ``[catalog]`` - service catalog driver configuration
* ``[token]`` - token driver configuration
* ``[policy]`` - policy system driver configuration for RBAC
* ``[ssl]`` - SSL configuration

The Keystone configuration file is expected to be named ``keystone.conf``.
When starting keystone, you can specify a different configuration file to
use with ``--config-file``. If you do **not** specify a configuration file,
keystone will look in the following directories for a configuration file, in
order:

* ``~/.keystone/``
* ``~/``
* ``/etc/keystone/``
* ``/etc/``

Service Catalog
---------------

Keystone provides two configuration options for your service catalog.

SQL-based Service Catalog (``sql.Catalog``)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

A dynamic database-backed driver fully supporting persistent configuration via
keystoneclient administration commands (e.g. ``keystone endpoint-create``).

``keystone.conf`` example::

    [catalog]
    driver = keystone.catalog.backends.sql.Catalog

.. NOTE::

    A `template_file` does not need to be defined for the sql.Catalog driver.

To build your service catalog using this driver, see the built-in help::

    $ keystone
    $ keystone help service-create
    $ keystone help endpoint-create

You can also refer to `an example in Keystone (tools/sample_data.sh)
<https://github.com/openstack/keystone/blob/master/tools/sample_data.sh>`_.

File-based Service Catalog (``templated.TemplatedCatalog``)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The templated catalog is an in-memory backend initialized from a read-only
``template_file``. Choose this option only if you know that your
service catalog will not change very much over time.

.. NOTE::

    Attempting to manage your service catalog using keystoneclient commands
    (e.g. ``keystone endpoint-create``) against this driver will result in
    ``HTTP 501 Not Implemented`` errors. This is the expected behavior. If you
    want to use these commands, you must instead use the SQL-based Service
    Catalog driver.

``keystone.conf`` example::

    [catalog]
    driver = keystone.catalog.backends.templated.TemplatedCatalog
    template_file = /opt/stack/keystone/etc/default_catalog.templates

The value of ``template_file`` is expected to be an absolute path to your
service catalog configuration. An example ``template_file`` is included in
Keystone, however you should create your own to reflect your deployment.
If you are migrating from a legacy deployment, a tool is available to help with
this task (see `Migrating your Service Catalog from legacy versions of
Keystone`_).

Another such example is `available in devstack
(files/default_catalog.templates)
<https://github.com/openstack-dev/devstack/blob/master/files/default_catalog.templates>`_.

Logging
-------

Logging is configured externally to the rest of Keystone. Configure the path
to your logging configuration file using the ``[DEFAULT] log_config`` option of
``keystone.conf``. If you wish to route all your logging through syslog, set
the ``[DEFAULT] use_syslog`` option.

A sample ``log_config`` file is included with the project at
``etc/logging.conf.sample``. Like other OpenStack projects, Keystone uses the
`python logging module`, which includes extensive configuration options for
choosing the output levels and formats.

.. _Paste: http://pythonpaste.org/
.. _`python logging module`: http://docs.python.org/library/logging.html

SSL
---

Keystone may be configured to support 2-way SSL out-of-the-box.  The x509
certificates used by Keystone must be obtained externally and configured for use
with Keystone as described in this section.  However, a set of sample certficates
is provided in the examples/ssl directory with the Keystone distribution for testing.
Here is the description of each of them and their purpose:

Types of certificates
^^^^^^^^^^^^^^^^^^^^^

ca.pem
    Certificate Authority chain to validate against.

keystone.pem
    Public certificate for Keystone server.

middleware.pem
    Public and private certificate for Keystone middleware/client.

cakey.pem
    Private key for the CA.

keystonekey.pem
    Private key for the Keystone server.

Note that you may choose whatever names you want for these certificates, or combine
the public/private keys in the same file if you wish.  These certificates are just
provided as an example.

Configuration
^^^^^^^^^^^^^

To enable SSL with client authentication, modify the etc/keystone.conf file accordingly
under the [ssl] section.  SSL configuration example using the included sample
certificates::

    [ssl]
    enable = True
    certfile = <path to keystone.pem>
    keyfile = <path to keystonekey.pem>
    ca_certs = <path to ca.pem>
    cert_required = True

* ``enable``:  True enables SSL.  Defaults to False.
* ``certfile``:  Path to Keystone public certificate file.
* ``keyfile``:  Path to Keystone private certificate file.  If the private key is included in the certfile, the keyfile maybe omitted.
* ``ca_certs``:  Path to CA trust chain.
* ``cert_required``:  Requires client certificate.  Defaults to False.


Sample Configuration Files
--------------------------

The ``etc/`` folder distributed with Keystone contains example configuration
files for each Server application.

* ``etc/keystone.conf``
* ``etc/logging.conf.sample``
* ``etc/default_catalog.templates``

.. _`prepare your Essex deployment`:

Preparing your Essex deployment
===============================

Step 1: Configure keystone.conf
-------------------------------

Ensure that your ``keystone.conf`` is configured to use a SQL driver::

    [identity]
    driver = keystone.identity.backends.sql.Identity

You may also want to configure your ``[sql]`` settings to better reflect your
environment::

    [sql]
    connection = sqlite:///keystone.db
    idle_timeout = 200

.. NOTE::

    It is important that the database that you specify be different from the
    one containing your existing install.

Step 2: Sync your new, empty database
-------------------------------------

You should now be ready to initialize your new database without error, using::

    $ keystone-manage db_sync

To test this, you should now be able to start ``keystone-all`` and use the
Keystone Client to list your tenants (which should successfully return an
empty list from your new database)::

    $ keystone --token ADMIN --endpoint http://127.0.0.1:35357/v2.0/ tenant-list
    +----+------+---------+
    | id | name | enabled |
    +----+------+---------+
    +----+------+---------+

.. NOTE::

    We're providing the default SERVICE_TOKEN and SERVICE_ENDPOINT values from
    ``keystone.conf`` to connect to the Keystone service. If you changed those
    values, or deployed Keystone to a different endpoint, you will need to
    change the provided command accordingly.

Migrating from legacy versions of Keystone
==========================================

Migration support is provided for the following legacy Keystone versions:

* diablo-5
* stable/diablo
* essex-2
* essex-3

.. NOTE::

    Before you can import your legacy data, you must first
    `prepare your Essex deployment`_.

Step 1: Ensure your Essex deployment can access your legacy database
--------------------------------------------------------------------

Your legacy ``keystone.conf`` contains a SQL configuration section called
``[keystone.backends.sqlalchemy]`` connection string which, by default,
looks like::

    sql_connection = sqlite:///keystone.db

This connection string needs to be accessible from your Essex deployment (e.g.
you may need to copy your SQLite ``*.db`` file to a new server, adjust the
relative path as appropriate, or open a firewall for MySQL, etc).

Step 2: Import your legacy data
-------------------------------

Use the following command to import your old data using the value of
``sql_connection`` from step 3::

    $ keystone-manage import_legacy <sql_connection>

You should now be able to run the same command you used to test your new
database above, but now you'll see your legacy Keystone data in Essex::

    $ keystone --token ADMIN --endpoint http://127.0.0.1:35357/v2.0/ tenant-list
    +----------------------------------+----------------+---------+
    |                id                |      name      | enabled |
    +----------------------------------+----------------+---------+
    | 12edde26a6224199a66ece67b762a065 | project-y      | True    |
    | 593715ed4359404999915ea7005a7da1 | ANOTHER:TENANT | True    |
    | be57fed798b049bc9637d2be30bfa857 | coffee-tea     | True    |
    | e3c382f4757a4385b502056431763cca | customer-x     | True    |
    +----------------------------------+----------------+---------+


Migrating your Service Catalog from legacy versions of Keystone
===============================================================

While legacy Keystone deployments stored the service catalog in the database,
the service catalog in Essex is stored in a flat ``template_file``. An example
service catalog template file may be found in
``etc/default_catalog.templates``. You can change the path to your service
catalog template in ``keystone.conf`` by changing the value of
``[catalog] template_file``.

Import your legacy catalog and redirect the output to your ``template_file``::

    $ keystone-manage export_legacy_catalog <sql_connection> > <template_file>

.. NOTE::

    After executing this command, you will need to restart the Keystone
    service to see your changes.

Migrating from Nova Auth
========================

Migration of users, projects (aka tenants), roles and EC2 credentials
is supported for the Essex release of Nova. To migrate your auth
data from Nova, use the following steps:

.. NOTE::

    Before you can migrate from nova auth, you must first
    `prepare your Essex deployment`_.

Step 1: Export your data from Nova
----------------------------------

Use the following command to export your data from Nova to a ``dump_file``::

    $ nova-manage export auth > /path/to/dump

It is important to redirect the output to a file so it can be imported in the
next step.

Step 2: Import your data to Keystone
------------------------------------

Import your Nova auth data from a ``dump_file`` created with ``nova-manage``::

    $ keystone-manage import_nova_auth <dump_file>

.. NOTE::

    Users are added to Keystone with the user ID from Nova as the user name.
    Nova's projects are imported with the project ID as the tenant name. The
    password used to authenticate a user in Keystone will be the API key
    (also EC2 access key) used in Nova. Users also lose any administrative
    privileges they had in Nova. The necessary admin role must be explicitly
    re-assigned to each user.

.. NOTE::

    Users in Nova's auth system have a single set of EC2 credentials that
    works with all projects (tenants) that user can access. In Keystone, these
    credentials are scoped to a single user/tenant pair. In order to use the
    same secret keys from Nova, you must prefix each corresponding access key
    with the ID of the project used in Nova. For example, if you had access
    to the 'Beta' project in your Nova installation with the access/secret
    keys 'ACCESS'/'SECRET', you should use 'Beta:ACCESS'/'SECRET' in Keystone.
    These credentials are active once your migration is complete.

Initializing Keystone
=====================

``keystone-manage`` is designed to execute commands that cannot be administered
through the normal REST API. At the moment, the following calls are supported:

* ``db_sync``: Sync the database schema.
* ``import_legacy``: Import data from a legacy (pre-Essex) database.
* ``export_legacy_catalog``: Export service catalog from a legacy (pre-Essex) database.
* ``import_nova_auth``: Load auth data from a dump created with ``nova-manage``.

Invoking ``keystone-manage`` by itself will give you additional usage
information.

Adding Users, Tenants, and Roles with python-keystoneclient
===========================================================

User, tenants, and roles must be administered using admin credentials.
There are two ways to configure ``python-keystoneclient`` to use admin
credentials, using the either an existing token or password credentials.

Authenticating with a Token
---------------------------

.. NOTE::

    If your Keystone deployment is brand new, you will need to use this
    authentication method, along with your ``[DEFAULT] admin_token``.

To use Keystone with a token, set the following flags:

* ``--endpoint SERVICE_ENDPOINT``: allows you to specify the Keystone endpoint
  to communicate with. The default endpoint is ``http://localhost:35357/v2.0``
* ``--token SERVICE_TOKEN``: your service token

To administer a Keystone endpoint, your token should be either belong to a user
with the ``admin`` role, or, if you haven't created one yet, should be equal to
the value defined by ``[DEFAULT] admin_token`` in your ``keystone.conf``.

You can also set these variables in your environment so that they do not need
to be passed as arguments each time::

    $ export SERVICE_ENDPOINT=http://localhost:35357/v2.0
    $ export SERVICE_TOKEN=ADMIN

Authenticating with a Password
------------------------------

To administer a Keystone endpoint, the following user referenced below should
be granted the ``admin`` role.

* ``--os_username OS_USERNAME``: Name of your user
* ``--os_password OS_PASSWORD``: Password for your user
* ``--os_tenant_name OS_TENANT_NAME``: Name of your tenant
* ``--os_auth_url OS_AUTH_URL``: URL of your Keystone auth server, e.g.
  ``http://localhost:35357/v2.0``

You can also set these variables in your environment so that they do not need
to be passed as arguments each time::

    $ export OS_USERNAME=my_username
    $ export OS_PASSWORD=my_password
    $ export OS_TENANT_NAME=my_tenant

Example usage
-------------

``keystone`` is set up to expect commands in the general form of
``keystone`` ``command`` ``argument``, followed by flag-like keyword arguments to
provide additional (often optional) information. For example, the command
``user-list`` and ``tenant-create`` can be invoked as follows::

    # Using token auth env variables
    export SERVICE_ENDPOINT=http://127.0.0.1:35357/v2.0/
    export SERVICE_TOKEN=secrete_token
    keystone user-list
    keystone tenant-create --name=demo

    # Using token auth flags
    keystone --token=secrete --endpoint=http://127.0.0.1:35357/v2.0/ user-list
    keystone --token=secrete --endpoint=http://127.0.0.1:35357/v2.0/ tenant-create --name=demo

    # Using user + password + tenant_name env variables
    export OS_USERNAME=admin
    export OS_PASSWORD=secrete
    export OS_TENANT_NAME=admin
    keystone user-list
    keystone tenant-create --name=demo

    # Using user + password + tenant_name flags
    keystone --os_username=admin --os_password=secrete --os_tenant_name=admin user-list
    keystone --os_username=admin --os_password=secrete --os_tenant_name=admin tenant-create --name=demo

Tenants
-------

Tenants are the high level grouping within Keystone that represent groups of
users. A tenant is the grouping that owns virtual machines within Nova, or
containers within Swift. A tenant can have zero or more users, Users can
be associated with more than one tenant, and each tenant - user pairing can
have a role associated with it.

``tenant-create``
^^^^^^^^^^^^^^^^^

keyword arguments

* name
* description (optional, defaults to None)
* enabled (optional, defaults to True)

example::

    $ keystone tenant-create --name=demo

creates a tenant named "demo".

``tenant-delete``
^^^^^^^^^^^^^^^^^

arguments

* tenant_id

example::

    $ keystone tenant-delete f2b7b39c860840dfa47d9ee4adffa0b3

Users
-----

``user-create``
^^^^^^^^^^^^^^^

keyword arguments

* name
* pass
* email
* tenant_id (optional, defaults to None)
* enabled (optional, defaults to True)

example::

    $ keystone user-create
    --name=admin \
    --pass=secrete \
    --tenant_id=2395953419144b67955ac4bab96b8fd2 \
    --email=admin@example.com

``user-delete``
^^^^^^^^^^^^^^^

keyword arguments

* user_id

example::

    $ keystone user-delete f2b7b39c860840dfa47d9ee4adffa0b3

``user-list``
^^^^^^^^^^^^^

list users in the system, optionally by a specific tenant (identified by tenant_id)

arguments

* tenant_id (optional, defaults to None)

example::

    $ keystone user-list

``user-update``
^^^^^^^^^^^^^^^^^^^^^

arguments

* user_id

keyword arguments

* name     Desired new user name (Optional)
* email    Desired new email address (Optional)
* enabled <true|false>   Enable or disable user (Optional)


example::

    $ keystone user-update 03c84b51574841ba9a0d8db7882ac645 --email=newemail@example.com

``user-password-update``
^^^^^^^^^^^^^^^^^^^^^^^^

arguments

* user_id
* password

example::

    $ keystone user-password-update --pass foo 03c84b51574841ba9a0d8db7882ac645

Roles
-----

``role-create``
^^^^^^^^^^^^^^^

arguments

* name

example::

    $ keystone role-create --name=demo

``role-delete``
^^^^^^^^^^^^^^^

arguments

* role_id

example::

    $ keystone role-delete 19d1d3344873464d819c45f521ff9890

``role-list``
^^^^^^^^^^^^^

example::

    $ keystone role-list

``role-get``
^^^^^^^^^^^^

arguments

* role_id

example::

    $ keystone role-get 19d1d3344873464d819c45f521ff9890


``user-role-add``
^^^^^^^^^^^^^^^^^

keyword arguments

* user <user-id>
* role <role-id>
* tenant_id <tenant-id>

example::

    $ keystone user-role-add  \
      --user=96a6ebba0d4c441887aceaeced892585  \
      --role=f8dd5a2e4dc64a41b96add562d9a764e  \
      --tenant_id=2395953419144b67955ac4bab96b8fd2

``user-role-remove``
^^^^^^^^^^^^^^^^^^^^

keyword arguments

* user <user-id>
* role <role-id>
* tenant_id <tenant-id>

example::

    $ keystone user-role-remove  \
      --user=96a6ebba0d4c441887aceaeced892585  \
      --role=f8dd5a2e4dc64a41b96add562d9a764e  \
      --tenant_id=2395953419144b67955ac4bab96b8fd2

Services
--------

``service-create``
^^^^^^^^^^^^^^^^^^

keyword arguments

* name
* type
* description

example::

    $ keystone service-create \
    --name=nova \
    --type=compute \
    --description="Nova Compute Service"

``service-list``
^^^^^^^^^^^^^^^^

arguments

* service_id

example::

    $ keystone service-list

``service-get``
^^^^^^^^^^^^^^^

arguments

* service_id

example::

    $ keystone service-get 08741d8ed88242ca88d1f61484a0fe3b

``service-delete``
^^^^^^^^^^^^^^^^^^

arguments

* service_id

example::

    $ keystone service-delete 08741d8ed88242ca88d1f61484a0fe3b


Configuring the LDAP Identity Provider
===========================================================

As an alternative to the SQL Databse backing store, Keystone can Use a
Directory server to provide the Identity service.  An example Schema
for openstack would look like this::

  dn: cn=openstack,cn=org
  dc: openstack
  objectClass: dcObject
  objectClass: organizationalUnit
  ou: openstack

  dn: ou=Groups,cn=openstack,cn=org
  objectClass: top
  objectClass: organizationalUnit
  ou: groups

  dn: ou=Users,cn=openstack,cn=org
  objectClass: top
  objectClass: organizationalUnit
  ou: users

  dn: ou=Roles,cn=openstack,cn=org
  objectClass: top
  objectClass: organizationalUnit
  ou: users

The corresponding entries in the Keystone configuration file are::

  [ldap]
  url = ldap://localhost
  suffix = dc=openstack,dc=org
  user = dc=Manager,dc=openstack,dc=org
  password = badpassword
