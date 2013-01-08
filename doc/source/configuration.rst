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

Memcached and System Time
=========================

If using `memcached`_ with Keystone - e.g. using the memcache token
driver or the ``auth_token`` middleware - ensure that the system time
of memcached hosts is set to UTC.  Memcached uses the host's system
time in determining whether a key has expired, whereas Keystone sets
key expiry in UTC.  The timezone used by Keystone and memcached must
match if key expiry is to behave as expected.

.. _`memcached`: http://memcached.org/

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
* ``[signing]`` - cryptographic signatures for PKI based tokens
* ``[ssl]`` - SSL configuration
* ``[auth]`` - Authentication plugin configuration

The Keystone configuration file is expected to be named ``keystone.conf``.
When starting keystone, you can specify a different configuration file to
use with ``--config-file``. If you do **not** specify a configuration file,
keystone will look in the following directories for a configuration file, in
order:

* ``~/.keystone/``
* ``~/``
* ``/etc/keystone/``
* ``/etc/``


Authentication Plugins
----------------------

Keystone supports authentication plugins and they are specified
in the ``[auth]`` section of the configuration file. However, an
authentication plugin may also have its own section in the configuration
file. It is up to the plugin to register its own configuration options.

* ``methods`` - comma-delimited list of authentication plugin names
* ``<plugin name>`` - specify the class which handles to authentication method, in the same manner as one would specify a backend driver.

Keystone provides two authentication methods by default. ``password`` handles password authentication and ``token`` handles token authentication.

How to Implement an Authentication Plugin
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

All authentication plugins must extend the
``keystone.auth.core.AuthMethodHandler`` class and implement the
``authenticate()`` method. The ``authenticate()`` method expects the
following parameters.

* ``context`` - Keystone's request context
* ``auth_payload`` - the content of the authentication for a given method
* ``auth_context`` - user authentication context, a dictionary shared by all plugins. It contains ``method_names`` and ``extras`` by default. ``method_names`` is a list and ``extras`` is a dictionary.

If successful, the ``authenticate()`` method must provide a valid ``user_id``
in ``auth_context`` and return ``None``. ``method_name`` is used to convey
any additional authentication methods in case authentication is for re-scoping.
For example, if the authentication is for re-scoping, a plugin must append
the previous method names into ``method_names``. Also, a plugin may add any
additional information into ``extras``. Anything in ``extras`` will be
conveyed in the token's ``extras`` field.

If authentication requires multiple steps, the ``authenticate()`` method must
return the payload in the form of a dictionary for the next authentication
step.

If authentication is unsuccessful, the ``authenticate()`` method must raise a
``keystone.exception.Unauthorized`` exception.

Simply add the new plugin name to the ``methods`` list along with your plugin
class configuration in the ``[auth]`` sections of the configuration file
to deploy it.

If the plugin require addition configurations, it may register its own section
in the configuration file.

Plugins are invoked in the order in which they are specified in the ``methods``
attribute of the ``authentication`` request body. If multiple plugins are
invoked, all plugins must succeed in order to for the entire
authentication to be successful. Furthermore, all the plugins invoked must
agree on the ``user_id`` in the ``auth_context``.

Certificates for PKI
--------------------

PKI stands for Public Key Infrastructure.  Tokens are documents,
cryptographically signed using the X509 standard.  In order to work correctly
token generation requires a public/private key pair.  The public key must be
signed in an X509 certificate, and the certificate used to sign it must be
available as Certificate Authority (CA) certificate.  These files can be
generated either using the keystone-manage utility, or externally generated.
The files need to be in the locations specified by the top level Keystone
configuration file as specified in the above section.  Additionally, the
private key should only be readable by the system user that will run Keystone.
The values that specify where to read the certificates are under the
``[signing]`` section of the configuration file.  The configuration values are:

* ``token_format`` - Determines the algorithm used to generate tokens.  Can be either ``UUID`` or ``PKI``. Defaults to ``PKI``
* ``certfile`` - Location of certificate used to verify tokens.  Default is ``/etc/keystone/ssl/certs/signing_cert.pem``
* ``keyfile`` - Location of private key used to sign tokens.  Default is ``/etc/keystone/ssl/private/signing_key.pem``
* ``ca_certs`` - Location of certificate for the authority that issued the above certificate. Default is ``/etc/keystone/ssl/certs/ca.pem``
* ``key_size`` - Default is ``1024``
* ``valid_days`` - Default is ``3650``
* ``ca_password``  - Password required to read the ca_file. Default is None

Signing Certificate Issued by External CA
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

You may use a signing certificate issued by an external CA instead of generated
by keystone-manage. However, certificate issued by external CA must satisfy
the following conditions:

* all certificate and key files must be in Privacy Enhanced Mail (PEM) format
* private key files must not be protected by a password

When using signing certificate issued by an external CA, you do not need to
specify ``key_size``, ``valid_days``, and ``ca_password`` as they will be
ignored.

The basic workflow for using a signing certificate issed by an external CA involves:

1. `Request Signing Certificate from External CA`_
2. convert certificate and private key to PEM if needed
3. `Install External Signing Certificate`_


Request Signing Certificate from External CA
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

One way to request a signing certificate from an external CA is to first
generate a PKCS #10 Certificate Request Syntax (CRS) using OpenSSL CLI.

First create a certificate request configuration file (e.g. ``cert_req.conf``)::

    [ req ]
    default_bits            = 1024
    default_keyfile         = keystonekey.pem
    default_md              = sha1

    prompt                  = no
    distinguished_name      = distinguished_name

    [ distinguished_name ]
    countryName             = US
    stateOrProvinceName     = CA
    localityName            = Sunnyvale
    organizationName        = OpenStack
    organizationalUnitName  = Keystone
    commonName              = Keystone Signing
    emailAddress            = keystone@openstack.org

Then generate a CRS with OpenSSL CLI. **Do not encrypt the generated private
key. Must use the -nodes option.**

For example::

    openssl req -newkey rsa:1024 -keyout signing_key.pem -keyform PEM -out signing_cert_req.pem -outform PEM -config cert_req.conf -nodes


If everything is successfully, you should end up with ``signing_cert_req.pem``
and ``signing_key.pem``. Send ``signing_cert_req.pem`` to your CA to request a token signing certificate and make sure to ask the certificate to be in PEM format. Also, make sure your trusted CA certificate chain is also in PEM format.


Install External Signing Certificate
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Assuming you have the following already:

* ``signing_cert.pem`` - (Keystone token) signing certificate in PEM format
* ``signing_key.pem`` - corresponding (non-encrypted) private key in PEM format
* ``cacert.pem`` - trust CA certificate chain in PEM format

Copy the above to your certificate directory. For example::

    mkdir -p /etc/keystone/ssl/certs
    cp signing_cert.pem /etc/keystone/ssl/certs/
    cp signing_key.pem /etc/keystone/ssl/certs/
    cp cacert.pem /etc/keystone/ssl/certs/
    chmod -R 700 /etc/keystone/ssl/certs

**Make sure the certificate directory is root-protected.**

If your certificate directory path is different from the default ``/etc/keystone/ssl/certs``, make sure it is reflected in the ``[signing]`` section of the
configuration file.


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

Monitoring
----------

Keystone provides some basic request/response monitoring statistics out of the
box.

Enable data collection by defining a ``stats_monitoring`` filter and including
it at the beginning of any desired WSGI pipelines::

    [filter:stats_monitoring]
    paste.filter_factory = keystone.contrib.stats:StatsMiddleware.factory

    [pipeline:public_api]
    pipeline = stats_monitoring [...] public_service

Enable the reporting of collected data by defining a ``stats_reporting`` filter
and including it near the end of your ``admin_api`` WSGI pipeline (After
``*_body`` middleware and before ``*_extension`` filters is recommended)::

    [filter:stats_reporting]
    paste.filter_factory = keystone.contrib.stats:StatsExtension.factory

    [pipeline:admin_api]
    pipeline = [...] json_body stats_reporting ec2_extension [...] admin_service

Query the admin API for statistics using::

    $ curl -H 'X-Auth-Token: ADMIN' http://localhost:35357/v2.0/OS-STATS/stats

Reset collected data using::

    $ curl -H 'X-Auth-Token: ADMIN' -X DELETE http://localhost:35357/v2.0/OS-STATS/stats

SSL
---

Keystone may be configured to support 2-way SSL out-of-the-box.  The x509
certificates used by Keystone must be obtained externally and configured for use
with Keystone as described in this section.  However, a set of sample certficates
is provided in the examples/pki/certs and examples/pki/private directories with the Keystone distribution for testing.
Here is the description of each of them and their purpose:

Types of certificates
^^^^^^^^^^^^^^^^^^^^^

cacert.pem
    Certificate Authority chain to validate against.

ssl_cert.pem
    Public certificate for Keystone server.

middleware.pem
    Public and private certificate for Keystone middleware/client.

cakey.pem
    Private key for the CA.

ssl_key.pem
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

User CRUD
---------

Keystone provides a user CRUD filter that can be added to the public_api
pipeline. This user crud filter allows users to use a HTTP PATCH to change
their own password. To enable this extension you should define a
user_crud_extension filter, insert it after the ``*_body`` middleware
and before the ``public_service`` app in the public_api WSGI pipeline in
keystone.conf e.g.::

    [filter:user_crud_extension]
    paste.filter_factory = keystone.contrib.user_crud:CrudExtension.factory

    [pipeline:public_api]
    pipeline = stats_monitoring url_normalize token_auth admin_token_auth xml_body json_body debug ec2_extension user_crud_extension public_service

Each user can then change their own password with a HTTP PATCH ::

    > curl -X PATCH http://localhost:5000/v2.0/OS-KSCRUD/users/<userid> -H "Content-type: application/json"  \
    -H "X_Auth_Token: <authtokenid>" -d '{"user": {"password": "ABCD", "original_password": "DCBA"}}'

In addition to changing their password all of the users current tokens will be
deleted (if the backend used is kvs or sql)


Sample Configuration Files
--------------------------

The ``etc/`` folder distributed with Keystone contains example configuration
files for each Server application.

* ``etc/keystone.conf``
* ``etc/logging.conf.sample``
* ``etc/default_catalog.templates``

.. _`prepare your deployment`:

Preparing your deployment
=========================

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
    `prepare your deployment`_.

Step 1: Ensure your deployment can access your legacy database
--------------------------------------------------------------------

Your legacy ``keystone.conf`` contains a SQL configuration section called
``[keystone.backends.sqlalchemy]`` connection string which, by default,
looks like::

    sql_connection = sqlite:///keystone.db

This connection string needs to be accessible from your deployment (e.g.
you may need to copy your SQLite ``*.db`` file to a new server, adjust the
relative path as appropriate, or open a firewall for MySQL, etc).

Step 2: Import your legacy data
-------------------------------

Use the following command to import your old data using the value of
``sql_connection`` from step 3::

    $ keystone-manage import_legacy <sql_connection>

You should now be able to run the same command you used to test your new
database above, but now you'll see your legacy Keystone data::

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
the service catalog is stored in a flat ``template_file``. An example
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
is supported for the Essex and later releases of Nova. To migrate your auth
data from Nova, use the following steps:

.. NOTE::

    Before you can migrate from nova auth, you must first
    `prepare your deployment`_.

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
* ``pki_setup``: Initialize the certificates for PKI based tokens.

Invoking ``keystone-manage`` by itself will give you additional usage
information.

The private key used for token signing can only be read by its owner.  This
prevents unauthorized users from spuriously signing tokens.
``keystone-manage pki_setup`` Should be run as the same system user that will
be running the Keystone service to ensure proper ownership for the private key
file and the associated certificates.

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

As an alternative to the SQL Database backing store, Keystone can use a
directory server to provide the Identity service.  An example Schema
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
  ou: roles

The corresponding entries in the Keystone configuration file are::

  [ldap]
  url = ldap://localhost
  user = dc=Manager,dc=openstack,dc=org
  password = badpassword
  suffix = dc=openstack,dc=org
  use_dumb_member = False
  allow_subtree_delete = False

  user_tree_dn = ou=Users,dc=openstack,dc=com
  user_objectclass = inetOrgPerson

  tenant_tree_dn = ou=Groups,dc=openstack,dc=com
  tenant_objectclass = groupOfNames

  role_tree_dn = ou=Roles,dc=example,dc=com
  role_objectclass = organizationalRole

The default object classes and attributes are intentionally simplistic.  They
reflect the common standard objects according to the LDAP RFCs.  However,
in a live deployment,  the correct attributes can be overridden to support a
preexisting, more complex schema.  For example,  in the user object,  the
objectClass posixAccount from RFC2307 is very common.  If this is the
underlying objectclass, then the *uid* field should probably be *uidNumber* and
*username* field either *uid* or *cn*.  To change these two fields,  the
corresponding entries in the Keystone configuration file are::

  [ldap]
  user_id_attribute = uidNumber
  user_name_attribute = cn


There is a set of allowed actions per object type that you can modify
depending on your specific deployment. For example, the users are managed by
another tool and you have only read access, in such case the configuration
is::

  [ldap]
  user_allow_create = False
  user_allow_update = False
  user_allow_delete = False

  tenant_allow_create = True
  tenant_allow_update = True
  tenant_allow_delete = True

  role_allow_create = True
  role_allow_update = True
  role_allow_delete = True

There are some configuration options for filtering users, tenants and roles,
if the backend is providing too much output, in such case the configuration
will look like::
  
  [ldap]
  user_filter = (memberof=CN=openstack-users,OU=workgroups,DC=openstack,DC=com)
  tenant_filter =
  role_filter =

In case that the directory server does not have an attribute enabled of type
boolean for the user, there is several configuration parameters that can be used
to extract the value from an integer attribute like in Active Directory::

  [ldap]
  user_enabled_attribute = userAccountControl
  user_enabled_mask      = 2
  user_enabled_default   = 512

In this case the attribute is an integer and the enabled attribute is listed
in bit 1, so the if the mask configured *user_enabled_mask* is different from 0,
it gets the value from the field *user_enabled_attribute* and it makes an ADD
operation with the value indicated on *user_enabled_mask* and if the value matches
the mask then the account is disabled.

It also saves the value without mask to the user identity in the attribute
*enabled_nomask*. This is needed in order to set it back in case that we need to
change it to enable/disable a user because it contains more information than the 
status like password expiration. Last setting *user_enabled_mask* is needed in order
to create a default value on the integer attribute (512 = NORMAL ACCOUNT on AD)

In case of Active Directory the classes and attributes could not match the
specified classes in the LDAP module so you can configure them like::

  [ldap]
  user_objectclass         = person
  user_id_attribute        = cn
  user_name_attribute      = cn
  user_mail_attribute      = mail
  user_enabled_attribute   = userAccountControl
  user_enabled_mask        = 2
  user_enabled_default     = 512
  user_attribute_ignore    = tenant_id,tenants
  tenant_objectclass       = groupOfNames
  tenant_id_attribute      = cn
  tenant_member_attribute  = member
  tenant_name_attribute    = ou
  tenant_desc_attribute    = description
  tenant_enabled_attribute = extensionName
  tenant_attribute_ignore  =
  role_objectclass         = organizationalRole
  role_id_attribute        = cn
  role_name_attribute      = ou
  role_member_attribute    = roleOccupant
  role_attribute_ignore    =
