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

====================
Configuring Keystone
====================

Config Files
============

Once keystone is installed, keystone is configured via a primary configuration
file (``etc/keystone.conf``), a PasteDeploy configuration file
(``etc/keystone-paste.ini``), possibly a separate logging configuration file,
and initializing data into keystone using the command line client.

The keystone configuration files are an ``ini`` file format based on Paste_, a
common system used to configure Python WSGI based applications. The PasteDeploy
configuration entries (WSGI pipeline definitions) can be provided in a separate
``keystone-paste.ini`` file, while general and driver-specific configuration
parameters are in the primary configuration file ``keystone.conf``.

.. NOTE::

   Since keystone's PasteDeploy configuration file has been separated
   from the main keystone configuration file, ``keystone.conf``, all
   local configuration or driver-specific configuration parameters must
   go in the main keystone configuration file instead of the PasteDeploy
   configuration file, i.e. configuration in ``keystone-paste.ini``
   is not supported.

Sample Configuration Files
--------------------------

The ``etc/`` folder distributed with keystone contains example configuration
files for each Server application.

* ``etc/keystone.conf.sample``
* ``etc/keystone-paste.ini``
* ``etc/logging.conf.sample``
* ``etc/default_catalog.templates``
* ``etc/sso_callback_template.html``

``keystone.conf`` sections
--------------------------

The primary configuration file is organized into the following sections:

* ``[DEFAULT]`` - General configuration
* ``[assignment]`` - Assignment system driver configuration
* ``[auth]`` - Authentication plugin configuration
* ``[cache]`` - Caching layer configuration
* ``[catalog]`` - Service catalog driver configuration
* ``[credential]`` - Credential system driver configuration
* ``[domain_config]`` - Domain configuration
* ``[endpoint_filter]`` - Endpoint filtering configuration
* ``[endpoint_policy]`` - Endpoint policy configuration
* ``[federation]`` - Federation driver configuration
* ``[fernet_tokens]`` - Fernet token configuration
* ``[identity]`` - Identity system driver configuration
* ``[identity_mapping]`` - Identity mapping system driver configuration
* ``[kvs]`` - KVS storage backend configuration
* ``[ldap]`` - LDAP configuration options
* ``[memcache]`` - Memcache configuration options
* ``[oauth1]`` - OAuth 1.0a system driver configuration
* ``[paste_deploy]`` - Pointer to the PasteDeploy configuration file
* ``[policy]`` - Policy system driver configuration for RBAC
* ``[resource]`` - Resource system driver configuration
* ``[revoke]`` - Revocation system driver configuration
* ``[role]`` - Role system driver configuration
* ``[saml]`` - SAML configuration options
* ``[security_compliance]`` - Security compliance configuration
* ``[shadow_users]`` - Shadow user configuration
* ``[signing]`` - Cryptographic signatures for PKI based tokens
* ``[token]`` - Token driver & token provider configuration
* ``[tokenless_auth]`` - Tokenless authentication configuration
* ``[trust]`` - Trust configuration

The keystone primary configuration file is expected to be named
``keystone.conf``. When starting keystone, you can specify a different
configuration file to use with ``--config-file``. If you do **not** specify a
configuration file, keystone will look in the following directories for a
configuration file, in order:

* ``~/.keystone/``
* ``~/``
* ``/etc/keystone/``
* ``/etc/``

PasteDeploy configuration file is specified by the ``config_file`` parameter in
``[paste_deploy]`` section of the primary configuration file. If the parameter
is not an absolute path, then keystone looks for it in the same directories as
above. If not specified, WSGI pipeline definitions are loaded from the primary
configuration file.

Bootstrapping Keystone with ``keystone-manage bootstrap``
=========================================================

Setting up projects, users, and roles
-------------------------------------

The ``keystone-manage bootstrap`` command will create a user, project and role,
and will assign the newly created role to the newly created user on the newly
created project. By default, the names of these new resources will be called
``admin``.

The defaults may be overridden by calling ``--bootstrap-username``,
``--bootstrap-project-name`` and ``--bootstrap-role-name``. Each of these have
an environment variable equivalent: ``OS_BOOTSTRAP_USERNAME``,
``OS_BOOTSTRAP_PROJECT_NAME`` and ``OS_BOOTSTRAP_ROLE_NAME``.

A user password must also be supplied. This can be passed in as either
``--bootstrap-password``, or set as an environment variable using
``OS_BOOTSTRAP_PASSWORD``.

Optionally, if specified by ``--bootstrap-public-url``,
``--bootstrap-admin-url`` and/or ``--bootstrap-internal-url`` or the equivalent
environment variables, the command will create an identity service with the
specified endpoint information. You may also configure the
``--bootstrap-region-id`` and ``--bootstrap-service-name`` for the endpoints to
your deployment's requirements.

.. NOTE::

    It is strongly encouraged to configure the identity service and its
    endpoints while bootstrapping keystone.

Minimally, keystone can be bootstrapped with:

.. code-block:: bash

    $ keystone-manage bootstrap --bootstrap-password s3cr3t

Verbosely, keystone can be bootstrapped with:

.. code-block:: bash

    $ keystone-manage bootstrap \
        --bootstrap-password s3cr3t \
        --bootstrap-username admin \
        --bootstrap-project-name admin \
        --bootstrap-role-name admin \
        --bootstrap-service-name keystone \
        --bootstrap-region-id RegionOne \
        --bootstrap-admin-url http://localhost:35357 \
        --bootstrap-public-url http://localhost:5000 \
        --bootstrap-internal-url http://localhost:5000

This will create an ``admin`` user with the ``admin`` role on the ``admin``
project. The user will have the password specified in the command. Note that
both the user and the project will be created in the ``default`` domain. By not
creating an endpoint in the catalog users will need to provide endpoint
overrides to perform additional identity operations.

By creating an ``admin`` user and an identity endpoint deployers may
authenticate to keystone and perform identity operations like creating
additional services and endpoints using that ``admin`` user. This will preclude
the need to ever use or configure the ``admin_token`` (described below).

To test a proper configuration, a user can use OpenStackClient CLI:

.. code-block:: bash

    $ openstack project list --os-username admin --os-project-name admin \
        --os-user-domain-id default --os-project-domain-id default \
        --os-identity-api-version 3 --os-auth-url http://localhost:5000 \
        --os-password s3cr3t

Bootstrapping Keystone with ``ADMIN_TOKEN``
===========================================

.. NOTE::

    It is strongly recommended to configure the identity service with the
     ``keystone-manage bootstrap`` command and not the ``ADMIN_TOKEN``.


Admin Token
-----------

For a default installation of Keystone, before you can use the REST API, you
need to define an authorization token. This is configured in ``keystone.conf``
file under the section ``[DEFAULT]``. In the sample file provided with the
Keystone project, the line defining this token is::

    [DEFAULT]
    admin_token = ADMIN

A "shared secret" that can be used to bootstrap Keystone. This token does not
represent a user, and carries no explicit authorization.
To disable in production (highly recommended), remove
``AdminTokenAuthMiddleware`` from your paste application pipelines (for example,
in ``keystone-paste.ini``)

Setting up projects, users, and roles
-------------------------------------

You need to minimally define a project, user, and role to link the project and
user as the most basic set of details to get other services authenticating
and authorizing with Keystone.

You will also want to create service users for nova, glance, swift, etc. to
be able to use to authenticate users against Keystone. The ``auth_token``
middleware supports using either the shared secret described above as
`admin_token` or users for each service.

Setting up other OpenStack Services
===================================

Creating Service Users
----------------------

To configure the OpenStack services with service users, we need to create
a project for all the services, and then users for each of the services. We
then assign those service users an ``admin`` role on the service project. This
allows them to validate tokens - and to authenticate and authorize other user
requests.

Create a project for the services, typically named ``service`` (however, the
name can be whatever you choose):

.. code-block:: bash

    $ openstack project create service

Create service users for ``nova``, ``glance``, ``swift``, and ``neutron``
(or whatever subset is relevant to your deployment):

.. code-block:: bash

    $ openstack user create nova --password Sekr3tPass --project service

Repeat this for each service you want to enable.

Create an administrative role for the service accounts, typically named
``admin`` (however the name can be whatever you choose). For adding the
administrative role to the service accounts, you'll need to know the
name of the role you want to add. If you don't have it handy, you can look it
up quickly with:

.. code-block:: bash

    $ openstack role list

Once you have it, grant the administrative role to the service users.

.. code-block:: bash

    $ openstack role add admin --project service --user nova

Defining Services
-----------------

Keystone also acts as a service catalog to let other OpenStack systems know
where relevant API endpoints exist for OpenStack Services. The OpenStack
Dashboard, in particular, uses this heavily - and this **must** be configured
for the OpenStack Dashboard to properly function.

The endpoints for these services are defined in a template, an example of
which is in the project as the file ``etc/default_catalog.templates``.

Keystone supports two means of defining the services, one is the catalog
template, as described above - in which case everything is detailed in that
template.

The other is a SQL backend for the catalog service, in which case after
Keystone is online, you need to add the services to the catalog:

.. code-block:: bash

    $ openstack service create compute --name nova \
                                    --description "Nova Compute Service"
    $ openstack service create ec2 --name ec2 \
                                   --description "EC2 Compatibility Layer"
    $ openstack service create image --name glance \
                                      --description "Glance Image Service"
    $ openstack service create identity --name keystone \
                                        --description "Keystone Identity Service"
    $ openstack service create object-store --name swift \
                                     --description "Swift Service"


Identity sources
================

One of the most impactful decisions you'll have to make when configuring
keystone is deciding how you want keystone to source your identity data.
Keystone supports several different choices that will substantially impact how
you'll configure, deploy, and interact with keystone.

You can also mix-and-match various sources of identity (see `Domain-specific
Drivers`_ below for an example). For example, you can store OpenStack service
users and their passwords in SQL, manage customers in LDAP, and authenticate
employees via SAML federation.

.. support_matrix:: identity-support-matrix.ini

.. Domain-specific Drivers:

Domain-specific Drivers
-----------------------

Keystone supports the option (disabled by default) to specify identity driver
configurations on a domain by domain basis, allowing, for example, a specific
domain to have its own LDAP or SQL server. This is configured by specifying the
following options:

.. code-block:: ini

 [identity]
 domain_specific_drivers_enabled = True
 domain_config_dir = /etc/keystone/domains

Setting ``domain_specific_drivers_enabled`` to ``True`` will enable this
feature, causing keystone to look in the ``domain_config_dir`` for config files
of the form::

 keystone.<domain_name>.conf

Options given in the domain specific configuration file will override those in
the primary configuration file for the specified domain only. Domains without a
specific configuration file will continue to use the options from the primary
configuration file.

Keystone also supports the ability to store the domain-specific configuration
options in the keystone SQL database, managed via the Identity API, as opposed
to using domain-specific configuration files.

This capability (which is disabled by default) is enabled by specifying the
following options in the main keystone configuration file:

.. code-block:: ini

  [identity]
  domain_specific_drivers_enabled = true
  domain_configurations_from_database = true

Once enabled, any existing domain-specific configuration files in the
configuration directory will be ignored and only those domain-specific
configuration options specified via the Identity API will be used.

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
sha256 generator as default, which produces regeneratable public IDs. The
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

Authentication Plugins
======================

.. NOTE::

    This feature is only supported by keystone for the Identity API v3 clients.

Keystone supports authentication plugins and they are specified in the
``[auth]`` section of the configuration file. However, an authentication plugin
may also have its own section in the configuration file. It is up to the plugin
to register its own configuration options.

* ``methods`` - comma-delimited list of authentication plugin names
* ``<plugin name>`` - specify the class which handles to authentication method,
  in the same manner as one would specify a backend driver.

Keystone provides three authentication methods by default. ``password`` handles
password authentication and ``token`` handles token authentication.
``external`` is used in conjunction with authentication performed by a
container web server that sets the ``REMOTE_USER`` environment variable. For
more details, refer to :doc:`External Authentication <external-auth>`.

How to Implement an Authentication Plugin
-----------------------------------------

All authentication plugins must extend the
:class:`keystone.auth.plugins.base.AuthMethodHandler` class and implement the
``authenticate()`` method. The ``authenticate()`` method expects the following
parameters.

* ``context`` - keystone's request context
* ``auth_payload`` - the content of the authentication for a given method
* ``auth_context`` - user authentication context, a dictionary shared by all
  plugins. It contains ``method_names`` and ``extras`` by default.
  ``method_names`` is a list and ``extras`` is a dictionary.

If successful, the ``authenticate()`` method must provide a valid ``user_id``
in ``auth_context`` and return ``None``. ``method_name`` is used to convey any
additional authentication methods in case authentication is for re-scoping. For
example, if the authentication is for re-scoping, a plugin must append the
previous method names into ``method_names``. Also, a plugin may add any
additional information into ``extras``. Anything in ``extras`` will be conveyed
in the token's ``extras`` field.

If authentication requires multiple steps, the ``authenticate()`` method must
return the payload in the form of a dictionary for the next authentication
step.

If authentication is unsuccessful, the ``authenticate()`` method must raise a
:class:`keystone.exception.Unauthorized` exception.

Simply add the new plugin name to the ``methods`` list along with your plugin
class configuration in the ``[auth]`` sections of the configuration file to
deploy it.

If the plugin requires additional configurations, it may register its own
section in the configuration file.

Plugins are invoked in the order in which they are specified in the ``methods``
attribute of the ``authentication`` request body. If multiple plugins are
invoked, all plugins must succeed in order to for the entire authentication to
be successful. Furthermore, all the plugins invoked must agree on the
``user_id`` in the ``auth_context``.

The ``REMOTE_USER`` environment variable is only set from a containing
webserver. However, to ensure that a user must go through other authentication
mechanisms, even if this variable is set, remove ``external`` from the list of
plugins specified in ``methods``. This effectively disables external
authentication. For more details, refer to :doc:`ExternalAuthentication
<external-auth>`.

Token Drivers and Providers
===========================

Token Persistence Driver
------------------------

Keystone supports customizable token persistence drivers. These can be
specified in the ``[token]`` section of the configuration file. Keystone
provides two non-test persistence backends. These can be set with the
``[token] driver`` configuration option.

The drivers keystone provides are:

* ``kvs`` - The key-value store token persistence engine. Implemented by
  :class:`keystone.token.persistence.backends.kvs.Token`

* ``sql`` - The SQL-based (default) token persistence engine. Implemented by
  :class:`keystone.token.persistence.backends.sql.Token`


Token Provider
--------------

Keystone supports customizable token providers and it is specified in the
``[token]`` section of the configuration file. Keystone provides two token
provider options (``fernet`` and ``uuid``, with ``fernet`` being the default).
Users may register their own token provider by configuring the
``[token] provider`` property.

* ``fernet`` - A Fernet based token provider. Implemented by
  :class:`keystone.token.providers.fernet.Provider`

* ``uuid`` - A UUID based token provider. Implemented by
  :class:`keystone.token.providers.uuid.Provider`


UUID or Fernet?
^^^^^^^^^^^^^^^
Each token format uses different technologies to achieve various performance,
scaling and architectural requirements.

UUID tokens contain randomly generated UUID4 IDs that are issued and
validated by the identity service. They are encoded using their hex digest for
transport and are thus URL-friendly. They must be persisted by the identity
service in order to be later validated. Revoking them is simply a matter of
deleting them from the token persistence backend.

Fernet tokens contain a limited amount of identity and authorization data in a
`MessagePacked <http://msgpack.org/>`_ payload. The payload is then wrapped as
a `Fernet <https://github.com/fernet/spec>`_ message for transport, where
Fernet provides the required web safe characteristics for use in URLs and
headers. Fernet tokens require symmetric encryption keys which can be
established using ``keystone-manage fernet_setup`` and periodically rotated
using ``keystone-manage fernet_rotate``.

.. WARNING::
    UUID and Fernet tokens are both bearer tokens, meaning that they
    must be protected from unnecessary disclosure to prevent unauthorized
    access.

.. support_matrix:: token-support-matrix.ini

Encryption Keys for Fernet Tokens
=================================

``keystone-manage fernet_setup`` will attempt to create a key repository as
configured in the ``[fernet_tokens]`` section of ``keystone.conf`` and
bootstrap it with encryption keys.

A single 256-bit key is actually composed of two smaller keys: a 128-bit key
used for SHA256 HMAC signing and a 128-bit key used for AES encryption. See the
`Fernet token <https://github.com/fernet/spec>`_ specification for more detail.

``keystone-manage fernet_rotate`` will rotate encryption keys through the
following states:

* **Staged key**: In a key rotation, a new key is introduced into the rotation
  in this state. Only one key is considered to be the *staged* key at any given
  time. This key will become the *primary* during the *next* key rotation. This
  key is only used to validate tokens and serves to avoid race conditions in
  multi-node deployments (all nodes should recognize all *primary* keys in the
  deployment at all times). In a multi-node keystone deployment this would
  allow for the *staged* key to be replicated to all keystone nodes before
  being promoted to *primary* on a single node. This prevents the case where a
  *primary* key is created on one keystone node and tokens encrypted/signed with
  that new *primary* are rejected on another keystone node because the new
  *primary* doesn't exist there yet.

* **Primary key**: In a key rotation, the old *staged* key is promoted to be
  the *primary*. Only one key is considered to be the *primary* key at any
  given time. This is the key used to generate new tokens. This key is also
  used to validate previously generated tokens.

* **Secondary keys**: In a key rotation, the old *primary* key is demoted to be
  a *secondary* key. *Secondary* keys are only used to validate previously
  generated tokens. You can maintain any number of *secondary* keys, up to
  ``[fernet_tokens] max_active_keys`` (where "active" refers to the sum of all
  recognized keys in any state: *staged*, *primary* or *secondary*). When
  ``max_active_keys`` is exceeded during a key rotation, the oldest keys are
  discarded.

When a new primary key is created, all new tokens will be encrypted using the
new primary key. The old primary key is demoted to a secondary key, which can
still be used for validating tokens. Excess secondary keys (beyond
``[fernet_tokens] max_active_keys``) are revoked. Revoked keys are permanently
deleted.

Rotating keys too frequently, or with ``[fernet_tokens] max_active_keys`` set
too low, will cause tokens to become invalid prior to their expiration. As
tokens may be fetched beyond there initial expiration period keys should not be
fully rotated within the period of ``[token] expiration`` + ``[token]
allow_expired_window`` seconds to prevent the tokens becoming unavailable.

Caching Layer
=============

Keystone's configuration file offers two separate sections related to caching,
``[memcache]`` and ``[cache]``. The ``[memcache]`` section provides caching
options to configure memcache backends. For example, if your deployment issues
UUID tokens (``[token] provider = uuid``) and your token storage driver is
memcache (``[token] driver = kvs``), the configuration options in the
``[memcache]`` section will effect token storage behavior. The ``[cache]``
section is provided through the ``oslo.cache`` library and consists of options
to configure the caching of data between a particular keystone subsystem (e.g.
``token``, ``identity``, etc) and its configured storage backend. For example,
if your deployment's identity backend is using SQL (``[identity] driver =
sql``) and you have caching enabled (``[cache] enabled = true``),
``oslo.cache`` will cache responses from SQL improving the overall performance
of the identity subsystem. The options in the ``[cache]`` section will effect
the caching layer in-between a keystone subsystem and its storage backend.

Keystone uses the `dogpile.cache`_ library which allows for flexible cache
backends. The majority of the caching configuration options are set in the
``[cache]`` section.  However, each section that has the capability to be
cached usually has a ``caching`` boolean value that will toggle caching for
that specific section.  The current default behavior is that global and
subsystem caching is enabled.

``[cache]`` configuration section
---------------------------------

* ``enabled`` - enables/disables caching across all of keystone
* ``debug_cache_backend`` - enables more in-depth logging from the cache
  backend (get, set, delete, etc)
* ``backend`` - the caching backend module to use e.g.
  ``dogpile.cache.memcached``

    .. NOTE::
        A given ``backend`` must be registered with ``dogpile.cache`` before it
        can be used. The default backend is the keystone no-op backend
        (``keystone.common.cache.noop``). If caching is desired a different
        backend will need to be specified. Current functional backends are:

    * ``dogpile.cache.memcached`` - Memcached backend using the standard
      `python-memcached`_ library (recommended for use with Apache httpd with
      ``mod_wsgi``)
    * ``dogpile.cache.pylibmc`` - Memcached backend using the `pylibmc`_
      library
    * ``dogpile.cache.bmemcached`` - Memcached using `python-binary-memcached`_
      library.
    * ``dogpile.cache.redis`` - `Redis`_ backend
    * ``dogpile.cache.dbm`` - local DBM file backend
    * ``dogpile.cache.memory`` - in-memory cache
    * ``oslo_cache.mongo`` - MongoDB as caching backend
    * ``oslo_cache.memcache_pool`` - Memcache with pooling.
      This implementation also provides client connection re-use.

        .. WARNING::
            ``dogpile.cache.memory`` is not suitable for use outside of unit
            testing as it does not cleanup its internal cache on cache
            expiration, does not provide isolation to the cached data (values
            in the store can be inadvertently changed without extra layers of
            data protection added), and does not share cache between processes.
            This means that caching and cache invalidation will not be
            consistent or reliable when using ``keystone`` and the
            ``dogpile.cache.memory`` backend under any real workload.

* ``expiration_time`` - int, the default length of time to cache a specific
  value. A value of ``0`` indicates to not cache anything. It is recommended
  that the ``enabled`` option be used to disable cache instead of setting this
  to ``0``.
* ``backend_argument`` - an argument passed to the backend when instantiated
  ``backend_argument`` should be specified once per argument to be passed to
  the backend and in the format of ``<argument name>:<argument value>``. e.g.:
  ``backend_argument = host:localhost``
* ``proxies`` - comma delimited list of `ProxyBackends`_ e.g.
  ``my.example.Proxy, my.example.Proxy2``

Current keystone systems that have caching capabilities:
    * ``token``
        The token system has a separate ``cache_time`` configuration option,
        that can be set to a value above or below the global
        ``expiration_time`` default, allowing for different caching behavior
        from the other systems in keystone. This option is set in the
        ``[token]`` section of the configuration file.

        The Token Revocation List cache time is handled by the configuration
        option ``revocation_cache_time`` in the ``[token]`` section. The
        revocation list is refreshed whenever a token is revoked. It typically
        sees significantly more requests than specific token retrievals or
        token validation calls.
    * ``resource``
        The resource system has a separate ``cache_time`` configuration option,
        that can be set to a value above or below the global
        ``expiration_time`` default, allowing for different caching behavior
        from the other systems in keystone. This option is set in the
        ``[resource]`` section of the configuration file.

        Currently ``resource`` has caching for ``project`` and ``domain``
        specific requests (primarily around the CRUD actions).  The
        ``list_projects`` and ``list_domains`` methods are not subject to
        caching.

        .. WARNING::
            Be aware that if a read-only ``resource`` backend is in use, the
            cache will not immediately reflect changes on the back end.  Any
            given change may take up to the ``cache_time`` (if set in the
            ``[resource]`` section of the configuration) or the global
            ``expiration_time`` (set in the ``[cache]`` section of the
            configuration) before it is reflected. If this type of delay (when
            using a read-only ``resource`` backend) is an issue, it is
            recommended that caching be disabled on ``resource``. To disable
            caching specifically on ``resource``, in the ``[resource]`` section
            of the configuration set ``caching`` to ``False``.
    * ``role``
        Currently ``role`` has caching for ``get_role``, but not for ``list_roles``.
        The role system has a separate ``cache_time`` configuration option,
        that can be set to a value above or below the global ``expiration_time``
        default, allowing for different caching behavior from the other systems in
        keystone.  This option is set in the ``[role]`` section of the
        configuration file.

        .. WARNING::
            Be aware that if a read-only ``role`` backend is in use, the cache
            will not immediately reflect changes on the back end.  Any given change
            may take up to the ``cache_time`` (if set in the ``[role]``
            section of the configuration) or the global ``expiration_time`` (set in
            the ``[cache]`` section of the configuration) before it is reflected.
            If this type of delay (when using a read-only ``role`` backend) is
            an issue, it is recommended that caching be disabled on ``role``.
            To disable caching specifically on ``role``, in the ``[role]``
            section of the configuration set ``caching`` to ``False``.

For more information about the different backends (and configuration options):
    * `dogpile.cache.backends.memory`_
    * `dogpile.cache.backends.memcached`_
    * `dogpile.cache.backends.redis`_
    * `dogpile.cache.backends.file`_

.. _`dogpile.cache`: http://dogpilecache.readthedocs.org/en/latest/
.. _`python-memcached`: http://www.tummy.com/software/python-memcached/
.. _`pylibmc`: http://sendapatch.se/projects/pylibmc/index.html
.. _`python-binary-memcached`: https://github.com/jaysonsantos/python-binary-memcached
.. _`Redis`: http://redis.io/
.. _`dogpile.cache.backends.memory`: http://dogpilecache.readthedocs.org/en/latest/api.html#memory-backend
.. _`dogpile.cache.backends.memcached`: http://dogpilecache.readthedocs.org/en/latest/api.html#memcached-backends
.. _`dogpile.cache.backends.redis`: http://dogpilecache.readthedocs.org/en/latest/api.html#redis-backends
.. _`dogpile.cache.backends.file`: http://dogpilecache.readthedocs.org/en/latest/api.html#file-backends
.. _`ProxyBackends`: http://dogpilecache.readthedocs.org/en/latest/api.html#proxy-backends


Certificates for PKI
====================

PKI stands for Public Key Infrastructure. Tokens are documents,
cryptographically signed using the X509 standard. In order to work correctly
token generation requires a public/private key pair. The public key must be
signed in an X509 certificate, and the certificate used to sign it must be
available as Certificate Authority (CA) certificate. These files can be either
externally generated or generated using the ``keystone-manage`` utility.

The files used for signing and verifying certificates are set in the keystone
configuration file. The private key should only be readable by the system user
that will run keystone. The values that specify the certificates are under the
``[signing]`` section of the configuration file. The configuration values are:

* ``certfile`` - Location of certificate used to verify tokens. Default is
  ``/etc/keystone/ssl/certs/signing_cert.pem``
* ``keyfile`` - Location of private key used to sign tokens. Default is
  ``/etc/keystone/ssl/private/signing_key.pem``
* ``ca_certs`` - Location of certificate for the authority that issued the
  above certificate. Default is ``/etc/keystone/ssl/certs/ca.pem``

Signing Certificate Issued by External CA
-----------------------------------------

You may use a signing certificate issued by an external CA instead of generated
by ``keystone-manage``. However, certificate issued by external CA must satisfy
the following conditions:

* all certificate and key files must be in Privacy Enhanced Mail (PEM) format
* private key files must not be protected by a password

The basic workflow for using a signing certificate issued by an external CA
involves:

1. `Request Signing Certificate from External CA`_
2. Convert certificate and private key to PEM if needed
3. `Install External Signing Certificate`_


Request Signing Certificate from External CA
--------------------------------------------

One way to request a signing certificate from an external CA is to first
generate a PKCS #10 Certificate Request Syntax (CRS) using OpenSSL CLI.

First create a certificate request configuration file (e.g. ``cert_req.conf``):

.. code-block:: ini

    [ req ]
    default_bits            = 2048
    default_keyfile         = keystonekey.pem
    default_md              = default

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
key. The -nodes option must be used.**

For example:

.. code-block:: bash

    $ openssl req -newkey rsa:2048 -keyout signing_key.pem -keyform PEM -out signing_cert_req.pem -outform PEM -config cert_req.conf -nodes


If everything is successfully, you should end up with ``signing_cert_req.pem``
and ``signing_key.pem``. Send ``signing_cert_req.pem`` to your CA to request a
token signing certificate and make sure to ask the certificate to be in PEM
format. Also, make sure your trusted CA certificate chain is also in PEM
format.


Install External Signing Certificate
------------------------------------

Assuming you have the following already:

* ``signing_cert.pem`` - (Keystone token) signing certificate in PEM format
* ``signing_key.pem`` - corresponding (non-encrypted) private key in PEM format
* ``cacert.pem`` - trust CA certificate chain in PEM format

Copy the above to your certificate directory. For example:

.. code-block:: bash

    $ mkdir -p /etc/keystone/ssl/certs
    $ cp signing_cert.pem /etc/keystone/ssl/certs/
    $ cp signing_key.pem /etc/keystone/ssl/certs/
    $ cp cacert.pem /etc/keystone/ssl/certs/
    $ chmod -R 700 /etc/keystone/ssl/certs

**Make sure the certificate directory is root-protected.**

If your certificate directory path is different from the default
``/etc/keystone/ssl/certs``, make sure it is reflected in the ``[signing]``
section of the configuration file.


Generating a Signing Certificate using ``pki_setup``
----------------------------------------------------

``keystone-manage pki_setup`` is a development tool. We recommend that you do
not use ``keystone-manage pki_setup`` in a production environment. In
production, an external CA should be used instead. This is because the CA
secret key should generally be kept apart from the token signing secret keys so
that a compromise of a node does not lead to an attacker being able to generate
valid signed keystone tokens. This is a low probability attack vector, as
compromise of a keystone service machine's filesystem security almost certainly
means the attacker will be able to gain direct access to the token backend.

When using the ``keystone-manage pki_setup`` to generate the certificates, the
following configuration options in the ``[signing]`` section are used:

* ``ca_key`` - Default is ``/etc/keystone/ssl/private/cakey.pem``
* ``key_size`` - Default is ``2048``
* ``valid_days`` - Default is ``3650``

If ``keystone-manage pki_setup`` is not used then these options don't need to
be set.


Service Catalog
===============

Keystone provides two configuration options for managing a service catalog.

SQL-based Service Catalog (``sql.Catalog``)
-------------------------------------------

A dynamic database-backed driver fully supporting persistent configuration.

``keystone.conf`` example:

.. code-block:: ini

    [catalog]
    driver = sql

.. NOTE::

    A `template_file` does not need to be defined for the sql based catalog.

To build your service catalog using this driver, see the built-in help:

.. code-block:: bash

    $ openstack --help
    $ openstack service create --help
    $ openstack endpoint create --help

File-based Service Catalog (``templated.Catalog``)
--------------------------------------------------

The templated catalog is an in-memory backend initialized from a read-only
``template_file``. Choose this option only if you know that your service
catalog will not change very much over time.

.. NOTE::

    Attempting to change your service catalog against this driver will result
    in ``HTTP 501 Not Implemented`` errors. This is the expected behavior. If
    you want to use these commands, you must instead use the SQL-based Service
    Catalog driver.

``keystone.conf`` example:

.. code-block:: ini

    [catalog]
    driver = templated
    template_file = /opt/stack/keystone/etc/default_catalog.templates

The value of ``template_file`` is expected to be an absolute path to your
service catalog configuration. An example ``template_file`` is included in
keystone, however you should create your own to reflect your deployment.

Endpoint Filtering
==================

Endpoint Filtering enables creation of ad-hoc catalogs for each project-scoped
token request.

Configure the endpoint filter catalog driver in the ``[catalog]`` section.
For example:

.. code-block:: ini

    [catalog]
    driver = catalog_sql

In the ``[endpoint_filter]`` section, set ``return_all_endpoints_if_no_filter``
to ``False`` to return an empty catalog if no associations are made.
For example:

.. code-block:: ini

    [endpoint_filter]
    return_all_endpoints_if_no_filter = False

See `API Specification for Endpoint Filtering <https://developer.openstack.org/
api-ref/identity/v3-ext/#os-ep-filter-api>`_ for the details of API definition.

Endpoint Policy
===============

The Endpoint Policy feature provides associations between service endpoints
and policies that are already stored in the Identity server and referenced
by a policy ID.

Configure the endpoint policy backend driver in the ``[endpoint_policy]``
section. For example:

.. code-block:: ini

    [endpoint_policy]
    driver = sql

See `API Specification for Endpoint Policy <https://specs.openstack.org/
openstack/keystone-specs/api/v3/identity-api-v3-os-endpoint-policy.html>`_
for the details of API definition.

Logging
=======

Logging is configured externally to the rest of keystone. Configure the path to
your logging configuration file using the ``[DEFAULT] log_config_append``
option of ``keystone.conf``. If you wish to route all your logging through
syslog, set the ``[DEFAULT] use_syslog`` option.

A sample ``log_config_append`` file is included with the project at
``etc/logging.conf.sample``. Like other OpenStack projects, keystone uses the
`Python logging module`_, which includes extensive configuration options for
choosing the output levels and formats.

.. _Paste: http://pythonpaste.org/
.. _`Python logging module`: http://docs.python.org/library/logging.html

SSL
===

A secure deployment should have keystone running in a web server (such as
Apache httpd), or behind an SSL terminator.


OAuth1 1.0a
===========

The OAuth 1.0a feature provides the ability for Identity users to delegate
roles to third party consumers via the OAuth 1.0a specification.

To enable OAuth1:

1. Add the oauth1 driver to the ``[oauth1]`` section in ``keystone.conf``. For
   example:

.. code-block:: ini

    [oauth1]
    driver = sql

2. Add the ``oauth1`` authentication method to the ``[auth]`` section in
   ``keystone.conf``:

.. code-block:: ini

    [auth]
    methods = external,password,token,oauth1

3. If deploying under Apache httpd with ``mod_wsgi``, set the
   `WSGIPassAuthorization` to allow the OAuth Authorization headers to pass
   through `mod_wsgi`. For example, add the following to the keystone virtual
   host file:

.. code-block:: ini

    WSGIPassAuthorization On

See `API Specification for OAuth 1.0a <https://specs.openstack.org/openstack/
keystone-specs/api/v3/identity-api-v3-os-oauth1-ext.html>`_ for the details of
API definition.


Revocation Events
=================

The Revocation Events feature provides a list of token revocations. Each event
expresses a set of criteria which describes a set of tokens that are
no longer valid.

Add the revoke backend driver to the ``[revoke]`` section in
``keystone.conf``. For example:

.. code-block:: ini

    [revoke]
    driver = sql

See `API Specification for Revocation Events <https://specs.openstack.org/
openstack/keystone-specs/api/v3/identity-api-v3-os-revoke-ext.html>`_ for
the details of API definition.


Token Binding
=============

Token binding refers to the practice of embedding information from external
authentication providers (like a company's Kerberos server) inside the token
such that a client may enforce that the token only be used in conjunction with
that specified authentication. This is an additional security mechanism as it
means that if a token is stolen it will not be usable without also providing
the external authentication.

To activate token binding you must specify the types of authentication that
token binding should be used for in ``keystone.conf`` e.g.:

.. code-block:: ini

    [token]
    bind = kerberos

Currently only ``kerberos`` is supported.

To enforce checking of token binding the ``enforce_token_bind`` parameter
should be set to one of the following modes:

* ``disabled`` disable token bind checking
* ``permissive`` enable bind checking, if a token is bound to a mechanism that
  is unknown to the server then ignore it. This is the default.
* ``strict`` enable bind checking, if a token is bound to a mechanism that is
  unknown to the server then this token should be rejected.
* ``required`` enable bind checking and require that at least 1 bind mechanism
  is used for tokens.
* named enable bind checking and require that the specified authentication
  mechanism is used. e.g.:

.. code-block:: ini

    [token]
    enforce_token_bind = kerberos

*Do not* set ``enforce_token_bind = named`` as there is not an authentication
mechanism called ``named``.

Limiting list return size
=========================

Keystone provides a method of setting a limit to the number of entities
returned in a collection, which is useful to prevent overly long response times
for list queries that have not specified a sufficiently narrow filter. This
limit can be set globally by setting ``list_limit`` in the default section of
``keystone.conf``, with no limit set by default. Individual driver sections may
override this global value with a specific limit, for example:

.. code-block:: ini

    [resource]
    list_limit = 100

If a response to ``list_{entity}`` call has been truncated, then the response
status code will still be 200 (OK), but the ``truncated`` attribute in the
collection will be set to ``true``.


URL safe naming of projects and domains
=======================================

In the future, keystone may offer the ability to identify a project in a
hierarchy via a URL style of naming from the root of the hierarchy (for example
specifying 'projectA/projectB/projectC' as the project name in an
authentication request). In order to prepare for this, keystone supports the
optional ability to ensure both projects and domains are named without
including any of the reserverd characters specified in section 2.2 of
`rfc3986 <http://tools.ietf.org/html/rfc3986>`_.

The safety of the names of projects and domains can be controlled via two
configuration options:

.. code-block:: ini

    [resource]
    project_name_url_safe = off
    domain_name_url_safe = off

When set to ``off`` (which is the default), no checking is done on the URL
safeness of names. When set to ``new``, an attempt to create a new project or
domain with an unsafe name (or update the name of a project or domain to be
unsafe) will cause a status code of 400 (Bad Request) to be returned. Setting
the configuration option to ``strict`` will, in addition to preventing the
creation and updating of entities with unsafe names, cause an authentication
attempt which specifies a project or domain name that is unsafe to return a
status code of 401 (Unauthorized).

It is recommended that installations take the steps necessary to where they
can run with both options set to ``strict`` as soon as is practical.

Health Check middleware
=======================

This health check middleware allows an operator to configure the endpoint URL
that will provide information to a load balancer if the given API endpoint at
the node should be available or not.

To enable the health check middleware, it must occur in the beginning of the
application pipeline.

The health check middleware should be placed in your
``keystone-paste.ini`` in a section titled ``[filter:healthcheck]``.
It should look like this::

  [filter:healthcheck]
  use = egg:oslo.middleware#healthcheck

Desired keystone application pipelines have been defined with this filter,
looking like so::

  [pipeline:public_version_api]
  pipeline = healthcheck cors sizelimit osprofiler url_normalize public_version_service

It's important that the healthcheck go to the front of the pipeline for the
most efficient checks.

For more information and configuration options for the middleware see
`oslo.middleware <https://docs.openstack.org/developer/oslo.middleware/api.html#oslo_middleware.Healthcheck>`_.

.. _`API protection with RBAC`:

API protection with Role Based Access Control (RBAC)
=====================================================

Like most OpenStack projects, keystone supports the protection of its APIs by
defining policy rules based on an RBAC approach. These are stored in a JSON
policy file, the name and location of which is set in the main keystone
configuration file.

Each keystone v3 API has a line in the policy file which dictates what level of
protection is applied to it, where each line is of the form::

  <api name>: <rule statement> or <match statement>

where:

``<rule statement>`` can contain ``<rule statement>`` or ``<match statement>``

``<match statement>`` is a set of identifiers that must match between the token
provided by the caller of the API and the parameters or target entities of the
API call in question. For example:

.. code-block:: javascript

    "identity:create_user": "role:admin and domain_id:%(user.domain_id)s"

Indicates that to create a user you must have the admin role in your token and
in addition the domain_id in your token (which implies this must be a domain
scoped token) must match the domain_id in the user object you are trying to
create. In other words, you must have the admin role on the domain in which you
are creating the user, and the token you are using must be scoped to that
domain.

Each component of a match statement is of the form::

  <attribute from token>:<constant> or <attribute related to API call>

The following attributes are available

* Attributes from token: user_id, the domain_id or project_id depending on
  the scope, and the list of roles you have within that scope

* Attributes related to API call: Any parameters that are passed into the API
  call are available, along with any filters specified in the query string.
  Attributes of objects passed can be referenced using an object.attribute
  syntax (e.g. user.domain_id). The target objects of an API are also available
  using a target.object.attribute syntax. For instance:

  .. code-block:: javascript

    "identity:delete_user": "role:admin and domain_id:%(target.user.domain_id)s"

  would ensure that the user object that is being deleted is in the same
  domain as the token provided.

Every target object (except token) has an `id` and a `name` available as
`target.<object>.id` and `target.<object>.name`. Other attributes are retrieved
from the database and vary between object types. Moreover, some database fields
are filtered out (e.g. user passwords).

List of object attributes:

* role:
    * target.role.domain_id
    * target.role.id
    * target.role.name

* user:
    * target.user.default_project_id
    * target.user.description
    * target.user.domain_id
    * target.user.enabled
    * target.user.id
    * target.user.name
    * target.user.password_expires_at

* group:
    * target.group.description
    * target.group.domain_id
    * target.group.id
    * target.group.name

* domain:
    * target.domain.description
    * target.domain.enabled
    * target.domain.id
    * target.domain.name

* project:
    * target.project.description
    * target.project.domain_id
    * target.project.enabled
    * target.project.id
    * target.project.is_domain
    * target.project.name
    * target.project.parent_id

* token
    * target.token.user_id
    * target.token.user.domain.id

The default policy.json file supplied provides a somewhat basic example of API
protection, and does not assume any particular use of domains. For multi-domain
configuration installations where, for example, a cloud provider wishes to
allow administration of the contents of a domain to be delegated, it is
recommended that the supplied policy.v3cloudsample.json is used as a basis for
creating a suitable production policy file. This example policy file also shows
the use of an admin_domain to allow a cloud provider to enable cloud
administrators to have wider access across the APIs.

A clean installation would need to perhaps start with the standard policy file,
to allow creation of the admin_domain with the first users within it. The
domain_id of the admin domain would then be obtained and could be pasted into a
modified version of policy.v3cloudsample.json which could then be enabled as
the main policy file.

.. _`prepare your deployment`:

Preparing your deployment
=========================

Step 1: Configure keystone.conf
-------------------------------

Ensure that your ``keystone.conf`` is configured to use a SQL driver:

.. code-block:: ini

    [identity]
    driver = sql

You may also want to configure your ``[database]`` settings to better reflect
your environment:

.. code-block:: ini

    [database]
    connection = sqlite:///keystone.db
    idle_timeout = 200

.. NOTE::

    It is important that the database that you specify be different from the
    one containing your existing install.

Step 2: Sync your new, empty database
-------------------------------------

You should now be ready to initialize your new database without error, using:

.. code-block:: bash

    $ keystone-manage db_sync

To test this, you should now be able to start keystone:

.. code-block:: bash

    $ uwsgi --http 127.0.0.1:35357 --wsgi-file $(which keystone-wsgi-admin)

And use the OpenStack Client to list your projects (which should successfully
return an empty list from your new database):

.. code-block:: bash

    $ openstack --os-token ADMIN --os-url http://127.0.0.1:35357/v2.0/ project list

.. NOTE::

    We're providing the default OS_TOKEN and OS_URL values from
    ``keystone.conf`` to connect to the keystone service. If you changed those
    values, or deployed keystone to a different endpoint, you will need to
    change the provided command accordingly.

``keystone-manage``
===================

``keystone-manage`` is the command line tool which interacts with the Keystone
service to initialize and update data within Keystone. Generally,
``keystone-manage`` is only used for operations that cannot be accomplished
with the HTTP API, such data import/export and database migrations.

.. include:: man/commands.rst

Removing Expired Tokens
=======================

In the SQL backend expired UUID tokens are not automatically removed. These
tokens can be removed with:

.. code-block:: bash

    $ keystone-manage token_flush

It is recommended to run this command periodically with ``cron`` if using UUID
tokens.

.. NOTE::

   It it not required to run this command at all if using Fernet tokens. Fernet
   tokens are not persisted.

Supported clients
=================

There are two supported clients, `python-keystoneclient`_ project provides
python bindings and `python-openstackclient`_ provides a command line
interface.

.. _`python-openstackclient`: https://docs.openstack.org/developer/python-openstackclient/
.. _`python-keystoneclient`: https://docs.openstack.org/developer/python-keystoneclient/


Authenticating with a Password via CLI
--------------------------------------

To authenticate with keystone using a password and ``python-openstackclient``,
set the following flags, note that the following user referenced below should
be granted the ``admin`` role.

* ``--os-username OS_USERNAME``: Name of your user
* ``--os-password OS_PASSWORD``: Password for your user
* ``--os-project-name OS_PROJECT_NAME``: Name of your project
* ``--os-auth-url OS_AUTH_URL``: URL of the keystone authentication server

You can also set these variables in your environment so that they do not need
to be passed as arguments each time:

.. code-block:: bash

    $ export OS_USERNAME=my_username
    $ export OS_PASSWORD=my_password
    $ export OS_PROJECT_NAME=my_project
    $ export OS_AUTH_URL=http://localhost:35357/v2.0

For example, the commands ``user list``, ``token issue`` and ``project create``
can be invoked as follows:

.. code-block:: bash

    # Using password authentication, with environment variables
    $ export OS_USERNAME=admin
    $ export OS_PASSWORD=secret
    $ export OS_PROJECT_NAME=admin
    $ export OS_AUTH_URL=http://localhost:35357/v2.0
    $ openstack user list
    $ openstack project create demo
    $ openstack token issue

    # Using password authentication, with flags
    $ openstack --os-username=admin --os-password=secret --os-project-name=admin --os-auth-url=http://localhost:35357/v2.0 user list
    $ openstack --os-username=admin --os-password=secret --os-project-name=admin --os-auth-url=http://localhost:35357/v2.0 project create demo


Using an LDAP server
====================

As an alternative to the SQL Database backing store, keystone can use a
directory server to provide the Identity service. An example schema for
OpenStack would look like this::

  dn: dc=openstack,dc=org
  dc: openstack
  objectClass: dcObject
  objectClass: organizationalUnit
  ou: openstack

  dn: ou=Groups,dc=openstack,dc=org
  objectClass: top
  objectClass: organizationalUnit
  ou: groups

  dn: ou=Users,dc=openstack,dc=org
  objectClass: top
  objectClass: organizationalUnit
  ou: users

The corresponding entries in the keystone configuration file are:

.. code-block:: ini

  [ldap]
  url = ldap://localhost
  user = dc=Manager,dc=openstack,dc=org
  password = badpassword
  suffix = dc=openstack,dc=org

  user_tree_dn = ou=Users,dc=openstack,dc=org
  user_objectclass = inetOrgPerson

The default object classes and attributes are intentionally simplistic. They
reflect the common standard objects according to the LDAP RFCs. However, in a
live deployment, the correct attributes can be overridden to support a
preexisting, more complex schema. For example, in the user object, the
objectClass posixAccount from RFC2307 is very common. If this is the underlying
objectclass, then the *uid* field should probably be *uidNumber* and *username*
field either *uid* or *cn*. To change these two fields, the corresponding
entries in the keystone configuration file are:

.. code-block:: ini

  [ldap]
  user_id_attribute = uidNumber
  user_name_attribute = cn

There are some configuration options for filtering users, tenants and roles, if
the backend is providing too much output, in such case the configuration will
look like:

.. code-block:: ini

  [ldap]
  user_filter = (memberof=CN=openstack-users,OU=workgroups,DC=openstack,DC=org)

In case that the directory server does not have an attribute enabled of type
boolean for the user, there is several configuration parameters that can be
used to extract the value from an integer attribute like in Active Directory:

.. code-block:: ini

  [ldap]
  user_enabled_attribute = userAccountControl
  user_enabled_mask      = 2
  user_enabled_default   = 512

In this case the attribute is an integer and the enabled attribute is listed in
bit 1, so the if the mask configured *user_enabled_mask* is different from 0,
it gets the value from the field *user_enabled_attribute* and it makes an ADD
operation with the value indicated on *user_enabled_mask* and if the value
matches the mask then the account is disabled.

It also saves the value without mask to the user identity in the attribute
*enabled_nomask*. This is needed in order to set it back in case that we need
to change it to enable/disable a user because it contains more information than
the status like password expiration. Last setting *user_enabled_mask* is needed
in order to create a default value on the integer attribute (512 = NORMAL
ACCOUNT on AD)

In case of Active Directory the classes and attributes could not match the
specified classes in the LDAP module so you can configure them like:

.. code-block:: ini

  [ldap]
  user_objectclass           = person
  user_id_attribute          = cn
  user_name_attribute        = cn
  user_description_attribute = displayName
  user_mail_attribute        = mail
  user_enabled_attribute     = userAccountControl
  user_enabled_mask          = 2
  user_enabled_default       = 512
  user_attribute_ignore      = tenant_id,tenants

Debugging LDAP
--------------

For additional information on LDAP connections, performance (such as slow
response time), or field mappings, setting ``debug_level`` in the [ldap]
section is used to enable debugging:

.. code-block:: ini

  debug_level = 4095

This setting in turn sets OPT_DEBUG_LEVEL in the underlying python library.
This field is a bit mask (integer), and the possible flags are documented in
the OpenLDAP manpages. Commonly used values include 255 and 4095, with 4095
being more verbose.

.. WARNING::
  Enabling ``debug_level`` will negatively impact performance.

Enabled Emulation
-----------------

Some directory servers do not provide any enabled attribute. For these servers,
the ``user_enabled_emulation`` attribute has been created. It is enabled by
setting the respective flags to True. Then the attribute
``user_enabled_emulation_dn`` may be set to specify how the enabled users are
selected. This attribute works by using a ``groupOfNames`` entry and adding
whichever users or that you want enabled to the respective group with the
``member`` attribute. For example, this will mark any user who is a member of
``enabled_users`` as enabled:

.. code-block:: ini

  [ldap]
  user_enabled_emulation = True
  user_enabled_emulation_dn = cn=enabled_users,cn=groups,dc=openstack,dc=org

The default values for user enabled emulation DN is
``cn=enabled_users,$user_tree_dn``.


If a different LDAP schema is used for group membership, it is possible to use
the ``group_objectclass`` and ``group_member_attribute`` attributes to
determine membership in the enabled emulation group by setting the
``user_enabled_emulation_use_group_config`` attribute to True.

Secure Connection
-----------------

If you are using a directory server to provide the Identity service, it is
strongly recommended that you utilize a secure connection from keystone to the
directory server. In addition to supporting LDAP, keystone also provides
Transport Layer Security (TLS) support. There are some basic configuration
options for enabling TLS, identifying a single file or directory that contains
certificates for all the Certificate Authorities that the keystone LDAP client
will recognize, and declaring what checks the client should perform on server
certificates. This functionality can easily be configured as follows:

.. code-block:: ini

  [ldap]
  use_tls = True
  tls_cacertfile = /etc/keystone/ssl/certs/cacert.pem
  tls_cacertdir = /etc/keystone/ssl/certs/
  tls_req_cert = demand

A few points worth mentioning regarding the above options. If both
``tls_cacertfile`` and ``tls_cacertdir`` are set then tls_cacertfile will be
used and ``tls_cacertdir`` is ignored. Furthermore, valid options for
``tls_req_cert`` are ``demand``, ``never``, and ``allow``. These correspond to
the standard options permitted by the ``TLS_REQCERT`` TLS option.

.. NOTE::

    If unable to connect to LDAP via keystone (more specifically, if a
    *SERVER DOWN* error is seen), set the ``TLS_CACERT`` in
    ``/etc/ldap/ldap.conf`` to the same value specified in the
    ``[ldap] tls_certificate`` section of ``keystone.conf``.

Read Only LDAP
--------------

Many environments typically have user and group information in directories that
are accessible by LDAP. This information is for read-only use in a wide array
of applications. Prior to the Havana release, we could not deploy keystone with
read-only directories as backends because keystone also needed to store
information such as projects, roles, domains and role assignments into the
directories in conjunction with reading user and group information.

Keystone now provides an option whereby these read-only directories can be
easily integrated as it now enables its identity entities (which comprises
users, groups, and group memberships) to be served out of directories while
resource (which comprises projects and domains), assignment and role
entities are to be served from different keystone backends (i.e. SQL). To
enable this option, you must have the following ``keystone.conf`` options set:

.. code-block:: ini

  [identity]
  driver = ldap

  [resource]
  driver = sql

  [assignment]
  driver = sql

  [role]
  driver = sql

With the above configuration, keystone will only lookup identity related
information such users, groups, and group membership from the directory, while
resources, roles and assignment related information will be provided by the SQL
backend. Also note that if there is an LDAP Identity, and no resource,
assignment or role backend is specified, they will default to LDAP. Although
this may seem counter intuitive, it is provided for backwards compatibility.
Nonetheless, the explicit option will always override the implicit option, so
specifying the options as shown above will always be correct.

.. NOTE::

    While having identity related information backed by LDAP while other
    information is backed by SQL is a supported configuration, as shown above;
    the opposite is not true. If either resource or assignment drivers are
    configured for LDAP, then Identity must also be configured for LDAP.

Connection Pooling
------------------

Various LDAP backends in keystone use a common LDAP module to interact with
LDAP data. By default, a new connection is established for each LDAP operation.
This can become highly expensive when TLS support is enabled, which is a likely
configuration in an enterprise setup. Reuse of connectors from a connection
pool drastically reduces overhead of initiating a new connection for every LDAP
operation.

Keystone provides connection pool support via configuration. This will keep
LDAP connectors alive and reused for subsequent LDAP operations. The connection
lifespan is configurable as other pooling specific attributes.

In the LDAP identity driver, keystone authenticates end users via an LDAP bind
with the user's DN and provided password. This kind of authentication bind
can fill up the pool pretty quickly, so a separate pool is provided for end
user authentication bind calls. If a deployment does not want to use a pool for
those binds, then it can disable pooling selectively by setting
``use_auth_pool`` to false. If a deployment wants to use a pool for those
authentication binds, then ``use_auth_pool`` needs to be set to true. For the
authentication pool, a different pool size (``auth_pool_size``) and connection
lifetime (``auth_pool_connection_lifetime``) can be specified. With an enabled
authentication pool, its connection lifetime should be kept short so that the
pool frequently re-binds the connection with the provided credentials and works
reliably in the end user password change case. When ``use_pool`` is false
(disabled), then the authentication pool configuration is also not used.

Connection pool configuration is part of the ``[ldap]`` configuration section:

.. code-block:: ini

  [ldap]
  # Enable LDAP connection pooling for queries to the LDAP server. There is
  # typically no reason to disable this. (boolean value)
  use_pool = true

  # The size of the LDAP connection pool. This option has no effect unless
  # `[ldap] use_pool` is also enabled. (integer value)
  # Minimum value: 1
  pool_size = 10

  # The maximum number of times to attempt reconnecting to the LDAP server before
  # aborting. A value of zero prevents retries. This option has no effect unless
  # `[ldap] use_pool` is also enabled. (integer value)
  # Minimum value: 0
  pool_retry_max = 3

  # The number of seconds to wait before attempting to reconnect to the LDAP
  # server. This option has no effect unless `[ldap] use_pool` is also enabled.
  # (floating point value)
  pool_retry_delay = 0.1

  # The connection timeout to use with the LDAP server. A value of `-1` means
  # that connections will never timeout. This option has no effect unless `[ldap]
  # use_pool` is also enabled. (integer value)
  # Minimum value: -1
  pool_connection_timeout = -1

  # The maximum connection lifetime to the LDAP server in seconds. When this
  # lifetime is exceeded, the connection will be unbound and removed from the
  # connection pool. This option has no effect unless `[ldap] use_pool` is also
  # enabled. (integer value)
  # Minimum value: 1
  pool_connection_lifetime = 600

  # Enable LDAP connection pooling for end user authentication. There is
  # typically no reason to disable this. (boolean value)
  use_auth_pool = true

  # The size of the connection pool to use for end user authentication. This
  # option has no effect unless `[ldap] use_auth_pool` is also enabled. (integer
  # value)
  # Minimum value: 1
  auth_pool_size = 100

  # The maximum end user authentication connection lifetime to the LDAP server in
  # seconds. When this lifetime is exceeded, the connection will be unbound and
  # removed from the connection pool. This option has no effect unless `[ldap]
  # use_auth_pool` is also enabled. (integer value)
  # Minimum value: 1
  auth_pool_connection_lifetime = 60

Specifying Multiple LDAP servers
--------------------------------

Multiple LDAP server URLs can be provided to keystone to provide
high-availability support for a single LDAP backend. To specify multiple LDAP
servers, simply change the ``url`` option in the ``[ldap]`` section. The new
option should list the different servers, each separated by a comma. For
example:

.. code-block:: ini

  [ldap]
  url = "ldap://localhost,ldap://backup.localhost"


Credential Encryption
=====================

As of the Newton release, keystone encrypts all credentials stored in the
default ``sql`` backend. Credentials are encrypted with the same mechanism used
to encrypt Fernet tokens, ``fernet``. Keystone provides only one type of
credential encryption but the encryption provider is pluggable in the event
you wish to supply a custom implementation.

This document details how credential encryption works, how to migrate existing
credentials in a deployment, and how to manage encryption keys for credentials.

Configuring credential encryption
---------------------------------

The configuration for credential encryption is straightforward. There are only
two configuration options needed:

.. code-block:: ini

    [credential]
    provider = fernet
    key_repository = /etc/keystone/credential-keys/

``[credential] provider`` defaults to the only option supplied by keystone,
``fernet``. There is no reason to change this option unless you wish to provide
a custom credential encryption implementation. The ``[credential]
key_repository`` location is a requirement of using ``fernet`` but will default
to the ``/etc/keystone/credential-keys/`` directory. Both ``[credential]
key_repository`` and ``[fernet_tokens] key_repository`` define locations for
keys used to encrypt things. One holds the keys to encrypt and decrypt
credentials and the other holds keys to encrypt and decrypt tokens. It is
imperative that these repositories are managed separately and they must not
share keys. Meaning they cannot share the same directory path. The
``[credential] key_repository`` is only allowed to have three keys. This is not
configurable and allows for credentials to be re-encrypted periodically with a
new encryption key for the sake of security.

How credential encryption works
-------------------------------

The implementation of this feature did not change any existing credential API
contracts. All changes are transparent to the user unless you're inspecting the
credential backend directly.

When creating a credential, keystone will encrypt the ``blob`` attribute before
persisting it to the backend. Keystone will also store a hash of the key that
was used to encrypt the information in that credential. Since Fernet is used to
encrypt credentials, a key repository consists of multiple keys. Keeping track
of which key was used to encrypt each credential is an important part of
encryption key management. Why this is important is detailed later in the
`Encryption key management` section.

When updating an existing credential's ``blob`` attribute, keystone will encrypt
the new ``blob`` and update the key hash.

When listing or showing credentials, all ``blob`` attributes are decrypted in
the response. Neither the cipher text, nor the hash of the key used to encrypt
the ``blob`` are exposed through the API. Furthermore, the key is only used
internally to keystone.

Encrypting existing credentials
-------------------------------

When upgrading a Mitaka deployment to Newton, three database migrations will
ensure all credentials are encrypted. The process is as follows:

1. An additive schema change is made to create the new ``encrypted_blob`` and
   ``key_hash`` columns in the existing ``credential`` table using
   ``keystone-manage db_sync --expand``.
2. A data migration will loop through all existing credentials, encrypt each
   ``blob`` and store the result in the new ``encrypted_blob`` column. The hash
   of the key used is also written to the ``key_hash`` column for that specific
   credential. This step is done using ``keystone-manage db_sync --migrate``.
3. A contractive schema will remove the ``blob`` column that held the plain
   text representations of the credential using ``keystone-manage db_sync
   --contract``. This should only be done after all nodes in the deployment are
   running Newton. If any Mitaka nodes are running after the database is
   contracted, they won't be able to read credentials since they are looking
   for the ``blob`` column that no longer exists.

If performing a rolling upgrade, please note that a limited service outage will
take affect during this migration. When the migration is in place, credentials
will become read-only until the database is contracted. After the contract
phase is complete, credentials will be writeable to the backend. A
``[credential] key_repository`` location must be specified through
configuration and bootstrapped with keys using ``keystone-manage
credential_setup`` prior to migrating any existing credentials. If a new key
repository isn't setup using ``keystone-manage credential_setup`` keystone will
assume a null key to encrypt and decrypt credentials until a proper key
repository is present. The null key is a key consisting of all null bytes and
its only purpose is to ease the upgrade process from Mitaka to Newton. It is
highly recommended that the null key isn't used. It is no more secure than
storing credentials in plain text. If the null key is used, you should migrate
to a proper key repository using ``keystone-manage credential_setup`` and
``keystone-manage credential_migrate``.

Encryption key management
-------------------------

Key management of ``[credential] key_repository`` is handled with three
``keystone-manage`` commands:

1. ``keystone-manage credential_setup``
2. ``keystone-manage credential_rotate``
3. ``keystone-manage credential_migrate``

``keystone-manage credential_setup`` will populate ``[credential]
key_repository`` with new encryption keys. This must be done in order for
proper credential encryption to work, with the exception of the null key. This
step should only be done once.

``keystone-manage credential_rotate`` will create and rotate a new encryption
key in the ``[credential] key_repository``. This will only be done if all
credential key hashes match the hash of the current primary key. If any
credential has been encrypted with an older key, or secondary key, the rotation
will fail. Failing the rotation is necessary to prevent overrotation, which
would leave some credentials indecipherable since the key used to encrypt it
no longer exists. If this step fails, it is possible to forcibly re-key all
credentials using the same primary key with ``keystone-manage
credential_migrate``.

``keystone-manage credential_migrate`` will check the backend for credentials
whose key hash doesn't match the hash of the current primary key. Any
credentials with a key hash mismatching the current primary key will be
re-encrypted with the current primary key. The new cipher text and key hash
will be updated in the backend.
