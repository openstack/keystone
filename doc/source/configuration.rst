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

.. toctree::
   :maxdepth: 1

   man/keystone-manage
   man/keystone-all

Once Keystone is installed, it is configured via a primary configuration file
(``etc/keystone.conf``), a PasteDeploy configuration file
(``etc/keystone-paste.ini``), possibly a separate logging configuration file,
and initializing data into Keystone using the command line client.

By default, Keystone starts a service on `IANA-assigned port 35357
<http://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.txt>`_.
This may overlap with your system's ephemeral port range, so another process
may already be using this port without being explicitly configured to do so. To
prevent this scenario from occurring, it's recommended that you explicitly
exclude port 35357 from the available ephemeral port range. On a Linux system,
this would be accomplished by:

.. code-block:: bash

    $ sysctl -w 'sys.net.ipv4.ip_local_reserved_ports=35357'

To make the above change persistent,
``net.ipv4.ip_local_reserved_ports = 35357`` should be added to
``/etc/sysctl.conf`` or to ``/etc/sysctl.d/keystone.conf``.

Starting and Stopping Keystone under Eventlet
=============================================

.. WARNING::

    Running keystone under eventlet has been deprecated as of the Kilo release.
    Support for utilizing eventlet will be removed as of the M-release. The
    recommended deployment is to run keystone in a WSGI server
    (e.g. ``mod_wsgi`` under ``HTTPD``).

Keystone can be run using either its built-in eventlet server or it can be run
embedded in a web server. While the eventlet server is convenient and easy to
use, it's lacking in security features that have been developed into Internet-
based web servers over the years. As such, running the eventlet server as
described in this section is not recommended.

Start Keystone services using the command:

.. code-block:: bash

    $ keystone-all

Invoking this command starts up two ``wsgi.Server`` instances, ``admin`` (the
administration API) and ``main`` (the primary/public API interface). Both
services are configured to run in a single process.

.. NOTE::

    The separation into ``admin`` and ``main`` interfaces is an historical
    anomaly. The new V3 API provides the same interface on both the admin and
    main interfaces (this can be configured in ``keystone-paste.ini``, but the
    default is to have both the same). The V2.0 API provides a limited public
    API (getting and validating tokens) on ``main``, and an administrative API
    (which can include creating users and such) on the ``admin`` interface.

Stop the process using ``Control-C``.

.. NOTE::

    If you have not already configured Keystone, it may not start as expected.


Configuration Files
===================

The Keystone configuration files are an ``ini`` file format based on Paste_, a
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

The primary configuration file is organized into the following sections:

* ``[DEFAULT]`` - General configuration
* ``[assignment]`` - Assignment system driver configuration
* ``[auth]`` - Authentication plugin configuration
* ``[cache]`` - Caching layer configuration
* ``[catalog]`` - Service catalog driver configuration
* ``[credential]`` - Credential system driver configuration
* ``[endpoint_filter]`` - Endpoint filtering extension configuration
* ``[endpoint_policy]`` - Endpoint policy extension configuration
* ``[eventlet_server]`` - Eventlet server configuration
* ``[eventlet_server_ssl]`` - Eventlet server SSL configuration
* ``[federation]`` - Federation driver configuration
* ``[identity]`` - Identity system driver configuration
* ``[identity_mapping]`` - Identity mapping system driver configuration
* ``[kvs]`` - KVS storage backend configuration
* ``[ldap]`` - LDAP configuration options
* ``[memcache]`` - Memcache configuration options
* ``[oauth1]`` - OAuth 1.0a system driver configuration
* ``[os_inherit]`` - Inherited role assignment extension
* ``[paste_deploy]`` - Pointer to the PasteDeploy configuration file
* ``[policy]`` - Policy system driver configuration for RBAC
* ``[resource]`` - Resource system driver configuration
* ``[revoke]`` - Revocation system driver configuration
* ``[role]`` - Role system driver configuration
* ``[saml]`` - SAML configuration options
* ``[signing]`` - Cryptographic signatures for PKI based tokens
* ``[ssl]`` - SSL certificate generation configuration
* ``[token]`` - Token driver & token provider configuration
* ``[trust]`` - Trust extension configuration

The Keystone primary configuration file is expected to be named
``keystone.conf``. When starting Keystone, you can specify a different
configuration file to use with ``--config-file``. If you do **not** specify a
configuration file, Keystone will look in the following directories for a
configuration file, in order:

* ``~/.keystone/``
* ``~/``
* ``/etc/keystone/``
* ``/etc/``

PasteDeploy configuration file is specified by the ``config_file`` parameter in
``[paste_deploy]`` section of the primary configuration file. If the parameter
is not an absolute path, then Keystone looks for it in the same directories as
above. If not specified, WSGI pipeline definitions are loaded from the primary
configuration file.

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
feature, causing Keystone to look in the ``domain_config_dir`` for config files
of the form::

 keystone.<domain_name>.conf

Options given in the domain specific configuration file will override those in
the primary configuration file for the specified domain only. Domains without a
specific configuration file will continue to use the options from the primary
configuration file.

Keystone also supports the ability to store the domain-specific configuration
options in the keystone SQL database, managed via the Identity API, as opposed
to using domain-specific configuration files.

.. NOTE::

    The ability to store and manage configuration options via the Identity API
    is new and experimental in Kilo.

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

    Although Keystone supports multiple LDAP backends via the above
    domain-specific configuration methods, it currently only supports one SQL
    backend. This could be either the default driver or a single
    domain-specific backend, perhaps for storing service users in a
    predominantly LDAP installation.

Due to the need for user and group IDs to be unique across an OpenStack
installation and for Keystone to be able to deduce which domain and backend to
use from just a user or group ID, it dynamically builds a persistent identity
mapping table from a public ID to the actual domain, local ID (within that
backend) and entity type. The public ID is automatically generated by Keystone
when it first encounters the entity. If the local ID of the entity is from a
backend that does not guarantee to generate UUIDs, a hash algorithm will
generate a public ID for that entity, which is what will be exposed by
Keystone.

The use of a hash will ensure that if the public ID needs to be regenerated
then the same public ID will be created. This is useful if you are running
multiple keystones and want to ensure the same ID would be generated whichever
server you hit.

While Keystone will dynamically maintain the identity mapping, including
removing entries when entities are deleted via the Keystone, for those entities
in backends that are managed outside of Keystone (e.g. a Read Only LDAP),
Keystone will not know if entities have been deleted and hence will continue to
carry stale identity mappings in its table. While benign, keystone provides an
ability for operators to purge the mapping table of such stale entries using
the keystone-manage command, for example:

.. code-block:: bash

    $ keystone-manage mapping_purge --domain-name DOMAINA --local-id abc@de.com

A typical usage would be for an operator to obtain a list of those entries in
an external backend that had been deleted out-of-band to Keystone, and then
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

Public ID Generators
--------------------

Keystone supports a customizable public ID generator and it is specified in the
``[identity_mapping]`` section of the configuration file. Keystone provides a
sha256 generator as default, which produces regeneratable public IDs. The
generator algorithm for public IDs is a balance between key size (i.e. the
length of the public ID), the probability of collision and, in some
circumstances, the security of the public ID. The maximum length of public ID
supported by Keystone is 64 characters, and the default generator (sha256) uses
this full capability. Since the public ID is what is exposed externally by
Keystone and potentially stored in external systems, some installations may
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
----------------------

.. NOTE::

    This feature is only supported by Keystone for the Identity API v3 clients.

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
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

All authentication plugins must extend the
:class:`keystone.auth.core.AuthMethodHandler` class and implement the
``authenticate()`` method. The ``authenticate()`` method expects the following
parameters.

* ``context`` - Keystone's request context
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


Token Persistence Driver
------------------------

Keystone supports customizable token persistence drivers. These can be
specified in the ``[token]`` section of the configuration file. Keystone
provides three non-test persistence backends. These can be set with the
``[token]\driver`` configuration option.

The drivers Keystone provides are:

* ``memcache_pool`` - The pooled memcached token persistence engine. This
  backend supports the concept of pooled memcache client object (allowing for
  the re-use of the client objects). This backend has a number of extra tunable
  options in the ``[memcache]`` section of the config. Implemented by
  :class:`keystone.token.persistence.backends.memcache_pool.Token`

* ``sql`` - The SQL-based (default) token persistence engine. Implemented by
  :class:`keystone.token.persistence.backends.sql.Token`

* ``memcache`` - The memcached based token persistence backend. This backend
  relies on ``dogpile.cache`` and stores the token data in a set of memcached
  servers. The servers URLs are specified in the ``[memcache]\servers``
  configuration option in the Keystone config. Implemented by
  :class:`keystone.token.persistence.backends.memcache.Token`


.. WARNING::
    It is recommended you use the ``memcache_pool`` backend instead of
    ``memcache`` as the token persistence driver if you are deploying Keystone
    under eventlet instead of Apache + mod_wsgi. This recommendation is due to
    known issues with the use of ``thread.local`` under eventlet that can allow
    the leaking of memcache client objects and consumption of extra sockets.


Token Provider
--------------

Keystone supports customizable token provider and it is specified in the
``[token]`` section of the configuration file. Keystone provides both UUID and
PKI token providers. However, users may register their own token provider by
configuring the following property.

* ``provider`` - token provider driver. Defaults to ``uuid``. Implemented by
  :class:`keystone.token.providers.uuid.Provider`


UUID, PKI, PKIZ, or Fernet?
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Each token format uses different technologies to achieve various performance,
scaling and architectural requirements.

UUID tokens contain randomly generated UUID4 payloads that are issued and
validated by the identity service. They are encoded using their hex digest for
transport and are thus URL-friendly. They must be persisted by the identity
service in order to be later validated. Revoking them is simply a matter of
deleting them from the token persistence backend.

Both PKI and PKIZ tokens contain JSON payloads that represent the entire token
validation response that would normally be retrieved from keystone. The payload
is then signed using `Cryptographic Message Syntax (CMS)
<http://en.wikipedia.org/wiki/Cryptographic_Message_Syntax>`_. The combination
of CMS and the exhaustive payload allows PKI and PKIZ tokens to be verified
offline using keystone's public signing key. The only reason for them to be
persisted by the identity service is to later build token revocation *lists*
(explicit lists of tokens that have been revoked), otherwise they are
theoretically ephemeral when supported by token revocation *events* (which
describe invalidated tokens rather than enumerate them). PKIZ tokens add zlib
compression after signing to achieve a smaller overall token size. To make them
URL-friendly, PKI tokens are base64 encoded and then arbitrarily manipulated to
replace unsafe characters with safe ones whereas PKIZ tokens use conventional
base64url encoding. Due to the size of the payload and the overhead incurred by
the CMS format, both PKI and PKIZ tokens may be too long to fit in either
headers or URLs if they contain extensive service catalogs or other additional
attributes. Some third-party applications such as web servers and clients may
need to be recompiled from source to customize the limitations that PKI and
PKIZ tokens would otherwise exceed). Both PKI and PKIZ tokens require signing
certificates which may be created using ``keystone-manage pki_setup`` for
demonstration purposes (this is not recommended for production deployments: use
certificates issued by an trusted CA instead).

Fernet tokens contain a limited amount of identity and authorization data in a
`MessagePacked <http://msgpack.org/>`_ payload. The payload is then wrapped as
a `Fernet <https://github.com/fernet/spec>`_ message for transport, where
Fernet provides the required web safe characteristics for use in URLs and
headers. Fernet tokens require symmetric encryption keys which can be
established using ``keystone-manage fernet_setup`` and periodically rotated
using ``keystone-manage fernet_rotate``.

.. WARNING::
    UUID, PKI, PKIZ, and Fernet tokens are all bearer tokens, meaning that they
    must be protected from unnecessary disclosure to prevent unauthorized
    access.

Caching Layer
-------------

Keystone supports a caching layer that is above the configurable subsystems
(e.g. ``token``, ``identity``, etc). Keystone uses the `dogpile.cache`_ library
which allows for flexible cache backends. The majority of the caching
configuration options are set in the ``[cache]`` section. However, each section
that has the capability to be cached usually has a ``caching`` boolean value
that will toggle caching for that specific section. The current default
behavior is that subsystem caching is enabled, but the global toggle is set to
disabled.

``[cache]`` configuration section:
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* ``enabled`` - enables/disables caching across all of keystone
* ``debug_cache_backend`` - enables more in-depth logging from the cache
  backend (get, set, delete, etc)
* ``backend`` - the caching backend module to use e.g.
  ``dogpile.cache.memcached``

    .. NOTE::
        A given ``backend`` must be registered with ``dogpile.cache`` before it
        can be used. The default backend is the ``Keystone`` no-op backend
        (``keystone.common.cache.noop``). If caching is desired a different
        backend will need to be specified. Current functional backends are:

    * ``dogpile.cache.memcached`` - Memcached backend using the standard
      `python-memcached`_ library
    * ``dogpile.cache.pylibmc`` - Memcached backend using the `pylibmc`_
      library
    * ``dogpile.cache.bmemcached`` - Memcached using `python-binary-memcached`_
      library.
    * ``dogpile.cache.redis`` - `Redis`_ backend
    * ``dogpile.cache.dbm`` - local DBM file backend
    * ``dogpile.cache.memory`` - in-memory cache
    * ``keystone.cache.mongo`` - MongoDB as caching backend
    * ``keystone.cache.memcache_pool`` - An eventlet safe implementation of
      ``dogpile.cache.memcached``. This implementation also provides client
      connection re-use.

        .. WARNING::
            ``dogpile.cache.memory`` is not suitable for use outside of unit
            testing as it does not cleanup its internal cache on cache
            expiration, does not provide isolation to the cached data (values
            in the store can be inadvertently changed without extra layers of
            data protection added), and does not share cache between processes.
            This means that caching and cache invalidation will not be
            consistent or reliable when using ``Keystone`` and the
            ``dogpile.cache.memory`` backend under any real workload.

        .. WARNING::
            Do not use ``dogpile.cache.memcached`` backend if you are deploying
            Keystone under eventlet. There are known issues with the use of
            ``thread.local`` under eventlet that can allow the leaking of
            memcache client objects and consumption of extra sockets.

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

Current Keystone systems that have caching capabilities:
    * ``token``
        The token system has a separate ``cache_time`` configuration option,
        that can be set to a value above or below the global
        ``expiration_time`` default, allowing for different caching behavior
        from the other systems in ``Keystone``. This option is set in the
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
        from the other systems in ``Keystone``. This option is set in the
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
        ``Keystone``.  This option is set in the ``[role]`` section of the
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
    * :py:mod:`keystone.common.cache.backends.mongo`

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
.. _`PyMongo API`: http://api.mongodb.org/python/current/api/pymongo/index.html


Certificates for PKI
--------------------

PKI stands for Public Key Infrastructure. Tokens are documents,
cryptographically signed using the X509 standard. In order to work correctly
token generation requires a public/private key pair. The public key must be
signed in an X509 certificate, and the certificate used to sign it must be
available as Certificate Authority (CA) certificate. These files can be either
externally generated or generated using the ``keystone-manage`` utility.

The files used for signing and verifying certificates are set in the Keystone
configuration file. The private key should only be readable by the system user
that will run Keystone. The values that specify the certificates are under the
``[signing]`` section of the configuration file. The configuration values are:

* ``certfile`` - Location of certificate used to verify tokens. Default is
  ``/etc/keystone/ssl/certs/signing_cert.pem``
* ``keyfile`` - Location of private key used to sign tokens. Default is
  ``/etc/keystone/ssl/private/signing_key.pem``
* ``ca_certs`` - Location of certificate for the authority that issued the
  above certificate. Default is ``/etc/keystone/ssl/certs/ca.pem``

Signing Certificate Issued by External CA
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

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
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

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
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

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


Generating a Signing Certificate using pki_setup
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

``keystone-manage pki_setup`` is a development tool. We recommend that you do
not use ``keystone-manage pki_setup`` in a production environment. In
production, an external CA should be used instead. This is because the CA
secret key should generally be kept apart from the token signing secret keys so
that a compromise of a node does not lead to an attacker being able to generate
valid signed Keystone tokens. This is a low probability attack vector, as
compromise of a Keystone service machine's filesystem security almost certainly
means the attacker will be able to gain direct access to the token backend.

When using the ``keystone-manage pki_setup`` to generate the certificates, the
following configuration options in the ``[signing]`` section are used:

* ``ca_key`` - Default is ``/etc/keystone/ssl/private/cakey.pem``
* ``key_size`` - Default is ``2048``
* ``valid_days`` - Default is ``3650``

If ``keystone-manage pki_setup`` is not used then these options don't need to
be set.


Encryption Keys for Fernet
--------------------------

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
  deployment at all times). In a multi-node Keystone deployment this would
  allow for the *staged* key to be replicated to all Keystone nodes before
  being promoted to *primary* on a single node. This prevents the case where a
  *primary* key is created on one Keystone node and tokens encrypted/signed with
  that new *primary* are rejected on another Keystone node because the new
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
too low, will cause tokens to become invalid prior to their expiration.

Service Catalog
---------------

Keystone provides two configuration options for your service catalog.

SQL-based Service Catalog (``sql.Catalog``)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

A dynamic database-backed driver fully supporting persistent configuration.

``keystone.conf`` example:

.. code-block:: ini

    [catalog]
    driver = sql

.. NOTE::

    A `template_file` does not need to be defined for the sql.Catalog driver.

To build your service catalog using this driver, see the built-in help:

.. code-block:: bash

    $ openstack --help
    $ openstack help service create
    $ openstack help endpoint create

You can also refer to `an example in Keystone (tools/sample_data.sh)
<https://git.openstack.org/cgit/openstack/keystone/tree/tools/sample_data.sh>`_.

File-based Service Catalog (``templated.Catalog``)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

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
Keystone, however you should create your own to reflect your deployment.

Another such example is `available in devstack
(files/default_catalog.templates)
<https://git.openstack.org/cgit/openstack-dev/devstack/tree/files/default_catalog.templates>`_.

Logging
-------

Logging is configured externally to the rest of Keystone. Configure the path to
your logging configuration file using the ``[DEFAULT] log_config`` option of
``keystone.conf``. If you wish to route all your logging through syslog, set
the ``[DEFAULT] use_syslog`` option.

A sample ``log_config`` file is included with the project at
``etc/logging.conf.sample``. Like other OpenStack projects, Keystone uses the
`Python logging module`, which includes extensive configuration options for
choosing the output levels and formats.

.. _Paste: http://pythonpaste.org/
.. _`Python logging module`: http://docs.python.org/library/logging.html

SSL
---

Keystone may be configured to support SSL and 2-way SSL out-of-the-box. The
X509 certificates used by Keystone can be generated by ``keystone-manage``
or obtained externally and configured for use with Keystone as described in
this section. Here is the description of each of them and their purpose:

.. WARNING::

    The SSL configuration options available to the eventlet server
    (``keystone-all``) described here are severely limited. A secure
    deployment should have Keystone running in a web server (such as Apache
    HTTPd), or behind an SSL terminator. When running Keystone in a web server
    or behind an SSL terminator the options described in this section have no
    effect and SSL is configured in the web server or SSL terminator.

Types of certificates
^^^^^^^^^^^^^^^^^^^^^

* ``cacert.pem``: Certificate Authority chain to validate against.
* ``ssl_cert.pem``: Public certificate for Keystone server.
* ``middleware.pem``: Public and private certificate for Keystone
  middleware/client.
* ``cakey.pem``: Private key for the CA.
* ``ssl_key.pem``: Private key for the Keystone server.

Note that you may choose whatever names you want for these certificates, or
combine the public/private keys in the same file if you wish. These
certificates are just provided as an example.

Configuration
^^^^^^^^^^^^^

To enable SSL modify the ``etc/keystone.conf`` file under the ``[ssl]`` and
``[eventlet_server_ssl]`` sections. The following is an SSL configuration
example using the included sample certificates:

.. code-block:: ini

    [eventlet_server_ssl]
    enable = True
    certfile = <path to keystone.pem>
    keyfile = <path to keystonekey.pem>
    ca_certs = <path to ca.pem>
    cert_required = False

    [ssl]
    ca_key = <path to cakey.pem>
    key_size = 1024
    valid_days=3650
    cert_subject=/C=US/ST=Unset/L=Unset/O=Unset/CN=localhost

* ``enable``: True enables SSL. Defaults to False.
* ``certfile``: Path to Keystone public certificate file.
* ``keyfile``: Path to Keystone private certificate file. If the private key is
  included in the certfile, the keyfile may be omitted.
* ``ca_certs``: Path to CA trust chain.
* ``cert_required``: Requires client certificate. Defaults to False.

When generating SSL certificates the following values are read

* ``key_size``: Key size to create. Defaults to 1024.
* ``valid_days``: How long the certificate is valid for. Defaults to 3650
  (10 years).
* ``ca_key``: The private key for the CA. Defaults to
  ``/etc/keystone/ssl/certs/cakey.pem``.
* ``cert_subject``: The subject to set in the certificate. Defaults to
  ``/C=US/ST=Unset/L=Unset/O=Unset/CN=localhost``. When setting the subject it
  is important to set CN to be the address of the server so client validation
  will succeed. This generally means having the subject be at least
  ``/CN=<keystone ip>``

Generating SSL certificates
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Certificates for encrypted HTTP communication can be generated by:

.. code-block:: bash

    $ keystone-manage ssl_setup

This will create a private key, a public key and a certificate that will be
used to encrypt communications with keystone. In the event that a Certificate
Authority is not given a testing one will be created.

It is likely in a production environment that these certificates will be
created and provided externally. Note that ``ssl_setup`` is a development tool
and is only recommended for developments environment. We do not recommend using
``ssl_setup`` for production environments.


User CRUD extension for the V2.0 API
------------------------------------

.. NOTE::

    The core V3 API includes user operations so no extension needs to be
    enabled for the V3 API.

For the V2.0 API, Keystone provides a user CRUD filter that can be added to the
public_api pipeline. This user crud filter allows users to use a HTTP PATCH to
change their own password. To enable this extension you should define a
user_crud_extension filter, insert it after the ``*_body`` middleware and
before the ``public_service`` app in the public_api WSGI pipeline in
``keystone-paste.ini`` e.g.:

.. code-block:: ini

    [filter:user_crud_extension]
    paste.filter_factory = keystone.contrib.user_crud:CrudExtension.factory

    [pipeline:public_api]
    pipeline = url_normalize token_auth admin_token_auth json_body debug ec2_extension user_crud_extension public_service

Each user can then change their own password with a HTTP PATCH :

.. code-block:: bash

    $ curl -X PATCH http://localhost:5000/v2.0/OS-KSCRUD/users/<userid> -H "Content-type: application/json" \
    -H "X_Auth_Token: <authtokenid>" -d '{"user": {"password": "ABCD", "original_password": "DCBA"}}'

In addition to changing their password all of the user's current tokens will be
revoked.


Inherited Role Assignment Extension
-----------------------------------

Keystone provides an optional extension that adds the capability to assign
roles on a project or domain that, rather than affect the project or domain
itself, are instead inherited to the project subtree or to all projects owned
by that domain. This extension is disabled by default, but can be enabled by
including the following in ``keystone.conf``:

.. code-block:: ini

    [os_inherit]
    enabled = True


Token Binding
-------------

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

Limiting the number of entities returned in a collection
--------------------------------------------------------

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

Sample Configuration Files
--------------------------

The ``etc/`` folder distributed with Keystone contains example configuration
files for each Server application.

* ``etc/keystone.conf.sample``
* ``etc/keystone-paste.ini``
* ``etc/logging.conf.sample``
* ``etc/default_catalog.templates``

.. _`API protection with RBAC`:

Keystone API protection with Role Based Access Control (RBAC)
=============================================================

Like most OpenStack projects, Keystone supports the protection of its APIs by
defining policy rules based on an RBAC approach. These are stored in a JSON
policy file, the name and location of which is set in the main Keystone
configuration file.

Each Keystone v3 API has a line in the policy file which dictates what level of
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
    * target.role.id
    * target.role.name

* user:
    * target.user.default_project_id
    * target.user.description
    * target.user.domain_id
    * target.user.enabled
    * target.user.id
    * target.user.name

* group:
    * target.group.description
    * target.group.domain_id
    * target.group.id
    * target.group.name

* domain:
    * target.domain.enabled
    * target.domain.id
    * target.domain.name

* project:
    * target.project.description
    * target.project.domain_id
    * target.project.enabled
    * target.project.id
    * target.project.name

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

To test this, you should now be able to start ``keystone-all`` and use the
OpenStack Client to list your projects (which should successfully return an
empty list from your new database):

.. code-block:: bash

    $ openstack --os-token ADMIN --os-url http://127.0.0.1:35357/v2.0/ project list

.. NOTE::

    We're providing the default OS_TOKEN and OS_URL values from
    ``keystone.conf`` to connect to the Keystone service. If you changed those
    values, or deployed Keystone to a different endpoint, you will need to
    change the provided command accordingly.

Initializing Keystone
=====================

``keystone-manage`` is designed to execute commands that cannot be administered
through the normal REST API. At the moment, the following calls are supported:

* ``db_sync``: Sync the database.
* ``db_version``: Print the current migration version of the database.
* ``domain_config_upload``: Upload domain configuration file.
* ``fernet_rotate``: Rotate keys in the Fernet key repository.
* ``fernet_setup``: Setup a Fernet key repository.
* ``mapping_engine``: Test your federation mapping rules.
* ``mapping_purge``: Purge the identity mapping table.
* ``pki_setup``: Initialize the certificates used to sign tokens.
* ``saml_idp_metadata``: Generate identity provider metadata.
* ``ssl_setup``: Generate certificates for SSL.
* ``token_flush``: Purge expired tokens

Invoking ``keystone-manage`` by itself will give you additional usage
information.

The private key used for token signing can only be read by its owner. This
prevents unauthorized users from spuriously signing tokens.
``keystone-manage pki_setup`` Should be run as the same system user that will
be running the Keystone service to ensure proper ownership for the private key
file and the associated certificates.

Adding Users, Projects, and Roles via Command Line Interfaces
=============================================================

Keystone APIs are protected by the rules in the policy file. The default policy
rules require admin credentials to administer ``users``, ``projects``, and
``roles``. See section
`Keystone API protection with Role Based Access Control (RBAC)`_ for more
details on policy files.

The Keystone command line interface packaged in `python-keystoneclient`_ only
supports the Identity v2.0 API. The OpenStack common command line interface
packaged in `python-openstackclient`_ supports both v2.0 and v3 APIs.

With both command line interfaces there are two ways to configure the client to
use admin credentials, using either an existing token or password credentials.

.. NOTE::

    As of the Juno release, it is recommended to use
    ``python-openstackclient``, as it supports both v2.0 and v3 APIs. For the
    purpose of backwards compatibility, the CLI packaged in
    ``python-keystoneclient`` is not being removed.

.. _`python-openstackclient`: http://docs.openstack.org/developer/python-openstackclient/
.. _`python-keystoneclient`: http://docs.openstack.org/developer/python-keystoneclient/

Authenticating with a Token
---------------------------

.. NOTE::

    If your Keystone deployment is brand new, you will need to use this
    authentication method, along with your ``[DEFAULT] admin_token``.

To authenticate with Keystone using a token and ``python-openstackclient``, set
the following flags.

* ``--os-url OS_URL``: Keystone endpoint the user communicates with
* ``--os-token OS_TOKEN``: User's service token

To administer a Keystone endpoint, your token should be either belong to a user
with the ``admin`` role, or, if you haven't created one yet, should be equal to
the value defined by ``[DEFAULT] admin_token`` in your ``keystone.conf``.

You can also set these variables in your environment so that they do not need
to be passed as arguments each time:

.. code-block:: bash

    $ export OS_URL=http://localhost:35357/v2.0
    $ export OS_TOKEN=ADMIN

Instead of ``python-openstackclient``, if using ``python-keystoneclient``, set
the following:

* ``--os-endpoint OS_SERVICE_ENDPOINT``: equivalent to ``--os-url OS_URL``
* ``--os-service-token OS_SERVICE_TOKEN``: equivalent to
  ``--os-token OS_TOKEN``


Authenticating with a Password
------------------------------

To authenticate with Keystone using a password and ``python-openstackclient``,
set the following flags, note that the following user referenced below should
be granted the ``admin`` role.

* ``--os-username OS_USERNAME``: Name of your user
* ``--os-password OS_PASSWORD``: Password for your user
* ``--os-project-name OS_PROJECT_NAME``: Name of your project
* ``--os-auth-url OS_AUTH_URL``: URL of the Keystone authentication server

You can also set these variables in your environment so that they do not need
to be passed as arguments each time:

.. code-block:: bash

    $ export OS_USERNAME=my_username
    $ export OS_PASSWORD=my_password
    $ export OS_PROJECT_NAME=my_project
    $ export OS_AUTH_URL=http://localhost:35357/v2.0

If using ``python-keystoneclient``, set the following instead:

* ``--os-tenant-name OS_TENANT_NAME``: equivalent to
  ``--os-project-name OS_PROJECT_NAME``


Example usage
-------------

``python-openstackclient`` is set up to expect commands in the general form of:

.. code-block:: bash

  $ openstack [<global-options>] <object-1> <action> [<object-2>] [<command-arguments>]

For example, the commands ``user list`` and ``project create`` can be invoked
as follows:

.. code-block:: bash

    # Using token authentication, with environment variables
    $ export OS_URL=http://127.0.0.1:35357/v2.0/
    $ export OS_TOKEN=secrete_token
    $ openstack user list
    $ openstack project create demo

    # Using token authentication, with flags
    $ openstack --os-token=secrete --os-url=http://127.0.0.1:35357/v2.0/ user list
    $ openstack --os-token=secrete --os-url=http://127.0.0.1:35357/v2.0/ project create demo

    # Using password authentication, with environment variables
    $ export OS_USERNAME=admin
    $ export OS_PASSWORD=secrete
    $ export OS_PROJECT_NAME=admin
    $ export OS_AUTH_URL=http://localhost:35357/v2.0
    $ openstack user list
    $ openstack project create demo

    # Using password authentication, with flags
    $ openstack --os-username=admin --os-password=secrete --os-project-name=admin --os-auth-url=http://localhost:35357/v2.0 user list
    $ openstack --os-username=admin --os-password=secrete --os-project-name=admin --os-auth-url=http://localhost:35357/v2.0 project create demo

For additional examples using ``python-keystoneclient`` refer to
`python-keystoneclient examples`_, likewise, for additional examples using
``python-openstackclient``, refer to `python-openstackclient examples`_.

.. _`python-keystoneclient examples`: cli_examples.html#using-python-keystoneclient-v2-0
.. _`python-openstackclient examples`: cli_examples.html#using-python-openstackclient-v3


Removing Expired Tokens
=======================

In the SQL backend expired tokens are not automatically removed. These tokens
can be removed with:

.. code-block:: bash

    $ keystone-manage token_flush

The memcache backend automatically discards expired tokens and so flushing is
unnecessary and if attempted will fail with a NotImplemented error.


Configuring the LDAP Identity Provider
======================================

As an alternative to the SQL Database backing store, Keystone can use a
directory server to provide the Identity service. An example Schema for
OpenStack would look like this::

  dn: dc=openstack,dc=org
  dc: openstack
  objectClass: dcObject
  objectClass: organizationalUnit
  ou: openstack

  dn: ou=Projects,dc=openstack,dc=org
  objectClass: top
  objectClass: organizationalUnit
  ou: groups

  dn: ou=Users,dc=openstack,dc=org
  objectClass: top
  objectClass: organizationalUnit
  ou: users

  dn: ou=Roles,dc=openstack,dc=org
  objectClass: top
  objectClass: organizationalUnit
  ou: roles

The corresponding entries in the Keystone configuration file are:

.. code-block:: ini

  [ldap]
  url = ldap://localhost
  user = dc=Manager,dc=openstack,dc=org
  password = badpassword
  suffix = dc=openstack,dc=org
  use_dumb_member = False
  allow_subtree_delete = False

  user_tree_dn = ou=Users,dc=openstack,dc=org
  user_objectclass = inetOrgPerson

  project_tree_dn = ou=Projects,dc=openstack,dc=org
  project_objectclass = groupOfNames

  role_tree_dn = ou=Roles,dc=openstack,dc=org
  role_objectclass = organizationalRole

The default object classes and attributes are intentionally simplistic. They
reflect the common standard objects according to the LDAP RFCs. However, in a
live deployment, the correct attributes can be overridden to support a
preexisting, more complex schema. For example, in the user object, the
objectClass posixAccount from RFC2307 is very common. If this is the underlying
objectclass, then the *uid* field should probably be *uidNumber* and *username*
field either *uid* or *cn*. To change these two fields, the corresponding
entries in the Keystone configuration file are:

.. code-block:: ini

  [ldap]
  user_id_attribute = uidNumber
  user_name_attribute = cn


There is a set of allowed actions per object type that you can modify depending
on your specific deployment. For example, the users are managed by another tool
and you have only read access, in such case the configuration is:

.. code-block:: ini

  [ldap]
  user_allow_create = False
  user_allow_update = False
  user_allow_delete = False

  project_allow_create = True
  project_allow_update = True
  project_allow_delete = True

  role_allow_create = True
  role_allow_update = True
  role_allow_delete = True

There are some configuration options for filtering users, tenants and roles, if
the backend is providing too much output, in such case the configuration will
look like:

.. code-block:: ini

  [ldap]
  user_filter = (memberof=CN=openstack-users,OU=workgroups,DC=openstack,DC=org)
  project_filter =
  role_filter =

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
  user_objectclass          = person
  user_id_attribute         = cn
  user_name_attribute       = cn
  user_mail_attribute       = mail
  user_enabled_attribute    = userAccountControl
  user_enabled_mask         = 2
  user_enabled_default      = 512
  user_attribute_ignore     = tenant_id,tenants
  project_objectclass       = groupOfNames
  project_id_attribute      = cn
  project_member_attribute  = member
  project_name_attribute    = ou
  project_desc_attribute    = description
  project_enabled_attribute = extensionName
  project_attribute_ignore  =
  role_objectclass          = organizationalRole
  role_id_attribute         = cn
  role_name_attribute       = ou
  role_member_attribute     = roleOccupant
  role_attribute_ignore     =

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
the ``user_enabled_emulation`` and ``project_enabled_emulation`` attributes
have been created. They are enabled by setting their respective flags to True.
Then the attributes ``user_enabled_emulation_dn`` and
``project_enabled_emulation_dn`` may be set to specify how the enabled users
and projects (tenants) are selected. These attributes work by using a
``groupOfNames`` and adding whichever users or projects (tenants) that you want
enabled to the respective group. For example, this will mark any user who is a
member of ``enabled_users`` as enabled:

.. code-block:: ini

  [ldap]
  user_enabled_emulation = True
  user_enabled_emulation_dn = cn=enabled_users,cn=groups,dc=openstack,dc=org

The default values for user and project (tenant) enabled emulation DN is
``cn=enabled_users,$user_tree_dn`` and ``cn=enabled_tenants,$project_tree_dn``
respectively.

Secure Connection
-----------------

If you are using a directory server to provide the Identity service, it is
strongly recommended that you utilize a secure connection from Keystone to the
directory server. In addition to supporting LDAP, Keystone also provides
Transport Layer Security (TLS) support. There are some basic configuration
options for enabling TLS, identifying a single file or directory that contains
certificates for all the Certificate Authorities that the Keystone LDAP client
will recognize, and declaring what checks the client should perform on server
certificates. This functionality can easily be configured as follows:

.. code-block:: ini

  [ldap]
  use_tls = True
  tls_cacertfile = /etc/keystone/ssl/certs/cacert.pem
  tls_cacertdir = /etc/keystone/ssl/certs/
  tls_req_cert = demand

A few points worth mentioning regarding the above options. If both
tls_cacertfile and tls_cacertdir are set then tls_cacertfile will be used and
tls_cacertdir is ignored. Furthermore, valid options for tls_req_cert are
demand, never, and allow. These correspond to the standard options permitted by
the TLS_REQCERT TLS option.

Read Only LDAP
--------------

Many environments typically have user and group information in directories that
are accessible by LDAP. This information is for read-only use in a wide array
of applications. Prior to the Havana release, we could not deploy Keystone with
read-only directories as backends because Keystone also needed to store
information such as projects, roles, domains and role assignments into the
directories in conjunction with reading user and group information.

Keystone now provides an option whereby these read-only directories can be
easily integrated as it now enables its identity entities (which comprises
users, groups, and group memberships) to be served out of directories while
resource (which comprises projects and domains), assignment and role
entities are to be served from different Keystone backends (i.e. SQL). To
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

With the above configuration, Keystone will only lookup identity related
information such users, groups, and group membership from the directory, while
resources, roles and assignment related information will be provided by the SQL
backend. Also note that if there is an LDAP Identity, and no resource,
assignment or role backend is specified, they will default to LDAP. Although
this may seem counter intuitive, it is provided for backwards compatibility.
Nonetheless, the explicit option will always override the implicit option, so
specifying the options as shown above will always be correct.  Finally, it is
also worth noting that whether or not the LDAP accessible directory is to be
considered read only is still configured as described in a previous section
above by setting values such as the following in the ``[ldap]`` configuration
section:

.. code-block:: ini

  [ldap]
  user_allow_create = False
  user_allow_update = False
  user_allow_delete = False

.. NOTE::

    While having identity related information backed by LDAP while other
    information is backed by SQL is a supported configuration, as shown above;
    the opposite is not true. If either resource or assignment drivers are
    configured for LDAP, then Identity must also be configured for LDAP.

Connection Pooling
------------------

Various LDAP backends in Keystone use a common LDAP module to interact with
LDAP data. By default, a new connection is established for each LDAP operation.
This can become highly expensive when TLS support is enabled, which is a likely
configuration in an enterprise setup. Reuse of connectors from a connection
pool drastically reduces overhead of initiating a new connection for every LDAP
operation.

Keystone provides connection pool support via configuration. This will keep
LDAP connectors alive and reused for subsequent LDAP operations. The connection
lifespan is configurable as other pooling specific attributes.

In the LDAP identity driver, Keystone authenticates end users via an LDAP bind
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
  # Enable LDAP connection pooling. (boolean value)
  use_pool=false

  # Connection pool size. (integer value)
  pool_size=10

  # Maximum count of reconnect trials. (integer value)
  pool_retry_max=3

  # Time span in seconds to wait between two reconnect trials.
  # (floating point value)
  pool_retry_delay=0.1

  # Connector timeout in seconds. Value -1 indicates indefinite wait for
  # response. (integer value)
  pool_connection_timeout=-1

  # Connection lifetime in seconds. (integer value)
  pool_connection_lifetime=600

  # Enable LDAP connection pooling for end user authentication. If use_pool
  # is disabled, then this setting is meaningless and is not used at all.
  # (boolean value)
  use_auth_pool=false

  # End user auth connection pool size. (integer value)
  auth_pool_size=100

  # End user auth connection lifetime in seconds. (integer value)
  auth_pool_connection_lifetime=60

