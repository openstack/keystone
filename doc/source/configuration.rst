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

See `API Specification for Endpoint Policy <https://developer.openstack.org/
api-ref/identity/v3-ext/index.html#os-endpoint-policy-api>`_
for the details of API definition.

SSL
===

A secure deployment should have keystone running in a web server (such as
Apache httpd), or behind an SSL terminator.

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

    $ openstack --os-token ADMIN --os-url http://127.0.0.1:35357/v3/ project list

.. NOTE::

    We're providing the default OS_TOKEN and OS_URL values from
    ``keystone.conf`` to connect to the keystone service. If you changed those
    values, or deployed keystone to a different endpoint, you will need to
    change the provided command accordingly.

Supported clients
=================

There are two supported clients, `python-keystoneclient`_ project provides
python bindings and `python-openstackclient`_ provides a command line
interface.

.. _`python-openstackclient`: https://docs.openstack.org/python-openstackclient/latest
.. _`python-keystoneclient`: https://docs.openstack.org/python-keystoneclient/latest


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
    $ export OS_AUTH_URL=http://localhost:35357/v3

For example, the commands ``user list``, ``token issue`` and ``project create``
can be invoked as follows:

.. code-block:: bash

    # Using password authentication, with environment variables
    $ export OS_USERNAME=admin
    $ export OS_PASSWORD=secret
    $ export OS_PROJECT_NAME=admin
    $ export OS_AUTH_URL=http://localhost:35357/v3
    $ openstack user list
    $ openstack project create demo
    $ openstack token issue

    # Using password authentication, with flags
    $ openstack --os-username=admin --os-password=secret --os-project-name=admin --os-auth-url=http://localhost:35357/v3 user list
    $ openstack --os-username=admin --os-password=secret --os-project-name=admin --os-auth-url=http://localhost:35357/v3 project create demo
