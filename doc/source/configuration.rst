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


Keystone Configuration File
===========================

The keystone configuration file is an 'ini' file format with sections,
extended from Paste_, a common system used to configure python WSGI based
applications. In addition to the paste config entries, general configuration
values are stored under ``[DEFAULT]``, ``[sql]``, ``[ec2]`` and then drivers
for the various services are included under their individual sections.

The services include:
* ``[identity]`` - the python module that backends the identity system
* ``[catalog]`` - the python module that backends the service catalog
* ``[token]`` - the python module that backends the token providing mechanisms
* ``[policy]`` - the python module that drives the policy system for RBAC

The keystone configuration file is expected to be named ``keystone.conf``.
When starting up Keystone, you can specify a different configuration file to
use with ``--config-file``. If you do **not** specify a configuration file,
keystone will look in the following directories for a configuration file, in
order:

* ``~/.keystone``
* ``~/``
* ``/etc/keystone``
* ``/etc``

Logging is configured externally to the rest of keystone, the file specifying
the logging configuration is in the [DEFAULT] section of the keystone conf
file under ``log_config``. If you wish to route all your logging through
syslog, there is a ``use_syslog`` option also in the [DEFAULT] section that
easy.

A sample logging file is available with the project in the directory
``etc/logging.conf.sample``. Like other OpenStack projects, keystone uses the
`python logging module`, which includes extensive configuration options for
choosing the output levels and formats.

In addition to this documentation page, you can check the ``etc/keystone.conf``
sample configuration files distributed with keystone for example configuration
files for each server application.

.. _Paste: http://pythonpaste.org/
.. _`python logging module`: http://docs.python.org/library/logging.html

Sample Configuration Files
--------------------------

* ``etc/keystone.conf``
* ``etc/logging.conf.sample``

Running Keystone
================

Running keystone is simply starting the services by using the command::

    keystone-all

Invoking this command starts up two wsgi.Server instances, configured by the
``keystone.conf`` file as described above. One of these wsgi 'servers' is
``admin`` (the administration API) and the other is ``main`` (the
primary/public  API interface). Both of these run in a single process.

Migrating from legacy versions of keystone
==========================================
Migration support is provided for the following legacy keystone versions:

* diablo-5
* stable/diablo
* essex-2
* essex-3

To migrate from legacy versions of keystone, use the following steps:

Step 1: Configure keystone.conf
-------------------------------
It is important that the database that you specify be different from the one
containing your existing install.

Step 2: db_sync your new, empty database
----------------------------------------
Run the following command to configure the most recent schema in your new
keystone installation::

    keystone-manage db_sync

Step 3: Import your legacy data
-------------------------------
Use the following command to import your old data::

    keystone-manage import_legacy [db_url, e.g. 'mysql://root@foobar/keystone']

Specify db_url as the connection string that was present in your old
keystone.conf file.

Step 4: Import your legacy service catalog
------------------------------------------
While the older keystone stored the service catalog in the database,
the updated version configures the service catalog using a template file.
An example service catalog template file may be found in
etc/default_catalog.templates.

To import your legacy catalog, run this command::

    keystone-manage export_legacy_catalog \
        [db_url e.g. 'mysql://root@foobar/keystone'] > \
        [path_to_templates e.g. 'etc/default_catalog.templates']

After executing this command, you will need to restart the keystone service to
see your changes.

Migrating from Nova Auth
========================
Migration of users, projects (aka tenants), roles and EC2 credentials
is supported for the Diablo and Essex releases of Nova. To migrate your auth
data from Nova, use the following steps:

Step 1: Export your data from Nova
----------------------------------
Use the following command to export your data fron Nova::

    nova-manage export auth > /path/to/dump

It is important to redirect the output to a file so it can be imported
in a later step.

Step 2: db_sync your new, empty database
----------------------------------------
Run the following command to configure the most recent schema in your new
keystone installation::

    keystone-manage db_sync

Step 3: Import your data to Keystone
------------------------------------
To import your Nova auth data from a dump file created with nova-manage,
run this command::

    keystone-manage import_nova_auth [dump_file, e.g. /path/to/dump]

.. note::
    Users are added to Keystone with the user id from Nova as the user name.
    Nova's projects are imported with the project id as the tenant name. The
    password used to authenticate a user in Keystone will be the api key
    (also EC2 access key) used in Nova. Users also lose any administrative
    privileges they had in Nova. The necessary admin role must be explicitly
    re-assigned to each user.

.. note::
    Users in Nova's auth system have a single set of EC2 credentials that
    works with all projects (tenants) that user can access. In Keystone, these
    credentials are scoped to a single user/tenant pair. In order to use the
    same secret keys from Nova, you must prefix each corresponding access key
    with the id of the project used in Nova. For example, if you had access
    to the 'Beta' project in your Nova installation with the access/secret
    keys 'XXX'/'YYY', you should use 'Beta:XXX'/'YYY' in Keystone. These
    credentials are active once your migration is complete.

Initializing Keystone
=====================

keystone-manage is designed to execute commands that cannot be administered
through the normal REST api.  At the moment, the following calls are supported:

* ``db_sync``: Sync the database.
* ``import_legacy``: Import a legacy (pre-essex) version of the db.
* ``export_legacy_catalog``: Export service catalog from a legacy (pre-essex) db.
* ``import_nova_auth``: Load auth data from a dump created with keystone-manage.


Generally, the following is the first step after a source installation::

    keystone-manage db_sync

Invoking keystone-manage by itself will give you additional usage information.

Adding Users, Tenants, and Roles with python-keystoneclient
===========================================================

User, tenants, and roles must be administered using admin credentials.
There are two ways to configure python-keystoneclient to use admin
credentials, using the token auth method, or password auth method.

Token Auth Method
-----------------
To use keystone client using token auth, set the following flags

* ``--endpoint SERVICE_ENDPOINT`` : allows you to specify the keystone endpoint to communicate
  with. The default endpoint is http://localhost:35357/v2.0'
* ``--token SERVICE_TOKEN`` : your administrator service token.

Password Auth Method
--------------------

* ``--username OS_USERNAME`` : allows you to specify the keystone endpoint to communicate
  with. For example, http://localhost:35357/v2.0'
* ``--password OS_PASSWORD`` : Your administrator password
* ``--tenant_name OS_TENANT_NAME`` : Name of your tenant
* ``--auth_url OS_AUTH_URL`` : url of your keystone auth server, for example
http://localhost:5000/v2.0'

Example usage
-------------
``keystone`` is set up to expect commands in the general form of
``keystone`` ``command`` ``argument``, followed by flag-like keyword arguments to
provide additional (often optional) information. For example, the command
``user-list`` and ``tenant-create`` can be invoked as follows::

    # Using token auth env variables
    export SERVICE_ENDPOINT=http://127.0.0.1:5000/v2.0/
    export SERVICE_TOKEN=secrete_token
    keystone user-list
    keystone tenant-create --name=demo

    # Using token auth flags
    keystone --token=secrete --endpoint=http://127.0.0.1:5000/v2.0/ user-list
    keystone --token=secrete --endpoint=http://127.0.0.1:5000/v2.0/ tenant-create --name=demo

    # Using user + password + tenant_name env variables
    export OS_USERNAME=admin
    export OS_PASSWORD=secrete
    export OS_TENANT_NAME=admin
    keystone user-list
    keystone tenant-create --name=demo

    # Using user + password + tenant_name flags
    keystone --username=admin --password=secrete --tenant_name=admin user-list
    keystone --username=admin --password=secrete --tenant_name=admin tenant-create --name=demo

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

	keystone tenant-create --name=demo

creates a tenant named "demo".

``tenant-delete``
^^^^^^^^^^^^^^^^^

arguments

* tenant_id

example::

	keystone tenant-delete f2b7b39c860840dfa47d9ee4adffa0b3

``tenant-enable``
^^^^^^^^^^^^^^^^^

arguments

* tenant_id

example::

	keystone tenant-enable f2b7b39c860840dfa47d9ee4adffa0b3

``tenant-disable``
^^^^^^^^^^^^^^^^^

arguments

* tenant_id

example::

	keystone tenant-disable f2b7b39c860840dfa47d9ee4adffa0b3

Users
-----

``user-create``
^^^^^^^^^^^^^^^

keyword arguments

* name
* pass
* email
* default_tenant (optional, defaults to None)
* enabled (optional, defaults to True)

example::

	keystone user-create
	--name=admin \
	--pass=secrete \
	--email=admin@example.com

``user-delete``
^^^^^^^^^^^^^^^

keyword arguments

* user

example::

	keystone user-delete f2b7b39c860840dfa47d9ee4adffa0b3

``user-list``
^^^^^^^^^^^^^

list users in the system, optionally by a specific tenant (identified by tenant_id)

arguments

* tenant_id (optional, defaults to None)

example::

	keystone user-list

``user-update-email``
^^^^^^^^^^^^^^^^^^^^^

arguments
* user_id
* email


example::

	keystone user-update-email 03c84b51574841ba9a0d8db7882ac645 "someone@somewhere.com"

``user-enable``
^^^^^^^^^^^^^^^^^^^^^^^

arguments

* user_id

example::

	keystone user-enable 03c84b51574841ba9a0d8db7882ac645

``user-disable``
^^^^^^^^^^^^^^^^^^^^^^^

arguments

* user_id

example::

	keystone user-disable 03c84b51574841ba9a0d8db7882ac645


``user-update-password``
^^^^^^^^^^^^^^^^^^^^^^^^

arguments

* user_id
* password

example::

    keystone user-update-password 03c84b51574841ba9a0d8db7882ac645 foo

Roles
-----

``role-create``
^^^^^^^^^^^^^^^

arguments

* name

exmaple::

	keystone role-create --name=demo

``role-delete``
^^^^^^^^^^^^^^^

arguments

* role_id

exmaple::

	keystone role-delete 19d1d3344873464d819c45f521ff9890

``role-list``
^^^^^^^^^^^^^^^

exmaple::

	keystone role-list

``role-get``
^^^^^^^^^^^^

arguments

* role_id

exmaple::

	keystone role-get role=19d1d3344873464d819c45f521ff9890


``add-user-role``
^^^^^^^^^^^^^^^^^^^^^^

arguments

* role_id
* user_id
* tenant_id

example::

	keystone role add-user-role \
	3a751f78ef4c412b827540b829e2d7dd \
	03c84b51574841ba9a0d8db7882ac645 \
	20601a7f1d94447daa4dff438cb1c209

``remove-user-role``
^^^^^^^^^^^^^^^^^^^^^^^^^

arguments

* role_id
* user_id
* tenant_id

example::

	keystone remove-user-role \
	19d1d3344873464d819c45f521ff9890 \
	08741d8ed88242ca88d1f61484a0fe3b \
	20601a7f1d94447daa4dff438cb1c209

Services
--------

``service-create``
^^^^^^^^^^^^^^^^^^

keyword arguments

* name
* type
* description

example::

    keystone service create \
    --name=nova \
    --type=compute \
    --description="Nova Compute Service"

``service-list``
^^^^^^^^^^^^^^^^

arguments

* service_id

example::

	keystone service-list

``service-get``
^^^^^^^^^^^^^^^

arguments

* service_id

example::

	keystone service-get 08741d8ed88242ca88d1f61484a0fe3b

``service-delete``
^^^^^^^^^^^^^^^^^^

arguments

* service_id

example::

	keystone service-delete 08741d8ed88242ca88d1f61484a0fe3b

