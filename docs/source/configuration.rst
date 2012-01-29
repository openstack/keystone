..
      Copyright 2011 OpenStack, LLC
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

Once Keystone is installed, it is configured via a primary configuration file
(``etc/keystone.conf``), possibly a separate logging configuration file, and
initializing data into keystone using the command line client.


Keystone Configuration File
===========================

The keystone configuration file is an 'ini' file format with sections, 
extended from Paste_, a common system used to configure python WSGI based
applications. In addition to the paste config entries, general configuration
values are stored under [DEFAULT] and [sql], and then drivers for the various
backend components are included under their individual sections.

The driver sections include:
* ``[identity]`` - the python module that backends the identity system
* ``[catalog]`` - the python module that backends the service catalog
* ``[token]`` - the python module that backends the token providing mechanisms
* ``[policy]`` - the python module that drives the policy system for RBAC
* ``[ec2]`` - the python module providing the EC2 translations for OpenStack

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

A sample logging file is available with the project in the directory ``etc/logging.conf.sample``. Like other OpenStack projects, keystone uses the
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

Initializing Keystone
=====================

Keystone must be running in order to initialize data within it. This is because
the keystone-manage commands are all used the same REST API that other
OpenStack systems utilize.

General keystone-manage options:
--------------------------------

* ``--id-only`` : causes ``keystone-manage`` to return only the UUID result
from the API call.
* ``--endpoint`` : allows you to specify the keystone endpoint to communicate with. The default endpoint is http://localhost:35357/v2.0'
* ``--auth-token`` : provides the authorization token

``keystone-manage`` is set up to expect commands in the general form of ``keystone-manage`` ``command`` ``subcommand``, with keyword arguments to provide additional information to the command. For example, the command
``tenant`` has the subcommand ``create``, which takes the required keyword ``tenant_name``::

	keystone-manage tenant create tenant_name=example_tenant

Invoking keystone-manage by itself will give you some usage information.

Available keystone-manage commands:

* ``db_sync``: Sync the database.
* ``ec2``: no docs
* ``role``: Role CRUD functions.
* ``service``: Service CRUD functions.
* ``tenant``: Tenant CRUD functions.
* ``token``: Token CRUD functions.
* ``user``: User CRUD functions.

Tenants
-------

Tenants are the high level grouping within Keystone that represent groups of
users. A tenant is the grouping that owns virtual machines within Nova, or
containers within Swift. A tenant can have zero or more users, Users can be assocaited with more than one tenant, and each tenant - user pairing can have a role associated with it.

``tenant create``
^^^^^^^^^^^^^^^^^

keyword arguments

* tenant_name
* id (optional)

example::

	keystone-manage --id-only tenant create tenant_name=admin

creates a tenant named "admin".

``tenant delete``
^^^^^^^^^^^^^^^^^

keyword arguments

* tenant_id
	
example::

	keystone-manage tenant delete tenant_id=f2b7b39c860840dfa47d9ee4adffa0b3

``tenant update``
^^^^^^^^^^^^^^^^^

keyword arguments

* description
* name
* tenant_id

example::

	keystone-manage tenant update \
	tenant_id=f2b7b39c860840dfa47d9ee4adffa0b3 \
	description="those other guys" \
	name=tog

Users
-----

``user create``
^^^^^^^^^^^^^^^

keyword arguments

* name
* password
* email
	
example::

	keystone-manage user --ks-id-only create \
	name=admin \
	password=secrete \
	email=admin@example.com
	
``user delete``
^^^^^^^^^^^^^^^

keyword arguments

``user list``
^^^^^^^^^^^^^

keyword arguments

``user update_email``
^^^^^^^^^^^^^^^^^^^^^

keyword arguments

``user update_enabled``
^^^^^^^^^^^^^^^^^^^^^^^

keyword arguments

``user update_password``
^^^^^^^^^^^^^^^^^^^^^^^^
 
keyword arguments

``user update_tenant``
^^^^^^^^^^^^^^^^^^^^^^

keyword arguments

Roles
-----

``role create``
^^^^^^^^^^^^^^^

keyword arguments

* name

exmaple::

	keystone-manage role --ks-id-only create name=Admin
	
``role add_user_to_tenant``
^^^^^^^^^^^^^^^^^^^^^^^^^^^

keyword arguments

* role_id
* user_id
* tenant_id

example::

	keystone-manage role add_user_to_tenant \
	role_id=19d1d3344873464d819c45f521ff9890 \
	user_id=08741d8ed88242ca88d1f61484a0fe3b \
	tenant_id=20601a7f1d94447daa4dff438cb1c209
	
``role remove_user_from_tenant``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

``role get_user_role_refs``
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Services
--------

``service create``
^^^^^^^^^^^^^^^^^^

keyword arguments

* name
* service_type
* description

example::

    keystone-manage service create \
    name=nova \
    service_type=compute \
    description="Nova Compute Service"
