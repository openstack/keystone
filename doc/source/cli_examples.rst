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

===============================
Command Line Interface Examples
===============================

The Keystone command line interface packaged in `python-keystoneclient`_ only
supports the Identity v2.0 API. The OpenStack common command line interface
packaged in `python-openstackclient`_  supports both v2.0 and v3 APIs.

.. NOTE::

    As of the Juno release, it is recommended to use ``python-openstackclient``,
    as it suports both v2.0 and v3 APIs. For the purpose of backwards compatibility,
    the CLI packaged in ``python-keystoneclient`` is not being removed.

.. _`python-openstackclient`: http://docs.openstack.org/developer/python-openstackclient/
.. _`python-keystoneclient`: http://docs.openstack.org/developer/python-keystoneclient/

Using python-openstackclient (v3)
=================================

Note that if using ``python-openstackclient`` for v3 commands, the following
environment variables must be updated:

.. code-block:: bash

    $ export OS_IDENTITY_API_VERSION=3 (Defaults to 2.0)
    $ export OS_AUTH_URL=http://localhost:5000/v3

Since Identity API v3 authentication is a bit more complex, there are additional
options that may be set, either as command options or environment variables.
The most common case will be a user supplying both user name and password, along
with the project name; previously in v2.0 this would be sufficient, but since
Identity API v3 has a ``Domain`` component, we need to tell the client in which
domain the user and project exists.

If using a project name as authorization scope, set either of these:

  * ``--os-project-domain-name OS_PROJECT_DOMAIN_NAME``  Domain name of the project
    which is the requested project-level authorization scope
  * ``--os-project-domain-id OS_PROJECT_DOMAIN_ID`` Domain ID of the project which
    is the requested project-level authorization scope

Note, if using a project ID as authorization scope, then it is not required to
set ``OS_PROJECT_DOMAIN_NAME`` or ``OS_PROJECT_DOMAIN_ID``, the project ID is
sufficient.

If using user name and password, set either of these:

  * ``--os-user-domain-name OS_USER_DOMAIN_NAME``  Domain name of the user
  * ``--os-user-domain-id OS_USER_DOMAIN_ID`` Domain ID of the user

If using a domain as authorization scope, set either of these:

  * ``--os-domain-name OS_DOMAIN_NAME``: Domain name of the requested domain-level
    authorization scope
  * ``--os-domain-id OS_DOMAIN_ID``: Domain ID of the requested domain-level
    authorization scope

In the examples below, the following are set:

.. code-block:: bash

    $ export OS_IDENTITY_API_VERSION=3
    $ export OS_AUTH_URL=http://localhost:5000/v3
    $ export OS_PROJECT_DOMAIN_ID=default
    $ export OS_USER_DOMAIN_ID=default
    $ export OS_USERNAME=admin
    $ export OS_PASSWORD=openstack
    $ export OS_PROJECT_NAME=admin

--------
Projects
--------

``project create``
------------------

positional arguments::

  <project-name>                        New project name

optional arguments::

  --description <project-description>   New project description
  --domain <project-domain>             Domain owning the project (name or ID)

  --enable                              Enable project (default)
  --disable                             Disable project

example:

.. code-block:: bash

    $ openstack project create heat-project --domain heat

Other commands
--------------

.. code-block:: bash

  $ openstack project delete
  $ openstack project list
  $ openstack project set
  $ openstack project show

-----
Users
-----

``user create``
---------------

positional arguments::

  <user-name>                  New user name

optional arguments::

  --password <user-password>   New user password
  --password-prompt            Prompt interactively for password
  --email <user-email>         New user email address
  --project <project>          Set default project (name or ID)
  --domain <domain>            New default domain name or ID
  --enable                     Enable user (default)
  --disable                    Disable user


example:

.. code-block:: bash

    $ openstack user create heat-user \
    --password secrete \
    --domain heat \
    --project demo \
    --email admin@example.com

Other commands
--------------

.. code-block:: bash

  $ openstack user delete
  $ openstack user list
  $ openstack user set
  $ openstack user show

------
Groups
------

``group create``
----------------

positional arguments::

  <group-name>                        New group name

optional arguments::

  --description <group-description>   New group description
  --domain <group-domain>             References the domain ID or name which owns the group

example:

.. code-block:: bash

    $ openstack group create heat-group --domain heat

Other commands
--------------

.. code-block:: bash

  $ openstack group delete
  $ openstack group list
  $ openstack group set
  $ openstack group show

-------
Domains
-------

``domain create``
-----------------

positional arguments::

  <domain-name>                        New domain name

optional arguments::

  --description <domain-description>   New domain description
  --enable                             Enable domain
  --disable                            Disable domain


example:

.. code-block:: bash

  $ openstack domain create heat --description "Heat domain for heat users"

Other commands
--------------

.. code-block:: bash

  $ openstack domain delete
  $ openstack domain list
  $ openstack domain set
  $ openstack domain show

Using python-openstackclient (v2.0)
===================================

--------
Projects
--------

``project create``
------------------

positional arguments::

  <project-name>                        New project name

optional arguments::

  --description <project-description>   New project description
  --enable                              Enable project (default)
  --disable                             Disable project

example:

.. code-block:: bash

    $ openstack project create demo


``project delete``
------------------

positional arguments::

  <project>   Project to delete (name or ID)

example:

.. code-block:: bash

    $ openstack project delete demo

-----
Users
-----

``user create``
---------------

positional arguments::

  <user-name>                  New user name

optional arguments::

  --password <user-password>   New user password
  --password-prompt            Prompt interactively for password
  --email <user-email>         New user email address
  --project <project>          Set default project (name or ID)
  --enable                     Enable user (default)
  --disable                    Disable user


example:

.. code-block:: bash

    $ openstack user create heat-user \
    --password secrete \
    --project demo \
    --email admin@example.com

``user delete``
---------------

positional arguments::

  <user>   User to delete (name or ID)

example:

.. code-block:: bash

    $ openstack user delete heat-user

``user list``
-------------

optional arguments::

  --project <project>   Filter users by project (name or ID)
  --long                List additional fields in output

example:

.. code-block:: bash

    $ openstack user list

``user set``
------------

positional arguments::

  <user>                       User to change (name or ID)

optional arguments::

  --name <new-user-name>       New user name
  --password <user-password>   New user password
  --password-prompt            Prompt interactively for password
  --email <user-email>         New user email address
  --project <project>          New default project (name or ID)
  --enable                     Enable user (default)
  --disable                    Disable user


example:

.. code-block:: bash

    $ openstack user set heat-user --email newemail@example.com

-----
Roles
-----

``role create``
---------------

positional arguments::

  <role-name>           New role name

example:

.. code-block:: bash

    $ openstack role create demo

``role delete``
---------------

positional arguments::

  <role>      Name or ID of role to delete

example:

.. code-block:: bash

    $ openstack role delete demo

``role list``
-------------

example:

.. code-block:: bash

    $ openstack role list

``role show``
-------------

positional arguments::

  <role>                Name or ID of role to display

example:

.. code-block:: bash

    $ openstack role show demo


``role add``
------------

positional arguments::

  <role>                Role name or ID to add to user

optional arguments::

  --project <project>   Include project (name or ID)
  --user <user>         Name or ID of user to include


example:

.. code-block:: bash

    $ openstack user role add  demo --user heat-user --project heat

``role remove``
---------------

positional arguments::

  <role>               Role name or ID to remove from user

optional arguments::

  --project <project>  Project to include (name or ID)
  --user <user>        Name or ID of user


example:

.. code-block:: bash

    $ openstack user role remove  demo --user heat-user --project heat

--------
Services
--------

``service create``
------------------

positional arguments::

  <service-name>   New service name

optional arguments::

  --type <service-type>   New service type (compute, image, identity, volume, etc)
  --description <service-description>   New service description

example:

.. code-block:: bash

  $ openstack service create nova --type compute --description "Nova Compute Service"

``service list``
----------------

optional arguments::

  --long   List additional fields in output

example:

.. code-block:: bash

  $ openstack service list

``service show``
----------------

positional arguments::

  <service>   Service to display (type, name or ID)

example:

.. code-block:: bash

  $ openstack service show nova

``service delete``
------------------

positional arguments::

  <service>   Service to delete (name or ID)

example:

.. code-block:: bash

  $ openstack service delete nova


Using python-keystoneclient (v2.0)
==================================

-------
Tenants
-------

``tenant-create``
-----------------

keyword arguments

* name
* description (optional, defaults to None)
* enabled (optional, defaults to True)

example:

.. code-block:: bash

    $ keystone tenant-create --name=demo

creates a tenant named "demo".

``tenant-delete``
-----------------

arguments

* tenant_id

example:

.. code-block:: bash

    $ keystone tenant-delete f2b7b39c860840dfa47d9ee4adffa0b3

-----
Users
-----

``user-create``
---------------

keyword arguments

* name
* pass
* email
* tenant_id (optional, defaults to None)
* enabled (optional, defaults to True)

example:

.. code-block:: bash

    $ keystone user-create
    --name=admin \
    --pass=secrete \
    --tenant_id=2395953419144b67955ac4bab96b8fd2 \
    --email=admin@example.com

``user-delete``
---------------

keyword arguments

* user_id

example:

.. code-block:: bash

    $ keystone user-delete f2b7b39c860840dfa47d9ee4adffa0b3

``user-list``
-------------

list users in the system, optionally by a specific tenant (identified by tenant_id)

arguments

* tenant_id (optional, defaults to None)

example:

.. code-block:: bash

    $ keystone user-list

``user-update``
---------------------

arguments

* user_id

keyword arguments

* name     Desired new user name (Optional)
* email    Desired new email address (Optional)
* enabled <true|false>   Enable or disable user (Optional)


example:

.. code-block:: bash

    $ keystone user-update 03c84b51574841ba9a0d8db7882ac645 --email=newemail@example.com

``user-password-update``
------------------------

arguments

* user_id
* password

example:

.. code-block:: bash

    $ keystone user-password-update --pass foo 03c84b51574841ba9a0d8db7882ac645

-----
Roles
-----

``role-create``
---------------

arguments

* name

example:

.. code-block:: bash

    $ keystone role-create --name=demo

``role-delete``
---------------

arguments

* role_id

example:

.. code-block:: bash

    $ keystone role-delete 19d1d3344873464d819c45f521ff9890

``role-list``
-------------

example:

.. code-block:: bash

    $ keystone role-list

``role-get``
------------

arguments

* role_id

example:

.. code-block:: bash

    $ keystone role-get 19d1d3344873464d819c45f521ff9890


``user-role-add``
-----------------

keyword arguments

* user <user-id>
* role <role-id>
* tenant_id <tenant-id>

example:

.. code-block:: bash

    $ keystone user-role-add  \
      --user=96a6ebba0d4c441887aceaeced892585  \
      --role=f8dd5a2e4dc64a41b96add562d9a764e  \
      --tenant_id=2395953419144b67955ac4bab96b8fd2

``user-role-remove``
--------------------

keyword arguments

* user <user-id>
* role <role-id>
* tenant_id <tenant-id>

example:

.. code-block:: bash

    $ keystone user-role-remove  \
      --user=96a6ebba0d4c441887aceaeced892585  \
      --role=f8dd5a2e4dc64a41b96add562d9a764e  \
      --tenant_id=2395953419144b67955ac4bab96b8fd2

--------
Services
--------

``service-create``
------------------

keyword arguments

* name
* type
* description

example:

.. code-block:: bash

    $ keystone service-create \
    --name=nova \
    --type=compute \
    --description="Nova Compute Service"

``service-list``
----------------

arguments

* service_id

example:

.. code-block:: bash

    $ keystone service-list

``service-get``
---------------

arguments

* service_id

example:

.. code-block:: bash

    $ keystone service-get 08741d8ed88242ca88d1f61484a0fe3b

``service-delete``
------------------

arguments

* service_id

example:

.. code-block:: bash

    $ keystone service-delete 08741d8ed88242ca88d1f61484a0fe3b
