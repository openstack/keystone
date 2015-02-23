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
    as it supports both v2.0 and v3 APIs. For the purpose of backwards compatibility,
    the CLI packaged in ``python-keystoneclient`` is not being removed.

.. _`python-openstackclient`: http://docs.openstack.org/developer/python-openstackclient/
.. _`python-keystoneclient`: http://docs.openstack.org/developer/python-keystoneclient/

Using python-openstackclient (v3 or v2.0)
=========================================

A complete list of OpenStackClient commands with full examples are located at
OpenStackClient's `Command List`_ page. Additionally, for details related to
authentication, refer to OpenStackClient's `Authentication`_ page.

.. _`Command List`: http://docs.openstack.org/developer/python-openstackclient/command-list.html
.. _`Authentication`: http://docs.openstack.org/developer/python-openstackclient/authentication.html

Using python-keystoneclient (v2.0-only)
=======================================

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
