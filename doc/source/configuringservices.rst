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

==========================================
Configuring Services to work with Keystone
==========================================

.. toctree::
   :maxdepth: 1

Once Keystone is installed and running (see :doc:`configuration`), services
need to be configured to work with it. To do this, we primarily install and
configure middleware for the OpenStack service to handle authentication tasks
or otherwise interact with Keystone.

In general:

* Clients making calls to the service will pass in an authentication token.
* The Keystone middleware will look for and validate that token, taking the
  appropriate action.
* It will also retrieve additional information from the token such as user
  name, user id, project name, project id, roles, etc...

The middleware will pass those data down to the service as headers. More
details on the architecture of that setup is described in the
`authentication middleware documentation`_.

Setting up credentials
======================

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
To disable in production (highly recommended), remove AdminTokenAuthMiddleware
from your paste application pipelines (for example, in keystone-paste.ini)

Setting up projects, users, and roles
-------------------------------------

You need to minimally define a project, user, and role to link the project and
user as the most basic set of details to get other services authenticating
and authorizing with Keystone.

You will also want to create service users for nova, glance, swift, etc. to
be able to use to authenticate users against Keystone. The ``auth_token``
middleware supports using either the shared secret described above as
`admin_token` or users for each service.

See :doc:`configuration` for a walk through on how to create projects, users,
and roles.

Setting up services
===================

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

Once you have it, grant the administrative role to the service users. This is
all assuming that you've already created the basic roles and settings as
described in :doc:`configuration`:

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


Setting Up Auth-Token Middleware
================================

The Keystone project provides the auth-token middleware which validates that
the request is valid before passing it on to the application. This must be
installed and configured in the applications (such as Nova, Glance, Swift,
etc.). The `authentication middleware documentation`_ describes how to install
and configure this middleware.

.. _`authentication middleware documentation`: http://docs.openstack.org/developer/keystonemiddleware/middlewarearchitecture.html
