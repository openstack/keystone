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
* It will also retrive additional information from the token such as user
  name, id, tenant name, id, roles, etc...

The middleware will pass those data down to the service as headers. More
details on the architecture of that setup is described in
:doc:`middlewarearchitecture`

Setting up credentials
======================

Admin Token
-----------

For a default installation of Keystone, before you can use the REST API, you
need to define an authorization token. This is configured in ``keystone.conf``
file under the section ``[DEFAULT]``. In the sample file provided with the
keystone project, the line defining this token is::

    [DEFAULT]
    admin_token = ADMIN

This configured token is a "shared secret" between keystone and other
openstack services, and is used by the client to communicate with the API to
create tenants, users, roles, etc.

Setting up tenants, users, and roles
------------------------------------

You need to minimally define a tenant, user, and role to link the tenant and
user as the most basic set of details to get other services authenticating
and authorizing with keystone.

You will also want to create service users for nova, glance, swift, etc. to
be able to use to authenticate users against keystone. The ``auth_token``
middleware supports using either the shared secret described above as
`admin_token` or users for each service.

See :doc:`configuration` for a walk through on how to create tenants, users,
and roles.

Setting up services
===================

Creating Service Users
----------------------

To configure the OpenStack services with service users, we need to create
a tenant for all the services, and then users for each of the services. We
then assign those service users an Admin role on the service tenant. This
allows them to validate tokens - and authenticate and authorize other user
requests.

Create a tenant for the services, typically named 'service' (however, the name can be whatever you choose)::

    keystone tenant-create --name=service

This returns a UUID of the tenant - keep that, you'll need it when creating
the users and specifying the roles.

Create service users for nova, glance, swift, and neutron (or whatever
subset is relevant to your deployment)::

    keystone user-create --name=nova \
                         --pass=Sekr3tPass \
                         --tenant_id=[the uuid of the tenant] \
                         --email=nova@nothing.com

Repeat this for each service you want to enable. Email is a required field
in keystone right now, but not used in relation to the service accounts. Each
of these commands will also return a UUID of the user. Keep those to assign
the Admin role.

For adding the Admin role to the service accounts, you'll need to know the UUID
of the role you want to add. If you don't have them handy, you can look it
up quickly with::

    keystone role-list

Once you have it, assign the service users to the Admin role. This is all
assuming that you've already created the basic roles and settings as described
in :doc:`configuration`:

    keystone user-role-add --tenant_id=[uuid of the service tenant] \
                           --user=[uuid of the service account] \
                           --role=[uuid of the Admin role]

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
keystone is online, you need to add the services to the catalog::

    keystone service-create --name=nova \
                                   --type=compute \
                                   --description="Nova Compute Service"
    keystone service-create --name=ec2 \
                                   --type=ec2 \
                                   --description="EC2 Compatibility Layer"
    keystone service-create --name=glance \
                                   --type=image \
                                   --description="Glance Image Service"
    keystone service-create --name=keystone \
                                   --type=identity \
                                   --description="Keystone Identity Service"
    keystone service-create --name=swift \
                                   --type=object-store \
                                   --description="Swift Service"


Setting Up Middleware
=====================

Keystone Auth-Token Middleware
--------------------------------

The Keystone auth_token middleware is a WSGI component that can be inserted in
the WSGI pipeline to handle authenticating tokens with Keystone. You can
get more details of the middleware in :doc:`middlewarearchitecture`.

Configuring Nova to use Keystone
--------------------------------

When configuring Nova, it is important to create a admin service token for
the service (from the Configuration step above) and include that as the key
'admin_token' in Nova's api-paste.ini [filter:authtoken] section or in
nova.conf [keystone_authtoken] section.

Configuring Swift to use Keystone
---------------------------------

Similar to Nova, swift can be configured to use Keystone for authentication
rather than its built in 'tempauth'. Refer to the `overview_auth` documentation
in Swift. 

Auth-Token Middleware with Username and Password
------------------------------------------------

It is also possible to configure Keystone's auth_token middleware using the
'admin_user' and 'admin_password' options. When using the 'admin_user' and
'admin_password' options the 'admin_token' parameter is optional. If
'admin_token' is specified it will by used only if the specified token is
still valid.

Here is an example paste config filter that makes use of the 'admin_user' and
'admin_password' parameters::

    [filter:authtoken]
    paste.filter_factory = keystoneclient.middleware.auth_token:filter_factory
    auth_port = 35357
    auth_host = 127.0.0.1
    auth_token = 012345SECRET99TOKEN012345
    admin_user = admin
    admin_password = keystone123

It should be noted that when using this option an admin tenant/role
relationship is required. The admin user is granted access to to the 'Admin'
role to the 'admin' tenant.

The auth_token middleware can also be configured in nova.conf
[keystone_authtoken] section to keep paste config clean of site-specific
parameters::

    [filter:authtoken]
    paste.filter_factory = keystoneclient.middleware.auth_token:filter_factory

and in nova.conf::

    [DEFAULT]
    ...
    auth_strategy=keystone

    [keystone_authtoken]
    auth_port = 35357
    auth_host = 127.0.0.1
    admin_user = admin
    admin_password = keystone123
