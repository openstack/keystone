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

==========================================
Configuring Services to work with Keystone
==========================================

.. toctree::
   :maxdepth: 1

    middleware_architecture

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
:doc:`middleware_architecture`

Setting up credentials
======================

Admin Token
-----------

For a default installation of Keystone, before you can use the REST API, you
need to define an authorization token. This is configured in ``keystone.conf``
file under the section ``[DEFAULT]``. In the sample file provided with the
keystone project, the line defining this token is

	[DEFAULT]
	admin_token = ADMIN

This configured token is a "shared secret" between keystone and other
openstack services (for example: nova, swift, glance, or horizon), and will
need to be set the same between those services in order for keystone services
to function correctly.

Setting up tenants, users, and roles
------------------------------------

You need to minimally define a tenant, user, and role to link the tenant and
user as the most basic set of details to get other services authenticating
and authorizing with keystone. See doc:`configuration` for a walk through on
how to create tenants, users, and roles.

Setting up services
===================

Defining Services
-----------------

Keystone also acts as a service catalog to let other OpenStack systems know
where relevant API endpoints exist for OpenStack Services. The OpenStack
Dashboard, in particular, uses this heavily - and this **must** be configured
for the OpenStack Dashboard to properly function.

Here's how we define the services::

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

The endpoints for these services are defined in a template, an example of
which is in the project as the file ``etc/default_catalog.templates``.

Setting Up Middleware
=====================

Keystone Auth-Token Middleware
--------------------------------

The Keystone auth_token middleware is a WSGI component that can be inserted in
the WSGI pipeline to handle authenticating tokens with Keystone.

Configuring Nova to use Keystone
--------------------------------

When configuring Nova, it is important to create a admin service token for
the service (from the Configuration step above) and include that as the key
'admin_token' in Nova's api-paste.ini.

Configuring Swift to use Keystone
---------------------------------

Similar to Nova, swift can be configured to use Keystone for authentication
rather than it's built in 'tempauth'.

1. Add a service endpoint for Swift to Keystone

2. Configure the paste file for swift-proxy (`/etc/swift/swift-proxy.conf`)

3. Reconfigure Swift's proxy server to use Keystone instead of TempAuth.
   Here's an example `/etc/swift/proxy-server.conf`::

    [DEFAULT]
    bind_port = 8888
    user = <user>

    [pipeline:main]
    pipeline = catch_errors healthcheck cache tokenauth keystone proxy-server

    [app:proxy-server]
    use = egg:swift#proxy
    account_autocreate = true

    [filter:keystone]
    paste.filter_factory = keystone.middleware.swift_auth:filter_factory
    operator_roles = admin, swiftoperator

    [filter:tokenauth]
    paste.filter_factory = keystone.middleware.auth_token:filter_factory
    service_port = 5000
    service_host = 127.0.0.1
    auth_port = 35357
    auth_host = 127.0.0.1
    auth_token = ADMIN
    admin_token = ADMIN

    [filter:cache]
    use = egg:swift#memcache
    set log_name = cache

    [filter:catch_errors]
    use = egg:swift#catch_errors

    [filter:healthcheck]
    use = egg:swift#healthcheck

.. Note::
   Your user needs to have the role swiftoperator or admin by default
   to be able to operate on an swift account or as specified by the
   variable `operator_roles`.

4. Restart swift

5. Verify that keystone is providing authentication to Swift

    $ swift -V 2 -A http://localhost:5000/v2.0 -U admin:admin -K ADMIN stat

.. NOTE::
   Instead of connecting to Swift here, as you would with other services, we
   are connecting directly to Keystone.

Configuring Swift with S3 emulation to use Keystone
---------------------------------------------------

Keystone support validating S3 tokens using the same tokens as the
generated EC2 tokens. When you have generated a pair of EC2 access
token and secret you can access your swift cluster directly with the
S3 api.

1. Configure the paste file for swift-proxy
   (`/etc/swift/swift-proxy.conf` to use S3token and Swift3
   middleware.

   Here's an example::

    [DEFAULT]
    bind_port = 8080
    user = <user>

    [pipeline:main]
    pipeline = catch_errors healthcheck cache swift3 s3token tokenauth keystone proxy-server

    [app:proxy-server]
    use = egg:swift#proxy
    account_autocreate = true

    [filter:catch_errors]
    use = egg:swift#catch_errors

    [filter:healthcheck]
    use = egg:swift#healthcheck

    [filter:cache]
    use = egg:swift#memcache

    [filter:swift3]
    use = egg:swift#swift3

    [filter:keystone]
    paste.filter_factory = keystone.middleware.swift_auth:filter_factory
    operator_roles = admin, swiftoperator

    [filter:s3token]
    paste.filter_factory = keystone.middleware.s3_token:filter_factory
    service_port = 5000
    service_host = 127.0.0.1
    auth_port = 35357
    auth_host = 127.0.0.1
    auth_token = ADMIN
    admin_token = ADMIN

    [filter:tokenauth]
    paste.filter_factory = keystone.middleware.auth_token:filter_factory
    service_port = 5000
    service_host = 127.0.0.1
    auth_port = 35357
    auth_host = 127.0.0.1
    auth_token = ADMIN
    admin_token = ADMIN

2. You can then access directly your Swift via the S3 API, here's an
   example with the `boto` library::

    import boto
    import boto.s3.connection

    connection = boto.connect_s3(
        aws_access_key_id='<ec2 access key for user>',
        aws_secret_access_key='<ec2 secret access key for user>',
        port=8080,
        host='localhost',
        is_secure=False,
        calling_format=boto.s3.connection.OrdinaryCallingFormat())


.. Note::
   With the S3 middleware you are connecting to the `Swift` proxy and
   not to `keystone`.

Auth-Token Middleware with Username and Password
------------------------------------------------

It is also possible to configure Keystone's auth_token middleware using the
'admin_user' and 'admin_password' options. When using the 'admin_user' and
'admin_password' options the 'admin_token' parameter is optional. If
'admin_token' is specified it will by used only if the specified token is
still valid.

Here is an example paste config filter that makes use of the 'admin_user' and
'admin_password' parameters::

    [filter:tokenauth]
    paste.filter_factory = keystone.middleware.auth_token:filter_factory
    service_port = 5000
    service_host = 127.0.0.1
    auth_port = 35357
    auth_host = 127.0.0.1
    auth_token = ADMIN
    admin_user = admin
    admin_password = keystone123

It should be noted that when using this option an 'admin' tenant/role relationship is required. The admin user is granted access to to the 'admin' role via the 'admin' tenant.
