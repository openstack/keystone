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

==========================================
Configuring Services to work with Keystone
==========================================

.. toctree::
   :maxdepth: 1

    nova-api-paste
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

    keystone-manage service create name=nova \
                                   service_type=compute \
                                   description="Nova Compute Service"
    keystone-manage service create name=ec2 \
                                   service_type=ec2 \
                                   description="EC2 Compatibility Layer"
    keystone-manage service create name=glance \
                                   service_type=image \
                                   description="Glance Image Service"
    keystone-manage service create name=keystone \
                                   service_type=identity \
                                   description="Keystone Identity Service"
    keystone-manage service create name=swift \
                                   service_type=object-store \
                                   description="Swift Service"

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

To configure Nova to use Keystone for authentication, the Nova API service
can be run against the api-paste file provided by Keystone. This is most
easily accomplished by setting the `--api_paste_config` flag in nova.conf to
point to `examples/paste/nova-api-paste.ini` from Keystone. This paste file
included references to the WSGI authentication middleware provided with the
keystone installation.

When configuring Nova, it is important to create a admin service token for
the service (from the Configuration step above) and include that as the key
'admin_token' in the nova-api-paste.ini. See the documented
:doc:`nova-api-paste` file for references.

Configuring Swift to use Keystone
---------------------------------

Similar to Nova, swift can be configured to use Keystone for authentication
rather than it's built in 'tempauth'.

1. Add a service endpoint for Swift to Keystone

2. Configure the paste file for swift-proxy (`/etc/swift/swift-proxy.conf`)

3.  Reconfigure Swift's proxy server to use Keystone instead of TempAuth.
    Here's an example `/etc/swift/proxy-server.conf`::

        [DEFAULT]
        bind_port = 8888
        user = <user>

        [pipeline:main]
        pipeline = catch_errors cache keystone proxy-server

        [app:proxy-server]
        use = egg:swift#proxy
        account_autocreate = true

        [filter:keystone]
        use = egg:keystone#tokenauth
        auth_protocol = http
        auth_host = 127.0.0.1
        auth_port = 35357
        admin_token = 999888777666
        delay_auth_decision = 0
        service_protocol = http
        service_host = 127.0.0.1
        service_port = 8100
        service_pass = dTpw
        cache = swift.cache

        [filter:cache]
        use = egg:swift#memcache
        set log_name = cache

        [filter:catch_errors]
        use = egg:swift#catch_errors

   Note that the optional "cache" property in the keystone filter allows any
   service (not just Swift) to register its memcache client in the WSGI
   environment.  If such a cache exists, Keystone middleware will utilize it
   to store validated token information, which could result in better overall
   performance.

4. Restart swift

5. Verify that keystone is providing authentication to Swift

Use `swift` to check everything works (note: you currently have to create a
container or upload something as your first action to have the account
created; there's a Swift bug to be fixed soon)::

    $ swift -A http://127.0.0.1:5000/v1.0 -U joeuser -K secrete post container
    $ swift -A http://127.0.0.1:5000/v1.0 -U joeuser -K secrete stat -v
    StorageURL: http://127.0.0.1:8888/v1/AUTH_1234
    Auth Token: 74ce1b05-e839-43b7-bd76-85ef178726c3
    Account: AUTH_1234
    Containers: 1
    Objects: 0
    Bytes: 0
    Accept-Ranges: bytes
    X-Trans-Id: tx25c1a6969d8f4372b63912f411de3c3b

.. WARNING::
    Keystone currently allows any valid token to do anything with any account.

