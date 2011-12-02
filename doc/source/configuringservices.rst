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

Once Keystone is installed and running, services need to be configured to work
with it. These are the steps to configure a service to work with Keystone:

1. Create or get credentials for the service to use

  A set of credentials are needed for each service (they may be
  shared if you chose to). Depending on the service, these credentials are
  either a username and password or a long-lived token..

2. Register the service, endpoints, roles and other entities

  In order for a service to have it's endpoints and roles show in the service
  catalog returned by Keystone, a service record needs to be added for the
  service. Endpoints and roles associated with that service can then be created.

  This can be done through the REST interface (using the OS-KSCATALOG extension)
  or using keystone-manage.

3. Install and configure middleware for the service to handle authentication

  Clients making calls to the service will pass in an authentication token. The
  Keystone middleware will look for and validate that token, taking the
  appropriate action. It will also retrive additional information from the token
  such as user name, id, tenant name, id, roles, etc...

  The middleware will pass those data down to the service as headers. The
  detailed description of this architecture is available here :doc:`middleware_architecture`

Setting up credentials
======================

First admin user - bootstrapping
--------------------------------

For a default installation of Keystone, before you can use the REST API, you
need to create your first initial user and grant that user the right to
administer Keystone.

For the keystone service itself, two
Roles are pre-defined in the keystone configuration file
(:doc:`keystone.conf`).

    #Role that allows admin operations (access to all operations)
    keystone-admin-role = Admin

    #Role that allows acting as service (validate tokens, register service,
    etc...)
    keystone-service-admin-role = KeystoneServiceAdmin

In order to create your first user, once Keystone is running use
the `keystone-manage` command:

    $ keystone-manage user add admin secrete
    $ keystone-manage role add Admin
    $ keystone-manage role add KeystoneServiceAdmin
    $ keystone-manage role grant Admin admin
    $ keystone-manage role grant KeystoneServiceAdmin admin

This creates the `admin` user (with a password of `secrete`), creates
two roles (`Admin` and `KeystoneServiceAdmin`), and assigns those roles to
the `admin` user. From here, you should now have the choice of using the
administrative API (as well as the :doc:`man/keystone-manage` commands) to
further configure keystone. There are a number of examples of how to use
that API at :doc:`adminAPI_curl_examples`.


Setting up services
===================

Defining Services and Service Endpoints
---------------------------------------

Keystone also acts as a service catalog to let other OpenStack systems know
where relevant API endpoints exist for OpenStack Services. The OpenStack
Dashboard, in particular, uses this heavily - and this **must** be configured
for the OpenStack Dashboard to properly function.

Here's how we define the services::

    $ keystone-manage service add nova compute "Nova Compute Service"
    $ keystone-manage service add glance image "Glance Image Service"
    $ keystone-manage service add swift storage "Swift Object Storage Service"
    $ keystone-manage service add keystone identity "Keystone Identity Service"

Once the services are defined, we create endpoints for them. Each service
has three relevant URL's associated with it that are used in the command:

* the public API URL
* an administrative API URL
* an internal URL

The "internal URL" is an endpoint the generally offers the same API as the
public URL, but over a high-bandwidth, low-latency, unmetered (free) network.
You would use that to transfer images from nova to glance for example, and
not the Public URL which would go over the internet and be potentially chargeable.

The "admin URL" is for administering the services and is not exposed or accessible
to customers without the apporpriate privileges.

An example of setting up the endpoint for Nova::

    $ keystone-manage endpointTemplates add RegionOne nova \
    http://nova-api.mydomain:8774/v1.1/ \
    http://nova-api.mydomain:8774/v1.1/ \
    http://nova-api.mydomain:8774/v1.1/ \
    1 1

Glance::

    $ keystone-manage endpointTemplates add RegionOne glance \
    http://glance.mydomain:9292/v1.1/ \
    http://glance.mydomain:9292/v1.1/ \
    http://glance.mydomain:9292/v1.1/ \
    1 1

Swift::

    $ keystone-manage endpointTemplates add RegionOne swift \
    http://swift.mydomain:8080/v1/AUTH_%tenant_id% \
    http://swift.mydomain:8080/v1.0/ \
    http://swift.mydomain:8080/v1/AUTH_%tenant_id% \
    1 1

And setting up an endpoint for Keystone::

    $ keystone-manage endpointTemplates add RegionOne keystone \
    http://keystone.mydomain:5000/v2.0 \
    http://keystone.mydomain:35357/v2.0 \
    http://keystone.mydomain:5000/v2.0 \
    1 1


Defining an Administrative Service Token
----------------------------------------

An Administrative Service Token is a bit of arbitrary text which is configured
in Keystone and used (typically configured into) Nova, Swift, Glance, and any
other OpenStack projects, to be able to use Keystone services.

This token is an arbitrary text string, but must be identical between Keystone
and the services using Keystone. This token is bound to a user and tenant as
well, so those also need to be created prior to setting it up.

The *admin* user was set up above, but we haven't created a tenant for that
user yet::

    $ keystone-manage tenant add admin

and while we're here, let's grant the admin user the 'Admin' role to the
'admin' tenant::

    $ keystone-manage role add Admin
    $ keystone-manage role grant Admin admin admin

Now we can create a service token::

    $ keystone-manage token add 999888777666 admin admin 2015-02-05T00:00

This creates a service token of '999888777666' associated to the admin user,
admin tenant, and expires on February 5th, 2015. This token will be used when
configuring Nova, Glance, or other OpenStack services.

Securing Communications with SSL
--------------------------------

To encrypt traffic between services and Keystone, see :doc:`ssl`


Setting up OpenStack users
==========================

Creating Tenants, Users, and Roles
----------------------------------

Let's set up a 'demo' tenant::

    $ keystone-manage tenant add demo

And add a 'demo' user with the password 'guest'::

    $ keystone-manage user add demo guest

Now let's add a role of "Member" and grant 'demo' user that role
as it pertains to the tenant 'demo'::

    $ keystone-manage role add Member
    $ keystone-manage role grant Member demo demo

Let's also add the admin user as an Admin role to the demo tenant::

    $ keystone-manage role grant Admin admin demo

Creating EC2 credentials
------------------------

To add EC2 credentials for the `admin` and `demo` accounts::

    $ keystone-manage credentials add admin EC2 'admin' 'secretpassword'
    $ keystone-manage credentials add admin EC2 'demo' 'secretpassword'

If you have a large number of credentials to create, you can put them all
into a single large file and import them using :doc:`man/keystone-import`. The
format of the document looks like::

    credentials add admin EC2 'username' 'password'
    credentials add admin EC2 'username' 'password'

Then use::

    $ keystone-import `filename`


Setting Up Middleware
=====================

Keystone Auth-Token Middleware
--------------------------------

The Keystone auth_token middleware is a WSGI component that can be inserted in
the WSGI pipeline to handle authenticating tokens with Keystone. See :doc:`middleware`
for details on middleware and configuration parameters.


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

