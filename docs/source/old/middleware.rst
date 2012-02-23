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

==========
Middleware
==========

The Keystone middleware sits in front of an OpenStack service and handles authenticating
incoming requests. The middleware was designed according to `this spec`.

The middleware is found in source under Keystone/middleware.

The middleware supports two interfaces; WSGI and REST/HTTP.

.. _`this spec`: http://wiki.openstack.org/openstack-authn

REST & HTTP API
===============

If an unauthenticated call comes in, the middleware will respond with a 401 Unauthorized error. As per
HTTP standards, it will also return a WWW-Authenticate header informing the caller
of what protocols are supported. For Keystone authentication, the response syntax will be::

    WWW-Authenticate: Keystone uri="url to Keystone server"

The client can then make the necessary calls to the Keystone server, obtain a token, and retry the call with the token.

The token is passed in using ther X-Auth-Token header.

WSGI API (Headers)
==================

Upon successful authentication the middleware sends the following
headers to the downstream WSGI app:

X-Identity-Status
    Provides information on whether the request was authenticated or not.

X-Tenant
    Provides the tenant ID (as it appears in the URL in Keystone). This is to support any legacy implementations before Keystone switched to an ID/Name schema for tenants.

X-Tenant-Id
    The unique, immutable tenant Id

X-Tenant-Name
    The unique, but mutable (it can change) tenant name.

X-User-Id
    The user id of the user used to log in

X-User-Name
    The username used to log in

X-User
    The username used to log in. This is to support any legacy implementations before Keystone switched to an ID/Name schema for tenants.

X-Roles
    The roles associated with that user


Configuration
=============

The middleware is configured within the config file of the main application as
a WSGI component. Example for the auth_token middleware::

    [app:myService]
    paste.app_factory = myService:app_factory

    [pipeline:main]
    pipeline =
        tokenauth
        myService

    [filter:tokenauth]
    paste.filter_factory = keystone.middleware.auth_token:filter_factory
    auth_host = 127.0.0.1
    auth_port = 35357
    auth_protocol = http
    auth_uri = http://127.0.0.1:5000/
    admin_token = 999888777666
    ;Uncomment next line and check ip:port to use memcached to cache token requests
    ;memcache_hosts = 127.0.0.1:11211

*The required configuration entries are:*

auth_host
    The IP address or DNS name of the Keystone server

auth_port
    The TCP/IP port of the Keystone server

auth_protocol
    The protocol of the Keystone server ('http' or 'https')

auth_uri
    The externally accessible URL of the Keystone server. This will be where unauthenticated
    clients are redirected to. This is in the form of a URL. For example, if they make an
    unauthenticated call, they get this response::
    
        HTTP/1.1 401 Unauthorized
        Www-Authenticate: Keystone uri='https://auth.example.com/'
        Content-Length: 381
    
    In this case, the auth_uri setting is set to https://auth.example.com/

admin_token
    This is the long-lived token issued to the service to authenticate itself when calling
    Keystone. See :doc:`configuration` for more information on setting this up.


*Optional parameters are:*

delay_auth_decision
    Whether the middleware should reject invalid or unauthenticated calls directly or not. If not,
    it will send all calls down to the service to decide, but it will set the HTTP-X-IDENTITY-STATUS
    header appropriately (set to'Confirmed' or 'Indeterminate' based on validation) and the
    service can then decide if it wants to honor the call or not. This is useful if the service offers
    some resources publicly, for example.

auth_timeout
    The amount of time to wait before timing out a call to Keystone (in seconds)

memcache_hosts
    This is used to point to a memcached server (in ip:port format). If supplied,
    the middleware will cache tokens and data retrieved from Keystone in memcached
    to minimize calls made to Keystone and optimize performance.

.. warning::
    Tokens are cached for the duration of their validity. If they are revoked eariler in Keystone,
    the service will not know and will continue to honor the token as it has them stored in memcached.
    Also note that tokens and data stored in memcached are not encrypted. The memcached server must
    be trusted and on a secure network.


*Parameters needed in a distributed topology.* In this configuration, the middleware is running
on a separate machine or cluster than the protected service (not common - see :doc:`middleware_architecture`
for details on different deployment topologies):

service_host
    The IP address or DNS name of the location of the service (since it is remote
    and not automatically down the WSGI chain)

service_port
    The TCP/IP port of the remote service.

service_protocol
    The protocol of the service ('http' or 'https')

service_pass
    The basic auth password used to authenticate to the service (so the service
    knows the call is coming from a server that has validated the token and not from
    an untrusted source or spoofer)

service_timeout
    The amount of time to wait for the service to respond before timing out.
