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

X-User
    The username used to log in

X-Roles
    The roles associated with that user
