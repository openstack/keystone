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

Keystone Architecture
=====================

Much of the design is precipitated from the expectation that the auth backends
for most deployments will actually be shims in front of existing user systems.


------------
The Services
------------

Keystone is organized as a group of internal services exposed on one or many
endpoints. Many of these services are used in a combined fashion by the
frontend, for example an authenticate call will validate user/tenant
credentials with the Identity service and, upon success, create and return a
token with the Token service.


Identity
--------

The Identity service provides auth credential validation and data about Users,
Tenants and Roles, as well as any associated metadata.

In the basic case all this data is managed by the service, allowing the service
to manage all the CRUD associated with the data.

In other cases, this data is pulled, by varying degrees, from an authoritative
backend service. An example of this would be when backending on LDAP. See
`LDAP Backend` below for more details.


Token
-----

The Token service validates and manages Tokens used for authenticating requests
once a user/tenant's credentials have already been verified.


Catalog
-------

The Catalog service provides an endpoint registry used for endpoint discovery.


Policy
------

The Policy service provides a rule-based authorization engine and the
associated rule management interface.


------------------------
Application Construction
------------------------

Keystone is an HTTP front-end to several services. Like other OpenStack
applications, this is done using python WSGI interfaces and applications are
configured together using Paste_. The application's HTTP endpoints are made up
of pipelines of WSGI middleware, such as::

    [pipeline:public_api]
    pipeline = token_auth admin_token_auth json_body debug ec2_extension public_service

These in turn use a subclass of :mod:`keystone.common.wsgi.ComposingRouter` to
link URLs to Controllers (a subclass of
:mod:`keystone.common.wsgi.Application`). Within each Controller, one or more
Managers are loaded (for example, see :mod:`keystone.catalog.core.Manager`),
which are thin wrapper classes which load the appropriate service driver based
on the keystone configuration.

* Identity
 * :mod:`keystone.identity.core.TenantController`
 * :mod:`keystone.identity.core.UserController`
 * :mod:`keystone.identity.core.RoleController`

* Catalog
 * :mod:`keystone.catalog.core.ServiceController`
 * :mod:`keystone.service.VersionController`

* Token
 * :mod:`keystone.service.TokenController`

* Misc
 * :mod:`keystone.service.ExtensionsController`

At this time, the policy service and associated manager is not exposed as a URL
frontend, and has no associated Controller class.

.. _Paste: http://pythonpaste.org/


----------------
Service Backends
----------------

Each of the services can configured to use a backend to allow Keystone to fit a
variety of environments and needs. The backend for each service is defined in
the keystone.conf file with the key ``driver`` under a group associated with
each service.

A general class under each backend named ``Driver`` exists to provide an
abstract base class for any implementations, identifying the expected service
implementations. The drivers for the services are:

* :mod:`keystone.identity.core.Driver`
* :mod:`keystone.token.core.Driver`

If you implement a backend driver for one of the keystone services, you're
expected to subclass from these classes. The default response for the defined
apis in these Drivers is to raise a :mod:`keystone.service.TokenController`.


KVS Backend
-----------

A simple backend interface meant to be further backended on anything that can
support primary key lookups, the most trivial implementation being an in-memory
dict.

Supports all features of the general data model.


SQL Backend
-----------

A SQL based backend using SQLAlchemy to store data persistently. The
keystone-manage command introspects the backends to identify SQL based backends
when running "db_sync" to establish or upgrade schema. If the backend driver
has a method db_sync(), it will be invoked to sync and/or migrate schema.


PAM Backend
-----------

Extra simple backend that uses the current system's PAM service to authenticate,
providing a one-to-one relationship between Users and Tenants with the `root`
User also having the 'admin' role.


Templated Backend
-----------------

Largely designed for a common use case around service catalogs in the Keystone
project, a Catalog backend that simply expands pre-configured templates to
provide catalog data.

Example paste.deploy config (uses $ instead of % to avoid ConfigParser's
interpolation)::

  [DEFAULT]
  catalog.RegionOne.identity.publicURL = http://localhost:$(public_port)s/v2.0
  catalog.RegionOne.identity.adminURL = http://localhost:$(public_port)s/v2.0
  catalog.RegionOne.identity.internalURL = http://localhost:$(public_port)s/v2.0
  catalog.RegionOne.identity.name = 'Identity Service'


LDAP Backend
------------

The LDAP backend stored Users and Tenents in separate Subtrees.  Roles are recorded
as entries under the Tenants.


----------
Data Model
----------

Keystone was designed from the ground up to be amenable to multiple styles of
backends and as such many of the methods and data types will happily accept
more data than they know what to do with and pass them on to a backend.

There are a few main data types:

 * **User**: has account credentials, is associated with one or more tenants
 * **Tenant**: unit of ownership in openstack, contains one or more users
 * **Role**: a first-class piece of metadata associated with many user-tenant pairs.
 * **Token**: identifying credential associated with a user or user and tenant
 * **Extras**: bucket of key-value metadata associated with a user-tenant pair.
 * **Rule**: describes a set of requirements for performing an action.

While the general data model allows a many-to-many relationship between Users
and Tenants and a many-to-one relationship between Extras and User-Tenant pairs,
the actual backend implementations take varying levels of advantage of that
functionality.


----------------
Approach to CRUD
----------------

While it is expected that any "real" deployment at a large company will manage
their users, tenants and other metadata in their existing user systems, a
variety of CRUD operations are provided for the sake of development and testing.

CRUD is treated as an extension or additional feature to the core feature set
in that it is not required that a backend support it. It is expected that
backends for services that don't support the CRUD operations will raise a
:mod:`keystone.exception.NotImplemented`.


----------------------------------
Approach to Authorization (Policy)
----------------------------------

Various components in the system require that different actions are allowed
based on whether the user is authorized to perform that action.

For the purposes of Keystone there are only a couple levels of authorization
being checked for:

 * Require that the performing user is considered an admin.
 * Require that the performing user matches the user being referenced.

Other systems wishing to use the policy engine will require additional styles
of checks and will possibly write completely custom backends. Backends included
in Keystone are:


Rules
-----

Given a list of matches to check for, simply verify that the credentials
contain the matches. For example::

  credentials = {'user_id': 'foo', 'is_admin': 1, 'roles': ['nova:netadmin']}

  # An admin only call:
  policy_api.enforce(('is_admin:1',), credentials)

  # An admin or owner call:
  policy_api.enforce(('is_admin:1', 'user_id:foo'), credentials)

  # A netadmin call:
  policy_api.enforce(('roles:nova:netadmin',), credentials)

Credentials are generally built from the user metadata in the 'extras' part
of the Identity API. So, adding a 'role' to the user just means adding the role
to the user metadata.


Capability RBAC
---------------

(Not yet implemented.)

Another approach to authorization can be action-based, with a mapping of roles
to which capabilities are allowed for that role. For example::

  credentials = {'user_id': 'foo', 'is_admin': 1, 'roles': ['nova:netadmin']}

  # add a policy
  policy_api.add_policy('action:nova:add_network', ('roles:nova:netadmin',))

  policy_api.enforce(('action:nova:add_network',), credentials)

In the backend this would look up the policy for 'action:nova:add_network' and
then do what is effectively a 'Simple Match' style match against the creds.
