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

Keystone Architecture
=====================

Much of the design is precipitated from the expectation that the auth backends
for most deployments will actually be shims in front of existing user systems.


------------
The Services
------------

Keystone is organized as a group of internal services exposed on one or many
endpoints. Many of these services are used in a combined fashion by the
frontend, for example an authenticate call will validate user/project
credentials with the Identity service and, upon success, create and return a
token with the Token service.


Identity
--------

The Identity service provides auth credential validation and data about Users,
Groups.

In the basic case all this data is managed by the service, allowing the service
to manage all the CRUD associated with the data.

In other cases from an authoritative backend service. An example of this would
be when backending on LDAP. See `LDAP Backend` below for more details.


Resource
--------

The Resource service provides data about Projects and Domains.

Like the Identity service, this data may either be managed directly by the
service or be pulled from another authoritative backend service, such as LDAP.


Assignment
----------

The Assignment service provides data about Roles and Role assignments to the
entities managed by the Identity and Resource services.  Again, like these two
services, this data may either be managed directly by the Assignment service
or be pulled from another authoritative backend service, such as LDAP.


Token
-----

The Token service validates and manages Tokens used for authenticating requests
once a user's credentials have already been verified.


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
of pipelines of WSGI middleware, such as:

.. code-block:: ini

    [pipeline:api_v3]
    pipeline = sizelimit url_normalize build_auth_context token_auth admin_token_auth
    json_body ec2_extension_v3 s3_extension service_v3

These in turn use a subclass of :mod:`keystone.common.wsgi.ComposingRouter` to
link URLs to Controllers (a subclass of
:mod:`keystone.common.wsgi.Application`). Within each Controller, one or more
Managers are loaded (for example, see :mod:`keystone.catalog.core.Manager`),
which are thin wrapper classes which load the appropriate service driver based
on the Keystone configuration.

* Assignment

 * :mod:`keystone.assignment.controllers.GrantAssignmentV3`
 * :mod:`keystone.assignment.controllers.ProjectAssignmentV3`
 * :mod:`keystone.assignment.controllers.TenantAssignment`
 * :mod:`keystone.assignment.controllers.Role`
 * :mod:`keystone.assignment.controllers.RoleAssignmentV2`
 * :mod:`keystone.assignment.controllers.RoleAssignmentV3`
 * :mod:`keystone.assignment.controllers.RoleV3`

* Authentication

 * :mod:`keystone.auth.controllers.Auth`

* Catalog

 * :mod:`keystone.catalog.controllers.EndpointV3`
 * :mod:`keystone.catalog.controllers.RegionV3`
 * :mod:`keystone.catalog.controllers.ServiceV3`

* Identity

 * :mod:`keystone.identity.controllers.GroupV3`
 * :mod:`keystone.identity.controllers.UserV3`

* Policy

 * :mod:`keystone.policy.controllers.PolicyV3`

* Resource

 * :mod:`keystone.resource.controllers.DomainV3`
 * :mod:`keystone.resource.controllers.ProjectV3`

* Token

 * :mod:`keystone.token.controllers.Auth`


.. _Paste: http://pythonpaste.org/


----------------
Service Backends
----------------

Each of the services can be configured to use a backend to allow Keystone to fit a
variety of environments and needs. The backend for each service is defined in
the keystone.conf file with the key ``driver`` under a group associated with
each service.

A general class exists under each backend to provide an
abstract base class for any implementations, identifying the expected service
implementations. The classes are named after the keystone release in which
they were introduced. For eg. ``DriverV8`` for keystone release version 8.
The corresponding drivers for the services are:

* :mod:`keystone.assignment.core.AssignmentDriverV8`
* :mod:`keystone.assignment.core.RoleDriverV8`
* :mod:`keystone.catalog.core.CatalogDriverV8`
* :mod:`keystone.identity.core.IdentityDriverV8`
* :mod:`keystone.policy.core.PolicyDriverV8`
* :mod:`keystone.resource.core.ResourceDriverV8`
* :mod:`keystone.token.core.TokenDriverV8`

If you implement a backend driver for one of the Keystone services, you're
expected to subclass from these classes.


SQL Backend
-----------

A SQL based backend using SQLAlchemy to store data persistently. The
``keystone-manage`` command introspects the backends to identify SQL based backends
when running "db_sync" to establish or upgrade schema. If the backend driver
has a method db_sync(), it will be invoked to sync and/or migrate schema.


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

The LDAP backend stores Users and Projects in separate Subtrees. Roles are recorded
as entries under the Projects.


----------
Data Model
----------

Keystone was designed from the ground up to be amenable to multiple styles of
backends and as such many of the methods and data types will happily accept
more data than they know what to do with and pass them on to a backend.

There are a few main data types:

 * **User**: has account credentials, is associated with one or more projects or domains
 * **Group**: a collection of users, is associated with one or more projects or domains
 * **Project**: unit of ownership in OpenStack, contains one or more users
 * **Domain**: unit of ownership in OpenStack, contains users, groups and projects
 * **Role**: a first-class piece of metadata associated with many user-project pairs.
 * **Token**: identifying credential associated with a user or user and project
 * **Extras**: bucket of key-value metadata associated with a user-project pair.
 * **Rule**: describes a set of requirements for performing an action.

While the general data model allows a many-to-many relationship between Users
and Groups to Projects and Domains; the actual backend implementations take
varying levels of advantage of that functionality.


----------------
Approach to CRUD
----------------

While it is expected that any "real" deployment at a large company will manage
their users, groups, projects and domains in their existing user systems, a
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
of checks and will possibly write completely custom backends. By default,
Keystone leverages Policy enforcement that is maintained in Oslo-Incubator,
found in `keystone/openstack/common/policy.py`.


Rules
-----

Given a list of matches to check for, simply verify that the credentials
contain the matches. For example:

.. code-block:: python

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
to which capabilities are allowed for that role. For example:

.. code-block:: python

  credentials = {'user_id': 'foo', 'is_admin': 1, 'roles': ['nova:netadmin']}

  # add a policy
  policy_api.add_policy('action:nova:add_network', ('roles:nova:netadmin',))

  policy_api.enforce(('action:nova:add_network',), credentials)

In the backend this would look up the policy for 'action:nova:add_network' and
then do what is effectively a 'Simple Match' style match against the credentials.
