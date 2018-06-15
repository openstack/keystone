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

=====================
Keystone Architecture
=====================

Much of the design assumes that in most deployments auth backends will be shims
in front of existing user systems.


Services
========

Keystone is organized as a group of internal services exposed on one or many
endpoints. Many of these services are used in a combined fashion by the
frontend. For example, an authenticate call will validate user/project
credentials with the Identity service and, upon success, create and return a
token with the Token service.


Identity
--------

The Identity service provides auth credential validation and data about `users`
and `groups`. In the basic case, this data is managed by the Identity service,
allowing it to also handle all CRUD operations associated with this data. In
more complex cases, the data is instead managed by an authoritative backend
service. An example of this would be when the Identity service acts as a
frontend for LDAP. In that case the LDAP server is the source of truth and the
role of the Identity service is to relay that information accurately.

Users
^^^^^

``Users`` represent an individual API consumer. A user itself must be owned by
a specific domain, and hence all user names are **not** globally unique, but
only unique to their domain.

Groups
^^^^^^

``Groups`` are a container representing a collection of users. A group itself
must be owned by a specific domain, and hence all group names are **not**
globally unique, but only unique to their domain.

Resource
--------

The Resource service provides data about `projects` and `domains`.

Projects
^^^^^^^^

``Projects`` represent the base unit of ``ownership`` in OpenStack, in that all
resources in OpenStack should be owned by a specific project. A project itself
must be owned by a specific domain, and hence all project names are **not**
globally unique, but unique to their domain. If the domain for a project is not
specified, then it is added to the default domain.

Domains
^^^^^^^

``Domains`` are a high-level container for projects, users and groups. Each is
owned by exactly one domain. Each domain defines a namespace where an
API-visible name attribute exists. Keystone provides a default domain, aptly
named 'Default'.

In the Identity v3 API, the uniqueness of attributes is as follows:

- Domain Name. Globally unique across all domains.

- Role Name. Unique within the owning domain.

- User Name. Unique within the owning domain.

- Project Name. Unique within the owning domain.

- Group Name. Unique within the owning domain.

Due to their container architecture, domains may be used as a way to delegate
management of OpenStack resources. A user in a domain may still access
resources in another domain, if an appropriate assignment is granted.


Assignment
----------

The Assignment service provides data about `roles` and `role assignments`.

Roles
^^^^^

``Roles`` dictate the level of authorization the end user can obtain. Roles
can be granted at either the domain or project level. A role can be assigned at
the individual user or group level. Role names are unique within the
owning domain.

Role Assignments
^^^^^^^^^^^^^^^^

A 3-tuple that has a ``Role``, a ``Resource`` and an ``Identity``.

Token
-----

The Token service validates and manages tokens used for authenticating requests
once a user's credentials have already been verified.


Catalog
-------

The Catalog service provides an endpoint registry used for endpoint discovery.


Application Construction
========================

Keystone is an HTTP front-end to several services. Like other OpenStack
applications, this is done using python WSGI interfaces and applications are
configured together using Paste_. The application's HTTP endpoints are made up
of pipelines of WSGI middleware, such as:

.. code-block:: ini

    [pipeline:api_v3]
    pipeline = healthcheck cors sizelimit http_proxy_to_wsgi osprofiler url_normalize request_id build_auth_context token_auth json_body ec2_extension_v3 s3_extension service_v3


These in turn use a subclass of :mod:`keystone.common.wsgi.ComposingRouter` to
link URLs to controllers (a subclass of
:mod:`keystone.common.wsgi.Application`). Within each controller, one or more
managers are loaded (for example, see :mod:`keystone.catalog.core.Manager`),
which are thin wrapper classes which load the appropriate service driver based
on the keystone configuration.

* Assignment

  * :mod:`keystone.assignment.controllers.GrantAssignmentV3`
  * :mod:`keystone.assignment.controllers.ImpliedRolesV3`
  * :mod:`keystone.assignment.controllers.ProjectAssignmentV3`
  * :mod:`keystone.assignment.controllers.TenantAssignment`
  * :mod:`keystone.assignment.controllers.RoleAssignmentV3`
  * :mod:`keystone.assignment.controllers.RoleV3`

* Authentication

  * :mod:`keystone.auth.controllers.Auth`

* Catalog

  * :mod:`keystone.catalog.controllers.EndpointFilterV3Controller`
  * :mod:`keystone.catalog.controllers.EndpointGroupV3Controller`
  * :mod:`keystone.catalog.controllers.EndpointV3`
  * :mod:`keystone.catalog.controllers.ProjectEndpointGroupV3Controller`
  * :mod:`keystone.catalog.controllers.RegionV3`
  * :mod:`keystone.catalog.controllers.ServiceV3`

* Credentials

  * :mod:`keystone.contrib.ec2.controllers.Ec2ControllerV3`
  * :mod:`keystone.credential.controllers.CredentialV3`

* Federation

  * :mod:`keystone.federation.controllers.IdentityProvider`
  * :mod:`keystone.federation.controllers.FederationProtocol`
  * :mod:`keystone.federation.controllers.MappingController`
  * :mod:`keystone.federation.controllers.Auth`
  * :mod:`keystone.federation.controllers.DomainV3`
  * :mod:`keystone.federation.controllers.ProjectAssignmentV3`
  * :mod:`keystone.federation.controllers.ServiceProvider`
  * :mod:`keystone.federation.controllers.SAMLMetadataV3`

* Identity

  * :mod:`keystone.identity.controllers.GroupV3`
  * :mod:`keystone.identity.controllers.UserV3`

* Oauth1

  * :mod:`keystone.oauth1.controllers.ConsumerCrudV3`
  * :mod:`keystone.oauth1.controllers.AccessTokenCrudV3`
  * :mod:`keystone.oauth1.controllers.AccessTokenRolesV3`
  * :mod:`keystone.oauth1.controllers.OAuthControllerV3`

* Policy

  * :mod:`keystone.policy.controllers.PolicyV3`

* Resource

  * :mod:`keystone.resource.controllers.DomainV3`
  * :mod:`keystone.resource.controllers.DomainConfigV3`
  * :mod:`keystone.resource.controllers.ProjectV3`
  * :mod:`keystone.resource.controllers.ProjectTagV3`

* Revoke

  * :mod:`keystone.revoke.controllers.RevokeController`

* Trust

  * :mod:`keystone.trust.controllers.TrustV3`

.. _Paste: http://pythonpaste.org/


Service Backends
================

Each of the services can be configured to use a backend to allow keystone to
fit a variety of environments and needs. The backend for each service is
defined in the keystone.conf file with the key ``driver`` under a group
associated with each service.

A general class exists under each backend to provide an abstract base class
for any implementations, identifying the expected service implementations. The
abstract base classes are stored in the service's backends directory as
``base.py``. The corresponding drivers for the services are:

* :mod:`keystone.assignment.backends.base.AssignmentDriverBase`
* :mod:`keystone.assignment.role_backends.base.RoleDriverBase`
* :mod:`keystone.auth.plugins.base.AuthMethodHandler`
* :mod:`keystone.catalog.backends.base.CatalogDriverBase`
* :mod:`keystone.credential.backends.base.CredentialDriverBase`
* :mod:`keystone.endpoint_policy.backends.base.EndpointPolicyDriverBase`
* :mod:`keystone.federation.backends.base.FederationDriverBase`
* :mod:`keystone.identity.backends.base.IdentityDriverBase`
* :mod:`keystone.identity.mapping_backends.base.MappingDriverBase`
* :mod:`keystone.identity.shadow_backends.base.ShadowUsersDriverBase`
* :mod:`keystone.oauth1.backends.base.Oauth1DriverBase`
* :mod:`keystone.policy.backends.base.PolicyDriverBase`
* :mod:`keystone.resource.backends.base.ResourceDriverBase`
* :mod:`keystone.resource.config_backends.base.DomainConfigDriverBase`
* :mod:`keystone.revoke.backends.base.RevokeDriverBase`
* :mod:`keystone.token.providers.base.Provider`
* :mod:`keystone.trust.backends.base.TrustDriverBase`

If you implement a backend driver for one of the keystone services, you're
expected to subclass from these classes.


Templated Backend
-----------------

Largely designed for a common use case around service catalogs in the keystone
project, a templated backend is a catalog backend that simply expands
pre-configured templates to provide catalog data.

Example paste.deploy config (uses $ instead of % to avoid ConfigParser's
interpolation)

.. code-block:: ini

    [DEFAULT]
    catalog.RegionOne.identity.publicURL = http://localhost:$(public_port)s/v3
    catalog.RegionOne.identity.adminURL = http://localhost:$(public_port)s/v3
    catalog.RegionOne.identity.internalURL = http://localhost:$(public_port)s/v3
    catalog.RegionOne.identity.name = 'Identity Service'


Data Model
==========

Keystone was designed from the ground up to be amenable to multiple styles of
backends. As such, many of the methods and data types will happily accept more
data than they know what to do with and pass them on to a backend.

There are a few main data types:

* **User**: has account credentials, is associated with one or more projects or domains
* **Group**: a collection of users, is associated with one or more projects or domains
* **Project**: unit of ownership in OpenStack, contains one or more users
* **Domain**: unit of ownership in OpenStack, contains users, groups and projects
* **Role**: a first-class piece of metadata associated with many user-project pairs.
* **Token**: identifying credential associated with a user or user and project
* **Extras**: bucket of key-value metadata associated with a user-project pair.
* **Rule**: describes a set of requirements for performing an action.

While the general data model allows a many-to-many relationship between users
and groups to projects and domains; the actual backend implementations take
varying levels of advantage of that functionality.


Approach to CRUD
================

While it is expected that any "real" deployment at a large company will manage
their users and groups in their existing user systems, a variety of CRUD
operations are provided for the sake of development and testing.

CRUD is treated as an extension or additional feature to the core feature set,
in that a backend is not required to support it. It is expected that
backends for services that don't support the CRUD operations will raise a
:mod:`keystone.exception.NotImplemented`.


Approach to Authorization (Policy)
==================================

Various components in the system require that different actions are allowed
based on whether the user is authorized to perform that action.

For the purposes of keystone there are only a couple levels of authorization
being checked for:

* Require that the performing user is considered an admin.
* Require that the performing user matches the user being referenced.

Other systems wishing to use the policy engine will require additional styles
of checks and will possibly write completely custom backends. By default,
keystone leverages policy enforcement that is maintained in `oslo.policy
<https://git.openstack.org/cgit/openstack/oslo.policy/>`_.


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

Approach to Authentication
==========================

Keystone provides several authentication plugins that inherit from
:mod:`keystone.auth.plugins.base`. The following is a list of available plugins.

* :mod:`keystone.auth.plugins.external.Base`
* :mod:`keystone.auth.plugins.mapped.Mapped`
* :mod:`keystone.auth.plugins.oauth1.OAuth`
* :mod:`keystone.auth.plugins.password.Password`
* :mod:`keystone.auth.plugins.token.Token`
* :mod:`keystone.auth.plugins.totp.TOTP`

In the most basic plugin ``password``, two pieces of information are required
to authenticate with keystone, a bit of ``Resource`` information and a bit of
``Identity``.

Take the following call POST data for instance:

.. code-block:: javascript

    {
        "auth": {
            "identity": {
                "methods": [
                    "password"
                ],
                "password": {
                    "user": {
                        "id": "0ca8f6",
                        "password": "secretsecret"
                    }
                }
            },
            "scope": {
                "project": {
                    "id": "263fd9"
                }
            }
        }
    }

The user (ID of 0ca8f6) is attempting to retrieve a token that is scoped to
project (ID of 263fd9).

To perform the same call with names instead of IDs, we now need to supply
information about the domain. This is because usernames are only unique within
a given domain, but user IDs are supposed to be unique across the deployment.
Thus, the auth request looks like the following:

.. code-block:: javascript

    {
        "auth": {
            "identity": {
                "methods": [
                    "password"
                ],
                "password": {
                    "user": {
                        "domain": {
                            "name": "acme"
                        }
                        "name": "userA",
                        "password": "secretsecret"
                    }
                }
            },
            "scope": {
                "project": {
                    "domain": {
                        "id": "1789d1"
                    },
                    "name": "project-x"
                }
            }
        }
    }

For both the user and the project portion, we must supply either a domain ID
or a domain name, in order to properly determine the correct user and project.

Alternatively, if we wanted to represent this as environment variables for a
command line, it would be:

.. code-block:: bash

    $ export OS_PROJECT_DOMAIN_ID=1789d1
    $ export OS_USER_DOMAIN_NAME=acme
    $ export OS_USERNAME=userA
    $ export OS_PASSWORD=secretsecret
    $ export OS_PROJECT_NAME=project-x

Note that the project the user is attempting to access must be in the same
domain as the user.

What is Scope?
--------------

Scope is an overloaded term.

In reference to authenticating, as seen above, scope refers to the portion of
the POST data that dictates what ``Resource`` (project, domain, or system) the
user wants to access.

In reference to tokens, scope refers to the effectiveness of a token,
i.e.: a `project-scoped` token is only useful on the project it was initially
granted for. A `domain-scoped` token may be used to perform domain-related
function. A `system-scoped` token is only useful for interacting with APIs that
affect the entire deployment.

In reference to users, groups, and projects, scope often refers to the domain
that the entity is owned by. i.e.: a user in domain X is scoped to domain X.
