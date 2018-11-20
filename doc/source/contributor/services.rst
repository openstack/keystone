..
    Licensed under the Apache License, Version 2.0 (the "License"); you may not
    use this file except in compliance with the License. You may obtain a copy
    of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
    License for the specific language governing permissions and limitations
    under the License.

===========================
Keystone for other services
===========================

This document provides a summary of some things that other services need to
know about how keystone works, and specifically about how they can take
advantage of the v3 API.

The v3 API was introduced as a stable API in the Grizzly release and included
in the default pipeline ever since. Until recently, its use has been hidden
from other services because the ``auth_token`` middleware translated the token
format so that both versions look the same. Once the services need to make use
of v3 features they need to know about how it works.


Glossary
========

Authentication
    The process of determining if a user is who they claim to be (authN).

Authorization
    The process of determining if a user can do what they are requesting
    (authZ).

Scope
    A specific operating context. This is commonly used when describing the
    authorization a user may have. For example, a user with a role assignment
    on a project can get a token scoped to that project, ultimately operating
    within that project's scope.

System
    An assignment target that refers to a collection of API services as a
    whole. Users and groups can be granted authorization on the *deployment
    system*.

Service
    OpenStack services like identity, compute, image, etc.

Domain
    A container for users, projects, and groups. A domain is also an assignment
    target for users and groups. It's possible for users and groups to have
    authorization on domains outside of the domain associated to their
    reference.

Project
    A container and a namespace for resources isolated within OpenStack. A
    user, or group of users, must have a role assignment on a project in order
    to interact with it.

Token
    A self-service resource that proves a user's identity and authentication.
    It can optionally carry a user's authorization, allowing them to interact
    with OpenStack services.

Role
    A string that represents one or more permissions or capabilities.

Role Assignment
    An association between an actor and a target that results in authorization.
    Actors can be users or groups of users. Targets can be projects, domains,
    or the deployment system itself.

User
    A entity modeling an end-user of the system.

Group
    A container for users. Users indirectly inherit any authorization the group
    has on projects, domains, or the system.


Domains
=======

A major new feature in v3 is domains. Every project, user, and user group is
owned by a domain (reflected by their ``domain_id`` value) which provides them
their own namespace. For example, unlike in v2.0, usernames are no longer
unique across the deployment. You can have two users with the same name, but
they must be in different domains. However, user IDs are assigned to users by
keystone and are expected to be unique across the deployment. All of this logic
applies to both projects and user groups as well. Note that roles are *not*
namespaced by domains.

One of the great things about domains is that you can have one domain backed by
SQL (for service users) and another backed by LDAP (the cloud is deployed into
existing infrastructure).

The "default" domain
====================

.. note::

    The v2.0 API has been removed as of the Queens release. While this section
    references the v2.0 API, it is purely for historical reasons that clarify
    the existance of the *default* domain.

Domains were introduced as a v3-only feature. As a result, the v2.0 API didn't
understand the concept of domains. To allow for both versions of the Identity
API to run side-by-side, the idea of a *default* domain was established.

The *default* domain was a domain that was guaranteed to exist and was created
during the ``keystone-manage db_sync`` process. By default, the domain ID is
``default`` and the name is ``Default``, but it is possible to change
these values through keystone's configuration file. The v2.0 API would consider
users and projects existing within that domain as valid, but it would never
expose domain information through the API. This allowed the v2.0 API to operate
under the assumption that everything within the *default* domain was
accessible. This was crucial in avoiding namespace conflicts between v2.0 and
v3 where multiple domains existed. Using v3 allowed deployers the ability to
experiment with domains, while isolating them from the v2.0 API.

As far as the v3 API is concerned, the *default* domain is simply a domain and
doesn't carry any special connotation like it did with v2.0.

Authorization Scopes
====================

End users use the Identity API as a way to express their authoritative power to
other OpenStack services. This is done using tokens, which can be scoped to one
of several targets depending on the users' role assignments. This is typically
referred to as a token's *scope*. This happens when a user presents
credentials, in some form or fashion, to keystone in addition to a desired
scope. If keystone can prove the user is who they say they are (authN), it will
then validate that the user has access to the scope they are requesting
(authZ). If successful, the token response will contain a token ID and data
about the transaction, such as the scope target and role assignments. Users can
use this token ID in requests to other OpenStack services, which consume the
authorization information associated to that token to make decisions about what
that user can or cannot do within that service.

This section describes the various scopes available, and what they mean for
services consuming tokens.

System Scope
------------

A *system-scoped* token implies the user has authorization to act on the
*deployment system*. These tokens are useful for interacting with resources
that affect the deployment as a whole, or exposes resources that may otherwise
violate project or domain isolation.

Good examples of system-scoped resources include:

* Services: Service entities within keystone that describe the services
  deployed in a cloud.
* Endpoints: Endpoints that tell users where to find services deployed in a
  cloud.
* Hypervisors: Hosts for servers that belong to various projects.

Domain Scope
------------

A *domain-scoped* token carries a user's authorization on a specific domain.
Ideally, these tokens would be useful for listing resources aggregated across
all projects with that domain. They can also be useful for creating entities
that must belong to a domain. Users and groups are good examples of this. The
following is an example of how a domain-scoped token could be used against a
service.

Assume a domain exists called `Foo`. and it contains projects call `bar` and
`baz`. Let's also assume both projects contain compute servers running a
workload. If Alice is a domain administrator for `Foo`, she should be able to
pass her domain-scoped token to nova and ask for a list of instances. If nova
supports domain-scoped token, the response would contain all instances in
projects `bar` and `baz`.

Another example of using a domain-scoped token would be if Alice wanted to
create a new project in domain `Foo`. When Alice sends a request for keystone
to create a project, keystone should ensure the new project is created within
the `Foo` domain, since that's the authorization associated to Alice's token.

.. WARNING::

    This behavior isn't completely implemented, and is still in progress. This
    example describes the ideal behavior, specifically for developers looking
    to implement scope into their APIs.

Project Scope
-------------

A *project-scoped* token carries the role assignments a user has on a project.
This type of scope is great for managing resources that fit nicely within
project boundaries. Good examples of project-level resources that can be
managed with project-scoped tokens are:

* Instances: Virtual compute servers that require a project association in
  order to be created.
* Volumes: Storage devices that can be attached to instances.

Unscoped
--------

An *unscoped* token is a token that proves authentication, but doesn't carry
any authorization. Users can obtain unscoped tokens by simply proving their
identity with credentials. Unscoped tokens can be exchanged for any of the
various scoped tokens if a user has authorization on the requested scope.

An example of where unscoped tokens are specifically useful is when users
perform federated authentication. First, a user will receive an unscoped token
pending successful federated authentication, which they can use to query
keystone for a list of projects they're allowed to access. Then they can
exchange their unscoped token for a project-scoped token allowing them to
perform actions within a particular project.

Auth Token middleware
=====================

The ``auth_token`` middleware handles token validation for the different
services. Conceptually, what happens is that ``auth_token`` pulls the token out
of the ``X-Auth-Token`` request header, validates the token using keystone,
produces information about the identity (the API user) and authorization
context (the project, roles, etc) of the token, and sets environment variables
with that data. The services typically take the environment variables, put them
in the service's "context", and use the context for policy enforcement via
``oslo.policy``.

Service tokens
--------------

Service tokens are a feature where the ``auth_token`` middleware will also
accept a service token in the ``X-Service-Token`` header. It does the same
thing with the service token as the user token, but the results of the token
are passed separately in environment variables for the service token (the
service user, project, and roles). If the service knows about these then it can
put this info in its "context" and use it for policy checks. For example,
assuming there's a special policy rule called ``service_role`` that works like
the ``role`` rule except checks the service roles, you could have an
``oslo.policy`` rule like ``service_role:service and user_id:%(user_id)s`` such
that a service token is required along with the user owning the object.

Picking the version
===================

Use version discovery to figure out what version the identity server supports
rather than configuring the version. This will make it easier to adopt new API
versions as they are implemented.

For information about how to accomplish service discovery with the keystoneauth
library, please see the `documentation
<https://docs.openstack.org/keystoneauth/latest/using-sessions.html#service-discovery>`_.

Hierarchical Multitenancy
=========================

This feature is specific to v3 and allows projects to have parents, siblings,
and children relationships with other projects.

Tokens scoped to projects in a hierarchical structure won't contain information
about the hierarchy in the token response. If the service needs to know the
hierarchy it should use the v3 API to fetch the hierarchy.
