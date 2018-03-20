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

Service
    OpenStack services like identity, compute, image, etc.

Project
    A project provides namespace and resource isolation for groups of OpenStack
    entities. Users must be assigned a role on a project in order to interact
    with it. Prior to the introduction of the v3 API, projects were referred to
    as tenants in the v2.0 API.


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

Token differences
=================

Domain-scoped tokens
--------------------

Domain-scoped tokens are scoped to a domain rather than a project. These are
useful for operating against keystone but are generally useless in other
services that don't have use cases for domain-level operations. Unless a
service has a real case for handling such authorization, they don't need to
concern themselves with domain-scoped tokens.


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
