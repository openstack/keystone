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
    as tenants and the term is still used in reference to the v2.0 API.


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

Conventionally the "default" domain has a domain ID of ``default`` and a domain
name of ``Default``. It is created by ``keystone-manage db_sync`` and thus
should always exist, although the domain ID is configurable in
``keystone.conf`` and the domain name is mutable through the v3 API.

Because only the v3 API is domain-aware, we must work to avoid perceived
namespace conflicts to v2.0 clients. The solution to this is to have a single
domain serve as the implied namespace for all user and tenant references in
v2.0. Thus, v2.0 clients can continue to be domain-unaware and avoid the
security risk posed by potential namespace conflicts. *This is the only purpose
of the default domain.*

For example, I could otherwise create a domain in v3, create a user in that
domain called "admin", authenticate using v2.0, and a domain-unaware v2.0
client might assume I'm the same "admin" user it has seen before and grant me
escalated privileges. Instead, users outside of the default domain simply
cannot authenticate against v2.0, nor can such tokens with references to users
and projects outside the default domain be validated on the v2.0 API.

From a v2.0 client's perspective, there's no way to specify the domain, so v2.0
operations implicitly work against the default domain. So if your client is
only capable of using v2.0 and you need to get a token, then you can only get
tokens for users and tenants (projects) in the default domain. In the real
world, this means that if your default domain is backed by SQL and you have a
separate domain for LDAP users, then you can't authenticate as an LDAP user
using v2.0. Conversely, if your default domain is backed by a read-only LDAP
driver, then you won't be able to create the service users using v2.0 clients
because any SQL-backed domain is unreachable.

From a v3 client's perspective, the default domain is not special, other than
the fact that such a domain can generally be assumed to exist (assuming the
deployment is also running the v2.0 API). It would be reasonable for a v3
client to assume a default user domain ID of ``default`` and a default project
domain ID of ``default`` unless overridden by more specific configuration.

To summarize, avoiding namespace conflicts in the v2.0 API is achieved by
limiting the v2.0 API and its clients to working with users and projects which
are namespaced by a single, arbitrary domain in v3.

Token differences
=================

The keystone service runs both v2.0 and v3, where v2.0 requests go to the
``/v2.0`` endpoint and v3 requests go to the ``/v3`` endpoint. If you're using
the default pipeline that ships with keystone, then you don't need "enable" the
v3 API in keystone, as it runs by default as a parallel pipeline to the v2.0
API.

If you get a token using the v2.0 API, then you can use it to do v3 operations
(such as list users). The reverse, using a v3 token against v2.0, is possible
only in certain circumstances. For example, if you're using a project-scoped
token wherein the user and project are both owned by the "default" domain,
everything will work. Otherwise, token validation against the v2.0 API will
fail.

You can get a v2.0 token using ``POST /v2.0/tokens``. You can get a v3 token
using ``POST /v3/auth/tokens``. Note that the responses are significantly
different. For example, the service catalog is in a different format, and the
v3 token conveys additional context (such as the user's domain and the
project's domain).

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

v2.0 or v3?
-----------

By default, the ``auth_token`` middleware will use discovery to determine the
best available API to use, or can be explicitly configured to use either v2.0
or v3. When discovery is used, ``auth_token`` will use v3 if keystone reports
that v3 is available. If ``auth_token`` is configured to use v2.0, then it will
fail when it receives a v3 token wherein the user is not in the default domain
(for example, the domain that heat creates users in). So if at all possible,
the ``auth_token`` middleware should be allowed to use v3.

Additionally, as other services begin to utilize features which are only found
in the v3 API, you'll need to use the v3 API in order to utilize those
services. For example, heat creates users in an isolated domain, and thus
requires the v3 API.

Do this, not that
=================

Config options for authentication
---------------------------------

If you need to get a token, don't define options for username and password and
get a token using v2.0. We've got an interface for using authentication plugins
where there's an option for that supports v2.0 or v3 and potentially other
authentication mechanisms (X.509 client certs!).

If your config file doesn't have the domain for the user, it's not going to be
able to use v3 for authentication.

Picking the version
-------------------

Use version discovery to figure out what version the identity server supports
rather than configuring the version.

Use OpenStack CLI not keystone CLI
----------------------------------

The keystone CLI is deprecated and will be removed soon. The `OpenStack CLI
<https://docs.openstack.org/developer/python-openstackclient/>`_ has all the
keystone CLI commands and even supports v3.


Hierarchical Multitenancy
=========================

This feature allows maintenance of a hierarchy of projects with "parent"
projects operating as domains.

The token format is the same (the token doesn't contain any info about the
hierarchy). If the service needs to know the hierarchy it will have to use the
v3 API to fetch the hierarchy.

While you can't use v2.0 to set up the hierarchy, you can get a v2.0 token
scoped to a project that's part of a hierarchy.
