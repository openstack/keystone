===========================
Keystone for other services
===========================

This document provides a summary of some things that other services
need to know about how keystone works. Specifically, we were requested
to describe what other services need to know about the v3 API. The v3
API was introduced in the Grizzly release, and its use until recently
has been hidden from other services since the auth_token middleware
translated the token format so that both versions look the same. Once
the services need to make use of v3 features they need to know about
how it works.


Glossary
========

Service
    OpenStack servers like keystone, nova, glance, etc.

Project
    A project is a namespace for a grouping of OpenStack entities. Users must
    be assigned a role on a project in order to interact with it. Prior to the
    introduction of the v3 API, projects were referred to as tenants and the
    term is still used in reference to the v2.0 API.


Token differences
=================

The keystone service runs both v2 and v3, v2 requests go to /v2.0 and v3
requests go to /v3. You don't need to "enable" the v3 API in keystone, it is
available by default via a separate pipeline from v2.0. If you get a token
using the v2 API you can use it to do v3 operations (like list users and
stuff). The reverse also works, get a v3 token and use it on v2 works fine.

You can get a v2 token using POST /v2.0/tokens. You can get a v3 token
using POST /v3/auth/tokens. The response is different: the service
catalog is a different format, and the v3 token has more fields (user
domain, project domain).


Domains
=======

A major change to v3 is domains. Every project, user, and group is in a domain.
This means they have a domain_id. You can have two users with the same name but
they must be in different domains, thus usernames are not globally unique
across the deployment. Unique identifiers assigned to users from keystone are
expected to be unique across the deployment. However, roles are not in domains.

One of the great things about domains is that you can have one domain
backed by SQL (for service users) and another backed by LDAP (the cloud
is deployed into existing infrastructure).

If you do v2 operations, there's no way to specify the domain, so v2
operations all work against the default domain. So if you're stuck with
v2 and need to get a token you can only get tokens for users in the
default domain. If your default domain is SQL and you have a domain for
LDAP users called "ldap" you can't get to the users in LDAP using v2.
Also, if your default domain is read-only LDAP then you won't be able
to create the service users using v2 clients because any SQL-backed
domain is unreachable.

Domain-scoped tokens
--------------------

Domain-scoped tokens are scoped to a domain rather than a project.
These are useful for operating against keystone but are useless in
other services, so other services don't need to concern themselves with
domain-scoped tokens.


Auth Token middleware
=====================

The auth_token middleware handles token validation for the different services.
Conceptually, what happens is that auth_token pulls the token out of the
X-Auth-Token header, sends the token to keystone to validate the token and get
information about the token (the user, project, and roles), and sets a bunch of
environment variables with the user, project, and roles. The services typically
take the environment variables, put them in the service's "context", and use
the context for policy enforcement via oslo.policy.

Service tokens
--------------

Service tokens are a new-ish feature where the auth_token middleware
will also accept a service token in the "X-Service-Token" header. It
does the same thing with the service token as the user token, but the
results of the token get stuck in environment variables for the service
token (the service user, project, and roles). If the service knows
about these then it can put this info in its "context" and use it for
policy checks. For example, assuming there's a special policy rule
called ``service_role`` that works like the ``role`` rule except checks
the service roles, you could have a rule like ``service_role:service
and user_id:%(user_id)s`` so that a service token is required along
with the user owning the object.

V2 / V3
-------

The auth_token middleware can be configured to authenticate tokens
using v2, v3, or to use discovery (the default). When discovery is
used, auth_token will pick v3 if the server reports that v3 is
available. If auth_token is configured to use v2 then if it receives a
v3 token it will fail if the user is not in the default domain (e.g.,
the domain that heat creates users in). So auth_token middleware needs
to use v3!


Do this, not that
=================

Config options for authentication
---------------------------------

If you need to get a token, don't define options for username and
password and get a token using v2. We've got an interface for using
authentication plugins where there's an option for that supports v2 or
v3 and potentially other authentication mechanisms (X.509 client
certs!).

If your config file doesn't have the domain for the user, it's not
going to be able to use v3 for authentication.

Picking the version
-------------------

Use version discovery to figure out what version the identity server
supports rather than configuring the version.

Use OpenStack CLI not keystone CLI
----------------------------------

The keystone CLI is deprecated and will be removed soon. The `OpenStack CLI
<http://docs.openstack.org/developer/python-openstackclient/>`_
has all the keystone CLI commands and even supports v3.


Hierarchical Multitenancy
=========================

This feature allows maintenance of a hierarchy of projects with
"parent" projects operating as domains.

The token format is the same (the token doesn't contain any info about
the hierarchy). If the service needs to know the hierarchy it will have
to use the v3 API to fetch the hierarchy.

While you can't use v2 to set up the hierarchy, you can get a v2 token
scoped to a project that's part of a hierarchy.

