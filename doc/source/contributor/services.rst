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
Keystone for Other Services
===========================

This document provides a summary of some things that other services need to
know about how keystone works, and specifically about how they can take
advantage of the v3 API. The v3 API was introduced as a stable API in the
Grizzly release.


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
applies to projects, user groups and roles.

One of the great things about domains is that you can have one domain backed by
SQL (for service users) and another backed by LDAP (the cloud is deployed into
existing infrastructure).

The "default" domain
====================

.. note::

    The v2.0 API has been removed as of the Queens release. While this section
    references the v2.0 API, it is purely for historical reasons that clarify
    the existence of the *default* domain.

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
* Hypervisors: Physical compute infrastructure that hosts instances where the
  instances may, or may not, be owned by the same project.

Domain Scope
------------

A *domain-scoped* token carries a user's authorization on a specific domain.
Ideally, these tokens would be useful for listing resources aggregated across
all projects with that domain. They can also be useful for creating entities
that must belong to a domain. Users and groups are good examples of this. The
following is an example of how a domain-scoped token could be used against a
service.

Assume a domain exists called `Foo`, and it contains projects called `bar` and
`baz`. Let's also assume both projects contain instances running a workload. If
Alice is a domain administrator for `Foo`, she should be able to pass her
domain-scoped token to nova and ask for a list of instances. If nova supports
domain-scoped tokens, the response would contain all instances in projects
`bar` and `baz`.

Another example of using a domain-scoped token would be if Alice wanted to
create a new project in domain `Foo`. When Alice sends a request to create a
new project (`POST /v3/projects`), keystone should ensure the new project is
created within the `Foo` domain, since that's the authorization associated to
Alice's token.

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

Why are authorization scopes important?
=======================================

Flexibility for exposing your work
----------------------------------

OpenStack provides a rich set of APIs and functionality. We wrote some APIs
with the intent of managing the deployment hardware, otherwise referred to as
the deployment system. We wrote others to orchestrate resources in a project or
a domain. Some APIs even operate on multiple levels. Since we use tokens to
authorize a user's actions against a given service, they needed to handle
different scope targets. For example, when a user asks for a new instance, we
expect that instance to belong to a project; thus we expect a project relayed
through the token's scope. This idea is fundamental in providing isolation, or
tenancy, between projects in OpenStack.

Initially, keystone only supported the ability to generate project-scoped
tokens as a product of a user having a role assignment on a project.
Consequently, services had no other choice but to require project-scoped tokens
to protect almost all of their APIs, even if that wasn't an ideal option. Using
project-scoped tokens to protect APIs they weren't designed to protect required
operators to write custom policy checks to secure those APIs. An example
showcases this more clearly.

Let's assume an operator wanted to create a read-only role. Users with the
`reader` role would be able to list things owned by the project, like
instances, volumes, or snapshots. The operator also wants to have a read-only
role for fellow operators or auditors, allowing them to view hypervisor
information or endpoints and services. Reusing the existing `reader` role is
difficult because users with that role on a project shouldn't see data about
hypervisors, which would violate tenancy. Operators could create a new role
called `operator` or `system-reader`, but then those users would still need to
have that role assigned on a project to access deployment-level APIs. The
concept of getting project-scoped tokens to access deployment-level resources
makes no sense for abstractions like hypervisors that cannot belong to a single
project. Furthermore, this requires deployers to maintain all of this in policy
files. You can quickly see how only using project-scope limits our ability to
protect APIs without convoluted or expensive-to-maintain solutions.

Each scope offered by keystone helps operators and users avoid these problems
by giving you, the developer, multiple options for protecting APIs you write,
instead of the one-size-fits-all approach we outgrew. You no longer have to
hope an operator configures policy correctly so their users can consume the
feature you wrote. The more options you have for protecting an API, the easier
it is to provide default policies that expose more of your work to users
safely.

Less custom code
----------------

Another crucial benefit of authorization scopes offered by keystone is less
custom code. For example, if you were writing an API to manage a
deployment-level resource but only allowed to consume project-scoped tokens,
how would you determine an operator from an end user? Would you attempt to
standardize a role name? Would you look for a unique project in the token's
scope? Would these checks be configurable in policy or hardcoded in your
service?

Chances are, different services will come up with different, inconsistent
solution for the same problem. These inconsistencies make it harder for
developers to context switch between services that process things differently.
Users also suffer from inconsistencies by having to maintain a mental mapping
of different behavior between services. Having different scopes at your
disposal, through keystone tokens, lets you build on a standard solution that
other projects also consume, reducing the likelihood of accidentally developing
inconsistencies between services. This commonality also gives us a similar set
of terms we can use when we communicate with each other and users, allowing us
to know what someone means by a `system-admin` and how that is different from a
`project-admin`.

Reusable default roles
----------------------

When OpenStack services originally started developing a policy enforcement
engine to protect APIs, the only real concrete role we assumed to be present in
the deployment was a role called `admin`. Because we assumed this, we were able
to write policies with `admin` as the default. Keystone also took steps to
ensure it had a role with that name during installation. While making this
assumption is beneficial for some APIs, having only one option is underwhelming
and leaves many common policy use cases for operators to implement through
policy overrides. For example, a typical ask from operators is to have a
read-only role, that only allows users with that role on a target to view its
contents, restricting them from making writable changes. Another example is a
membership role that isn't the administrator. To put it clearly, a user with a
`member` role assignment on a project may create new storage volumes, but
they're unable to perform backups. Users with the `admin` role on a project can
access the backups functionality.

Keep in mind, the examples above are only meant to describe the need for other
roles besides `admin` in a deployment. Service developers should be able to
reuse these definitions for similar APIs and assume those roles exist. As a
result, keystone implemented support for ensuring the `admin`, `member`, and
`reader` roles are present during the installation process, specifically when
running ``keystone-manage bootstrap``. Additionally, keystone creates a
relationship among these roles that make them easier for service developers to
use. During creation, keystone implies that the `admin` role is a superset of
the `member` role, and the `member` role is a superset of the `reader` role.
The benefit may not be obvious, but what this means is that users with the
`admin` role on a target also have the `member`  and `reader` roles generated
in their token. Similarly, users with the `member` role also have the `reader`
role relayed in their token, even though they don't have a direct role
assignment using the `reader` role. This subtle relationship allows developers
to use a short-hand notation for writing policies. The following assumes
``foobar`` is a project-level resource available over a service API and is
protected by policies using generic roles:

.. code-block:: yaml

   "service:foobar:get": "role:admin OR role:member OR role:reader"
   "service:foobar:list": "role:admin OR role:member OR role:reader"
   "service:foobar:create": "role:admin OR role:member"
   "service:foobar:update": "role:admin OR role:member"
   "service:foobar:delete": "role:admin"

The following policies are functionally equivalent to the policies above, but
rely on the implied relationship between the three roles, resulting in a
simplified check string expression:

.. code-block:: yaml

   "service:foobar:get": "role:reader"
   "service:foobar:list": "role:reader"
   "service:foobar:create": "role:member"
   "service:foobar:update": "role:member"
   "service:foobar:delete": "role:admin"

In addition to above roles, from 2023.2 (Bobcat) release
``keystone-manage bootstrap`` will provide `service` role as well. If a
``service`` role is already present in the deployment, then a new one
is not created.  This way any local scripts relying on the role ID will not
be broken.

.. note::
    If you already have a ``service`` role in your deployment, you should
    review its usage to make sure it is used only for service-to-service
    communication.

Once ``service`` role is created, OpenStack service
developers can start integrating it into their default policies as expressed:

.. code-block:: python

   policy.DocumentedRuleDefault(
       name='os_compute_api:os-server-external-events:create',
       check_str='role:service',
       scope_types=['project']
   )

It is important to note that we need to keep all the service-to-service APIs
default to ``service`` role only. For example, a policy that requires
``service`` can be expressed as:

.. code-block:: yaml

    "service:foobar:create": "role:service"

There might be exception service-to-service APIs which project think are
useful to be used by admin or non-admin user then they can take the
exceptional decision to default them to user role and ``service`` role.  For
example, a policy that requires ``service`` and ``admin`` can be expressed as:

.. code-block:: yaml

    "service:foobar:create": "role:service" OR "role:admin"

Additionally, any deployment tools that create service accounts for OpenStack
services, should start preparing for these policy changes by updating their
role assignments and performing the deployment language equivalent of the
following:

.. code-block:: console

   $ openstack role add --user nova --project service service
   $ openstack role add --user cinder --project service service
   $ openstack role add --user neutron --project service service
   $ openstack role add --user glance  --project service service
   $ openstack role add --user manila  --project service service

How do I incorporate authorization scopes into a service?
=========================================================

Now that you understand the advantages of a shared approach to policy
enforcement, the following section details the order of operations you can use
to implement it in your service.

Ruthless Testing
----------------

Policy enforcement implementations vary greatly across OpenStack services. Some
enforce authorization near the top of the API while others push the logic
deeper into the service. Differences and intricacies between services make
testing imperative to adopt a uniform, consistent approach. Positive and
negative protection testing helps us assert users with specific roles can, or
cannot, access APIs. A protection test is similar to an API, or functional
test, but purely focused on the authoritative outcome. In other words,
protection testing is sufficient when we can assert that a user is or isn't
allowed to do or see something. For example, a user with a role assignment on
project `foo` shouldn't be able to list volumes in project `bar`. A user with a
role on a project shouldn't be able to modify entries in the service catalog.
Users with a `reader` role on the system, a domain, or a project shouldn't be
able to make writable changes. You commonly see protection tests conclude with
an assertion checking for a successful response code or an HTTP 403 Forbidden.

If your service has minimal or non-existent protection coverage, you should
start by introducing tests that exercise the current default policies, whatever
those are. This step serves three significant benefits.

First, it puts us in the shoes of our users from an authorization perspective,
allowing us to see the surface of the API a user has access to with a given
assignment. This information helps audit the API to make sure the user has all
the authorization to do what they need_, but nothing more. We should note
inconsistencies here as feedback that we should fix, especially since operators
are probably attempting to fix these inconsistencies through customized policy
today.

Second, a collection of protection tests make sure we don't have unwanted
security-related regressions. Imagine making a policy change that introduced a
regression and allowed a user to access an API and data they aren't supposed to
see. Conversely, imagine a patch that accidentally tightened restriction on an
API that resulted in a broken workflow for users. Testing makes sure we catch
cases like this early and handle them accordingly.

Finally, protection tests help us use test-driven development to evolve policy
enforcement. We can make a change and assert the behavior using tests locally,
allowing us to be proactive and not reactive in our authoritative business
logic.

To get started, refer to the `oslo.policy documentation`_ that describes
techniques for writing useful protection tests. This document also describes
some historical context you might recognize in your service and how you should
deal with it. You can also look at protection tests examples in other services,
like keystone_ or cinder_. Note that these examples test the three default
roles provided from keystone (reader, member, and admin) against the three
scopes keystone offers, allowing for nine different personas without operators
creating roles specific to their deployment. We recommend testing these
personas where applicable in your service:

* project reader
* project member
* project admin
* system reader
* system member
* system admin
* domain reader
* domain member
* domain admin

.. _need: https://en.wikipedia.org/wiki/Principle_of_least_privilege
.. _oslo.policy documentation: https://docs.openstack.org/oslo.policy/latest/user/usage.html#testing-default-policies
.. _keystone: https://opendev.org/openstack/keystone/src/commit/77e50e49c5af37780b8b4cfe8721ba28e8a58183/keystone/tests/unit/protection/v3
.. _cinder: https://review.opendev.org/#/c/602489/

Auditing the API
----------------

After going through the API and adding protection tests, you should have a good
idea of how each API is or isn't exposed to end users with different role
assignments. You might also have a list of areas where policies could be
improved. For example, maybe you noticed an API in your service that consumes
project-scoped tokens to protect a system-level resource. If your service has a
bug tracker, you can use it to document these gaps. The keystone team went
through this exercise and used bugs_. Feel free to use these bug reports as a
template for describing gaps in policy enforcement. For example, if your
service has APIs for listing or getting resources, you could implement the
reader role on that API.

.. _bugs: http://tinyurl.com/y5kj6fn9

Setting scope types
-------------------

With testing in place and gaps documented, you can start refactoring. The first
step is to start using oslo.policy for scope checking, which reduces complexity
in your service by having a library do some lifting for you. For example, if
you have an API that requires a project-scoped token, you can set the scope of
the policy protecting that API accordingly. If an instance of ``RuleDefault``
has scope associated to it, oslo.policy checks that it matches the scope of the
token used to make the request. This behavior is configurable_, allowing
operators to turn it on once all policies have a scope type and once operators
have audited their assignments and educated their users on how to get the scope
necessary to access an API. Once that happens, an operator can configure
oslo.policy to reject requests made with the wrong scope. Otherwise,
oslo.policy logs a warning for operators that describes the mismatched scope.

The oslo.policy library provides `documentation for setting scope`_. You can
also see `keystone examples`_ or `placement examples`_ of setting scope types
on policies.

If you have difficulty deciding which scope an API or resource requires, try
thinking about the intended user. Are they an operator managing the deployment?
Then you might choose `system`. Are they an end user meant to operate only
within a given project? Then `project` scope is likely what you need. Scopes
aren't mutually exclusive.

You may have APIs that require more than one scope. Keystone's user and project
APIs are good examples of resources that need different scopes. For example, a
system administrator should be able to list all users in the system, but domain
administrators should only be able to list users within their domain. If you
have an API that falls into this category, you may be required to implicitly
filter responses based on the scope type. If your service uses oslo.context and
keystonemiddleware, you can query a `RequestContext` object about the token's
scope. There are keystone patches_ that show how to filter responses according
to scope using oslo.context, in case you need inspiration.

If you still can't seem to find a solution, don't hesitate to send a note to
the `OpenStack Discuss mailing list`_ tagged with `[keystone]` or ask in
#openstack-keystone on IRC_.

.. _configurable: https://docs.openstack.org/oslo.policy/latest/configuration/index.html#oslo_policy.enforce_scope
.. _documentation for setting scope: https://docs.openstack.org/oslo.policy/latest/user/usage.html#setting-scope
.. _keystone examples: https://review.opendev.org/#/q/status:merged+project:openstack/keystone+branch:master+topic:add-scope-types
.. _placement examples: https://review.opendev.org/#/c/571201/
.. _patches: https://review.opendev.org/#/c/623319/
.. _OpenStack Discuss mailing list: http://lists.openstack.org/cgi-bin/mailman/listinfo/openstack-discuss
.. _IRC: https://wiki.openstack.org/wiki/IRC

Rewriting check string
----------------------

With oslo.policy able to check scope, you can start refactoring check strings
where-ever necessary. For example, adding support for default roles or removing
hard-coded ``is_admin: True`` checks. Remember that oslo.policy provides
deprecation tooling that makes upgrades easier for operators. Specifically,
upgrades are made easier by combining old defaults or overrides with the new
defaults using a logical `OR`. We encourage you to use the available
deprecation tooling when you change policy names or check strings. You can
refer to examples_ that show you how to build descriptive rule objects using
all the default roles from keystone and consuming scopes.

.. _examples: https://review.opendev.org/#/q/(status:open+OR+status:merged)+project:openstack/keystone+branch:master+topic:implement-default-roles

Communication
-------------

Communicating early and often is never a bad thing, especially when a change is
going to impact operators. At this point, it's crucial to emphasize the changes
you've made to policy enforcement in your service. Release notes are an
excellent way to signal changes to operators. You can find examples when
keystone implemented support for default roles. Additionally, you might have
operators or users ask questions about the various scopes or what they mean.
Don't hesitate to refer them to keystone's :ref:`scope documentation
<authorization_scopes>`.

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
