===============
Keystone tokens
===============

Tokens are used to authenticate and authorize your interactions with OpenStack
APIs. Tokens come in many scopes, representing various authorization and
sources of identity.

.. _authorization_scopes:

Authorization scopes
--------------------

Tokens are used to relay information about your role assignments. It's not
uncommon for a user to have multiple role assignments, sometimes spanning
projects, domains, or the entire system. These are referred to as authorization
scopes, where a token has a single scope of operation (e.g., a project, domain,
or the system). For example, a token scoped to a project can't be reused to do
something else in a different project.

Each level of authorization scope is useful for certain types of operations in
certain OpenStack services, and are not interchangeable.

Unscoped tokens
~~~~~~~~~~~~~~~

An unscoped token does not contain a service catalog, roles, or authorization
scope (e.g., project, domain, or system attributes within the token). Their
primary use case is simply to prove your identity to keystone at a later time
(usually to generate scoped tokens), without repeatedly presenting your
original credentials.

The following conditions must be met to receive an unscoped token:

* You must not specify an authorization scope in your authentication request
  (for example, on the command line with arguments such as
  ``--os-project-name`` or ``--os-domain-id``),

* Your identity must not have a "default project" associated with it that you
  also have role assignments, and thus authorization, upon.

Project-scoped tokens
~~~~~~~~~~~~~~~~~~~~~

Projects are containers for resources, like volumes or instances.
Project-scoped tokens express your authorization to operate in a specific
tenancy of the cloud and are useful for things like spinning up compute
resources or carving off block storage. They contain a service catalog, a set
of roles, and information about the project.

Most end-users need role assignments on projects to consume resources in a
deployment.

Domain-scoped tokens
~~~~~~~~~~~~~~~~~~~~

Domains are namespaces for projects, users, and groups. A domain-scoped token
expresses your authorization to operate on the contents of a domain or the
domain itself.

While some OpenStack services are still adopting the domain concept, domains
are fully supported in keystone. This means users with authorization on a
domain have the ability to manage things within the domain. For example, a
domain administrator can create new users and projects within that domain.

Domain-scoped tokens contain a service catalog, roles, and information about
the domain.

People who need to manage users and projects typically need domain-level
access.

System-scoped tokens
~~~~~~~~~~~~~~~~~~~~

Some OpenStack APIs fit nicely within the concept of projects (e.g.,
creating an instance) or domains (e.g., creating a new user), but there are also
APIs that affect the entire deployment system (e.g. modifying endpoints,
service management, or listing information about hypervisors). These operations
are typically reserved for operators and require system-scoped tokens, which
represents the role assignments a user has to operate on the deployment as a
whole. The term *system* refers to the deployment system, which is a collection
of hardware (e.g., compute nodes) and services (e.g., nova, cinder, neutron,
barbican, keystone) that provide Infrastructure-as-a-Service.

System-scoped tokens contain a service catalog, roles, and information about
the *system*. System role assignments and system-scoped tokens are typically
reserved for operators and cloud administrators.

Token providers
---------------

The token type issued by keystone is configurable through the
``/etc/keystone/keystone.conf`` file. Currently, there are two supported token
providers, ``fernet`` and ``jws``.

Fernet tokens
~~~~~~~~~~~~~

The fernet token format was introduced in the OpenStack Kilo release and now
is the default token provider in Keystone. Unlike the other token types
mentioned in this document, fernet tokens do not need to be persisted in a back
end. ``AES256`` encryption is used to protect the information stored in the
token and integrity is verified with a ``SHA256 HMAC`` signature. Only the
Identity service should have access to the keys used to encrypt and decrypt
fernet tokens. Like UUID tokens, fernet tokens must be passed back to the
Identity service in order to validate them. For more information on the fernet
token type, see the :doc:`fernet-token-faq`.

A deployment might consider using the fernet provider as opposed to JWS tokens
if they are concerned about public expose of the payload used to build tokens.

JWS tokens
~~~~~~~~~~

The JSON Web Signature (JWS) token format is a type of JSON Web Token (JWT) and
it was implemented in the Stein release. JWS tokens are signed, meaning the
information used to build the token ID is not opaque to users and can it can be
decoded by anyone. JWS tokens are ephemeral, or non-persistent, which means
they won't bloat the database or require replication across nodes. Since the
JWS token provider uses asymmetric keys, the tokens are signed with private
keys and validated with public keys. The JWS token provider implementation
only supports the ``ES256`` JSON Web Algorithm (JWA), which is an Elliptic
Curve Digital Signature Algorithm (ECDSA) using the P-256 curve and a SHA-256
hash algorithm.

A deployment might consider using JWS tokens as opposed to fernet tokens if
there are security concerns about sharing symmetric encryption keys across
hosts. Note that a major difference between the two providers is that JWS
tokens are not opaque and can be decoded by anyone with the token ID. Fernet
tokens are opaque in that the token ID is ciphertext. Despite the JWS token
payload being readable by anyone, keystone reserves the right to make backwards
incompatible changes to the token payload itself, which is not an API contract.
We only recommend validating the token against keystone's authentication API to
inspect its associated metadata. We strongly discourage relying on decoded
payloads for information about tokens.

More information about JWTs can be found in the `specification`_.

.. _`specification`: https://tools.ietf.org/html/rfc7519

.. support_matrix:: token-support-matrix.ini
