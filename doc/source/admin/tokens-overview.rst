===============
Keystone tokens
===============

Tokens are used to authenticate and authorize your interactions with the
various OpenStack APIs. Tokens come in many scopes, representing various
authorization and sources of identity.

Authorization scopes
--------------------

Tokens are used to relay information about your user's role assignments. It's
not uncommon for a user to have multiple role assignments, sometimes spanning
projects, domains, or the entire system. These are referred to as authorization
scopes, where a token has a single scope of operation. For example, a token
scoped to a project can't be reused to do something else in a different
project.

Each level of authorization scope is useful for certain types of operations in
certain OpenStack services, and are not interchangeable.

Unscoped tokens
~~~~~~~~~~~~~~~

An unscoped token contains neither a service catalog, any roles, a project
scope, nor a domain scope. Their primary use case is simply to prove your
identity to keystone at a later time (usually to generate scoped tokens),
without repeatedly presenting your original credentials.

The following conditions must be met to receive an unscoped token:

* You must not specify an authorization scope in your authentication request
  (for example, on the command line with arguments such as
  ``--os-project-name`` or ``--os-domain-id``),

* Your identity must not have a "default project" associated with it that you
  also have role assignments, and thus authorization, upon.

Project-scoped tokens
~~~~~~~~~~~~~~~~~~~~~

Project-scoped tokens express your authorization to operate in a specific
tenancy of the cloud and are useful to authenticate yourself when working with
most other services.

They contain a service catalog, a set of roles, and details of the project upon
which you have authorization.

Domain-scoped tokens
~~~~~~~~~~~~~~~~~~~~

Domain-scoped tokens have limited use cases in OpenStack. They express your
authorization to operate a domain-level, above that of the user and projects
contained therein (typically as a domain-level administrator).  Depending on
Keystone's configuration, they are useful for working with a single domain in
Keystone.

They contain a limited service catalog (only those services which do not
explicitly require per-project endpoints), a set of roles, and details of the
project upon which you have authorization.

They can also be used to work with domain-level concerns in other services,
such as to configure domain-wide quotas that apply to all users or projects in
a specific domain.

System-scoped tokens
~~~~~~~~~~~~~~~~~~~~

There are APIs across OpenStack that fit nicely within the concept of a project
or domain, but there are also APIs that affect the entire deployment system
(e.g. modifying endpoints, service management, or listing information about
hypervisors). These operations require the use of a system-scoped token, which
represents the role assignments a user has to operate on the deployment as a
whole.

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
