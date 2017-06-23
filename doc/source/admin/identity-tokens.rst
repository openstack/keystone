===============
Keystone tokens
===============

Tokens are used to authenticate and authorize your interactions with the
various OpenStack APIs. Tokens come in many flavors, representing various
authorization scopes and sources of identity. There are also several different
"token providers", each with their own user experience, performance, and
deployment characteristics.

Authorization scopes
--------------------

Tokens can express your authorization in different scopes. You likely have
different sets of roles, in different projects, and in different domains.
While tokens always express your identity, they may only ever express one set
of roles in one authorization scope at a time.

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

Project-scoped tokens are the bread and butter of OpenStack. They express your
authorization to operate in a specific tenancy of the cloud and are useful to
authenticate yourself when working with most other services.

They contain a service catalog, a set of roles, and details of the project upon
which you have authorization.

Domain-scoped tokens
~~~~~~~~~~~~~~~~~~~~

Domain-scoped tokens also have limited use cases in OpenStack. They express
your authorization to operate a domain-level, above that of the user and
projects contained therein (typically as a domain-level administrator).
Depending on Keystone's configuration, they are useful for working with a
single domain in Keystone.

They contain a limited service catalog (only those services which do not
explicitly require per-project endpoints), a set of roles, and details of the
project upon which you have authorization.

They can also be used to work with domain-level concerns in other services,
such as to configure domain-wide quotas that apply to all users or projects in
a specific domain.

Token providers
---------------

The token type issued by keystone is configurable through the
``/etc/keystone/keystone.conf`` file. Currently, there are four supported
token types and they include ``UUID``, ``fernet``, ``PKI``, and ``PKIZ``.

UUID tokens
~~~~~~~~~~~

UUID was the first token type supported and is currently the default token
provider. UUID tokens are 32 bytes in length and must be persisted in a back
end. Clients must pass their UUID token to the Identity service in order to
validate it.

Fernet tokens
~~~~~~~~~~~~~

The fernet token format was introduced in the OpenStack Kilo release. Unlike
the other token types mentioned in this document, fernet tokens do not need to
be persisted in a back end. ``AES256`` encryption is used to protect the
information stored in the token and integrity is verified with a ``SHA256
HMAC`` signature. Only the Identity service should have access to the keys used
to encrypt and decrypt fernet tokens. Like UUID tokens, fernet tokens must be
passed back to the Identity service in order to validate them. For more
information on the fernet token type, see the :doc:`identity-fernet-token-faq`.

PKI and PKIZ tokens
~~~~~~~~~~~~~~~~~~~

PKI tokens are signed documents that contain the authentication context, as
well as the service catalog. Depending on the size of the OpenStack deployment,
these tokens can be very long. The Identity service uses public/private key
pairs and certificates in order to create and validate PKI tokens.

The same concepts from PKI tokens apply to PKIZ tokens. The only difference
between the two is PKIZ tokens are compressed to help mitigate the size issues
of PKI. For more information on the certificate setup for PKI and PKIZ tokens,
see the :doc:`identity-certificates-for-pki`.

.. note::

   PKI and PKIZ tokens are deprecated and not supported in Ocata.
