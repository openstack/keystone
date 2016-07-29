.. -*- rst -*-

===================
 OS-FEDERATION API
===================

Provide the ability for users to manage Identity Providers (IdPs) and establish
a set of rules to map federation protocol attributes to Identity API
attributes. Requires v3.0+ of the Identity API.

What's New in Version 1.3
=========================

Corresponding to Identity API v3.5 release.

- Added Identity Provider specific websso routes.


What's New in Version 1.2
=========================

Corresponding to Identity API v3.4 release.

- Add websso routes.


What's New in Version 1.1
=========================

Corresponding to Identity API v3.3 release. These features are considered
stable as of September 4th, 2014.

- Deprecate list projects and domains in favour of core functionality available
  in Identity API v3.3.

- Introduced a mechanism to exchange an Identity Token for a SAML assertion.

- Introduced a mechanism to retrieve Identity Provider Metadata.

Definitions
===========

- *Trusted Identity Provider*: An identity provider set up within the Identity
  API that is trusted to provide authenticated user information.

- *Service Provider*: A system entity that provides services to principals or
  other system entities, in this case, the OpenStack Identity API is the
  Service Provider.

- *Attribute Mapping*: The user information passed by a federation protocol for
  an already authenticated identity are called ``attributes``. Those
  ``attributes`` may not align directly with the Identity API concepts. To help
  overcome such mismatches, a mapping can be done either on the sending side
  (third party identity provider), on the consuming side (Identity API
  service), or both.

- *Protocol*: A protocol capable of performing federated identity authentication.
  For example, the OpenID Connect or SAML 2.0 protocols.

API Resources
=============

Identity Providers
------------------

::

    /v3/OS-FEDERATION/identity_providers

An Identity Provider (IdP) is a third party service that is trusted by the
Identity API to authenticate identities.

Optional attributes:

- ``description`` (string)

  Describes the identity provider.

  If a value is not specified by the client, the service will default this
  value to ``null``.

- ``enabled`` (boolean)

  Indicates whether this identity provider should accept federated
  authentication requests.

  If a value is not specified by the client, the service will default this to
  ``false``.

- ``remote_ids`` (list)

  Valid remote IdP entity values from Identity Providers. If a value is not
  specified by the client, the list will be empty.

Protocols
---------

::

    /v3/OS-FEDERATION/identity_providers/{idp_id}/protocols

A protocol entry contains information that dictates which mapping rules to use
for a given incoming request. An IdP may have multiple supported protocols.

Required attributes:

- ``mapping_id`` (string)

  Indicates which mapping should be used to process federated authentication
  requests.

Mappings
--------

::

    /v3/OS-FEDERATION/mappings

A ``mapping`` is a set of rules to map federation protocol attributes to
Identity API objects. An Identity Provider can have a single ``mapping``
specified per protocol. A mapping is simply a list of ``rules``.

Required attributes:

- ``rules`` (list of objects)

  Each object contains a rule for mapping attributes to Identity API concepts.
  A rule contains a ``remote`` attribute description and the destination
  ``local`` attribute.

- ``local`` (list of objects)

   References a local Identity API resource, such as a ``group`` or ``user`` to
   which the remote attributes will be mapped.

   Each object has one of two structures, as follows.

   To map a remote attribute value directly to a local attribute, identify the
   local resource type and attribute:

   ::

       {
           "user": {
               "name": "{0}"
           }
       }

   If the ``user`` attribute is missing when processing an assertion, server
   tries to directly map ``REMOTE_USER`` environment variable. If this variable
   is also unavailable the server returns an HTTP ``401 Unauthorized`` error.

   If the ``user`` has domain specified, the user is treated as existing in the
   backend, hence the server will fetch user details (id, name, roles, groups).

   If, however, the user does not exist in the backend, the server will
   respond with an appropriate HTTP error code.

   If no domain is specified in the local rule, user is deemed ephemeral
   and becomes a member of service domain named ``Federated``.

   An example of user object mapping to an existing user:

   ::

       {
            "user": {
                "name": "username"
                "domain": {
                    "name": "domain_name"
                }
            }
       }


   For attribute type and value mapping, identify the local resource type,
   attribute, and value:

   ::

       {
           "group": {
               "id": "89678b"
           }
       }

   This assigns authorization attributes, by way of role assignments on the
   specified group, to ephemeral users.

   ::

       {
           "group_ids": "{0}"
       }

   It is also possible to map multiple groups by providing a list of group ids.
   Those group ids can also be white/blacklisted.

- ``remote`` (list of objects)

  At least one object must be included.

  If more than one object is included, the local attribute is applied only if
  all remote attributes match.

  The value identified by ``type`` is always passed through unless a constraint
  is specified using either ``any_one_of`` or ``not_one_of``.

  - ``type`` (string)

    This represents an assertion type keyword.

  - ``any_one_of`` (list of strings)

    This is mutually exclusive with ``not_any_of``.

    The rule is matched only if any of the specified strings appear in the
    remote attribute ``type``.

  - ``not_any_of`` (list of strings)

    This is mutually exclusive with ``any_one_of``.

    The rule is not matched if any of the specified strings appear in the
    remote attribute ``type``.

  - ``regex`` (boolean)

    If ``true``, then each string will be evaluated as a `regular expression
    <http://docs.python.org/2/library/re.html>`__ search against the remote
    attribute ``type``.

  The ``blacklist`` and ``whitelist`` rules are always used in conjunction with
  ``type``.

  - ``blacklist`` (list of strings)

    This is mutually exclusive with ``whitelist``.

    The rule works as a filter, removing any specified strings that are
    listed there from the remote attribute ``type``.

  - ``whitelist`` (list of strings)

    This is mutually exclusive with ``blacklist``.

    The rule works as a filter, allowing only the specified strings in
    the remote attribute ``type`` to be passed ahead.

Service Providers
-----------------

::

    /v3/OS-FEDERATION/service_providers

A service provider is a third party service that is trusted by the Identity
Service.

Required attributes:

- ``auth_url`` (string)

Specifies the protected URL where tokens can be retrieved once the user is
authenticated.

- ``sp_url`` (string)

Specifies the URL at the remote peer where assertion should be sent.

Optional attributes:

- ``description`` (string)

Describes the service provider

If a value is not specified by the client, the service may default this value
to ``null``.

- ``enabled`` (boolean)

Indicates whether bursting into this service provider is enabled by cloud
administrators. If set to ``false`` the SP will not appear in the catalog and
requests to generate an assertion will result in a 403 error.
If a value is not specified by the client, the service will default this to
``false``.

- ``relay_state_prefix`` (string)

Indicates the relay state prefix, used in the ECP wrapped SAML messages, by the
Service Provider.

If a value is not specified by the client, the service will default this value
to ``ss:mem:``.


.. TODO(samueldmq): This is the Mapping API, move it to its own file.

Create a mapping
================

.. rest_method::  PUT /v3/OS-FEDERATION/mappings/{mapping_id}

Normal response codes: 201

Request Example
---------------

.. literalinclude:: ./samples/OS-FEDERATION/mapping-create-request.json
   :language: javascript

Response Example
----------------

.. literalinclude:: ./samples/OS-FEDERATION/mapping-create-response.json
   :language: javascript


Get a mapping
=============

.. rest_method::  GET /v3/OS-FEDERATION/mappings/{mapping_id}

Normal response codes: 200

Response Example
----------------

.. literalinclude:: ./samples/OS-FEDERATION/mapping-get-response.json
   :language: javascript


Update a mapping
================

.. rest_method::  PATCH /v3/OS-FEDERATION/mappings/{mapping_id}

Normal response codes: 200

Request Example
---------------

.. literalinclude:: ./samples/OS-FEDERATION/mapping-update-request.json
   :language: javascript

Response Example
----------------

.. literalinclude:: ./samples/OS-FEDERATION/mapping-update-response.json
   :language: javascript


List all mappings
=================

.. rest_method::  GET /v3/OS-FEDERATION/mappings

Normal response codes: 200

Response Example
----------------

.. literalinclude:: ./samples/OS-FEDERATION/mapping-list-response.json
   :language: javascript


Delete a mapping
================

.. rest_method::  DELETE /v3/OS-FEDERATION/mappings/{mapping_id}

Normal response codes: 204


.. TODO(samueldmq): This is the Service Provider API, move it to its own file.

Register a Service Provider
===========================

.. rest_method::  PUT /v3/OS-FEDERATION/service_providers/{sp_id}

Normal response codes: 201
Error response codes: 400 Bad Request when registering a service provider with
invalid URLs for either `auth_url` or `sp_url`.

Request Example
---------------

.. literalinclude:: ./samples/OS-FEDERATION/sp-register-request.json
   :language: javascript

Response Example
----------------

.. literalinclude:: ./samples/OS-FEDERATION/sp-register-response.json
   :language: javascript


Listing Service Providers
=========================

.. rest_method::  GET /v3/OS-FEDERATION/service_providers

Normal response codes: 200

Response Example
----------------

.. literalinclude:: ./samples/OS-FEDERATION/sp-list-response.json
   :language: javascript


Get Service Provider
====================

.. rest_method::  GET /v3/OS-FEDERATION/service_providers/{sp_id}

Normal response codes: 200

Response Example
----------------

.. literalinclude:: ./samples/OS-FEDERATION/sp-get-response.json
   :language: javascript


Delete Service Provider
=======================

.. rest_method::  DELETE /v3/OS-FEDERATION/service_providers/{sp_id}

Normal response codes: 204


Update Service Provider
=======================

.. rest_method::  PATCH /v3/OS-FEDERATION/service_providers/{sp_id}

Normal response codes: 200
Error response codes: 400 Bad Request when updating a service provider with
invalid URLs for either `auth_url` or `sp_url`.

Request Example
---------------

.. literalinclude:: ./samples/OS-FEDERATION/sp-update-request.json
   :language: javascript

Response Example
----------------

.. literalinclude:: ./samples/OS-FEDERATION/sp-update-response.json
   :language: javascript


.. TODO(samueldmq): This is the Listing Projects and Domains API, move it to its
   own file.
.. **Deprecated in v1.1**. This section is deprecated as the functionality is
   available in the core Identity API.

List projects a federated user can access
=========================================

.. rest_method::  GET /v3/OS-FEDERATION/projects

Normal response codes: 200

**Deprecated in v1.1**. Use core ``GET /auth/projects``. This call has the same
response format.

Returns a collection of projects to which the federated user has authorization
to access. To access this resource, an unscoped token is used, the user can
then select a project and request a scoped token. Note that only enabled
projects will be returned.

Response Example
----------------

.. literalinclude:: ./samples/OS-FEDERATION/project-list-response.json
   :language: javascript


List domains a federated user can access
========================================

.. rest_method::  GET /v3/OS-FEDERATION/domains

Normal response codes: 200

**Deprecated in v1.1**. Use core ``GET /auth/domains``. This call has the same
response format.

Returns a collection of domains to which the federated user has authorization
to access. To access this resource, an unscoped token is used, the user can
then select a domain and request a scoped token. Note that only enabled domains
will be returned.

Response Example
----------------

.. literalinclude:: ./samples/OS-FEDERATION/domain-list-response.json
   :language: javascript

.. TODO(samueldmq): This is the Federation Authentication API, move it to its
   own file.

Request an unscoped OS-FEDERATION token
=======================================

.. rest_method::  GET /v3/OS-FEDERATION/identity_providers/{identity_provider}/protocols/{protocol}/auth

A federated ephemeral user may request an unscoped token, which can be used to
get a scoped token.

If the user is mapped directly (mapped to an existing user), a standard,
unscoped token will be issued.

Due to the fact that this part of authentication is strictly connected with the
SAML2 authentication workflow, a client should not send any data, as the
content may be lost when a client is being redirected between Service Provider
and Identity Provider. Both HTTP methods - GET and POST should be allowed as
Web Single Sign-On (WebSSO) and Enhanced Client Proxy (ECP) mechanisms have
different authentication workflows and use different HTTP methods while
accessing protected endpoints.

The returned token will contain information about the groups to which the
federated user belongs.

Example Identity API token response: `Various OpenStack token responses
<identity-api-v3.md#authentication-responses>`__

Response Example
----------------

.. literalinclude:: ./samples/OS-FEDERATION/unscoped-token-response.json
   :language: javascript


Request a scoped OS-FEDERATION token
====================================

.. rest_method::  POST /v3/auth/tokens

A federated user may request a scoped token, by using the unscoped token. A
project or domain may be specified by either id or name. An id is sufficient to
uniquely identify a project or domain.

Request Example
---------------

.. literalinclude:: ./samples/OS-FEDERATION/scoped-token-request.json
   :language: javascript

Similarly to the returned unscoped token, the returned scoped token will have
an ``OS-FEDERATION`` section added to the ``user`` portion of the token.

Response Example
----------------

.. literalinclude:: ./samples/OS-FEDERATION/scoped-token-response.json
   :language: javascript


Web Single Sign On authentication (New in version 1.2)
======================================================

.. rest_method::  GET /v3/auth/OS-FEDERATION/websso/{protocol}?origin=https%3A//horizon.example.com

For Web Single Sign On (WebSSO) authentication, users are expected to enter
another URL endpoint. Upon successful authentication, instead of issuing a
standard unscoped token, keystone will issue JavaScript code that redirects
the web browser to the originating Horizon. An unscoped federated token will
be included in the form being sent.


Web Single Sign On authentication (New in version 1.3)
======================================================

.. rest_method::  GET /v3/auth/OS-FEDERATION/identity_providers/{idp_id}/protocol/{protocol_id}/websso?origin=https%3A//horizon.example.com

In contrast to the above route, this route begins a Web Single Sign On request
that is specific to the supplied Identity Provider and Protocol. Keystone will
issue JavaScript that handles redirections in the same way as the other route.
An unscoped federated token will be included in the form being sent.


.. TODO(samueldmq): This is the Generating Assertions API, move it to its own
   file.
.. *New in version 1.1*

Generate a SAML assertion
=========================

.. rest_method::  POST /v3/auth/OS-FEDERATION/saml2

A user may generate a SAML assertion document based on the scoped token that is
used in the request.

Request Parameters:

To generate a SAML assertion, a user must provides a scoped token ID and
Service Provider ID in the request body.

Request Example
---------------

.. literalinclude:: ./samples/OS-FEDERATION/saml-assertion-request.json
   :language: javascript

The response will be a full SAML assertion. Note that for readability the
certificate has been truncated. Server will also set two HTTP headers:
``X-sp-url`` and ``X-auth-url``. The former is the URL where assertion should
be sent, whereas the latter remote URL where token will be issued once the
client is finally authenticated.

Response Example
----------------

.. literalinclude:: ./samples/OS-FEDERATION/saml-assertion-response.xml
   :language: xml

For more information about how a SAML assertion is structured, refer to the
`specification <http://saml.xml.org/saml-specifications>`__.

Generate an ECP wrapped SAML assertion
======================================

.. rest_method::  POST /v3/auth/OS-FEDERATION/saml2/ecp

A user may generate a SAML assertion document to work with the
*Enhanced Client or Proxy* (ECP) profile based on the scoped token that is
used in the request.

Request Parameters:

To generate an ECP wrapped SAML assertion, a user must provides a scoped token
ID and Service Provider ID in the request body.

Request Example
---------------

.. literalinclude:: ./samples/OS-FEDERATION/ecp-saml-assertion-request.json
   :language: javascript

The response will be an ECP wrapped SAML assertion. Note that for readability
the certificate has been truncated. Server will also set two HTTP headers:
``X-sp-url`` and ``X-auth-url``. The former is the URL where assertion should
be sent, whereas the latter remote URL where token will be issued once the
client is finally authenticated.

Response Example
----------------

.. literalinclude:: ./samples/OS-FEDERATION/ecp-saml-assertion-response.xml
   :language: xml


Retrieve Metadata properties
============================

.. rest_method::  GET /v3/OS-FEDERATION/saml2/metadata

A user may retrieve Metadata about an Identity Service acting as an Identity
Provider.

The response will be a full document with Metadata properties. Note that for
readability, this example certificate has been truncated.

Response Example
----------------

.. literalinclude:: ./samples/OS-FEDERATION/metadata-response.xml
   :language: xml

For more information about how a SAML assertion is structured, refer to the
`specification <http://saml.xml.org/saml-specifications>`__.
