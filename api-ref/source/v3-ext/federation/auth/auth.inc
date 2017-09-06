.. -*- rst -*-

Request an unscoped OS-FEDERATION token
=======================================

.. rest_method::  GET /v3/OS-FEDERATION/identity_providers/{idp_id}/protocols/{protocol_id}/auth

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

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/ext/OS-FEDERATION/1.0/rel/identity_provider_protocol_auth``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: federation/auth/parameters.yaml

   - idp_id: idp_id
   - protocol_id: protocol_id

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: federation/auth/parameters.yaml

   - X-Subject-Token: X-Subject-Token
   - token: unscoped_token

Example
~~~~~~~

.. literalinclude:: federation/auth/samples/unscoped-token-response.json
   :language: javascript


Request a scoped OS-FEDERATION token
====================================

.. rest_method::  POST /v3/auth/tokens

A federated user may request a scoped token, by using the unscoped token. A
project or domain may be specified by either id or name. An id is sufficient to
uniquely identify a project or domain.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/auth_tokens``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: federation/auth/parameters.yaml

   - auth: auth

Example
~~~~~~~

.. literalinclude:: federation/auth/samples/scoped-token-request.json
   :language: javascript

Similarly to the returned unscoped token, the returned scoped token will have
an ``OS-FEDERATION`` section added to the ``user`` portion of the token.

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: federation/auth/parameters.yaml

   - X-Subject-Token: X-Subject-Token
   - token: scoped_token

Example
~~~~~~~

.. literalinclude:: federation/auth/samples/scoped-token-response.json
   :language: javascript


Web Single Sign On authentication (New in version 1.2)
======================================================

.. rest_method::  GET /v3/auth/OS-FEDERATION/websso/{protocol_id}?origin=https%3A//horizon.example.com

For Web Single Sign On (WebSSO) authentication, users are expected to enter
another URL endpoint. Upon successful authentication, instead of issuing a
standard unscoped token, keystone will issue JavaScript code that redirects
the web browser to the originating Horizon. An unscoped federated token will
be included in the form being sent.

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: federation/auth/parameters.yaml

   - protocol_id: protocol_id


Web Single Sign On authentication (New in version 1.3)
======================================================

.. rest_method::  GET /v3/auth/OS-FEDERATION/identity_providers/{idp_id}/protocol/{protocol_id}/websso?origin=https%3A//horizon.example.com

In contrast to the above route, this route begins a Web Single Sign On request
that is specific to the supplied Identity Provider and Protocol. Keystone will
issue JavaScript that handles redirections in the same way as the other route.
An unscoped federated token will be included in the form being sent.

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: federation/auth/parameters.yaml

   - idp_id: idp_id
   - protocol_id: protocol_id
