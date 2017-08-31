.. -*- rst -*-

======
Tokens
======


Authenticate for admin API
==========================

.. rest_method::  POST /v2.0/tokens

Authenticates and generates a token.

A REST interface provides client authentication by using the POST
method with ``v2.0/tokens`` as the path. Include a payload of
credentials in the body.

The Identity API is a RESTful web service. It is the entry point to
all service APIs. To access the Identity API, you must know its
URL.

Each REST request against the Identity Service requires the ``X
-Auth-Token`` header. Clients obtain this token and the URL
endpoints for other service APIs by supplying their valid
credentials to the authentication service.

If the authentication token has expired, this call returns the HTTP
``unauthorized (401)`` response code.

If the token has expired, this call returns the ``itemNotFound
(404)`` response code.

The Identity API treats expired tokens as no longer valid tokens.

The deployment determines how long expired tokens are stored.

To view the ``trust`` object, you need to set ``trust`` enable on
the keystone configuration.

Normal response codes: 200,203
Error response codes: 413,405,404,403,401,400,503

Request Example
---------------

.. literalinclude:: ../v2/samples/admin/authenticate-token-request.json
   :language: javascript

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - token: token
   - access: access
   - issued_at: token_issued_at
   - expires: token_expires
   - id: token_id
   - tenant: tenant
   - description: tenant_description
   - serviceCatalog: serviceCatalog
   - type: serviceCatalog_type
   - endpoints_links: serviceCatalog_endpoints_links
   - impersonation: impersonation
   - endpoints: endpoints
   - user: user
   - roles: roles
   - metadata: metadata
   - trust: trust

Response Example
----------------

.. literalinclude:: ../v2/samples/admin/authenticate-response.json
   :language: javascript
