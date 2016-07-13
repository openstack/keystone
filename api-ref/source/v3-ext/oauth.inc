.. -*- rst -*-

===============
 OS-OAUTH1 API
===============

Enables users to delegate roles to third-party consumers through
`The OAuth 1.0 Protocol <http://tools.ietf.org/html/rfc5849>`_.

A user is an Identity API user who delegates its roles and who
authorizes request tokens.

A consumer is a third-party application that uses OAuth to access a
protected resource.

Administrative users use an OAuth-derived token to act on behalf of
the authorizing user.

The consumer uses a request token to get authorization from the
user. The consumer provides an OAuth verifier string with the
request token in exchange for an access token.

The consumer uses an access token to request Identity API tokens on
behalf of the authorizing user instead of using the credentials for
the user.

Request and access tokens use token keys to identify themselves.
For OpenStack purposes, the token key is the token ID. The consumer
uses a token secret to establish ownership of a token. Both request
and access tokens have token secrets.

Delegated authentication through OAuth occurs as follows:

- A user creates a consumer.

- The consumer gets an unauthorized request token. Then, the
  consumer uses the request token to initiate user authorization.

- The user authorizes the request token.

- The consumer exchanges the authorized request token and the OAuth
  verifier for an access token.

 The authorizing user receives the request token key from the
  consumer out-of-band.

- The consumer uses the access token to request an Identity API
  token.


Create consumer
===============

.. rest_method::  POST /v3/OS-OAUTH1/consumers

Enables a user to create a consumer.

Normal response codes: 201
Error response codes: 413, 415, 405, 404, 403, 401, 400, 503, 409

Request
-------

.. rest_parameters:: parameters.yaml

    - description: description

Request Example
---------------

.. literalinclude:: ./samples/OS-OAUTH1/consumers-create-request.json
   :language: javascript


List consumers
==============

.. rest_method::  GET /v3/OS-OAUTH1/consumers

Lists consumers.

Normal response codes: 200
Error response codes: 413, 405, 404, 403, 401, 400, 503

Response Example
----------------

.. literalinclude:: ./samples/OS-OAUTH1/consumers-list-response.json
   :language: javascript


Get authorized access token
===========================

.. rest_method::  GET /v3/OS-OAUTH1/users/{user_id}/access_tokens/{access_token_id}

Gets an authorized access token.

Normal response codes: 200
Error response codes: 413, 405, 404, 403, 401, 400, 503

Request
-------

.. rest_parameters:: parameters.yaml

   - user_id: user_id
   - access_token_id: access_token_id

Response Example
----------------

.. literalinclude:: ./samples/OS-OAUTH1/access-token-show-response.json
   :language: javascript


Revoke access token
===================

.. rest_method::  DELETE /v3/OS-OAUTH1/users/{user_id}/access_tokens/{access_token_id}

Enables a user to revoke an access token, which prevents the consumer from requesting new Identity Service API tokens. Also, revokes any Identity Service API tokens that were issued to the consumer through that access token.

Normal response codes: 204
Error response codes: 413, 415, 405, 404, 403, 401, 400, 503, 409

Request
-------

.. rest_parameters:: parameters.yaml

   - user_id: user_id
   - access_token_id: access_token_id


Create access token
===================

.. rest_method::  POST /v3/OS-OAUTH1/access_token

Enables a consumer to create an access token by exchanging a request token for an access token.

After the user authorizes the request token, the consumer exchanges
the authorized request token and OAuth verifier for an access
token.

Supported signature methods: HMAC-SHA1.

The consumer must provide all required OAuth parameters in the
request. See `Consumer Obtains a Request Token
<http://oauth.net/core/1.0a/#auth_step1>`_.

Supported signature methods: HMAC-SHA1.

You must provide all required OAuth parameters in the request. See
`Consumer Obtains a Request Token
<http://oauth.net/core/1.0a/#auth_step1>`_.

Normal response codes: 200
Error response codes: 413, 415, 405, 404, 403, 401, 400, 503, 409

Response Example
----------------

.. literalinclude:: ./samples/OS-OAUTH1/access-token-create-response.txt
   :language: javascript


Get an Identity Service token
=============================

.. rest_method::  POST /v3/auth/tokens

Enables a consumer to get an Identity Service authentication token.

The token represents the delegated authorization and identity
(impersonation) of the authorizing user. The roles and scope of the
generated token match those that the consumer initially requested.

Supported signature methods: HMAC-SHA1.

The consumer must provide required OAuth parameters in the request.
See `Consumer Obtains a Request Token
<http://oauth.net/core/1.0a/#auth_step1>`_.

The returned token is scoped to the requested project and with the
requested roles. In addition to the standard token response, the
token has an OAuth-specific object.

Example OAuth-specific object in a token:

.. code-block:: json

   "OS-OAUTH1": {
       "access_token_id": "cce0b8be7"
   }

Normal response codes: 200
Error response codes: 413, 405, 404, 403, 401, 400, 503


List authorized access tokens
=============================

.. rest_method::  GET /v3/OS-OAUTH1/users/{user_id}/access_tokens

Lists authorized access tokens.

Normal response codes: 200
Error response codes: 413, 405, 404, 403, 401, 400, 503

Request
-------

.. rest_parameters:: parameters.yaml

   - user_id: user_id

Response Example
----------------

.. literalinclude:: ./samples/OS-OAUTH1/access-tokens-list-response.json
   :language: javascript


Show consumer details
=====================

.. rest_method::  GET /v3/OS-OAUTH1/consumers/{consumer_id}

Shows details for a consumer.

Normal response codes: 200
Error response codes: 413, 405, 404, 403, 401, 400, 503

Request
-------

.. rest_parameters:: parameters.yaml

   - consumer_id: consumer_id

Response Example
----------------

.. literalinclude:: ./samples/OS-OAUTH1/consumer-show-response.json
   :language: javascript


Delete consumer
===============

.. rest_method::  DELETE /v3/OS-OAUTH1/consumers/{consumer_id}

Deletes a consumer.

When you delete a consumer, any associated request tokens, access
tokens, and Identity API tokens are also deleted.

Normal response codes: 204
Error response codes: 413, 415, 405, 404, 403, 401, 400, 503, 409

Request
-------

.. rest_parameters:: parameters.yaml

   - consumer_id: consumer_id


Update consumer
===============

.. rest_method::  PATCH /v3/OS-OAUTH1/consumers/{consumer_id}

Updates the description for a consumer.

If you try to update any attribute other than description, the HTTP
400 Bad Request error is returned.

Normal response codes: 200
Error response codes: 413, 415, 405, 404, 403, 401, 400, 503, 409

Request
-------

.. rest_parameters:: parameters.yaml

   - consumer_id: consumer_id

Request Example
---------------

.. literalinclude:: ./samples/OS-OAUTH1/consumer-update-request.json
   :language: javascript

Response Example
----------------

.. literalinclude:: ./samples/OS-OAUTH1/consumer-update-response.json
   :language: javascript


Show unauthorized request token
===============================

.. rest_method::  POST /v3/OS-OAUTH1/request_token

Enables a consumer to get an unauthorized request token.

Supported signature methods: HMAC-SHA1.

The consumer must provide all required OAuth parameters in the
request. See `Consumer Obtains a Request Token
<http://oauth.net/core/1.0a/#auth_step1>`_.

Normal response codes: 200
Error response codes: 413, 415, 405, 404, 403, 401, 400, 503, 409

Request
-------

.. rest_parameters:: parameters.yaml

    - requested_project_id: requested_project_id

Response Example
----------------

.. literalinclude:: ./samples/OS-OAUTH1/request-token-create-response.txt
   :language: javascript


List roles for an access token
==============================

.. rest_method::  GET /v3/OS-OAUTH1/users/{user_id}/access_tokens/{access_token_id}/roles

Lists associated roles for an access token.

Normal response codes: 200
Error response codes: 413, 415, 405, 404, 403, 401, 400, 503

Request
-------

.. rest_parameters:: parameters.yaml

   - user_id: user_id
   - access_token_id: access_token_id


Show role details for an access token
=====================================

.. rest_method::  GET /v3/OS-OAUTH1/users/{user_id}/access_tokens/{access_token_id}/roles/{role_id}

Shows details for a role for an access token.

Normal response codes: 200
Error response codes: 413, 415, 405, 404, 403, 401, 400, 503

Request
-------

.. rest_parameters:: parameters.yaml

   - user_id: user_id
   - role_id: role_id
   - access_token_id: access_token_id
