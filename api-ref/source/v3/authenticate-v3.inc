.. -*- rst -*-

==================================================
Authentication and token management (auth, tokens)
==================================================

In exchange for a set of authentication credentials, the Identity
service generates tokens. A token represents the authenticated
identity of a user and, optionally, grants authorization on a
specific project or domain.

The body of an authentication request must include a payload that
specifies the authentication method, which is ``password`` or
``token``, the credentials, and, optionally, the authorization
scope. You can scope a token to a project or domain, or the token
can be unscoped. You cannot scope a token to both a project and
domain.

Tokens have IDs, which the Identity API returns in the ``X-Subject-
Token`` response header.

Also, validates an authentication token and lists the domains,
projects, roles, and endpoints to which the token gives access.
Forces the immediate revocation of a token.

After you obtain an authentication token, you can:

- Make REST API requests to other OpenStack services. You supply the
  ID of your authentication token in the ``X-Auth-Token`` request
  header.

- Validate your authentication token and list the domains, projects,
  roles, and endpoints that your token gives you access to.

- Use your token to request another token scoped for a different
  domain and project.

- Force the immediate revocation of a token.

- List revoked public key infrastructure (PKI) tokens.

The Identity API treats expired tokens as no longer valid tokens.
The deployment determines how long expired tokens are stored.

These authentication errors can occur:

**Authentication errors**

+------------------------+----------------------------------------------------------------------+
| Response code          | Description                                                          |
+------------------------+----------------------------------------------------------------------+
| ``Bad Request (400)``  | The Identity service failed to parse the request as expected. One    |
|                        | of the following errors occurred:                                    |
|                        |                                                                      |
|                        | - A required attribute was missing.                                  |
|                        |                                                                      |
|                        | - An attribute that is not allowed was specified, such as an ID on a |
|                        |   POST request in a basic CRUD operation.                            |
|                        |                                                                      |
|                        | - An attribute of an unexpected data type was specified.             |
+------------------------+----------------------------------------------------------------------+
| ``Unauthorized (401)`` | One of the following errors occurred:                                |
|                        |                                                                      |
|                        | - Authentication was not performed.                                  |
|                        |                                                                      |
|                        | - The specified ``X-Auth-Token`` header is not valid.                |
|                        |                                                                      |
|                        | - The authentication credentials are not valid.                      |
+------------------------+----------------------------------------------------------------------+
| ``Forbidden (403)``    | The identity was successfully authenticated but it is not            |
|                        | authorized to perform the requested action.                          |
+------------------------+----------------------------------------------------------------------+
| ``Not Found (404)``    | An operation failed because a referenced entity cannot be found by   |
|                        | ID. For a POST request, the referenced entity might be specified in  |
|                        | the request body rather than in the resource path.                   |
+------------------------+----------------------------------------------------------------------+
| ``Conflict (409)``     | A POST or PATCH operation failed. For example, a client tried to     |
|                        | update a unique attribute for an entity, which conflicts with that   |
|                        | of another entity in the same collection.                            |
|                        |                                                                      |
|                        | Or, a client issued a create operation twice on a collection with a  |
|                        | user-defined, unique attribute. For example, a client made a POST    |
|                        | ``/users`` request two times for the unique, user-defined name       |
|                        | attribute for a user entity.                                         |
+------------------------+----------------------------------------------------------------------+


Password authentication with unscoped authorization
===================================================

.. rest_method::  POST /v3/auth/tokens

Authenticates an identity and generates a token. Uses the password authentication method. Authorization is unscoped.

The request body must include a payload that specifies the
authentication method, which is ``password``, and the user, by ID
or name, and password credentials.

Error response codes:201,413,415,405,404,403,401,400,503,409,

Request
-------

.. rest_parameters:: parameters.yaml

   - domain: domain
   - name: name
   - auth: auth
   - user: user
   - password: password
   - id: id
   - identity: identity
   - methods: methods
   - nocatalog: nocatalog

Request Example
---------------

.. literalinclude:: ./samples/admin/auth-password-unscoped-request-with-domain.json
   :language: javascript

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - X-Subject-Token: X-Subject-Token
   - domain: domain
   - methods: methods
   - expires_at: expires_at
   - token: token
   - extras: extras
   - user: user
   - audit_ids: audit_ids
   - issued_at: issued_at
   - id: id
   - name: name


Password authentication with scoped authorization
=================================================

.. rest_method::  POST /v3/auth/tokens

Authenticates an identity and generates a token. Uses the password authentication method and scopes authorization to a project or domain.

The request body must include a payload that specifies the
``password`` authentication method, the credentials, and the
``project`` or ``domain`` authorization scope.

Error response codes:201,413,415,405,404,403,401,400,503,409,

Request
-------

.. rest_parameters:: parameters.yaml

   - name: name
   - auth: auth
   - user: user
   - scope: scope
   - password: password
   - id: id
   - identity: identity
   - methods: methods
   - nocatalog: nocatalog

Request Example
---------------

.. literalinclude:: ./samples/admin/auth-password-project-scoped-request.json
   :language: javascript

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - X-Subject-Token: X-Subject-Token
   - domain: domain
   - region_id: region_id
   - methods: methods
   - roles: roles
   - url: url
   - region: region
   - token: token
   - expires_at: expires_at
   - project: project
   - issued_at: issued_at
   - catalog: catalog
   - extras: extras
   - user: user
   - audit_ids: audit_ids
   - interface: interface
   - endpoints: endpoints
   - type: type
   - id: id
   - name: name


Password authentication with explicit unscoped authorization
============================================================

.. rest_method::  POST /v3/auth/tokens

Authenticates an identity and generates a token. Uses the password authentication method with explicit unscoped authorization.

The request body must include a payload that specifies the
``password`` authentication method, the credentials, and the
``unscoped`` authorization scope.

Error response codes:201,413,415,405,404,403,401,400,503,409,

Request
-------

.. rest_parameters:: parameters.yaml

   - name: name
   - auth: auth
   - user: user
   - scope: scope
   - password: password
   - id: id
   - identity: identity
   - methods: methods
   - nocatalog: nocatalog

Request Example
---------------

.. literalinclude:: ./samples/admin/auth-password-explicit-unscoped-request.json
   :language: javascript

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - X-Subject-Token: X-Subject-Token
   - domain: domain
   - methods: methods
   - roles: roles
   - expires_at: expires_at
   - token: token
   - extras: extras
   - user: user
   - audit_ids: audit_ids
   - issued_at: issued_at
   - id: id
   - name: name


Token authentication with unscoped authorization
================================================

.. rest_method::  POST /v3/auth/tokens

Authenticates an identity and generates a token. Uses the token authentication method. Authorization is unscoped.

In the request body, provide the token ID.

Error response codes:201,413,415,405,404,403,401,400,503,409,

Request
-------

.. rest_parameters:: parameters.yaml

   - identity: identity
   - token: token
   - id: id
   - auth: auth
   - methods: methods
   - nocatalog: nocatalog

Request Example
---------------

.. literalinclude:: ./samples/admin/auth-token-unscoped-request.json
   :language: javascript

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - X-Subject-Token: X-Subject-Token
   - X-Auth-Token: X-Auth-Token


Token authentication with scoped authorization
==============================================

.. rest_method::  POST /v3/auth/tokens

Authenticates an identity and generates a token. Uses the token authentication method and scopes authorization to a project or domain.

In the request body, provide the token ID and the ``project`` or
``domain`` authorization scope.

Error response codes:201,413,415,405,404,403,401,400,503,409,

Request
-------

.. rest_parameters:: parameters.yaml

   - methods: methods
   - auth: auth
   - token: token
   - audit_ids: audit_ids
   - scope: scope
   - id: id
   - identity: identity
   - nocatalog: nocatalog

Request Example
---------------

.. literalinclude:: ./samples/admin/auth-token-scoped-request.json
   :language: javascript

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - X-Subject-Token: X-Subject-Token
   - X-Auth-Token: X-Auth-Token


Validate and show information for token
=======================================

.. rest_method::  GET /v3/auth/tokens

Validates and shows information for a token, including its expiration date and authorization scope.

Pass your own token in the ``X-Auth-Token`` request header.

Pass the token that you want to validate in the ``X-Subject-Token``
request header.

Normal response codes: 200
Error response codes:413,405,404,403,401,400,503,

Request
-------

.. rest_parameters:: parameters.yaml

   - X-Auth-Token: X-Auth-Token
   - X-Subject-Token: X-Subject-Token

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - X-Subject-Token: X-Subject-Token
   - X-Auth-Token: X-Auth-Token
   - domain: domain
   - methods: methods
   - links: links
   - user: user
   - token: token
   - expires_at: expires_at
   - project: project
   - catalog: catalog
   - extras: extras
   - roles: roles
   - audit_ids: audit_ids
   - issued_at: issued_at
   - id: id
   - name: name

Response Example
----------------

.. literalinclude:: ./samples/admin/auth-token-unscoped-response.json
   :language: javascript


Check token
===========

.. rest_method::  HEAD /v3/auth/tokens

Validates a token.

This call is similar to ``GET /auth/tokens`` but no response body
is provided even in the ``X-Subject-Token`` header.

The Identity API returns the same response as when the subject
token was issued by ``POST /auth/tokens`` even if an error occurs
because the token is not valid. An HTTP ``204`` response code
indicates that the ``X-Subject-Token`` is valid.


Normal response codes: 200
Error response codes:413,405,404,403,401,400,503,

Request
-------

.. rest_parameters:: parameters.yaml

   - X-Auth-Token: X-Auth-Token
   - X-Subject-Token: X-Subject-Token


Revoke token
============

.. rest_method::  DELETE /v3/auth/tokens

Revokes a token.

This call is similar to the HEAD ``/auth/tokens`` call except that
the ``X-Subject-Token`` token is immediately not valid, regardless
of the ``expires_at`` attribute value. An additional ``X-Auth-
Token`` is not required.

Error response codes:413,415,405,404,403,401,400,503,409,

Request
-------

.. rest_parameters:: parameters.yaml

   - X-Auth-Token: X-Auth-Token
   - X-Subject-Token: X-Subject-Token
