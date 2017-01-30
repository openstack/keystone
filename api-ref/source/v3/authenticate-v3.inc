.. -*- rst -*-

=====================================
 Authentication and token management
=====================================

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

Tokens have IDs, which the Identity API returns in the
``X-Subject-Token`` response header.

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

In v3.7 of the Identity API service, two new configuration options
were added: ``[resource] admin_project_name`` and
``[resource] admin_project_domain_name``. The options represent the
project that only the cloud administrator should be able to access.
When an authentication request for a token scoped to the admin project
is processed, it will have an additional field in the token
``{is_admin_project: True}``. The additional field can be used when
writing policy rules that evaluate access control to APIs.

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

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/auth_tokens``

Authenticates an identity and generates a token. Uses the password authentication method. Authorization is unscoped.

The request body must include a payload that specifies the
authentication method, which is ``password``, and the user, by ID
or name, and password credentials.

Normal response codes: 201

Error response codes: 413,415,405,404,403,401,400,503,409

Request
-------

.. rest_parameters:: parameters.yaml

   - nocatalog: nocatalog
   - domain: domain
   - name: user_name
   - auth: auth
   - user: user
   - password: password
   - id: user_id
   - identity: identity
   - methods: auth_methods_passwd

Request Example
---------------

.. literalinclude:: ./samples/admin/auth-password-unscoped-request-with-domain.json
   :language: javascript

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - X-Subject-Token: X-Subject-Token
   - domain: domain
   - methods: auth_methods_passwd
   - expires_at: expires_at
   - token: token
   - extras: extras
   - user: user
   - audit_ids: audit_ids
   - issued_at: issued_at
   - id: user_id
   - name: user_name

Response Example
----------------

.. literalinclude:: ./samples/admin/auth-password-unscoped-response.json
   :language: javascript


Password authentication with scoped authorization
=================================================

.. rest_method::  POST /v3/auth/tokens

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/auth_tokens``

Authenticates an identity and generates a token. Uses the password authentication method and scopes authorization to a project or domain.

The request body must include a payload that specifies the
``password`` authentication method, the credentials, and the
``project`` or ``domain`` authorization scope.

Normal response codes: 201

Error response codes: 413,415,405,404,403,401,400,503,409

Request
-------

.. rest_parameters:: parameters.yaml

   - nocatalog: nocatalog
   - name: user_name
   - auth: auth
   - user: user
   - scope: scope
   - password: password
   - id: user_id
   - identity: identity
   - methods: auth_methods_passwd

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
   - methods: auth_methods_passwd
   - roles: roles
   - url: endpoint_url
   - region: endpoint_region
   - token: token
   - expires_at: expires_at
   - project: project
   - issued_at: issued_at
   - catalog: catalog
   - extras: extras
   - user: user
   - audit_ids: audit_ids
   - interface: endpoint_interface
   - endpoints: endpoints
   - type: endpoint_type
   - id: user_id
   - name: user_name


Password authentication with explicit unscoped authorization
============================================================

.. rest_method::  POST /v3/auth/tokens

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/auth_tokens``

Authenticates an identity and generates a token. Uses the password authentication method with explicit unscoped authorization.

The request body must include a payload that specifies the
``password`` authentication method, the credentials, and the
``unscoped`` authorization scope.

Normal response codes: 201

Error response codes: 413,415,405,404,403,401,400,503,409

Request
-------

.. rest_parameters:: parameters.yaml

   - nocatalog: nocatalog
   - name: user_name
   - auth: auth
   - user: user
   - scope: scope
   - password: password
   - id: user_id
   - identity: identity
   - methods: auth_methods_passwd

Request Example
---------------

.. literalinclude:: ./samples/admin/auth-password-explicit-unscoped-request.json
   :language: javascript

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - X-Subject-Token: X-Subject-Token
   - domain: domain
   - methods: auth_methods_passwd
   - roles: roles
   - expires_at: expires_at
   - token: token
   - extras: extras
   - user: user
   - audit_ids: audit_ids
   - issued_at: issued_at
   - id: user_id
   - name: user_name


Token authentication with unscoped authorization
================================================

.. rest_method::  POST /v3/auth/tokens

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/auth_tokens``

Authenticates an identity and generates a token. Uses the token authentication method. Authorization is unscoped.

In the request body, provide the token ID.

Normal response codes: 201

Error response codes: 413,415,405,404,403,401,400,503,409

Request
-------

.. rest_parameters:: parameters.yaml

   - nocatalog: nocatalog
   - identity: identity
   - token: auth_token
   - id: auth_token_id
   - auth: auth
   - methods: auth_methods_token

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

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/auth_tokens``

Authenticates an identity and generates a token. Uses the token authentication method and scopes authorization to a project or domain.

In the request body, provide the token ID and the ``project`` or
``domain`` authorization scope.

Normal response codes: 201

Error response codes: 413,415,405,404,403,401,400,503,409

Request
-------

.. rest_parameters:: parameters.yaml

   - nocatalog: nocatalog
   - methods: auth_methods_token
   - auth: auth
   - token: auth_token
   - audit_ids: audit_ids
   - scope: scope
   - id: auth_token_id
   - identity: identity

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

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/auth_tokens``

Validates and shows information for a token, including its expiration date and authorization scope.

Pass your own token in the ``X-Auth-Token`` request header.

Pass the token that you want to validate in the ``X-Subject-Token``
request header.

Normal response codes: 200

Error response codes: 413,405,404,403,401,400,503

Request
-------

.. rest_parameters:: parameters.yaml

   - X-Auth-Token: X-Auth-Token
   - X-Subject-Token: X-Subject-Token
   - nocatalog: nocatalog
   - allow_expired: allow_expired

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - X-Subject-Token: X-Subject-Token
   - X-Auth-Token: X-Auth-Token
   - domain: domain
   - methods: auth_methods
   - links: domain_link_response_body
   - user: user
   - token: token
   - expires_at: expires_at
   - project: project
   - catalog: catalog
   - extras: extras
   - roles: roles
   - audit_ids: audit_ids
   - issued_at: issued_at
   - id: user_id
   - name: user_name

Response Example
----------------

.. literalinclude:: ./samples/admin/auth-token-unscoped-response.json
   :language: javascript


Check token
===========

.. rest_method::  HEAD /v3/auth/tokens

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/auth_tokens``

Validates a token.

This call is similar to ``GET /auth/tokens`` but no response body
is provided even in the ``X-Subject-Token`` header.

The Identity API returns the same response as when the subject
token was issued by ``POST /auth/tokens`` even if an error occurs
because the token is not valid. An HTTP ``204`` response code
indicates that the ``X-Subject-Token`` is valid.


Normal response codes: 200

Error response codes: 413,405,404,403,401,400,503

Request
-------

.. rest_parameters:: parameters.yaml

   - X-Auth-Token: X-Auth-Token
   - X-Subject-Token: X-Subject-Token
   - allow_expired: allow_expired


Revoke token
============

.. rest_method::  DELETE /v3/auth/tokens

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/auth_tokens``

Revokes a token.

This call is similar to the HEAD ``/auth/tokens`` call except that
the ``X-Subject-Token`` token is immediately not valid, regardless
of the ``expires_at`` attribute value. An additional
``X-Auth-Token`` is not required.

Normal response codes: 204

Error response codes: 413,415,405,404,403,401,400,503,409

Request
-------

.. rest_parameters:: parameters.yaml

   - X-Auth-Token: X-Auth-Token
   - X-Subject-Token: X-Subject-Token


Get service catalog
===================

.. rest_method:: GET /v3/auth/catalog

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/auth_catalog``

New in version 3.3

This call returns a service catalog for the X-Auth-Token provided in the
request, even if the token does not contain a catalog itself (for example,
if it was generated using ?nocatalog).

The structure of the catalog object is identical to that contained in a token.

Normal response codes: 204

Error response codes: 413,415,405,404,403,401,400,503,409

Request
-------

.. rest_parameters:: parameters.yaml

   - X-Auth-Token: X-Auth-Token
   - X-Subject-Token: X-Subject-Token

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - endpoints: endpoints
   - id: service_id
   - type: service_type
   - name: service_name

Response Example
----------------

.. literalinclude:: ./samples/admin/get-service-catalog-response.json
   :language: javascript


Get available project scopes
============================

.. rest_method:: GET /v3/auth/projects

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/auth_projects``

New in version 3.3

This call returns the list of projects that are available to be scoped
to based on the X-Auth-Token provided in the request.

The structure of the response is exactly the same as listing projects
for a user.

Normal response codes: 204

Error response codes: 413,415,405,404,403,401,400,503,409

Request
-------

.. rest_parameters:: parameters.yaml

   - X-Auth-Token: X-Auth-Token
   - X-Subject-Token: X-Subject-Token

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - domain_id: project_domain_id_response_body
   - enabled: project_enabled_response_body
   - id: project_id
   - links: links_project
   - name: project_name_response_body

Response Example
----------------

.. literalinclude:: ./samples/admin/get-available-project-scopes-response.json
   :language: javascript


Get available domain scopes
===========================

.. rest_method:: GET /v3/auth/domains

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/auth_domains``

New in version 3.3

This call returns the list of domains that are available to be scoped
to based on the X-Auth-Token provided in the request.

The structure is the same as listing domains.

Normal response codes: 204

Error response codes: 413,415,405,404,403,401,400,503,409

Request
-------

.. rest_parameters:: parameters.yaml

   - X-Auth-Token: X-Auth-Token
   - X-Subject-Token: X-Subject-Token

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - description: domain_description_response_body
   - enabled: domain_enabled_response_body
   - id: domain_id_response_body
   - links: domain_link_response_body
   - name: domain_name_response_body

Response Example
----------------

.. literalinclude:: ./samples/admin/get-available-domain-scopes-response.json
   :language: javascript
