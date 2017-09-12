.. -*- rst -*-

=======
Tenants
=======


List users on a tenant
======================

.. rest_method::  GET /v2.0/tenants/{tenantId}/users

Lists all users for a tenant.

Normal response codes: 200, 203
Error response codes: 413, 405, 404, 403, 401, 400, 503

Request
-------

.. rest_parameters:: parameters.yaml

   - tenantId: tenant_id_path

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - users: users
   - users_link: users_link
   - enabled: user_enabled
   - username: user_name
   - email: user_email
   - id: user_id

Response Example
----------------

.. literalinclude:: samples/admin/users-list-response.json
   :language: javascript


List roles for user
===================

.. rest_method::  GET /v2.0/tenants/{tenantId}/users/{userId}/roles

Lists roles for a user on a tenant. Excludes global roles.

Normal response codes: 200,203
Error response codes: 413,405,404,403,401,400,503

Request
-------

.. rest_parameters:: parameters.yaml

   - userId: user_id_path
   - tenantId: tenant_id_path

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - roles: roles
   - roles_links: roles_links
   - description: role_description
   - name: role_name
   - id: role_id

Response Example
----------------

.. literalinclude:: samples/admin/roles-list-response.json
   :language: javascript
