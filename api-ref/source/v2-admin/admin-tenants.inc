.. -*- rst -*-

=======
Tenants
=======


Show tenant details, by ID
==========================

.. rest_method::  GET /v2.0/tenants/{tenantId}

Shows details for a tenant, by ID.

Normal response codes: 200,203
Error response codes: 413,405,404,403,401,400,503

Request
-------

.. rest_parameters:: parameters.yaml

   - tenantId: tenant_id_path

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - tenant: tenant
   - enabled: tenant_enabled
   - description: tenant_description
   - name: tenant_name
   - id: tenant_id

Response Example
----------------

.. literalinclude:: samples/admin/tenant-show-response.json
   :language: javascript


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


List tenants (admin endpoint)
=============================

.. rest_method::  GET /v2.0/tenants

Lists all tenants.

Normal response codes: 200,203
Error response codes: 413,405,404,403,401,400,503

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - tenants: tenants
   - tenant_links: tenant_links
   - enabled: tenant_enabled
   - description: tenant_description
   - name: tenant_name
   - id: tenant_id

Response Example
----------------

.. literalinclude:: ../v2/samples/admin/tenants-list-response.json
   :language: javascript


Show tenant details, by name
============================

.. rest_method::  GET /v2.0/tenants

Shows details for a tenant, by name.

Normal response codes: 200,203
Error response codes: 413,405,404,403,401,400,503

Request
-------

.. rest_parameters:: parameters.yaml

   - name: tenant_name_query

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - tenant: tenant
   - enabled: tenant_enabled
   - description: tenant_description
   - name: tenant_name
   - id: tenant_id

Response Example
----------------

.. literalinclude:: samples/admin/tenant-show-response.json
   :language: javascript


Delete tenant
=============

.. rest_method::  DELETE /v2.0/tenants/{tenantId}

Deletes a tenant.

Normal response codes: 204
Error response codes: 413,415,405,404,403,401,400,503,409

Request
-------

.. rest_parameters:: parameters.yaml

   - tenantId: tenant_id_path


Update tenant
=============

.. rest_method::  POST /v2.0/tenants/{tenantId}

Updates a tenant.

Normal response codes: 200
Error response codes: 413,415,405,404,403,401,400,503,409

Request
-------

.. rest_parameters:: parameters.yaml

   - tenantId: tenant_id_path
   - tenant: tenant
   - enabled: tenant_enabled
   - description: tenant_description
   - name: tenant_name

Request Example
---------------

.. literalinclude:: samples/admin/tenant-update-request.json
   :language: javascript

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - tenant: tenant
   - enabled: tenant_enabled
   - description: tenant_description
   - name: tenant_name
   - id: tenant_id

Response Example
----------------

.. literalinclude:: samples/admin/tenant-show-response.json
   :language: javascript


Create tenant
=============

.. rest_method::  POST /v2.0/tenants

Creates a tenant.

Normal response codes: 201
Error response codes: 413,415,405,404,403,401,400,503,409

Request Example
---------------

.. literalinclude:: samples/admin/tenantwithoutid-create-request.json
   :language: javascript

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - tenant: tenant
   - enabled: tenant_enabled
   - description: tenant_description
   - name: tenant_name
   - id: tenant_id
