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

   - tenantId: tenantId

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - tenant: tenant
   - enabled: enabled
   - description: description
   - name: name
   - id: id

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

   - tenantId: tenantId

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - users_link: users_link
   - users: users
   - enabled: enabled
   - username: username
   - email: email
   - id: id

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

   - userId: userId
   - tenantId: tenantId

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - roles_links: roles_links
   - roles: roles
   - description: description
   - name: name
   - id: id

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

   - tenant_links: tenant_links
   - tenants: tenants
   - enabled: enabled
   - description: description
   - name: name
   - id: id

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

   - name: name

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - tenant: tenant
   - enabled: enabled
   - description: description
   - name: name
   - id: id

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

   - tenantId: tenantId


Update tenant
=============

.. rest_method::  POST /v2.0/tenants/{tenantId}

Updates a tenant.

Normal response codes: 200
Error response codes: 413,415,405,404,403,401,400,503,409

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant: tenant
   - enabled: enabled
   - description: description
   - name: name
   - id: id
   - tenantId: tenantId

Request Example
---------------

.. literalinclude:: samples/admin/tenant-update-request.json
   :language: javascript

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - tenant: tenant
   - enabled: enabled
   - description: description
   - name: name
   - id: id

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
   - enabled: enabled
   - description: description
   - name: name
   - id: id
