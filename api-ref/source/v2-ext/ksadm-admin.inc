.. -*- rst -*-

========================
OS-KSADM admin extension
========================

Supports create, read, update, and delete (CRUD) operations for
roles, and services. Requires administrator privileges.


Enable (Disable) user
=====================

.. rest_method::  PUT /v2.0/users/{user_id}/OS-KSADM/enabled

Enables or disables a user.

Normal response codes: 200
Error response codes: 413,415,405,404,403,401,400,503,409

Request
-------

.. rest_parameters:: parameters.yaml

   - user_id: user_id_path
   - enabled: user_enabled

Request Example
---------------

.. literalinclude:: samples/OS-KSADM/user-set-enabled-request.json
   :language: javascript

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - user: user
   - email: user_email
   - enabled: user_enabled
   - id: user_id_response
   - name: user_name
   - username: user_name
   - tenantId: tenant_id_response

Response Example
----------------

.. literalinclude:: samples/OS-KSADM/user-show-response.json
   :language: javascript


Set user password
=================

.. rest_method::  PUT /v2.0/users/{user_id}/OS-KSADM/password

Sets a user's password

Normal response codes: 200
Error response codes: 413,415,405,404,403,401,400,503,409

Request
-------

.. rest_parameters:: parameters.yaml

   - user_id: user_id_path
   - password: user_new_password

Request Example
---------------

.. literalinclude:: samples/OS-KSADM/user-set-password-request.json
   :language: javascript

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - user: user
   - enabled: user_enabled
   - email: user_email
   - name: user_name
   - username: user_name
   - id: user_id_response
   - tenantId: tenant_id_response

Response Example
----------------

.. literalinclude:: samples/OS-KSADM/user-show-response.json
   :language: javascript


Update user tenant
==================

.. rest_method:: PUT /v2.0/users/{user_id}/OS-KSADM/tenant

Sets a user's tenant

Normal response codes: 200

Error response codes: 413, 415, 405, 404, 403, 401, 400, 503, 409

Request
-------

.. rest_parameters:: parameters.yaml

   - user_id: user_id_path
   - tenantId: tenant_id_request

Request Example
---------------

.. literalinclude:: samples/OS-KSADM/user-update-tenant-request.json
   :language: javascript

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - user: user
   - email: user_email
   - enabled: user_enabled
   - tenant: tenant_id_response
   - id: user_id_response
   - name: user_name
   - username: user_name
   - tenantId: tenant_id_response

Response Example
----------------

.. literalinclude:: samples/OS-KSADM/user-show-response.json
   :language: javascript


Create service (admin extension)
================================

.. rest_method::  POST /v2.0/OS-KSADM/services

Creates a service.

Normal response codes: 201
Error response codes: 413,415,405,404,403,401,400,503,409

Request Example
---------------

.. literalinclude:: samples/OS-KSADM/service-create-request.json
   :language: javascript

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - Location: Location
   - type: service_type
   - description: service_description
   - name: service_name
   - id: service_id


List services (admin extension)
===============================

.. rest_method::  GET /v2.0/OS-KSADM/services

Lists all services.

Normal response codes: 200,203
Error response codes: 413,405,404,403,401,400,503

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - type: service_type
   - description: service_description
   - name: service_name
   - id: service_id

Response Example
----------------

.. literalinclude:: samples/OS-KSADM/services-list-response.json
   :language: javascript


Shows service information by ID
===============================

.. rest_method::  GET /v2.0/OS-KSADM/services/{service_id}

Shows information for a service, by ID.

Normal response codes: 200,203
Error response codes: 413,405,404,403,401,400,503

Request
-------

.. rest_parameters:: parameters.yaml

   - service_id: service_id_path

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - type: service_type
   - description: service_description
   - name: service_name
   - id: service_id

Response Example
----------------

.. literalinclude:: samples/OS-KSADM/service-show-response.json
   :language: javascript


Show service information by name
================================

.. rest_method::  GET /v2.0/OS-KSADM/services/{serviceName}

Shows information for a service, by name.

Normal response codes: 200,203
Error response codes: 413,405,404,403,401,400,503

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - serviceName: service_name_path
   - type: service_type
   - description: service_description
   - name: service_name
   - id: service_id

Response Example
----------------

.. literalinclude:: samples/OS-KSADM/service-show-response.json
   :language: javascript


Delete service (admin extension)
================================

.. rest_method::  DELETE /v2.0/OS-KSADM/services/{service_id}

Deletes a service.

Normal response codes: 204
Error response codes: 413,415,405,404,403,401,400,503,409

Request
-------

.. rest_parameters:: parameters.yaml

   - service_id: service_id_path


Create a role
=============

.. rest_method::  POST /v2.0/OS-KSADM/roles

Creates a role.

Normal response codes: 201
Error response codes: 413,415,405,404,403,401,400,503,409

Request Example
---------------

.. literalinclude:: samples/OS-KSADM/role-create-request.json
   :language: javascript

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - Location: Location


List all roles
==============

.. rest_method::  GET /v2.0/OS-KSADM/roles

Lists all roles.

Normal response codes: 200,203
Error response codes: 413,405,404,403,401,400,503

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - role_links: role_links
   - roles: roles
   - description: role_description
   - name: role_name
   - id: role_id

Response Example
----------------

.. literalinclude:: samples/OS-KSADM/roles-list-response.json
   :language: javascript


Show a role
===========

.. rest_method::  GET /v2.0/OS-KSADM/roles/{role_id}

Shows details for a role.

Normal response codes: 200,203
Error response codes: 413,415,405,404,403,401,400,503,409

Request
-------

.. rest_parameters:: parameters.yaml

   - role_id: role_id_path

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - Location: Location
   - description: role_description
   - name: role_name
   - id: role_id

Response Example
----------------

.. literalinclude:: samples/OS-KSADM/role-show-response.json
   :language: javascript


Show role information by name
=============================

.. rest_method::  GET /v2.0/OS-KSADM/roles/{role_name}

Shows information for a role, by name.

Normal response codes: 200,203
Error response codes: 413,415,405,404,403,401,400,503,409

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - Location: Location
   - role_name: role_name_path
   - description: role_description
   - name: role_name
   - id: role_id

Response Example
----------------

.. literalinclude:: samples/OS-KSADM/role-show-response.json
   :language: javascript


Delete a role
=============

.. rest_method::  DELETE /v2.0/OS-KSADM/roles/{role_id}

Deletes a role.

Normal response codes: 204
Error response codes: 413,415,405,404,403,401,400,503,409

Request
-------

.. rest_parameters:: parameters.yaml

   - role_id: role_id_path


Grant roles to user on tenant
=============================

.. rest_method::  PUT /v2.0/tenants/{tenant_id}/users/{user_id}/roles/OS-KSADM/{role_id}

Grants a role to a user for a tenant.

Normal response codes: 201
Error response codes: 413,415,405,404,403,401,400,503,409

Request
-------

.. rest_parameters:: parameters.yaml

   - user_id: user_id_path
   - role_id: role_id_path
   - tenant_id: tenant_id_path


Revoke role from user on tenant
===============================

.. rest_method::  DELETE /v2.0/tenants/{tenant_id}/users/{user_id}/roles/OS-KSADM/{role_id}

Revokes a role from a user for a tenant.

Normal response codes: 204
Error response codes: 413,415,405,404,403,401,400,503,409

Request
-------

.. rest_parameters:: parameters.yaml

   - user_id: user_id_path
   - role_id: role_id_path
   - tenant_id: tenant_id_path
