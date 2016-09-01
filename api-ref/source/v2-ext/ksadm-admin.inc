.. -*- rst -*-

========================
OS-KSADM admin extension
========================

Supports create, read, update, and delete (CRUD) operations for
roles, and services. Requires administrator privileges.


Enable (Disable) user
=====================

.. rest_method::  PUT /v2.0/users/{userId}/OS-KSADM/enabled

Enables or disables a user.

Normal response codes: 200
Error response codes: 413,415,405,404,403,401,400,503,409

Request
-------

.. rest_parameters:: parameters.yaml

   - userId: userId
   - enabled: enabled_user

Request Example
---------------

.. literalinclude:: samples/OS-KSADM/user-set-enabled-request.json
   :language: javascript

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - email: email
   - enabled: enabled
   - id: id
   - name: name
   - username: username

Response Example
----------------

.. literalinclude:: samples/OS-KSADM/user-show-response.json
   :language: javascript


Set user password
=================

.. rest_method::  PUT /v2.0/users/{userId}/OS-KSADM/password

Sets a user's password

Normal response codes: 200
Error response codes: 413,415,405,404,403,401,400,503,409

Request
-------

.. rest_parameters:: parameters.yaml

   - userId: userId
   - password: new_password

Request Example
---------------

.. literalinclude:: samples/OS-KSADM/user-set-password-request.json
   :language: javascript

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - enabled: enabled
   - email: email
   - name: name
   - id: id
   - username: username

Response Example
----------------

.. literalinclude:: samples/OS-KSADM/user-show-response.json
   :language: javascript


Update user tenant
==================

.. rest_method:: PUT /v2.0/users/{userId}/OS-KSADM/tenant

Sets a user's tenant

Normal response codes: 200

Error response codes: 413, 415, 405, 404, 403, 401, 400, 503, 409

Request
-------

.. rest_parameters:: parameters.yaml

   - userId: userId
   - tenantId: tenantId

Request Example
---------------

.. literalinclude:: samples/OS-KSADM/user-update-tenant-request.json
   :language: javascript

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - email: email
   - enabled: enabled
   - tenantId: tenantId
   - id: id
   - name: name
   - username: username

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
   - type: type
   - description: description
   - name: name
   - id: id


List services (admin extension)
===============================

.. rest_method::  GET /v2.0/OS-KSADM/services

Lists all services.

Normal response codes: 200,203
Error response codes: 413,405,404,403,401,400,503

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - type: type
   - description: description
   - name: name
   - id: id

Response Example
----------------

.. literalinclude:: samples/OS-KSADM/services-list-response.json
   :language: javascript


Shows service information by ID
===============================

.. rest_method::  GET /v2.0/OS-KSADM/services/{serviceId}

Shows information for a service, by ID.

Normal response codes: 200,203
Error response codes: 413,405,404,403,401,400,503

Request
-------

.. rest_parameters:: parameters.yaml

   - serviceId: serviceId

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - type: type
   - description: description
   - name: name
   - id: id

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

   - type: type
   - description: description
   - name: name
   - id: id

Response Example
----------------

.. literalinclude:: samples/OS-KSADM/service-show-response.json
   :language: javascript


Delete service (admin extension)
================================

.. rest_method::  DELETE /v2.0/OS-KSADM/services/{serviceId}

Deletes a service.

Normal response codes: 204
Error response codes: 413,415,405,404,403,401,400,503,409

Request
-------

.. rest_parameters:: parameters.yaml

   - serviceId: serviceId


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

   - roles_links: roles_links
   - roles: roles
   - description: description
   - name: name
   - id: id

Response Example
----------------

.. literalinclude:: samples/OS-KSADM/roles-list-response.json
   :language: javascript


Show a role
===========

.. rest_method::  GET /v2.0/OS-KSADM/roles/{roleId}

Shows details for a role.

Normal response codes: 200,203
Error response codes: 413,415,405,404,403,401,400,503,409

Request
-------

.. rest_parameters:: parameters.yaml

   - roleId: roleId

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - Location: Location
   - description: description
   - name: name
   - id: id

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
   - description: description
   - name: name
   - id: id

Response Example
----------------

.. literalinclude:: samples/OS-KSADM/role-show-response.json
   :language: javascript


Delete a role
=============

.. rest_method::  DELETE /v2.0/OS-KSADM/roles/{roleId}

Deletes a role.

Normal response codes: 204
Error response codes: 413,415,405,404,403,401,400,503,409

Request
-------

.. rest_parameters:: parameters.yaml

   - roleId: roleId


Grant roles to user on tenant
=============================

.. rest_method::  PUT /v2.0/tenants/{tenantId}/users/{userId}/roles/OS-KSADM/{roleId}

Grants a role to a user for a tenant.

Normal response codes: 201
Error response codes: 413,415,405,404,403,401,400,503,409

Request
-------

.. rest_parameters:: parameters.yaml

   - userId: userId
   - roleId: roleId
   - tenantId: tenantId


Revoke role from user on tenant
===============================

.. rest_method::  DELETE /v2.0/tenants/{tenantId}/users/{userId}/roles/OS-KSADM/{roleId}

Revokes a role from a user for a tenant.

Normal response codes: 204
Error response codes: 413,415,405,404,403,401,400,503,409

Request
-------

.. rest_parameters:: parameters.yaml

   - userId: userId
   - roleId: roleId
   - tenantId: tenantId
