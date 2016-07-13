.. -*- rst -*-

========================
OS-KSADM admin extension
========================

Supports create, read, update, and delete (CRUD) operations for
users, tenants, roles, and services. Requires administrator
privileges.


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


Shows service information by ID
===============================

.. rest_method::  GET /v2.0/services/{serviceId}

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


Delete service (admin extension)
================================

.. rest_method::  DELETE /v2.0/services/{serviceId}

Deletes a service.

Normal response codes: 204
Error response codes: 413,415,405,404,403,401,400,503,409

Request
-------

.. rest_parameters:: parameters.yaml

   - serviceId: serviceId


List users on a tenant
======================

.. rest_method::  GET /v2.0/tenants/{tenantId}/users

Lists all users for a tenant.

Normal response codes: 200,203
Error response codes: 413,405,404,403,401,400,503

Request
-------

.. rest_parameters:: parameters.yaml

   - tenantId: tenantId

Response Example
----------------

.. literalinclude:: samples/OS-KSADM/users-list-response.json
   :language: javascript


Enable user
===========

.. rest_method::  PUT /v2.0/users/{userId}/OS-KSADM/enabled

Enables a user.

Normal response codes: 200
Error response codes: 413,415,405,404,403,401,400,503,409

Request
-------

.. rest_parameters:: parameters.yaml

   - userId: userId

Request Example
---------------

.. literalinclude:: samples/OS-KSADM/userwithenabledonly-enable-request.json
   :language: javascript

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - enabled: enabled
   - email: email
   - name: name
   - id: id

Response Example
----------------

.. literalinclude:: samples/OS-KSADM/user-show-response.json
   :language: javascript


List roles (admin extension)
============================

.. rest_method::  GET /v2.0/OS-KSADM/

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


List users (admin extension)
============================

.. rest_method::  GET /v2.0/users

Lists all users.

Normal response codes: 200,203
Error response codes: 413,405,404,403,401,400,503

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - users: users
   - enabled: enabled
   - email: email
   - name: name
   - id: id

Response Example
----------------

.. literalinclude:: samples/OS-KSADM/users-list-response.json
   :language: javascript


Create user (admin extension)
=============================

.. rest_method::  POST /v2.0/users

Creates a user.

Normal response codes: 201
Error response codes: 413,415,405,404,403,401,400,503,409

Request
-------

.. rest_parameters:: parameters.yaml

   - name: name
   - enabled: enabled
   - id: id
   - user: user
   - users_links: users_links
   - email: email

Request Example
---------------

.. literalinclude:: samples/OS-KSADM/userwithoutid-create-request.json
   :language: javascript

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - enabled: enabled
   - email: email
   - name: name
   - id: id


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


Grant global role to user
=========================

.. rest_method::  PUT /v2.0/users/{userId}/roles/OS-KSADM/{roleId}

Grants a global role to a user.

Normal response codes: 201
Error response codes: 413,415,405,404,403,401,400,503,409

Request
-------

.. rest_parameters:: parameters.yaml

   - userId: userId
   - roleId: roleId


Delete global role from user
============================

.. rest_method::  DELETE /v2.0/users/{userId}/roles/OS-KSADM/{roleId}

Deletes a global role from a user.

Normal response codes: 204
Error response codes: 413,415,405,404,403,401,400,503,409

Request
-------

.. rest_parameters:: parameters.yaml

   - userId: userId
   - roleId: roleId


List services (admin extension)
===============================

.. rest_method::  GET /v2.0/services

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


Create service (admin extension)
================================

.. rest_method::  POST /v2.0/services

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


Show service information by name
================================

.. rest_method::  GET /v2.0/services/{serviceName}

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


Create role (admin extension)
=============================

.. rest_method::  POST /v2.0/OS-KSADM

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


Create tenant
=============

.. rest_method::  POST /v2.0/tenants

Creates a tenant.

Normal response codes: 201
Error response codes: 413,415,405,404,403,401,400,503,409

Request Example
---------------

.. literalinclude:: samples/OS-KSADM/tenantwithoutid-create-request.json
   :language: javascript

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - tenant: tenant
   - enabled: enabled
   - description: description
   - name: name
   - id: id


List global roles for user
==========================

.. rest_method::  GET /v2.0/users/{userId}/roles

Lists global roles for a user.

Normal response codes: 200,203
Error response codes: 413,405,404,403,401,400,503

Request
-------

.. rest_parameters:: parameters.yaml

   - userId: userId

Response Example
----------------

.. literalinclude:: samples/OS-KSADM/user-roles-list-response.json
   :language: javascript


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

.. literalinclude:: samples/OS-KSADM/tenant-update-request.json
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

.. literalinclude:: samples/OS-KSADM/tenant-show-response.json
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


Show role details, by ID
========================

.. rest_method::  GET /v2.0/OS-KSADM/{roleId}

Shows details for a role, by ID.

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


Delete role (admin extension)
=============================

.. rest_method::  DELETE /v2.0/OS-KSADM/{roleId}

Deletes a role.

Normal response codes: 204
Error response codes: 413,415,405,404,403,401,400,503,409

Request
-------

.. rest_parameters:: parameters.yaml

   - roleId: roleId


Update user (admin extension)
=============================

.. rest_method::  PUT /v2.0/users/{userId}

Updates a user.

Normal response codes: 200
Error response codes: 413,415,405,404,403,401,400,503,409

Request
-------

.. rest_parameters:: parameters.yaml

   - userId: userId

Request Example
---------------

.. literalinclude:: samples/OS-KSADM/user-update-request.json
   :language: javascript

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - users: users
   - enabled: enabled
   - email: email
   - name: name
   - id: id

Response Example
----------------

.. literalinclude:: samples/OS-KSADM/user-show-response.json
   :language: javascript


Delete user (admin extension)
=============================

.. rest_method::  DELETE /v2.0/users/{userId}

Deletes a user.

Normal response codes: 204
Error response codes: 413,415,405,404,403,401,400,503,409

Request
-------

.. rest_parameters:: parameters.yaml

   - userId: userId
