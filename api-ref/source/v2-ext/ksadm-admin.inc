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

.. literalinclude:: samples/OS-KSADM/userwithenabledonly-show-response.json
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
