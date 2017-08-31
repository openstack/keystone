.. -*- rst -*-

========================
OS-KSADM admin extension
========================

Supports create, read, update, and delete (CRUD) operations for
users. Requires administrator privileges.


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
