.. -*- rst -*-

=====
Users
=====


List user global roles
======================

.. rest_method::  GET /v2.0/users/{userId}/roles

Lists global roles for a user. Excludes tenant roles.

Normal response codes: 200,203
Error response codes: 413,405,404,403,401,400,503

Request
-------

.. rest_parameters:: parameters.yaml

   - userId: user_id_path

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


Create user (admin endpoint)
============================

.. rest_method::  POST /v2.0/users

Creates a user.

Normal response codes: 201
Error response codes: 413,415,405,404,403,401,400,503,409

Request
-------

.. rest_parameters:: parameters.yaml

   - user: user
   - tenantId: tenant_id_path
   - password: user_password
   - enabled: user_enabled
   - email: user_email
   - name: user_name
   - username: username_request

Request Example
---------------

.. literalinclude:: samples/admin/user-create-request.json
   :language: javascript

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - user: user
   - enabled: user_enabled
   - email: user_email
   - name: user_name
   - username: username
   - id: user_id


List users (admin endpoint)
===========================

.. rest_method::  GET /v2.0/users

Lists all users.

To show detailed information about a user by name, include the
``name`` query parameter in the request.

Normal response codes: 200,203
Error response codes: 413,405,404,403,401,400,503

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - users: users
   - enabled: user_enabled
   - id: user_id
   - email: user_email
   - name: user_name
   - username: username

Response Example
----------------

.. literalinclude:: samples/admin/users-list-response.json
   :language: javascript


Update user (admin endpoint)
============================

.. rest_method::  PUT /v2.0/users/{userId}

Updates a user.

Normal response codes: 201
Error response codes: 413,415,405,404,403,401,400,503,409

Request
-------

.. rest_parameters:: parameters.yaml

   - userId: user_id_path
   - user: user
   - enabled: user_enabled
   - email: user_email
   - name: user_name

Request Example
---------------

.. literalinclude:: samples/admin/user-update-request.json
   :language: javascript

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - user: user
   - enabled: user_enabled
   - email: user_email
   - name: user_name
   - username: username
   - id: user_id

Response Example
----------------

.. literalinclude:: samples/admin/user-update-response.json
   :language: javascript


Delete user (admin endpoint)
============================

.. rest_method::  DELETE /v2.0/users/{userId}

Deletes a user.

Normal response codes: 204
Error response codes: 413,405,404,403,401,400,503

Request
-------

.. rest_parameters:: parameters.yaml

   - userId: user_id_path


Show user details (admin endpoint)
==================================

.. rest_method::  GET /v2.0/users/{userId}

Shows details for a user, by ID.

The `openstack user show <https://docs.openstack.org/cli-
reference/openstack.html#openstack-user-show>`_ command supports
showing user details by name or ID. However, the command actually
looks up the user ID for a user name and queries the user by ID.

As a workaround, complete these steps to show details for a user by
name:

- `List all users <https://developer.openstack.org/api-ref-identity-
  admin-v2.html#admin-listUsers>`_.

- In the response, find the user name for which you want to show
  details and note its corresponding user ID.

- `Show details for user <https://developer.openstack.org/api-ref-
  identity-admin-v2.html#admin-showUser>`_.

Normal response codes: 200,203
Error response codes: 413,405,404,403,401,400,503

Request
-------

.. rest_parameters:: parameters.yaml

   - userId: user_id

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - user: user
   - enabled: user_enabled
   - email: user_email
   - name: user_name
   - username: username
   - id: user_id

Response Example
----------------

.. literalinclude:: samples/admin/user-show-response.json
   :language: javascript
