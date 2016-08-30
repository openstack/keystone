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

   - userId: userId

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


Create user (admin endpoint)
============================

.. rest_method::  POST /v2.0/users

Creates a user.

Normal response codes: 201
Error response codes: 413,415,405,404,403,401,400,503,409

Request
-------

.. rest_parameters:: parameters.yaml

   - tenantId: tenantId
   - password: password
   - enabled: enabled
   - email: email
   - name: name
   - X-Auth-Token: X-Auth-Token

Request Example
---------------

.. literalinclude:: samples/admin/user-create-request.json
   :language: javascript

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - username: username
   - enabled: enabled
   - email: email
   - name: name
   - id: id


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

   - username: username
   - users: users
   - enabled: enabled
   - id: id
   - email: email
   - name: name

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

   - userId: userId
   - username: username
   - enabled: enabled
   - email: email
   - name: name
   - tenantId: tenantId

Request Example
---------------

.. literalinclude:: samples/admin/user-update-request.json
   :language: javascript

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - users: users
   - enabled: enabled
   - email: email
   - name: name
   - id: id
   - tenantId: tenantId

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

   - userId: userId


Show user details (admin endpoint)
==================================

.. rest_method::  GET /v2.0/users/{userId}

Shows details for a user, by ID.

The `openstack user show <http://docs.openstack.org/cli-
reference/openstack.html#openstack-user-show>`_ command supports
showing user details by name or ID. However, the command actually
looks up the user ID for a user name and queries the user by ID.

As a workaround, complete these steps to show details for a user by
name:

- `List all users <http://developer.openstack.org/api-ref-identity-
  admin-v2.html#admin-listUsers>`_.

- In the response, find the user name for which you want to show
  details and note its corresponding user ID.

- `Show details for user <http://developer.openstack.org/api-ref-
  identity-admin-v2.html#admin-showUser>`_.

Normal response codes: 200,203
Error response codes: 413,405,404,403,401,400,503

Request
-------

.. rest_parameters:: parameters.yaml

   - userId: userId

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - username: username
   - enabled: enabled
   - email: email
   - name: name
   - id: id

Response Example
----------------

.. literalinclude:: samples/admin/user-show-response.json
   :language: javascript
