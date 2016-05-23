.. -*- rst -*-

======================================
Users (users, groups, projects, roles)
======================================

A user is an individual API consumer that is owned by a domain. A
role explicitly associates a user with projects or domains. A user
with no assigned roles has no access to OpenStack resources.

You can list, create, show details for, update, delete, and change
the password for users.

You can also list groups, projects, and roles for a specified user.
To list user roles, see `Roles <http://developer.openstack.org/api-
ref-identity-v3.html#roles-v3>`_.


Show user details
=================

.. rest_method::  GET /v3/users/{user_id}

Shows details for a user.

Normal response codes: 200
Error response codes:413,405,404,403,401,400,503,

Request
-------

.. rest_parameters:: parameters.yaml

   - user_id: user_id

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - description: description
   - links: links
   - user: user
   - enabled: enabled
   - email: email
   - default_project_id: default_project_id
   - id: id
   - domain_id: domain_id
   - name: name

Response Example
----------------

.. literalinclude:: ./samples/admin/user-show-response.json
   :language: javascript


Update user
===========

.. rest_method::  PATCH /v3/users/{user_id}

Updates the password for or enables or disables a user.

If the back-end driver does not support this functionality, this
call might return the HTTP ``Not Implemented (501)`` response code.

Normal response codes: 200
Error response codes:413,415,405,404,403,401,400,503,409,

Request
-------

.. rest_parameters:: parameters.yaml

   - name: name
   - user: user
   - enabled: enabled
   - email: email
   - default_project_id: default_project_id
   - password: password
   - domain_id: domain_id
   - description: description
   - user_id: user_id

Request Example
---------------

.. literalinclude:: ./samples/admin/user-update-request.json
   :language: javascript

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - description: description
   - links: links
   - user: user
   - enabled: enabled
   - email: email
   - default_project_id: default_project_id
   - id: id
   - domain_id: domain_id
   - name: name

Response Example
----------------

.. literalinclude:: ./samples/admin/user-update-response.json
   :language: javascript


Delete user
===========

.. rest_method::  DELETE /v3/users/{user_id}

Deletes a user.

Error response codes:204,413,415,405,404,403,401,400,503,409,

Request
-------

.. rest_parameters:: parameters.yaml

   - user_id: user_id


List groups to which a user belongs
===================================

.. rest_method::  GET /v3/users/{user_id}/groups

Lists groups to which a user belongs.

Normal response codes: 200
Error response codes:413,405,404,403,401,400,503,

Request
-------

.. rest_parameters:: parameters.yaml

   - user_id: user_id

Response Example
----------------

.. literalinclude:: ./samples/admin/user-groups-list-response.json
   :language: javascript


Change password for user
========================

.. rest_method::  POST /v3/users/{user_id}/password

Changes the password for a user.

Error response codes:204,413,415,405,404,403,401,400,503,409,

Request
-------

.. rest_parameters:: parameters.yaml

   - original_password: original_password
   - password: password
   - user: user
   - user_id: user_id

Request Example
---------------

.. literalinclude:: ./samples/admin/user-password-update-request.json
   :language: javascript


Create user
===========

.. rest_method::  POST /v3/users

Creates a user.

Error response codes:201,413,415,405,404,403,401,400,503,409,

Request
-------

.. rest_parameters:: parameters.yaml

   - name: name
   - user: user
   - enabled: enabled
   - email: email
   - default_project_id: default_project_id
   - password: password
   - domain_id: domain_id
   - description: description

Request Example
---------------

.. literalinclude:: ./samples/admin/user-create-request.json
   :language: javascript

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - description: description
   - links: links
   - user: user
   - enabled: enabled
   - email: email
   - default_project_id: default_project_id
   - id: id
   - domain_id: domain_id
   - name: name


List users
==========

.. rest_method::  GET /v3/users

Lists users.

Normal response codes: 200
Error response codes:413,405,404,403,401,400,503,

Request
-------

.. rest_parameters:: parameters.yaml

   - domain_id: domain_id
   - name: name
   - enabled: enabled

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - description: description
   - links: links
   - enabled: enabled
   - email: email
   - default_project_id: default_project_id
   - id: id
   - users: users
   - domain_id: domain_id
   - name: name

Response Example
----------------

.. literalinclude:: ./samples/admin/users-list-response.json
   :language: javascript


List projects for user
======================

.. rest_method::  GET /v3/users/{user_id}/projects

List projects for a user.

Normal response codes: 200
Error response codes:413,405,404,403,401,400,503,

Request
-------

.. rest_parameters:: parameters.yaml

   - user_id: user_id

Response Example
----------------

.. literalinclude:: ./samples/admin/user-projects-list-response.json
   :language: javascript
