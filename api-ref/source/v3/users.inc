.. -*- rst -*-

=======
 Users
=======

A user is an individual API consumer that is owned by a domain. A
role explicitly associates a user with projects or domains. A user
with no assigned roles has no access to OpenStack resources.

You can list, create, show details for, update, delete, and change
the password for users.

You can also list groups, projects, and role assignments for a specified
user.
To list user roles, see `Roles <http://developer.openstack.org/api-ref/
identity/v3/index.html#roles>`_.


Show user details
=================

.. rest_method::  GET /v3/users/{user_id}

Relationship: ``http://docs.openstack.org/api/openstack-identity/3/rel/user``

Shows details for a user.

Normal response codes: 200

Error response codes:413,405,404,403,401,400,503,

Request
-------

.. rest_parameters:: parameters.yaml

   - user_id: user_id_path

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - user: user_object
   - default_project_id: default_project_id_response_body
   - domain_id: domain_id_response_body
   - enabled: enabled_user_response_body
   - id: id_user_body
   - links: links_user
   - name: user_name_response_body
   - password_expires_at: password_expires_at

Response Example
----------------

.. literalinclude:: ./samples/admin/user-show-response.json
   :language: javascript


Update user
===========

.. rest_method::  PATCH /v3/users/{user_id}

Relationship: ``http://docs.openstack.org/api/openstack-identity/3/rel/user``

Updates a user's password, or whether they are enabled or
disabled.

If the back-end driver does not support this functionality, this
call might return the HTTP ``Not Implemented (501)`` response code.

Normal response codes: 200

Error response codes:413,415,405,404,403,401,400,503,409,

Request
-------

.. rest_parameters:: parameters.yaml

   - user_id: user_id_path
   - user: user_object
   - default_project_id: default_project_id_update_body
   - domain_id: user_domain_id_update_body
   - enabled: enabled_user_update_body
   - name: user_name_update_body
   - password: user_update_password_body

Request Example
---------------

.. literalinclude:: ./samples/admin/user-update-request.json
   :language: javascript

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - user: user_object
   - default_project_id: default_project_id_response_body
   - domain_id: domain_id_response_body
   - enabled: enabled_user_response_body
   - id: id_user_body
   - links: links_user
   - name: user_name_response_body
   - password_expires_at: password_expires_at

Response Example
----------------

.. literalinclude:: ./samples/admin/user-update-response.json
   :language: javascript


Delete user
===========

.. rest_method::  DELETE /v3/users/{user_id}

Relationship: ``http://docs.openstack.org/api/openstack-identity/3/rel/user``

Deletes a user.

Error response codes:204,413,415,405,404,403,401,400,503,409,

Request
-------

.. rest_parameters:: parameters.yaml

   - user_id: user_id_path


List groups to which a user belongs
===================================

.. rest_method::  GET /v3/users/{user_id}/groups

Relationship: ``http://docs.openstack.org/api/openstack-identity/3/rel/user_groups``

Lists groups to which a user belongs.

Normal response codes: 200

Error response codes:413,405,404,403,401,400,503,

Request
-------

.. rest_parameters:: parameters.yaml

   - user_id: user_id_path

Response Example
----------------

.. literalinclude:: ./samples/admin/user-groups-list-response.json
   :language: javascript


Change password for user
========================

.. rest_method::  POST /v3/users/{user_id}/password

Relationship: ``http://docs.openstack.org/api/openstack-identity/3/rel/user_change_password``

Changes the password for a user.

Error response codes:204,413,415,405,404,403,401,400,503,409,

Request
-------

.. rest_parameters:: parameters.yaml

   - user_id: user_id_path
   - user: user_object
   - original_password: original_password
   - password: user_password_update_body

Request Example
---------------

.. literalinclude:: ./samples/admin/user-password-update-request.json
   :language: javascript


Create user
===========

.. rest_method::  POST /v3/users

Relationship: ``http://docs.openstack.org/api/openstack-identity/3/rel/users``

Creates a user.

Error response codes:201,413,415,405,404,403,401,400,503,409,

Request
-------

.. rest_parameters:: parameters.yaml

   - user: user_object
   - default_project_id: default_project_id_request_body
   - domain_id: user_domain_id_request_body
   - enabled: enabled_user_request_body
   - name: user_name_create_request_body
   - password: password_request_body

Request Example
---------------

.. literalinclude:: ./samples/admin/user-create-request.json
   :language: javascript

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - user: user_object
   - default_project_id: default_project_id_response_body
   - domain_id: domain_id_response_body
   - enabled: enabled_user_response_body
   - id: id_user_body
   - links: links_user
   - name: user_name_response_body
   - password_expires_at: password_expires_at


List users
==========

.. rest_method::  GET /v3/users

Relationship: ``http://docs.openstack.org/api/openstack-identity/3/rel/users``

Lists users.

Normal response codes: 200

Error response codes:413,405,404,403,401,400,503,

Request
-------

.. rest_parameters:: parameters.yaml

   - domain_id: domain_id_query
   - enabled: enabled_user_query
   - name: name_user_query

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - links: link_collection
   - users: users_object
   - default_project_id: default_project_id_response_body
   - domain_id: domain_id_response_body
   - enabled: enabled_user_response_body
   - id: id_user_body
   - links: links_user
   - name: user_name_response_body
   - password_expires_at: password_expires_at

Response Example
----------------

.. literalinclude:: ./samples/admin/users-list-response.json
   :language: javascript


List projects for user
======================

.. rest_method::  GET /v3/users/{user_id}/projects

Relationship: ``http://docs.openstack.org/api/openstack-identity/3/rel/user_projects``

List projects for a user.

Normal response codes: 200

Error response codes:413,405,404,403,401,400,503,

Request
-------

.. rest_parameters:: parameters.yaml

   - user_id: user_id_path

Response Example
----------------

.. literalinclude:: ./samples/admin/user-projects-list-response.json
   :language: javascript
