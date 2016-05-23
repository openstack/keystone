.. -*- rst -*-

======================
Groups (groups, users)
======================

A group is a collection of users. Each group is owned by a domain.

When you grant a role to a group, you explicitly associate that
group with a project or domain. This action is equivalent to
granting the role to each group member on that project and domain.

When you grant a role to a group, that role is automatically
granted to any user that you add to the group. When you revoke a
role from a group, that role is automatically revoked from any user
that you remove from the group. Any token that authenticates that
user, project, and domain is revoked.

As with users, a group without any role grants is useless from the
perspective an OpenStack service and has no access to resources.
However, a group without role grants is permitted as a way of
acquiring or loading users and groups from external sources before
mapping them to projects and domains.


Show group details
==================

.. rest_method::  GET /v3/groups/{group_id}

Shows details for a group.

Normal response codes: 200
Error response codes:413,405,404,403,401,400,503,

Request
-------

.. rest_parameters:: parameters.yaml

   - group_id: group_id

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - group: group
   - name: name
   - links: links
   - domain_id: domain_id
   - id: id
   - description: description

Response Example
----------------

.. literalinclude:: ./samples/admin/group-show-response.json
   :language: javascript


Update group
============

.. rest_method::  PATCH /v3/groups/{group_id}

Updates a group.

If the back-end driver does not support this functionality, the
call returns the ``Not Implemented (501)`` response code.

Normal response codes: 200
Error response codes:413,415,405,404,403,401,400,503,409,

Request
-------

.. rest_parameters:: parameters.yaml

   - group: group
   - description: description
   - name: name
   - domain_id: domain_id
   - group_id: group_id

Request Example
---------------

.. literalinclude:: ./samples/admin/group-update-request.json
   :language: javascript

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - group: group
   - name: name
   - links: links
   - domain_id: domain_id
   - id: id
   - description: description

Response Example
----------------

.. literalinclude:: ./samples/admin/group-update-response.json
   :language: javascript


Delete group
============

.. rest_method::  DELETE /v3/groups/{group_id}

Deletes a group.

Error response codes:204,413,415,405,404,403,401,400,503,409,

Request
-------

.. rest_parameters:: parameters.yaml

   - group_id: group_id


Add user to group
=================

.. rest_method::  PUT /v3/groups/{group_id}/users/{user_id}

Adds a user to a group.

Error response codes:204,413,415,405,404,403,401,400,503,409,

Request
-------

.. rest_parameters:: parameters.yaml

   - user_id: user_id
   - group_id: group_id


Remove user from group
======================

.. rest_method::  DELETE /v3/groups/{group_id}/users/{user_id}

Removes a user from a group.

Error response codes:204,413,415,405,404,403,401,400,503,409,

Request
-------

.. rest_parameters:: parameters.yaml

   - user_id: user_id
   - group_id: group_id


Check whether user belongs to group
===================================

.. rest_method::  HEAD /v3/groups/{group_id}/users/{user_id}

Validates that a user belongs to a group.

Error response codes:204,413,405,404,403,401,400,503,

Request
-------

.. rest_parameters:: parameters.yaml

   - user_id: user_id
   - group_id: group_id


List users in group
===================

.. rest_method::  GET /v3/groups/{group_id}/users

Lists the users that belong to a group.

Normal response codes: 200
Error response codes:413,405,404,403,401,400,503,

Request
-------

.. rest_parameters:: parameters.yaml

   - group_id: group_id

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - name: name
   - links: links
   - enabled: enabled
   - domain_id: domain_id
   - email: email
   - id: id
   - users: users

Response Example
----------------

.. literalinclude:: ./samples/admin/group-users-list-response.json
   :language: javascript


Create group
============

.. rest_method::  POST /v3/groups

Creates a group.

Error response codes:201,413,415,405,404,403,401,400,503,409,

Request
-------

.. rest_parameters:: parameters.yaml

   - group: group
   - description: description
   - name: name
   - domain_id: domain_id

Request Example
---------------

.. literalinclude:: ./samples/admin/group-create-request.json
   :language: javascript

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - group: group
   - name: name
   - links: links
   - domain_id: domain_id
   - id: id
   - description: description


List groups
===========

.. rest_method::  GET /v3/groups

Lists groups.

Normal response codes: 200
Error response codes:413,405,404,403,401,400,503,

Request
-------

.. rest_parameters:: parameters.yaml

   - name: name
   - domain_id: domain_id

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - name: name
   - links: links
   - domain_id: domain_id
   - groups: groups
   - id: id
   - description: description

Response Example
----------------

.. literalinclude:: ./samples/admin/groups-list-response.json
   :language: javascript
