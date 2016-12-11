.. -*- rst -*-

========
 Groups
========

A group is a collection of users. Each group is owned by a domain.

You can use groups to ease the task of managing role assignments for users.
Assigning a role to a group on a project or domain is equivalent to
assigning the role to each group member on that project or domain.

When you unassign a role from a group, that role is automatically unassigned
from any user that is a member of the group. Any tokens that authenticates those
users to the relevant project or domain are revoked.

As with users, a group without any role assignments is useless from the
perspective of an OpenStack service and has no access to resources.
However, a group without role assignments is permitted as a way of
acquiring or loading users and groups from external sources before
mapping them to projects and domains.


List groups
===========

.. rest_method::  GET /v3/groups

Relationship: ``http://docs.openstack.org/api/openstack-identity/3/rel/groups``

Lists groups.

Response Codes
--------------

.. rest_status_code:: success status.yaml

   - 200

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403

Request Parameters
------------------

.. rest_parameters:: parameters.yaml

   - name: group_name_query
   - domain_id: domain_id_query

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - links: link_collection
   - groups: groups
   - description: group_description_response_body
   - domain_id: group_domain_id_response_body
   - id: group_id_response_body
   - links: link_response_body
   - name: group_name_response_body

Response Example
----------------

.. literalinclude:: ./samples/admin/groups-list-response.json
   :language: javascript


Create group
============

.. rest_method::  POST /v3/groups

Relationship: ``http://docs.openstack.org/api/openstack-identity/3/rel/groups``

Creates a group.

Response Codes
--------------

.. rest_status_code:: success status.yaml

   - 201

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 409

Request Parameters
------------------

.. rest_parameters:: parameters.yaml

   - group: group
   - description: group_description_request_body
   - domain_id: group_domain_id_request_body
   - name: group_name_request_body

Request Example
---------------

.. literalinclude:: ./samples/admin/group-create-request.json
   :language: javascript

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - group: group
   - description: group_description_response_body
   - domain_id: group_domain_id_response_body
   - id: group_id_response_body
   - links: link_response_body
   - name: group_name_response_body

Response Example
----------------

.. literalinclude:: ./samples/admin/group-show-response.json
   :language: javascript


Show group details
==================

.. rest_method::  GET /v3/groups/{group_id}

Relationship: ``http://docs.openstack.org/api/openstack-identity/3/rel/group``

Shows details for a group.

Response Codes
--------------

.. rest_status_code:: success status.yaml

   - 200

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404

Request Parameters
------------------

.. rest_parameters:: parameters.yaml

   - group_id: group_id_path

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - group: group
   - description: group_description_response_body
   - domain_id: group_domain_id_response_body
   - id: group_id_response_body
   - links: link_response_body
   - name: group_name_response_body

Response Example
----------------

.. literalinclude:: ./samples/admin/group-show-response.json
   :language: javascript


Update group
============

.. rest_method::  PATCH /v3/groups/{group_id}

Relationship: ``http://docs.openstack.org/api/openstack-identity/3/rel/group``

Updates a group.

If the back-end driver does not support this functionality, the
call returns the ``Not Implemented (501)`` response code.

Response Codes
--------------

.. rest_status_code:: success status.yaml

   - 200

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404
   - 409
   - 501

Request Parameters
------------------

.. rest_parameters:: parameters.yaml

   - group_id: group_id_path
   - group: group
   - description: group_description_update_request_body
   - domain_id: group_domain_id_update_request_body
   - name: group_name_update_request_body

Request Example
---------------

.. literalinclude:: ./samples/admin/group-update-request.json
   :language: javascript

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - group: group
   - description: group_description_response_body
   - domain_id: group_domain_id_response_body
   - id: group_id_response_body
   - links: link_response_body
   - name: group_name_response_body

Response Example
----------------

.. literalinclude:: ./samples/admin/group-update-response.json
   :language: javascript


Delete group
============

.. rest_method::  DELETE /v3/groups/{group_id}

Relationship: ``http://docs.openstack.org/api/openstack-identity/3/rel/group``

Deletes a group.

Response Codes
--------------

.. rest_status_code:: success status.yaml

   - 204

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404

Request Parameters
------------------

.. rest_parameters:: parameters.yaml

   - group_id: group_id_path


List users in group
===================

.. rest_method::  GET /v3/groups/{group_id}/users

Relationship: ``http://docs.openstack.org/api/openstack-identity/3/rel/group_users``

Lists the users that belong to a group.

Response Codes
--------------

.. rest_status_code:: success status.yaml

   - 200

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404

Request Parameters
------------------

.. rest_parameters:: parameters.yaml

   - group_id: group_id_path

Response Example
----------------

.. literalinclude:: ./samples/admin/group-users-list-response.json
   :language: javascript


List users in group based on password expiration time
=====================================================

.. rest_method:: GET /v3/groups/{group_id}/users?password_expires_at={operator}:{timestamp}

List users that belong to a group with a password expiring in relation
to the `timestamp` given based on the `operator`. Similar to listing
users based on password expiration time, but also filtering by
the specified group.

The operators are:

- lt: expiration time lower than the timestamp
- lte: expiration time lower than or equal to the timestamp
- gt: expiration time higher than the timestamp
- gte: expiration time higher than or equal to the timestamp
- eq: expiration time equal to the timestamp
- neq: expiration time not equal to the timestamp

For example::

  GET /v3/groups/079c578fd99b428ab61fcd4c9bd88ecd/users?password_expires_at=lt:2016-12-08T22:02:00Z

The example would return a list of users that belong to the group with
ID `079c578fd99b428ab61fcd4c9bd88ecd1 and whose password has expired
before the given timestamp `2016-12-08T22:02:00Z`.

Response Codes
--------------

.. rest_status_code:: success status.yaml

   - 200

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404
   - 409
   - 501

Request Parameters
------------------

.. rest_parameters:: parameters.yaml

   - group_id: group_id_path
   - operator: operator_query
   - timestamp: timestamp_query

Response Parameters
-------------------

Responses will contain a list of users in the group, each
represented with the response parameters described below.

.. rest_parameters:: parameters.yaml

   - default_project_id: default_project_id_response_body
   - domain_id: domain_id_response_body
   - enabled: enabled_user_response_body
   - id: id_user_body
   - links: links_user
   - name: user_name_response_body
   - password_expires_at: password_expires_at

Response Example
----------------

.. literalinclude:: ./samples/admin/users-in-group-list-password-expired.json
   :language: javascript


Add user to group
=================

.. rest_method::  PUT /v3/groups/{group_id}/users/{user_id}

Relationship: ``http://docs.openstack.org/api/openstack-identity/3/rel/group_user``

Adds a user to a group.

Response Codes
--------------

.. rest_status_code:: success status.yaml

   - 200

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404

Request Parameters
------------------

.. rest_parameters:: parameters.yaml

   - user_id: user_id_path
   - group_id: group_id_path


Check whether user belongs to group
===================================

.. rest_method::  HEAD /v3/groups/{group_id}/users/{user_id}

Relationship: ``http://docs.openstack.org/api/openstack-identity/3/rel/group_user``

Validates that a user belongs to a group.

Response Codes
--------------

.. rest_status_code:: success status.yaml

   - 204

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404

Request Parameters
------------------

.. rest_parameters:: parameters.yaml

   - user_id: user_id_path
   - group_id: group_id_path


Remove user from group
======================

.. rest_method::  DELETE /v3/groups/{group_id}/users/{user_id}

Relationship: ``http://docs.openstack.org/api/openstack-identity/3/rel/group_user``

Removes a user from a group.

Response Codes
--------------

.. rest_status_code:: success status.yaml

   - 204

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404

Request Parameters
------------------

.. rest_parameters:: parameters.yaml

   - user_id: user_id_path
   - group_id: group_id_path
