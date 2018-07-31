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

Lists groups.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/groups``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - name: group_name_query
   - domain_id: domain_id_query

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - links: link_collection
   - groups: groups
   - description: group_description_response_body
   - domain_id: group_domain_id_response_body
   - id: group_id_response_body
   - links: link_response_body
   - name: group_name_response_body

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success status.yaml

   - 200

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403

Example
~~~~~~~

.. literalinclude:: ./samples/admin/groups-list-response.json
   :language: javascript


Create group
============

.. rest_method::  POST /v3/groups

Creates a group.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/groups``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - group: group
   - description: group_description_request_body
   - domain_id: group_domain_id_request_body
   - name: group_name_request_body

Example
~~~~~~~

.. literalinclude:: ./samples/admin/group-create-request.json
   :language: javascript

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - group: group
   - description: group_description_response_body
   - domain_id: group_domain_id_response_body
   - id: group_id_response_body
   - links: link_response_body
   - name: group_name_response_body

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success status.yaml

   - 201

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 409

Example
~~~~~~~

.. literalinclude:: ./samples/admin/group-show-response.json
   :language: javascript


Show group details
==================

.. rest_method::  GET /v3/groups/{group_id}

Shows details for a group.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/group``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - group_id: group_id_path

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - group: group
   - description: group_description_response_body
   - domain_id: group_domain_id_response_body
   - id: group_id_response_body
   - links: link_response_body
   - name: group_name_response_body

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success status.yaml

   - 200

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404

Example
~~~~~~~

.. literalinclude:: ./samples/admin/group-show-response.json
   :language: javascript


Update group
============

.. rest_method::  PATCH /v3/groups/{group_id}

Updates a group.

If the back-end driver does not support this functionality, the
call returns the ``Not Implemented (501)`` response code.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/group``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - group_id: group_id_path
   - group: group
   - description: group_description_update_request_body
   - domain_id: group_domain_id_update_request_body
   - name: group_name_update_request_body

Example
~~~~~~~

.. literalinclude:: ./samples/admin/group-update-request.json
   :language: javascript

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - group: group
   - description: group_description_response_body
   - domain_id: group_domain_id_response_body
   - id: group_id_response_body
   - links: link_response_body
   - name: group_name_response_body

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success status.yaml

   - 200

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404
   - 409
   - 501

Example
~~~~~~~

.. literalinclude:: ./samples/admin/group-update-response.json
   :language: javascript


Delete group
============

.. rest_method::  DELETE /v3/groups/{group_id}

Deletes a group.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/group``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - group_id: group_id_path

Response
--------

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success status.yaml

   - 204

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404


List users in group
===================

.. rest_method::  GET /v3/groups/{group_id}/users

Lists the users that belong to a group.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/group_users``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - group_id: group_id_path
   - password_expires_at: password_expires_at_query

Response
--------

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success status.yaml

   - 200

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404

Example
~~~~~~~

.. literalinclude:: ./samples/admin/group-users-list-response.json
   :language: javascript


Add user to group
=================

.. rest_method::  PUT /v3/groups/{group_id}/users/{user_id}

Adds a user to a group.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/group_user``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - user_id: user_id_path
   - group_id: group_id_path

Response
--------

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success status.yaml

   - 204

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404


Check whether user belongs to group
===================================

.. rest_method::  HEAD /v3/groups/{group_id}/users/{user_id}

Validates that a user belongs to a group.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/group_user``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - user_id: user_id_path
   - group_id: group_id_path

Response
--------

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success status.yaml

   - 204

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404


Remove user from group
======================

.. rest_method::  DELETE /v3/groups/{group_id}/users/{user_id}

Removes a user from a group.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/group_user``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - user_id: user_id_path
   - group_id: group_id_path

Response
--------

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success status.yaml

   - 204

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404
