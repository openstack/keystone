.. -*- rst -*-

=======================
System Role Assignments
=======================

A system role assignment ultimately controls access to system-level API calls.
System role assignments are similar to project or domain role assignments, but
are meant for a different target. Instead of giving a user or group a role on a
project, they can be given a system role.

Good examples of system-level APIs include management of the service catalog
and compute hypervisors.

List system role assignments for a user
=======================================

.. rest_method::  GET /v3/system/users/{user_id}/roles

Lists all system role assignment a user has.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/system_user_roles``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - user_id: user_id_path

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - links: link_response_body
   - roles: system_roles_response_body

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

.. literalinclude:: ./samples/admin/list-system-roles-for-user-response.json
   :language: javascript

The functionality of this request can also be achieved using the generalized
list assignments API::

  GET /role_assignments?user.id={user_id}&scope.system

Assign a system role to a user
==============================

.. rest_method::  PUT /v3/system/users/{user_id}/roles/{role_id}

Grant a user a role on the system.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/system_user_role``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - user_id: user_id_path
   - role_id: role_id_path

Response
--------

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success status.yaml

   - 204

.. rest_status_code:: error status.yaml

   - 401
   - 403
   - 404

Check user for a system role assignment
=======================================

.. rest_method::  HEAD /v3/system/users/{user_id}/roles/{role_id}

Check if a specific user has a role assignment on the system.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/system_user_role``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - user_id: user_id_path
   - role_id: role_id_path

Response
--------

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success status.yaml

   - 204

.. rest_status_code:: error status.yaml

   - 401
   - 403
   - 404

Get system role assignment for a user
=====================================

.. rest_method::  GET /v3/system/users/{user_id}/roles/{role_id}

Get a specific system role assignment for a user. This is the same API as
``HEAD /v3/system/users/{user_id}/roles/{role_id}``.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/system_user_role``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - user_id: user_id_path
   - role_id: role_id_path

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

Delete a system role assignment from a user
===========================================

.. rest_method::  DELETE /v3/system/users/{user_id}/roles/{role_id}

Remove a system role assignment from a user.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/system_user_role``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - user_id: user_id_path
   - role_id: role_id_path

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

List system role assignments for a group
========================================

.. rest_method::  GET /v3/system/groups/{group_id}/roles

Lists all system role assignment a group has.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/system_group_roles``

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

   - links: link_response_body
   - roles: system_roles_response_body

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

.. literalinclude:: ./samples/admin/list-system-roles-for-group-response.json
   :language: javascript

The functionality of this request can also be achieved using the generalized
list assignments API::

  GET /role_assignments?group.id={group_id}&scope.system

Assign a system role to a group
===============================

.. rest_method::  PUT /v3/system/groups/{group_id}/roles/{role_id}

Grant a group a role on the system.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/system_group_role``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - group_id: group_id_path
   - role_id: role_id_path

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

Check group for a system role assignment
========================================

.. rest_method::  HEAD /v3/system/groups/{group_id}/roles/{role_id}

Check if a specific group has a role assignment on the system.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/system_group_role``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - group_id: group_id_path
   - role_id: role_id_path

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

Get system role assignment for a group
======================================

.. rest_method::  GET /v3/system/groups/{group_id}/roles/{role_id}

Get a specific system role assignment for a group. This is the same API as
``HEAD /v3/system/groups/{group_id}/roles/{role_id}``.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/system_group_role``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - group_id: group_id_path
   - role_id: role_id_path

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

Delete a system role assignment from a group
============================================

.. rest_method::  DELETE /v3/system/groups/{group_id}/roles/{role_id}

Remove a system role assignment from a group.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/system_group_role``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - group_id: group_id_path
   - role_id: role_id_path

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
