.. -*- rst -*-

=====
Roles
=====

OpenStack services typically determine whether a user's API request should be
allowed using Role Based Access Control (RBAC). For OpenStack this means the
service compares the roles that user has on the project (as indicated by the
roles in the token), against the roles required for the API in question
(as defined in the service's policy file). A user obtains roles on a project by
having these assigned to them via the Identity service API.

Roles must initially be created as entities via the Identity services API and,
once created, can then be assigned. You can assign roles to a user or group on a
project, including projects owned by other domains. You can also assign roles
to a user or group on a domain, although this is only currently relevant for
using a domain scoped token to execute domain-level Identity service API
requests.

The creation, checking and deletion of role assignments is done with each of
the attributes being specified in the URL. For example to assign a role to a
user on a project::

  PUT /v3/projects/{project_id}/users/{user_id}/roles/{role_id}

You can also list roles assigned to the system, or to a specified domain,
project, or user using this form of API, however a more generalized API for
list assignments is provided where query parameters are used to filter the set
of assignments returned in the collection. For example:

- List role assignments for the specified user::

    GET /role_assignments?user.id={user_id}

- List role assignments for the specified project::

    GET /role_assignments?scope.project.id={project_id}

- List system role assignments for a specific user::

    GET /role_assignments?scope.system=all?user.id={user_id}

- List system role assignments for all users and groups::

    GET /role_assignments?scope.system=all

Since Identity API v3.10, you can grant role assignments to users and groups on
an entity called the ``system``. The role assignment API also supports listing
and filtering role assignments on the system.

Since Identity API v3.6, you can also list all role assignments within a tree of projects,
for example the following would list all role assignments for a specified
project and its sub-projects::

  GET /role_assignments?scope.project.id={project_id}&include_subtree=true

If you specify ``include_subtree=true``, you must also specify the
``scope.project.id``. Otherwise, this call returns the ``Bad Request (400)``
response code.

Each role assignment entity in the collection contains a link to
the assignment that created the entity.

As mentioned earlier, role assignments can be made to a user or a group on a
particular project, domain, or the entire system. A user who is a member of a
group that has a role assignment, will also be treated as having that role
assignment by virtue of their group membership. The *effective* role
assignments of a user (on a given project or domain) therefore consists of any
direct assignments they have, plus any they gain by virtue of membership of
groups that also have assignments on the given project or domain. This set of
effective role assignments is what is placed in the token for reference by
services wishing to check policy. You can list the effective role assignments
using the ``effective`` query parameter at the user, project, and domain level:

- Determine what a user can actually do::

    GET /role_assignments?user.id={user_id}&effective

- Get the equivalent set of role assignments that are included in a
  project-scoped token response::

    GET /role_assignments?user.id={user_id}&scope.project.id={project_id}&effective

When listing in effective mode, since the group assignments have been
effectively expanded out into assignments for each user, the group role
assignment entities themselves are not returned in the collection. However,
in the response, the ``links`` entity section for each assignment gained by
virtue of group membership will contain a URL that enables access to the
membership of the group.

By default only the IDs of entities are returned in collections from the
role_assignment API calls. The names of entities may also be returned,
in addition to the IDs, by using the ``include_names`` query parameter
on any of these calls, for example:

- List role assignments including names::

    GET /role_assignments?include_names


List roles
==========

.. rest_method::  GET /v3/roles

Lists roles.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/roles``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - name: role_name_query
   - domain_id: domain_id_query

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - links: link_collection
   - roles: roles
   - domain_id: domain_id_response_body
   - id: role_id_response_body
   - links: link_response_body
   - name: role_name_response_body

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

.. literalinclude:: ./samples/admin/roles-list-response.json
   :language: javascript


Create role
===========

.. rest_method::  POST /v3/roles

Creates a role.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/roles``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - role: role
   - name: role_name_create_body
   - domain_id: role_domain_id_request_body

Example
~~~~~~~

.. literalinclude:: ./samples/admin/role-create-request.json
   :language: javascript

Example for Domain Specific Role
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. literalinclude:: ./samples/admin/domain-specific-role-create-request.json
   :language: javascript

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - role: role
   - domain_id: domain_id_response_body
   - id: role_id_response_body
   - links: link_response_body
   - name: role_name_response_body

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success status.yaml

   - 201

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 409


Show role details
=================

.. rest_method::  GET /v3/roles/{role_id}

Shows details for a role.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/role``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - role_id: role_id_path

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - role: role
   - domain_id: domain_id_response_body
   - id: role_id_response_body
   - links: link_response_body
   - name: role_name_response_body

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

.. literalinclude:: ./samples/admin/role-show-response.json
   :language: javascript


Update role
===========

.. rest_method::  PATCH /v3/roles/{role_id}

Updates a role.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/role``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - role_id: role_id_path
   - role: role
   - name: role_name_update_body

Example
~~~~~~~

.. literalinclude:: ./samples/admin/role-update-request.json
   :language: javascript

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - role: role
   - domain_id: domain_id_response_body
   - id: role_id_response_body
   - links: link_response_body
   - name: role_name_response_body

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

Example
~~~~~~~

.. literalinclude:: ./samples/admin/role-update-response.json
   :language: javascript


Delete role
===========

.. rest_method::  DELETE /v3/roles/{role_id}

Deletes a role.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/role``

Request
-------

Parameters
~~~~~~~~~~
.. rest_parameters:: parameters.yaml

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


List role assignments for group on domain
=========================================

.. rest_method::  GET /v3/domains/{domain_id}/groups/{group_id}/roles

Lists role assignments for a group on a domain.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/domain_group_roles``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - domain_id: domain_id_path
   - group_id: group_id_path

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

Example
~~~~~~~

.. literalinclude:: ./samples/admin/domain-group-roles-list-response.json
   :language: javascript

The functionality of this request can also be achieved using the generalized
list assignments API::

  GET /role_assignments?group.id={group_id}&scope.domain.id={domain_id}


Assign role to group on domain
==============================

.. rest_method::  PUT /v3/domains/{domain_id}/groups/{group_id}/roles/{role_id}

Assigns a role to a group on a domain.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/domain_group_role``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - domain_id: domain_id_path
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
   - 409

Check whether group has role assignment on domain
=================================================

.. rest_method::  HEAD /v3/domains/{domain_id}/groups/{group_id}/roles/{role_id}

Validates that a group has a role assignment on a domain.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/domain_group_role``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - domain_id: domain_id_path
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


Unassign role from group on domain
==================================

.. rest_method::  DELETE /v3/domains/{domain_id}/groups/{group_id}/roles/{role_id}

Unassigns a role from a group on a domain.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/domain_group_role``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - domain_id: domain_id_path
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


List role assignments for user on domain
========================================

.. rest_method::  GET /v3/domains/{domain_id}/users/{user_id}/roles

Lists role assignments for a user on a domain.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/domain_user_roles``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - domain_id: domain_id_path
   - user_id: user_id_path

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - roles: roles
   - id: role_id_response_body
   - links: link_response_body
   - name: role_name_response_body

Status Codes
~~~~~~~~~~~~~~

.. rest_status_code:: success status.yaml

   - 200

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403

Example
~~~~~~~

.. literalinclude:: ./samples/admin/domain-user-roles-list-response.json
   :language: javascript

The functionality of this request can also be achieved using the generalized
list assignments API::

  GET /role_assignments?user.id={user_id}&scope.domain.id={domain_id}


Assign role to user on domain
=============================

.. rest_method::  PUT /v3/domains/{domain_id}/users/{user_id}/roles/{role_id}

Assigns a role to a user on a domain.

Relationship: ``https://developer.openstack.org/api-ref/identity/v3/index.html#assign-role-to-user-on-domain``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - domain_id: domain_id_path
   - user_id: user_id_path
   - role_id: role_id_path

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

Check whether user has role assignment on domain
================================================

.. rest_method::  HEAD /v3/domains/{domain_id}/users/{user_id}/roles/{role_id}

Validates that a user has a role assignment on a domain.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/domain_user_role``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - domain_id: domain_id_path
   - user_id: user_id_path
   - role_id: role_id_path

Response
--------

Status Codes
~~~~~~~~~~~~~

.. rest_status_code:: success status.yaml

   - 204

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404


Unassigns role from user on domain
==================================

.. rest_method::  DELETE /v3/domains/{domain_id}/users/{user_id}/roles/{role_id}

Unassigns a role from a user on a domain.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/domain_user_role``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - domain_id: domain_id_path
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
   - 409


List role assignments for group on project
==========================================

.. rest_method::  GET /v3/projects/{project_id}/groups/{group_id}/roles

Lists role assignments for a group on a project.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/project_user_role``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
   - group_id: group_id_path

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

Example
~~~~~~~

.. literalinclude:: ./samples/admin/project-group-roles-list-response.json
   :language: javascript

The functionality of this request can also be achieved using the generalized
list assignments API::

  GET /role_assignments?group.id={group_id}&scope.project.id={project_id}


Assign role to group on project
===============================

.. rest_method::  PUT /v3/projects/{project_id}/groups/{group_id}/roles/{role_id}

Assigns a role to a group on a project.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/project_group_role``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
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
   - 409


Check whether group has role assignment on project
==================================================

.. rest_method::  HEAD /v3/projects/{project_id}/groups/{group_id}/roles/{role_id}

Validates that a group has a role assignment on a project.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/project_group_role``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
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


Unassign role from group on project
===================================

.. rest_method::  DELETE /v3/projects/{project_id}/groups/{group_id}/roles/{role_id}

Unassigns a role from a group on a project.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/project_group_role``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
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


List role assignments for user on project
=========================================

.. rest_method::  GET /v3/projects/{project_id}/users/{user_id}/roles

Lists role assignments for a user on a project.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/project_user_role``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
   - user_id: user_id_path

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

Example
~~~~~~~

.. literalinclude:: ./samples/admin/project-user-roles-list-response.json
   :language: javascript

The functionality of this request can also be achieved using the generalized
list assignments API::

  GET /role_assignments?user.id={user_id}&scope.project.id={project_id}


Assign role to user on project
==============================

.. rest_method::  PUT /v3/projects/{project_id}/users/{user_id}/roles/{role_id}

Assigns a role to a user on a project.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/project_user_role``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
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
   - 409


Check whether user has role assignment on project
=================================================

.. rest_method::  HEAD /v3/projects/{project_id}/users/{user_id}/roles/{role_id}

Validates that a user has a role on a project.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/project_user_role``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
   - user_id: user_id_path
   - role_id: role_id_path

Response
--------

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success status.yaml

   - 201

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404


Unassign role from user on project
==================================

.. rest_method::  DELETE /v3/projects/{project_id}/users/{user_id}/roles/{role_id}

Unassigns a role from a user on a project.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/project_user_role``

Request
-------

Parameters
~~~~~~~~~~
.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
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


List implied (inference) roles for role
=======================================

.. rest_method:: GET /v3/roles/{prior_role_id}/implies

Lists implied (inference) roles for a role.

Relationship:
``https://developer.openstack.org/api-ref/identity/v3/#list-implied-roles-for-role``

Request
-------

Parameters
~~~~~~~~~~
.. rest_parameters:: parameters.yaml

   - prior_role_id: prior_role_id

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - role_inference: role_inference_body
   - prior_role: prior_role_body
   - implies: implies_role_array_body
   - id: role_id_response_body
   - links: link_response_body
   - name: role_name_response_body

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success status.yaml

   - 200

.. rest_status_code:: error status.yaml

   - 401
   - 404

Example
~~~~~~~

.. literalinclude:: ./samples/admin/list-implied-roles-for-role-response.json
   :language: javascript


Create role inference rule
==========================

.. rest_method:: PUT /v3/roles/{prior_role_id}/implies/{implies_role_id}

Creates a role inference rule.

Relationship:
``https://developer.openstack.org/api-ref/identity/v3/#create-role-inference-rule``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - prior_role_id: prior_role_id
   - implies_role_id: implies_role_id

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - role_inference: role_inference_body
   - prior_role: prior_role_body
   - implies: implies_role_object_body
   - id: role_id_response_body
   - links: link_response_body
   - name: role_name_response_body

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success status.yaml

   - 201

.. rest_status_code:: error status.yaml

   - 401
   - 404

Example
~~~~~~~

.. literalinclude:: ./samples/admin/create-role-inferences-response.json
   :language: javascript


Get role inference rule
=======================

.. rest_method:: GET /v3/roles/{prior_role_id}/implies/{implies_role_id}

Gets a role inference rule.

Relationship:
``https://developer.openstack.org/api-ref/identity/v3/#get-role-inference-rule``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - prior_role_id: prior_role_id
   - implies_role_id: implies_role_id

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - role_inference: role_inference_body
   - prior_role: prior_role_body
   - implies: implies_role_object_body
   - id: role_id_response_body
   - links: link_response_body
   - name: role_name_response_body

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success status.yaml

   - 200

.. rest_status_code:: error status.yaml

   - 401
   - 404

Example
~~~~~~~

.. literalinclude:: ./samples/admin/get-role-inferences-response.json
   :language: javascript


Confirm role inference rule
===========================

.. rest_method:: HEAD /v3/roles/{prior_role_id}/implies/{implies_role_id}

Checks a role role inference rule.

Relationship:
``https://developer.openstack.org/api-ref/identity/v3/#confirm-role-inference-rule``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - prior_role_id: prior_role_id
   - implies_role_id: implies_role_id

Response
--------

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success status.yaml

   - 204

.. rest_status_code:: error status.yaml

   - 401
   - 404

Example
~~~~~~~

Status: 204 No Content


Delete role inference rule
==========================

.. rest_method:: DELETE /v3/roles/{prior_role_id}/implies/{implies_role_id}

Deletes a role inference rule.

Relationship:
``https://developer.openstack.org/api-ref/identity/v3/#delete-role-inference-rule``

Request
-------

Parameters
~~~~~~~~~~
.. rest_parameters:: parameters.yaml

   - prior_role_id: prior_role_id
   - implies_role_id: implies_role_id

Response
--------

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success status.yaml

   - 204

.. rest_status_code:: error status.yaml

   - 401
   - 404

Example
~~~~~~~

Status: 204 No Content


List role assignments
=====================

.. rest_method::  GET /v3/role_assignments

Lists role assignments.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/role_assignments``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - effective: effective_query
   - include_names: include_names_query
   - include_subtree: include_subtree_query
   - group.id: group_id_query
   - role.id: role_id_query
   - scope.system: scope_system_query
   - scope.domain.id: scope_domain_id_query
   - scope.project.id: scope_project_id_query
   - user.id: user_id_query

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - role_assignments: role_assignments

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

.. literalinclude:: ./samples/admin/role-assignments-list-response.json
   :language: javascript


List all role inference rules
=============================

.. rest_method:: GET /v3/role_inferences

Lists all role inference rules.

Relationship:
``https://developer.openstack.org/api-ref/identity/v3/#list-all-role-inference-rules``

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - role_inferences: role_inference_array_body
   - prior_role: prior_role_body
   - implies: implies_role_object_body
   - id: role_id_response_body
   - links: link_response_body
   - name: role_name_response_body

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success status.yaml

   - 200

.. rest_status_code:: error status.yaml

   - 401
   - 404

Example
~~~~~~~

.. literalinclude:: ./samples/admin/role-inferences-response.json
   :language: javascript
