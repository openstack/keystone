.. -*- rst -*-

================
 OS-INHERIT
================

Enables projects to inherit role assignments from either their
owning domain or projects that are higher in the hierarchy.

(Since API v3.4) The OS-INHERIT extension allows inheritance from
both projects and domains. To access project inheritance, the
Identity service server must run at least API v3.4.


Assign role to user on projects owned by domain
===============================================

.. rest_method::  PUT /v3/OS-INHERIT/domains/{domain_id}/users/{user_id}/roles/{role_id}/inherited_to_projects

Assigns a role to a user in projects owned by a domain.

The inherited role is only applied to the owned projects (both existing and
future projects), and will not appear as a role in a domain scoped token.

Relationship:
``https://docs.openstack.org/api/openstack-identity/3/ext/OS-INHERIT/1.0/rel/domain_user_role_inherited_to_projects``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - domain_id: domain_id_path
   - role_id: role_id_path
   - user_id: user_id_path

Response
--------

Status Codes
~~~~~~~~~~~~~

.. rest_status_code:: success status.yaml

   - 204

Assign role to group on projects owned by a domain
==================================================

.. rest_method::  PUT /v3/OS-INHERIT/domains/{domain_id}/groups/{group_id}/roles/{role_id}/inherited_to_projects

The inherited role is only applied to the owned projects (both existing and
future projects), and will not appear as a role in a domain scoped token.

Relationship:
``https://docs.openstack.org/api/openstack-identity/3/ext/OS-INHERIT/1.0/rel/domain_group_role_inherited_to_projects``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - domain_id: domain_id_path
   - group_id: role_id_path
   - role_id: user_id_path

Response
--------

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success status.yaml

   - 204

List user's inherited project roles on a domain
===============================================

.. rest_method::  GET /v3/OS-INHERIT/domains/{domain_id}/users/{user_id}/roles/inherited_to_projects

The list only contains those role assignments to the domain that were specified
as being inherited to projects within that domain.

Relationship:
``https://docs.openstack.org/api/openstack-identity/3/ext/OS-INHERIT/1.0/rel/domain_user_roles_inherited_to_projects``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - domain_id: domain_id_path
   - user_id: user_id_path

Response
--------

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success status.yaml

   - 200

Example
~~~~~~~

.. literalinclude:: samples/admin/user-roles-domain-list-response.json
   :language: javascript


List group's inherited project roles on domain
==============================================

.. rest_method::  GET /v3/OS-INHERIT/domains/{domain_id}/groups/{group_id}/roles/inherited_to_projects

The list only contains those role assignments to the domain that were specified
as being inherited to projects within that domain.

Relationship:
``https://docs.openstack.org/api/openstack-identity/3/ext/OS-INHERIT/1.0/rel/domain_group_roles_inherited_to_projects``

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

Example
-------

.. literalinclude:: samples/admin/group-roles-domain-list-response.json
   :language: javascript


Check if user has an inherited project role on domain
=====================================================

.. rest_method::  HEAD /v3/OS-INHERIT/domains/{domain_id}/users/{user_id}/roles/{role_id}/inherited_to_projects

Checks whether a user has an inherited project role in a domain.

Relationship:
``https://docs.openstack.org/api/openstack-identity/3/ext/OS-INHERIT/1.0/rel/domain_user_role_inherited_to_projects``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - domain_id: domain_id_path
   - role_id: role_id_path
   - user_id: user_id_path

Response
--------

Status Codes
~~~~~~~~~~~~
.. rest_status_code:: success status.yaml

   - 204

Check if group has an inherited project role on domain
======================================================

.. rest_method::  HEAD /v3/OS-INHERIT/domains/{domain_id}/groups/{group_id}/roles/{role_id}/inherited_to_projects

Checks whether a group has an inherited project role in a domain.

Relationship:
``https://docs.openstack.org/api/openstack-identity/3/ext/OS-INHERIT/1.0/rel/domain_group_role_inherited_to_projects``

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

Revoke an inherited project role from user on domain
====================================================

.. rest_method::  DELETE /v3/OS-INHERIT/domains/{domain_id}/users/{user_id}/roles/{role_id}/inherited_to_projects

Revokes an inherited project role from a user in a domain.

Relationship:
``https://docs.openstack.org/api/openstack-identity/3/ext/OS-INHERIT/1.0/rel/domain_user_role_inherited_to_projects``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - domain_id: domain_id_path
   - role_id: role_id_path
   - user_id: user_id_path

Response
--------

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success status.yaml

   - 204

Revoke an inherited project role from group on domain
=====================================================

.. rest_method::  DELETE /v3/OS-INHERIT/domains/{domain_id}/groups/{group_id}/roles/{role_id}/inherited_to_projects

Revokes an inherited project role from a group in a domain.

Relationship:
``https://docs.openstack.org/api/openstack-identity/3/ext/OS-INHERIT/1.0/rel/domain_group_role_inherited_to_projects``

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

Assign role to user on projects in a subtree
============================================

.. rest_method::  PUT /v3/OS-INHERIT/projects/{project_id}/users/{user_id}/roles/{role_id}/inherited_to_projects

The inherited role assignment is anchored to a project and applied to its
subtree in the projects hierarchy (both existing and future projects).

* Note: The inherited role is not applied to the project itself, and only
  applied to its subtree projects.
* Note: It is possible for a user to have both a regular (non-inherited) and an
  inherited role assignment on the same project.
* Note: The request doesn't require a body, which will be ignored if provided.

Relationship:
``https://docs.openstack.org/api/openstack-identity/3/ext/OS-INHERIT/1.0/rel/project_user_role_inherited_to_projects``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - project_id: project_id
   - role_id: role_id_path
   - user_id: user_id_path

Response
--------

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success status.yaml

   - 204

Assign role to group on projects in a subtree
=============================================

.. rest_method::  PUT /v3/OS-INHERIT/projects/{project_id}/groups/{group_id}/roles/{role_id}/inherited_to_projects

The inherited role assignment is anchored to a project and applied to its
subtree in the projects hierarchy (both existing and future projects).

* Note: The inherited role is not applied to the project itself, and only
  applied to its subtree projects.
* Note: It is possible for a group to have both a regular (non-inherited) and
  an inherited role assignment on the same project.
* Note: The request doesn't require a body, which will be ignored if provided.

Relationship:
``https://docs.openstack.org/api/openstack-identity/3/ext/OS-INHERIT/1.0/rel/project_group_role_inherited_to_projects``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - group_id: group_id_path
   - project_id: project_id_path
   - role_id: role_id_path

Response
--------

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success status.yaml

   - 204

Check if user has an inherited project role on project
======================================================

.. rest_method::  HEAD /v3/OS-INHERIT/projects/{project_id}/users/{user_id}/roles/{role_id}/inherited_to_projects

Checks whether a user has a role assignment with the ``inherited_to_projects`` flag in a project.

Relationship:
``https://docs.openstack.org/api/openstack-identity/3/ext/OS-INHERIT/1.0/rel/project_user_role_inherited_to_projects``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
   - role_id: role_id_path
   - user_id: user_id_path

Response
--------

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success status.yaml

   - 204

Check if group has an inherited project role on project
=======================================================

.. rest_method::  HEAD /v3/OS-INHERIT/projects/{project_id}/groups/{group_id}/roles/{role_id}/inherited_to_projects

Checks whether a group has a role assignment with the ``inherited_to_projects`` flag in a project.

Relationship:
``https://docs.openstack.org/api/openstack-identity/3/ext/OS-INHERIT/1.0/rel/project_group_role_inherited_to_projects``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - group_id: group_id_path
   - project_id: project_id_path
   - role_id: role_id_path

Response
--------

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success status.yaml

   - 204

Revoke an inherited project role from user on project
=====================================================

.. rest_method::  DELETE /v3/OS-INHERIT/projects/{project_id}/users/{user_id}/roles/{role_id}/inherited_to_projects

Relationship:
``https://docs.openstack.org/api/openstack-identity/3/ext/OS-INHERIT/1.0/rel/project_user_role_inherited_to_projects``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
   - role_id: role_id_path
   - user_id: user_id_path

Response
--------

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success status.yaml

   - 204

Revoke an inherited project role from group on project
======================================================

.. rest_method::  DELETE /v3/OS-INHERIT/projects/{project_id}/groups/{group_id}/roles/{role_id}/inherited_to_projects

Relationship:
``https://docs.openstack.org/api/openstack-identity/3/ext/OS-INHERIT/1.0/rel/project_group_role_inherited_to_projects``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - group_id: group_id_path
   - project_id: project_id_path
   - role_id: role_id_path

Response
--------

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success status.yaml

   - 204

List role assignments
=====================

.. rest_method::  GET /v3/role_assignments

Get a list of role assignments.

If no query parameters are specified, then this API will return a list of all
role assignments.

.. literalinclude:: samples/admin/role-assignments-list-response.json
   :language: javascript

Since this list is likely to be very long, this API would typically always be
used with one of more of the filter queries. Some typical examples are:

``GET /v3/role_assignments?user.id={user_id}`` would list all role assignments
involving the specified user.

``GET /v3/role_assignments?scope.project.id={project_id}`` would list all role
assignments involving the specified project.

It is also possible to list all role assignments within
a tree of projects:
``GET /v3/role_assignments?scope.project.id={project_id}&include_subtree=true``
would list all role assignments involving the specified project and all
sub-projects. ``include_subtree=true`` can only be specified in conjunction
with ``scope.project.id``, specifiying it without this will result in an
HTTP 400 Bad Request being returned.

Each role assignment entity in the collection contains a link to the assignment
that gave rise to this entity.

The scope section in the list response is extended to allow the representation
of role assignments that are inherited to projects.

.. literalinclude:: samples/admin/role-assignments-list-include-subtree-response.json
   :language: javascript

The query filter ``scope.OS-INHERIT:inherited_to`` can be used to filter based
on role assignments that are inherited. The only value of
``scope.OS-INHERIT:inherited_to`` that is currently supported is ``projects``,
indicating that this role is inherited to all projects of the owning domain or
parent project.

If the query parameter ``effective`` is specified, rather than simply returning
a list of role assignments that have been made, the API returns a list of
effective assignments at the user, project and domain level, having allowed for
the effects of group membership, role inference rules as well as inheritance
from the parent domain or project. Since the effects of group membership have
already been allowed for, the group role assignment entities themselves will
not be returned in the collection. Likewise, since the effects of inheritance
have already been allowed for, the role assignment entities themselves that
specify the inheritance will also not be returned in the collection. This
represents the effective role assignments that would be included in a scoped
token. The same set of query parameters can also be used in combination with
the ``effective`` parameter.

For example:

``GET /v3/role_assignments?user.id={user_id}&effective`` would, in other words,
answer the question "what can this user actually do?".

``GET
/v3/role_assignments?user.id={user_id}&scope.project.id={project_id}&effective``
would return the equivalent set of role assignments that would be included in
the token response of a project scoped token.

An example response for an API call with the query parameter ``effective``
specified is given below:

.. literalinclude:: samples/admin/role-assignments-effective-list-response.json
   :language: javascript

The entity ``links`` section of a response using the ``effective`` query
parameter also contains, for entities that are included by virtue of group
membership, a url that can be used to access the membership of the group.

If the query parameter ``include_names`` is specified, rather than simply
returning the entity IDs in the role assignments, the collection will
additionally include the names of the entities. For example:

``GET /v3/role_assignments?user.id={user_id}&effective&include_names=true``
would return:

.. literalinclude:: samples/admin/role-assignments-effective-list-include-names-response.json
   :language: javascript

Relationship:
``https://docs.openstack.org/api/openstack-identity/3/rel/role_assignments``

Request
-------

Parameters
~~~~~~~~~~

Optional query parameters:

.. rest_parameters:: parameters.yaml

   - effective: effective_query
   - include_names: include_names_query
   - include_subtree: include_subtree_query
   - group.id: group_id_query
   - role.id: role_id_query
   - scope.domain.id: scope_domain_id_query
   - scope.OS-INHERIT:inherited_to: scope_os_inherit_inherited_to
   - scope.project.id: scope_project_id_query
   - user.id: user_id_query

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
   - 405
   - 413
   - 503