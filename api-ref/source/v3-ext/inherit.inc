.. -*- rst -*-

================
 OS-INHERIT API
================

Enables projects to inherit role assignments from either their
owning domain or projects that are higher in the hierarchy.

(Since API v3.4) The OS-INHERIT extension allows inheritance from
both projects and domains. To access project inheritance, the
Identity service server must run at least API v3.4.


Assign role to user owned by domain projects
============================================

.. rest_method::  PUT /v3/OS-INHERIT/domains/{domain_id}/users/{user_id}/roles/{role_id}/inherited_to_projects

Assigns a role to a user in projects owned by a domain.

The API applies the inherited role to the existing and future owned
projects. The inherited role does not appear as a role in a domain-
scoped token.

Normal response codes: 204

Request
-------

.. rest_parameters:: parameters.yaml

   - user_id: user_id
   - role_id: role_id
   - domain_id: domain_id


Check project role for user in domain
=====================================

.. rest_method::  HEAD /v3/OS-INHERIT/domains/{domain_id}/users/{user_id}/roles/{role_id}/inherited_to_projects

Checks whether a user has an inherited project role in a domain.

Normal response codes: 200

Request
-------

.. rest_parameters:: parameters.yaml

   - user_id: user_id
   - role_id: role_id
   - domain_id: domain_id


Revoke project role from user in domain
=======================================

.. rest_method::  DELETE /v3/OS-INHERIT/domains/{domain_id}/users/{user_id}/roles/{role_id}/inherited_to_projects

Revokes an inherited project role from a user in a domain.

Normal response codes: 204

Request
-------

.. rest_parameters:: parameters.yaml

   - user_id: user_id
   - role_id: role_id
   - domain_id: domain_id


Assign role to group
====================

.. rest_method::  PUT /v3/OS-INHERIT/projects/{project_id}/groups/{group_id}/roles/{role_id}/inherited_to_projects

Assigns a role to a group in projects in a subtree.

The API anchors the inherited role assignment to a project and
applies it to its subtree in the projects hierarchy to both
existing and future projects.

A group can have both a regular, non-inherited role assignment and
an inherited role assignment in the same project.

Normal response codes: 204

Request
-------

.. rest_parameters:: parameters.yaml

   - group_id: group_id
   - role_id: role_id
   - project_id: project_id


Check role for group
====================

.. rest_method::  HEAD /v3/OS-INHERIT/projects/{project_id}/groups/{group_id}/roles/{role_id}/inherited_to_projects

Checks whether a group has a role assignment with the ``inherited_to_projects`` flag in a project.

Normal response codes: 200

Request
-------

.. rest_parameters:: parameters.yaml

   - group_id: group_id
   - role_id: role_id
   - project_id: project_id


Revoke role from group
======================

.. rest_method::  DELETE /v3/OS-INHERIT/projects/{project_id}/groups/{group_id}/roles/{role_id}/inherited_to_projects

Revokes an inherited role from a group in a project.

Normal response codes: 204

Request
-------

.. rest_parameters:: parameters.yaml

   - group_id: group_id
   - role_id: role_id
   - project_id: project_id


Assign role to group in domain projects
=======================================

.. rest_method::  PUT /v3/OS-INHERIT/domains/{domain_id}/groups/{group_id}/roles/{role_id}/inherited_to_projects

Assigns a role to a group in projects owned by a domain.

The API applies the inherited role to owned projects, both existing
and future. The inherited role does not appear as a role in a
domain-scoped token.

Normal response codes: 204

Request
-------

.. rest_parameters:: parameters.yaml

   - group_id: group_id
   - role_id: role_id
   - domain_id: domain_id


Check project role for group in domain
======================================

.. rest_method::  HEAD /v3/OS-INHERIT/domains/{domain_id}/groups/{group_id}/roles/{role_id}/inherited_to_projects

Checks whether a group has an inherited project role in a domain.

Normal response codes: 200

Request
-------

.. rest_parameters:: parameters.yaml

   - group_id: group_id
   - role_id: role_id
   - domain_id: domain_id


Revoke project role from group in domain
========================================

.. rest_method::  DELETE /v3/OS-INHERIT/domains/{domain_id}/groups/{group_id}/roles/{role_id}/inherited_to_projects

Revokes an inherited project role from a group in a domain.

Normal response codes: 204

Request
-------

.. rest_parameters:: parameters.yaml

   - group_id: group_id
   - role_id: role_id
   - domain_id: domain_id


Assign role to user
===================

.. rest_method::  PUT /v3/OS-INHERIT/projects/{project_id}/users/{user_id}/roles/{role_id}/inherited_to_projects

Assigns a role to a user in projects in a subtree.

The API anchors the inherited role assignment to a project and
applies it to its subtree in the projects hierarchy to both
existing and future projects.

A user can have both a regular, non-inherited role assignment and
an inherited role assignment in the same project.

Normal response codes: 204

Request
-------

.. rest_parameters:: parameters.yaml

   - user_id: user_id
   - role_id: role_id
   - project_id: project_id


Check role for user
===================

.. rest_method::  HEAD /v3/OS-INHERIT/projects/{project_id}/users/{user_id}/roles/{role_id}/inherited_to_projects

Checks whether a user has a role assignment with the ``inherited_to_projects`` flag in a project.

Normal response codes: 200

Request
-------

.. rest_parameters:: parameters.yaml

   - user_id: user_id
   - role_id: role_id
   - project_id: project_id


Revoke role from user
=====================

.. rest_method::  DELETE /v3/OS-INHERIT/projects/{project_id}/users/{user_id}/roles/{role_id}/inherited_to_projects

Revokes an inherited role from a user in a project.

Normal response codes: 204

Request
-------

.. rest_parameters:: parameters.yaml

   - user_id: user_id
   - role_id: role_id
   - project_id: project_id


List project roles for group in domain
======================================

.. rest_method::  GET /v3/OS-INHERIT/domains/{domain_id}/groups/{group_id}/roles/inherited_to_projects

Lists the project roles that a group inherits from a parent project in a domain.

Normal response codes: 200

Request
-------

.. rest_parameters:: parameters.yaml

   - group_id: group_id
   - domain_id: domain_id

Response Example
----------------

.. literalinclude:: samples/OS-INHERIT/group-roles-domain-list-response.json
   :language: javascript


List effective role assignments
===============================

.. rest_method::  GET /v3/role_assignments

Lists role assignments.

The scope section in the list response is extended to allow the
representation of role assignments that are inherited to projects.

The list of all role assignments can be long. To filter the list,
use the query parameters.

Some typical examples are:

``GET /role_assignments?user.id={user_id}`` lists all role
assignments for a user.

``GET /role_assignments?scope.project.id={project_id}`` lists all
role assignments for a project.

Each role assignment entity in the collection contains a link to
the assignment that created this entity.

Use the ``effective`` query parameter to list effective assignments
at the user, project, and domain level. This parameter allows for
the effects of group membership as well as inheritance from the
parent domain or project, for role assignments that were made using
OS-INHERIT assignment APIs.

The group role assignment entities themselves are not returned in
the collection. Because, like group membership, the effects of
inheritance have already been allowed for, the role assignment
entities themselves that specify the inheritance are not returned
in the collection. This represents the effective role assignments
that would be included in a scoped token. You can use the other
query parameters with the ``effective`` parameter.

For example, to determine what a user can actually do, issue this
request: ``GET /role_assignments?user.id={user_id} & effective``

To get the equivalent set of role assignments that would be
included in the token response of a project-scoped token, issue
``GET /role_assignments?user.id={user_id} &
scope.project.id={project_id} & effective``

In the response, the entity ``links`` section for entities that are
included by virtue of group members also contains a url that you
can use to access the membership of the group.

Use the ``scope.OS-INHERIT:inherited_to`` query parameter to filter
the response by inherited role assignments. The ``scope.OS-
INHERIT:inherited_to`` value of ``projects`` is currently
supported. This value indicates that this role is inherited to all
projects of the owning domain or parent project.

An example response for an API call with the ``effective`` query
string:

Normal response codes: 200
Error response codes: 413,405,404,403,401,400,503

Response Example
----------------

.. literalinclude:: samples/OS-INHERIT/role-assignments-effective-list-response.json
   :language: javascript


List project roles for user in domain
=====================================

.. rest_method::  GET /v3/OS-INHERIT/domains/{domain_id}/users/{user_id}/roles/inherited_to_projects

Lists the project roles that a user inherits from a parent project in a domain.

Normal response codes: 200

Request
-------

.. rest_parameters:: parameters.yaml

   - user_id: user_id
   - domain_id: domain_id

Response Example
----------------

.. literalinclude:: samples/OS-INHERIT/user-roles-domain-list-response.json
   :language: javascript


List roles for group
====================

.. rest_method::  GET /v3/OS-INHERIT/projects/{project_id}/groups/{group_id}/roles/inherited_to_projects

Lists the project roles that a group in a project inherits from a parent project.

The list shows only roles that the group project inherits from the
parent project.

Normal response codes: 200

Request
-------

.. rest_parameters:: parameters.yaml

   - group_id: group_id
   - project_id: project_id

Response Example
----------------

.. literalinclude:: samples/OS-INHERIT/group-roles-list-response.json
   :language: javascript


List inherited roles for user
=============================

.. rest_method::  GET /v3/OS-INHERIT/projects/{project_id}/users/{user_id}/roles/inherited_to_projects

Lists the project roles that a user in a project inherits from a parent project.

The list shows only roles that the user project inherits from the
parent project.

Normal response codes: 200

Request
-------

.. rest_parameters:: parameters.yaml

   - user_id: user_id
   - project_id: project_id

Response Example
----------------

.. literalinclude:: samples/OS-INHERIT/user-roles-list-response.json
   :language: javascript
