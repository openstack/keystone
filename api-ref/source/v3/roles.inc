.. -*- rst -*-

=============
Roles (roles)
=============

Roles grant a user a set of permitted actions for either a specific
project or an entire domain.

You can grant roles to a user on a project, including projects
owned by other domains.

You can create, list, and delete roles. You can also list roles
assigned to a specified domain, project, or user.

You can list role assignments and, since v3.6, all role assignments
within a tree of projects. Use the query parameters to filter the
list because the role assignments list can be long. Some typical
examples are:

- List role assignments for the specified user:

  ::     GET /role_assignments?user.id={user_id}

- List role assignments for the specified project:

  ::     GET /role_assignments?scope.project.id={project_id}

- List all role assignments for a specified project and its sub-
  projects:

  ::     GET /role_assignments?scope.project.id={project_id}?includ
  e_subtree=true

  If you specify ``include_subtree=true``, you must also specify
  the ``scope.project.id``. Otherwise, this call returns the ``Bad
  Request (400)`` response code.

Each role assignment entity in the collection contains a link to
the assignment that created the entity.

Use the ``effective`` query parameter to list effective assignments
at the user, project, and domain level. This parameter allows for
the effects of group membership. The group role assignment entities
themselves are not returned in the collection. This represents the
effective role assignments that would be included in a scoped
token.

In the response, the ``links`` entity section for entities for
group members also contains a URL that enables access to the
membership of the group.

You can use the other query parameters with the ``effective``
parameter, such as:

- Determine what a user can actually do:

  ::     GET /role_assignments?user.id={user_id}    &    effective

- Get the equivalent set of role assignments that are included in a
  project-scoped token response:

  ::     GET /role_assignments?user.id={user_id}    &
  scope.project.id={project_id}    &    effective


Grant role to group on project
==============================

.. rest_method::  PUT /v3/projects/{project_id}/groups/{group_id}/roles/{role_id}

Grants a role to a group on a project.

Error response codes:204,413,415,405,404,403,401,400,503,409,

Request
-------

.. rest_parameters:: parameters.yaml

   - role_id: role_id
   - project_id: project_id
   - group_id: group_id


Check whether group has role on project
=======================================

.. rest_method::  HEAD /v3/projects/{project_id}/groups/{group_id}/roles/{role_id}

Validates that a group has a role on a project.

Error response codes:204,413,405,404,403,401,400,503,

Request
-------

.. rest_parameters:: parameters.yaml

   - role_id: role_id
   - project_id: project_id
   - group_id: group_id


Revoke role from group on project
=================================

.. rest_method::  DELETE /v3/projects/{project_id}/groups/{group_id}/roles/{role_id}

Revokes a role from a group on a project.

Error response codes:204,413,415,405,404,403,401,400,503,409,

Request
-------

.. rest_parameters:: parameters.yaml

   - role_id: role_id
   - project_id: project_id
   - group_id: group_id


Grant role to user on project
=============================

.. rest_method::  PUT /v3/projects/{project_id}/users/{user_id}/roles/{role_id}

Grants a role to a user on a project.

Error response codes:204,413,415,405,404,403,401,400,503,409,

Request
-------

.. rest_parameters:: parameters.yaml

   - role_id: role_id
   - project_id: project_id
   - user_id: user_id


Check whether user has role on project
======================================

.. rest_method::  HEAD /v3/projects/{project_id}/users/{user_id}/roles/{role_id}

Validates that a user has a role on a project.

Error response codes:204,413,405,404,403,401,400,503,

Request
-------

.. rest_parameters:: parameters.yaml

   - role_id: role_id
   - project_id: project_id
   - user_id: user_id


Revoke role from user on project
================================

.. rest_method::  DELETE /v3/projects/{project_id}/users/{user_id}/roles/{role_id}

Revokes a role from a user on a project.

Error response codes:204,413,415,405,404,403,401,400,503,409,

Request
-------

.. rest_parameters:: parameters.yaml

   - role_id: role_id
   - project_id: project_id
   - user_id: user_id


List roles for user on project
==============================

.. rest_method::  GET /v3/projects/{project_id}/users/{user_id}/roles

Lists roles for a user on a project.

Normal response codes: 200
Error response codes:413,405,404,403,401,400,503,

Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id
   - user_id: user_id

Response Example
----------------

.. literalinclude:: ./samples/admin/project-user-roles-list-response.json
   :language: javascript


List roles for group on project
===============================

.. rest_method::  GET /v3/projects/{project_id}/groups/{group_id}/roles

Lists roles for a group on a project.

Normal response codes: 200
Error response codes:413,405,404,403,401,400,503,

Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id
   - group_id: group_id

Response Example
----------------

.. literalinclude:: ./samples/admin/project-group-roles-list-response.json
   :language: javascript


Grant role to group on domain
=============================

.. rest_method::  PUT /v3/domains/{domain_id}/groups/{group_id}/roles/{role_id}

Grants a role to a group on a domain.

Error response codes:204,413,415,405,404,403,401,400,503,409,

Request
-------

.. rest_parameters:: parameters.yaml

   - domain_id: domain_id
   - role_id: role_id
   - group_id: group_id


Check whether group has role on domain
======================================

.. rest_method::  HEAD /v3/domains/{domain_id}/groups/{group_id}/roles/{role_id}

Validates that a group has a role on a domain.

Error response codes:204,413,405,404,403,401,400,503,

Request
-------

.. rest_parameters:: parameters.yaml

   - domain_id: domain_id
   - role_id: role_id
   - group_id: group_id


Revoke role from group on domain
================================

.. rest_method::  DELETE /v3/domains/{domain_id}/groups/{group_id}/roles/{role_id}

Revokes a role from a group on a domain.

Error response codes:204,413,415,405,404,403,401,400,503,409,

Request
-------

.. rest_parameters:: parameters.yaml

   - domain_id: domain_id
   - role_id: role_id
   - group_id: group_id


List roles for user on domain
=============================

.. rest_method::  GET /v3/domains/{domain_id}/users/{user_id}/roles

Lists roles for a user on a domain.

Normal response codes: 200
Error response codes:413,405,404,403,401,400,503,

Request
-------

.. rest_parameters:: parameters.yaml

   - domain_id: domain_id
   - user_id: user_id

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - roles: roles
   - id: id
   - links: links
   - name: name

Response Example
----------------

.. literalinclude:: ./samples/admin/domain-user-roles-list-response.json
   :language: javascript


List roles
==========

.. rest_method::  GET /v3/roles

Lists roles.

Normal response codes: 200
Error response codes:413,405,404,403,401,400,503,

Request
-------

.. rest_parameters:: parameters.yaml

   - name: name

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - roles: roles
   - id: id
   - links: links
   - name: name

Response Example
----------------

.. literalinclude:: ./samples/admin/roles-list-response.json
   :language: javascript


Create role
===========

.. rest_method::  POST /v3/roles

Creates a role.

Error response codes:201,413,415,405,404,403,401,400,503,409,

Request
-------

.. rest_parameters:: parameters.yaml

   - role: role
   - name: name

Request Example
---------------

.. literalinclude:: ./samples/admin/role-create-request.json
   :language: javascript

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - role: role
   - id: id
   - links: links
   - name: name


Grant role to user on domain
============================

.. rest_method::  PUT /v3/domains/{domain_id}/users/{user_id}/roles/{role_id}

Grants a role to a user on a domain.

Error response codes:204,413,415,405,404,403,401,400,503,409,

Request
-------

.. rest_parameters:: parameters.yaml

   - domain_id: domain_id
   - role_id: role_id
   - user_id: user_id


Check whether user has role on domain
=====================================

.. rest_method::  HEAD /v3/domains/{domain_id}/users/{user_id}/roles/{role_id}

Validates that a user has a role on a domain.

Error response codes:204,413,405,404,403,401,400,503,

Request
-------

.. rest_parameters:: parameters.yaml

   - domain_id: domain_id
   - role_id: role_id
   - user_id: user_id


Revoke role from user on domain
===============================

.. rest_method::  DELETE /v3/domains/{domain_id}/users/{user_id}/roles/{role_id}

Revokes a role from a user on a domain.

Error response codes:204,413,415,405,404,403,401,400,503,409,

Request
-------

.. rest_parameters:: parameters.yaml

   - domain_id: domain_id
   - role_id: role_id
   - user_id: user_id


List role assignments
=====================

.. rest_method::  GET /v3/role_assignments

Lists role assignments.

Normal response codes: 200
Error response codes:413,405,404,403,401,400,503,

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - role_assignments: role_assignments

Response Example
----------------

.. literalinclude:: ./samples/admin/role-assignments-list-response.json
   :language: javascript


Show role details
=================

.. rest_method::  GET /v3/roles/{role_id}

Shows details for a role.

Normal response codes: 200
Error response codes:413,405,404,403,401,400,503,

Request
-------

.. rest_parameters:: parameters.yaml

   - role_id: role_id

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - role: role
   - id: id
   - links: links
   - name: name

Response Example
----------------

.. literalinclude:: ./samples/admin/role-show-response.json
   :language: javascript


Update role
===========

.. rest_method::  PATCH /v3/roles/{role_id}

Updates a role.

Normal response codes: 200
Error response codes:413,415,405,404,403,401,400,503,409,

Request
-------

.. rest_parameters:: parameters.yaml

   - role: role
   - name: name
   - role_id: role_id

Request Example
---------------

.. literalinclude:: ./samples/admin/role-update-request.json
   :language: javascript

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - role: role
   - id: id
   - links: links
   - name: name

Response Example
----------------

.. literalinclude:: ./samples/admin/role-update-response.json
   :language: javascript


Delete role
===========

.. rest_method::  DELETE /v3/roles/{role_id}

Deletes a role.

Error response codes:204,413,415,405,404,403,401,400,503,409,

Request
-------

.. rest_parameters:: parameters.yaml

   - role_id: role_id


List roles for group on domain
==============================

.. rest_method::  GET /v3/domains/{domain_id}/groups/{group_id}/roles

Lists roles for a group on a domain.

Normal response codes: 200
Error response codes:413,405,404,403,401,400,503,

Request
-------

.. rest_parameters:: parameters.yaml

   - domain_id: domain_id
   - group_id: group_id

Response Example
----------------

.. literalinclude:: ./samples/admin/domain-group-roles-list-response.json
   :language: javascript
