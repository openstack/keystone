.. -*- rst -*-

==========
 Projects
==========

A project is the base unit of ownership. Resources are owned by a
specific project. A project is owned by a specific domain.

(Since v3.4) You can create a hierarchy of projects by setting a
parent ID when you create projects. All projects in a hierarchy
must be owned by the same domain.

(Since v3.6) Optionally, you can create a project that behaves both
as a project and a domain. As a domain, the project provides a name
space in which you can create users, groups, and other projects. If
you create a project that behaves as a domain, you cannot update
this project to behave like a regular project.


List projects
=============

.. rest_method::  GET /v3/projects

Lists projects.

Normal response codes: 200
Error response codes: 413,405,404,403,401,400,503

Request
-------

.. rest_parameters:: parameters.yaml

   - domain_id: domain_id
   - parent_id: parent_id
   - name: name
   - enabled: enabled

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - is_domain: is_domain
   - description: description
   - links: links
   - enabled: enabled
   - domain_id: domain_id
   - parent_id: parent_id
   - id: id
   - projects: projects
   - name: name

Response Example
----------------

.. literalinclude:: ./samples/admin/projects-list-response.json
   :language: javascript


Create project
==============

.. rest_method::  POST /v3/projects

Creates a project.

Normal response codes: 201
Error response codes: 413,415,405,404,403,401,400,503,409

Request
-------

.. rest_parameters:: parameters.yaml

   - is_domain: is_domain
   - description: description
   - enabled: enabled
   - project: project
   - parent_id: parent_id
   - domain_id: domain_id
   - name: name

Request Example
---------------

.. literalinclude:: ./samples/admin/project-create-request.json
   :language: javascript

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - is_domain: is_domain
   - description: description
   - links: links
   - enabled: enabled
   - domain_id: domain_id
   - project: project
   - parent_id: parent_id
   - id: id
   - name: name


Show project details
====================

.. rest_method::  GET /v3/projects/{project_id}

Shows details for a project.

Normal response codes: 200
Error response codes: 413,405,404,403,401,400,503

Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - is_domain: is_domain
   - description: description
   - links: links
   - enabled: enabled
   - domain_id: domain_id
   - project: project
   - parent_id: parent_id
   - id: id
   - name: name

Response Example
----------------

.. literalinclude:: ./samples/admin/project-show-response.json
   :language: javascript


Update project
==============

.. rest_method::  PATCH /v3/projects/{project_id}

Updates a project.

Normal response codes: 200
Error response codes: 413,415,405,404,403,401,400,503,409

Request
-------

.. rest_parameters:: parameters.yaml

   - description: description
   - enabled: enabled
   - project: project
   - parent_id: parent_id
   - domain_id: domain_id
   - name: name
   - project_id: project_id

Request Example
---------------

.. literalinclude:: ./samples/admin/project-update-request.json
   :language: javascript

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - is_domain: is_domain
   - description: description
   - links: links
   - enabled: enabled
   - domain_id: domain_id
   - project: project
   - parent_id: parent_id
   - id: id
   - name: name

Response Example
----------------

.. literalinclude:: ./samples/admin/project-update-response.json
   :language: javascript


Delete project
==============

.. rest_method::  DELETE /v3/projects/{project_id}

Deletes a project.

Normal response codes: 204
Error response codes: 413,415,405,404,403,401,400,503,409

Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id


Enable or disable project and its subtree
=========================================

.. rest_method::  PATCH /v3/projects/{project_id}/cascade

(Since v3.6) Enables or disables a project and its entire subtree.

A project subtree includes all projects beneath the parent project
in the hierarchy.

If you include attributes other than the ``enabled`` attribute,
this call fails and returns the ``Bad Request (400)`` response
code.

If you perform this action against a project that acts as a domain
(``is_domain`` is set to ``true``, this call fails and returns the
``Forbidden (403)`` response code.


Normal response codes: 200
Error response codes: 413,415,405,404,403,401,400,503,409

Request
-------

.. rest_parameters:: parameters.yaml

   - project: project
   - enabled: enabled
   - project_id: project_id

Request Example
---------------

.. literalinclude:: ./samples/admin/project-enable-request.json
   :language: javascript

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - is_domain: is_domain
   - description: description
   - links: links
   - enabled: enabled
   - domain_id: domain_id
   - project: project
   - parent_id: parent_id
   - id: id
   - name: name

Response Example
----------------

.. literalinclude:: ./samples/admin/project-update-response.json
   :language: javascript


Delete project subtree
======================

.. rest_method::  DELETE /v3/projects/{project_id}/cascade

(Since v3.6) Deletes a project and its entire subtree.

A project subtree includes all projects beneath the parent project
in the hierarchy. You must disable the projects in the subtree
before you perform this operation.

Normal response codes: 204
Error response codes: 413,415,405,404,403,401,400,503,409

Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id
