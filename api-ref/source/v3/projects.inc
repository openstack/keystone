.. -*- rst -*-

==========
 Projects
==========

A project is the base unit of resource ownership. Resources are owned by a
specific project. A project is owned by a specific domain.

(Since Identity API v3.4) You can create a hierarchy of projects by setting a
``parent_id`` when you create a project. All projects in a hierarchy must be
owned by the same domain.

(Since Identity API v3.6) Projects may, in addition to acting as containers for
OpenStack resources, act as a domain (by setting the attribute ``is_domain`` to
``true``), in which case it provides a namespace in which users, groups and
other projects can be created. In fact, a domain created using the
``POST /domains`` API will actually be represented as a project with
``is_domain`` set to ``true`` with no parent (``parent_id`` is null).

Given this, all projects are considered part of a project hierarchy. Projects
created in a domain prior to v3.6 are represented as a two-level hierarchy,
with a project that has ``is_domain`` set to ``true`` as the root and all other
projects referencing the root as their parent.

A project acting as a domain can potentially also act as a container for
OpenStack resources, although this depends on whether the policy rule for the
relevant resource creation allows this.

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

Projects that are acting as a domain (i.e. with ``parent_id`` set to
``true``) must also be specified with no parent (i.e. if ``parent_id`` is
included it must be null). Issuing a create project request for a project
acting as a domain with a ``parent_id`` that is not null will fail with a
``Bad Request (400)`` response code being returned.

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

(Since Identity API v3.6) Enables or disables a project and its entire subtree.

A project subtree includes all projects beneath the parent project
in the hierarchy.

If you include attributes other than the ``enabled`` attribute,
this call fails and returns the ``Bad Request (400)`` response
code.

If you perform this action against a project that acts as a domain
(``is_domain`` is set to ``true``), this call fails and returns the
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

(Since Identity API v3.6) Deletes a project and its entire subtree.

A project subtree includes all projects beneath the parent project
in the hierarchy. You must disable all the projects in the subtree
before you perform this operation.

Normal response codes: 204
Error response codes: 413,415,405,404,403,401,400,503,409

Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id
