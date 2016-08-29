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

Relationship: ``http://docs.openstack.org/api/openstack-identity/3/rel/projects``

Lists projects.

Normal response codes: 200

Error response codes: 413,405,404,403,401,400,503

Request
-------

.. rest_parameters:: parameters.yaml

   - domain_id: domain_id_query
   - enabled: project_enabled_query
   - is_domain: is_domain_query
   - name: project_name_query
   - parent_id: parent_id_query

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - links: link_collection
   - projects: projects
   - is_domain: is_domain_response_body
   - description: project_description_response_body
   - domain_id: project_domain_id_response_body
   - enabled: project_enabled_response_body
   - id: project_id
   - links: link_response_body
   - name: project_name_response_body
   - parent_id: project_parent_id_response_body

Response Example
----------------

.. literalinclude:: ./samples/admin/projects-list-response.json
   :language: javascript


Create project
==============

.. rest_method::  POST /v3/projects

Relationship: ``http://docs.openstack.org/api/openstack-identity/3/rel/projects``

Creates a project, including a project acting as a domain.

Normal response codes: 201

Error response codes: 413,415,405,404,403,401,400,503,409

Request
-------

.. rest_parameters:: parameters.yaml

   - project: project
   - is_domain: is_domain_request_body
   - description: project_description_request_body
   - domain_id: project_domain_id_request_body
   - enabled: project_enabled_request_body
   - name: project_name_request_body
   - parent_id: project_parent_id_request_body

Request Examples
----------------

.. literalinclude:: ./samples/admin/project-create-request.json
   :language: javascript

.. literalinclude:: ./samples/admin/project-create-domain-request.json
   :language: javascript

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - project: project
   - is_domain: is_domain_response_body
   - description: project_description_response_body
   - domain_id: project_domain_id_response_body
   - enabled: project_enabled_response_body
   - id: project_id
   - links: link_response_body
   - name: project_name_response_body
   - parent_id: project_parent_id_response_body


Show project details
====================

.. rest_method::  GET /v3/projects/{project_id}

Relationship: ``http://docs.openstack.org/api/openstack-identity/3/rel/project``

Shows details for a project.

Normal response codes: 200

Error response codes: 413,405,404,403,401,400,503

Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
   - parents_as_list: parents_as_list
   - subtree_as_list: subtree_as_list
   - parents_as_ids: parents_as_ids
   - subtree_as_ids: subtree_as_ids

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - project: project
   - is_domain: is_domain_response_body
   - description: project_description_response_body
   - domain_id: project_domain_id_response_body
   - enabled: project_enabled_response_body
   - id: project_id
   - links: link_response_body
   - name: project_name_response_body
   - parent_id: project_parent_id_response_body

Response Example
----------------

.. literalinclude:: ./samples/admin/project-show-response.json
   :language: javascript

Response Example with ``parents_as_list``
-----------------------------------------

.. literalinclude:: ./samples/admin/project-show-parents-response.json
   :language: javascript

Response Example with ``subtree_as_list``
-----------------------------------------

.. literalinclude:: ./samples/admin/project-show-subtree-response.json
   :language: javascript


Update project
==============

.. rest_method::  PATCH /v3/projects/{project_id}

Relationship: ``http://docs.openstack.org/api/openstack-identity/3/rel/project``

Updates a project.

Normal response codes: 200

Error response codes: 413,415,405,404,403,401,400,503,409

Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
   - project: project
   - is_domain: is_domain_request_body
   - description: project_description_request_body
   - domain_id: project_domain_id_update_request_body
   - enabled: project_enabled_update_request_body
   - name: project_name_update_request_body

Request Example
---------------

.. literalinclude:: ./samples/admin/project-update-request.json
   :language: javascript

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - project: project
   - is_domain: is_domain_response_body
   - description: project_description_response_body
   - domain_id: project_domain_id_response_body
   - enabled: project_enabled_response_body
   - id: project_id
   - name: project_name_response_body
   - links: link_response_body
   - parent_id: project_parent_id_response_body

Response Example
----------------

.. literalinclude:: ./samples/admin/project-update-response.json
   :language: javascript


Delete project
==============

.. rest_method::  DELETE /v3/projects/{project_id}

Relationship: ``http://docs.openstack.org/api/openstack-identity/3/rel/project``

Deletes a project.

Normal response codes: 204

Error response codes: 413,415,405,404,403,401,400,503,409

Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path


Enable or disable project and its subtree
=========================================

.. rest_method::  PATCH /v3/projects/{project_id}/cascade

Relationship: ``http://docs.openstack.org/api/openstack-identity/3/rel/project``

(Since Identity API v3.7) Enables or disables a project and its entire subtree.

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

   - project_id: project_id_path
   - project: project
   - enabled: project_enabled_cascade_request_body

Request Example
---------------

.. literalinclude:: ./samples/admin/project-enable-request.json
   :language: javascript

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - project: project
   - is_domain: is_domain_response_body
   - description: project_description_response_body
   - domain_id: project_domain_id_response_body
   - enabled: project_enabled_response_body
   - id: project_id
   - name: project_name_response_body
   - links: link_response_body
   - parent_id: project_parent_id_response_body

Response Example
----------------

.. literalinclude:: ./samples/admin/project-update-response.json
   :language: javascript


Delete project subtree
======================

.. rest_method::  DELETE /v3/projects/{project_id}/cascade

Relationship: ``http://docs.openstack.org/api/openstack-identity/3/rel/project``

(Since Identity API v3.7) Deletes a project and its entire subtree.

A project subtree includes all projects beneath the parent project
in the hierarchy. You must disable all the projects in the subtree
before you perform this operation.

Normal response codes: 204

Error response codes: 413,415,405,404,403,401,400,503,409

Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
