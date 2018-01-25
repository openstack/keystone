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

.. note::

  A project's name must be unique within a domain and no more than 64 characters.
  A project's name must be able to be sent within valid JSON, which could be any
  UTF-8 character. However, this is constrained to the given backend where project
  names are stored. For instance, MySQL's restrictions states that UTF-8 support
  is constrained to the characters in the Basic Multilingual Plane (BMP).
  Supplementary characters are not permitted. Note that this last restriction is
  generally true for all ``names`` within resources of the Identity API.


List projects
=============

.. rest_method::  GET /v3/projects

Lists projects.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/projects``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - domain_id: domain_id_query
   - enabled: project_enabled_query
   - is_domain: is_domain_query
   - name: project_name_query
   - parent_id: parent_id_query

Response
--------

Parameters
~~~~~~~~~~

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
   - tags: response_body_project_tags_required

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

.. literalinclude:: ./samples/admin/projects-list-response.json
   :language: javascript


Create project
==============

.. rest_method::  POST /v3/projects

Creates a project, where the project may act as a domain.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/projects``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - project: project
   - name: project_name_request_body
   - is_domain: is_domain_request_body
   - description: project_description_request_body
   - domain_id: project_domain_id_request_body
   - enabled: project_enabled_request_body
   - parent_id: project_parent_id_request_body
   - tags: project_tags_request_body

Examples
~~~~~~~~

Sample for creating a regular project:

.. literalinclude:: ./samples/admin/project-create-request.json
   :language: javascript

Sample for creating a project that also acts as a domain:

.. literalinclude:: ./samples/admin/project-create-domain-request.json
   :language: javascript

Response
--------

Parameters
~~~~~~~~~~

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

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success status.yaml

   - 201

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 409

Show project details
====================

.. rest_method::  GET /v3/projects/{project_id}

Shows details for a project.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/project``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
   - parents_as_list: parents_as_list
   - subtree_as_list: subtree_as_list
   - parents_as_ids: parents_as_ids
   - subtree_as_ids: subtree_as_ids

Response
--------

Parameters
~~~~~~~~~~

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

.. literalinclude:: ./samples/admin/project-show-response.json
   :language: javascript

Example with ``parents_as_list``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. literalinclude:: ./samples/admin/project-show-parents-response.json
   :language: javascript

Example with ``subtree_as_list``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. literalinclude:: ./samples/admin/project-show-subtree-response.json
   :language: javascript


Update project
==============

.. rest_method::  PATCH /v3/projects/{project_id}

Updates a project.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/project``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
   - project: project
   - name: project_name_update_request_body
   - is_domain: is_domain_request_body
   - description: project_description_request_body
   - domain_id: project_domain_id_update_request_body
   - enabled: project_enabled_update_request_body
   - tags: project_tags_request_body

Example
~~~~~~~

.. literalinclude:: ./samples/admin/project-update-request.json
   :language: javascript

Response
--------

Parameters
~~~~~~~~~~

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

.. literalinclude:: ./samples/admin/project-update-response.json
   :language: javascript


Delete project
==============

.. rest_method::  DELETE /v3/projects/{project_id}

Deletes a project.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/project``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path

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