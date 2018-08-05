.. -*- rst -*-

============
Project tags
============

Projects within keystone can be tagged with one to many simple strings.
Tags for projects follow the guidelines for resource tags set by the
`API Working Group <https://specs.openstack.org/openstack/api-wg/guidelines/tags.html>`_.

Tags for projects have the following restrictions:

.. Note::

   - Tags are case sensitive
   - Forward Slash '/' is not allowed to be in a tag name
   - Commas ',' are not allowed to be in a tag name in order
     to simplify requests that specify lists of tags
   - Each project can have a maximum of 80 tags
   - Each tag can be a maximum of 255 characters in length


List tags for a project
=======================

.. rest_method:: GET /v3/projects/{project_id}/tags

Lists all tags within a project.

.. note::
    HEAD can be used here as well

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/projects``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - tags: response_body_project_tags_required

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

.. literalinclude:: ./samples/admin/project-tags-list-response.json
   :language: javascript


Check if project contains tag
=============================

.. rest_method:: GET /v3/projects/{project_id}/tags/{tag}

Checks if a project contains the specified tag.

.. note::
    HEAD can be used here as well

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/projects``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
   - tag: project_tag_path

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


Add single tag to a project
===========================

.. rest_method:: PUT /v3/projects/{project_id}/tags/{tag}

Creates the specified tag and adds it to the list of tags in the project.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/projects``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
   - tag: project_tag_path

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


Modify tag list for a project
=============================

.. rest_method:: PUT /v3/projects/{project_id}/tags

Modifies the tags for a project. Any existing tags not specified will
be deleted.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/projects``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
   - tags: response_body_project_tags_required

Example
~~~~~~~

.. literalinclude:: ./samples/admin/project-tags-update-request.json
   :language: javascript

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - tags: response_body_project_tags_required

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

.. literalinclude:: ./samples/admin/project-tags-update-response.json
   :language: javascript


Delete single tag from project
==============================

.. rest_method:: DELETE /v3/projects/{project_id}/tags/{tag}

Remove a single tag from a project.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/projects``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
   - tag: project_tag_path

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


Remove all tags from a project
==============================

.. rest_method:: DELETE /v3/projects/{project_id}/tags

Remove all tags from a given project.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/projects``

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


===============================
Filtering and searching by tags
===============================

Projects can be searched or filtered by tags. The following table and examples
define how to filter projects by tags. Filters can also be combined for more
complex searching.

.. list-table::
   :widths: 100 250
   :header-rows: 1

   * - Tag Query
     - Description
   * - tags
     - Projects that contain all of the specified tags
   * - tags-any
     - Projects that contain at least one of the specified tags
   * - not-tags
     - Projects that do not contain exactly all of the specified tags
   * - not-tags-any
     - Projects that do not contain any one of the specified tags


To request the list of projects that have a single tag, the ``tags`` query
parameter should be set to the desired tag name. The following example returns
projects with the "foo" tag:

.. code-block:: bash

   GET /v3/projects?tags=foo

To request the list of projects that have two or more tags, the ``tags``
argument should be set to the list of tags, separated by commas. In this
situation, the tags given must all be present for a project to be included
in the query result. The following example returns projects that have the
"foo" and "bar" tags:

.. code-block:: bash

   GET /v3/projects?tags=foo,bar

To request the list of projects that have at least one tag from a given list,
the ``tags-any`` argument should be set to the list of tags, separated
by commas. In this situation as long as one of the given tags is present,
the project will be included in the query result. The following example returns
projects that have the “foo” OR “bar” tag:

.. code-block:: bash

   GET /v3/projects?tags-any=foo,bar

To request the list of projects that do not have a list of tags, the
``not-tags`` argument should be set to the list of tags, separated by commas.
In this situation, the tags given must all be absent for a project to be
included in the query result. The following example returns projects that
do not have the “foo” nor the “bar” tag:

.. code-block:: bash

   GET /v3/projects?not-tags=foo,bar

To request the list of projects that do not have at least one of a list of
tags, the ``not-tags-any`` argument should be set to the list of tags,
separated by commas. In this situation, as long as one of the given tags
is absent, the project will be included in the query result. Example
The following example returns projects that do not have the “foo” tag or
do not have the “bar” tag:

.. code-block:: bash

   GET /v3/projects?not-tags-any=foo,bar

The ``tags``, ``tags-any``, ``not-tags`` and ``not-tags-any`` arguments can
be combined to build more complex queries. The following example returns
projects that have the “foo” and “bar” tags, plus at least one of “red”
and “blue”:

.. code-block:: bash

   GET /v3/projects?tags=foo,bar&tags-any=red,blue
