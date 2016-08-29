.. -*- rst -*-

================
OS-EP-FILTER API
================

This API enables creation of ad-hoc catalogs for each project-scoped token
request. To do so, this API uses either static project-endpoint associations
or dynamic custom endpoints groups to associate service endpoints with
projects.

API Resources
=============

Endpoint Group
--------------

Represents a dynamic collection of service endpoints having the same
characteristics, such as ``service_id``, ``interface``, or ``region``. Indeed,
any endpoint attribute could be used as part of a filter.

A classic use case is to filter endpoints based on region. For example, suppose
a user wants to filter service endpoints returned in the service catalog by
region, the following endpoint group may be used:

.. literalinclude:: samples/OS-EP-FILTER/create-endpoint-group-request.json
   :language: javascript

This implies an Endpoint Group with filtering criteria of::

  ``region_id = "1b501"``

Create Association
==================

.. rest_method:: PUT /v3/OS-EP-FILTER/projects/{project_id}/endpoints/{endpoint_id}

Creates an association between ``project_id`` and ``endpoint_id``.

Relationship: ``http://docs.openstack.org/api/openstack-identity/3/ext/OS-EP-FILTER/1.0/rel/project_endpoint``

Normal response codes: 204

Error response codes: 401

Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
   - endpoint_id: endpoint_id_path

Response
--------

Status: 204 No Content

Check Association
=================

.. rest_method:: HEAD /v3/OS-EP-FILTER/projects/{project_id}/endpoints/{endpoint_id}

Verifies the existence of an association between ``project_id`` and ``endpoint_id``.

Relationship: ``http://docs.openstack.org/api/openstack-identity/3/ext/OS-EP-FILTER/1.0/rel/project_endpoint``

Normal response codes: 204

Error response codes: 401

Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
   - endpoint_id: endpoint_id_path

Response
--------

Status: 204 No Content

Delete Association
==================

.. rest_method:: DELETE /v3/OS-EP-FILTER/projects/{project_id}/endpoints/{endpoint_id}

Removes the association between ``project_id`` and ``endpoint_id``.

Relationship: ``http://docs.openstack.org/api/openstack-identity/3/ext/OS-EP-FILTER/1.0/rel/project_endpoint``

Normal response codes: 204

Error response codes: 401

Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
   - endpoint_id: endpoint_id_path

Response
--------

Status: 204 No Content

List Associations for Project
=============================

.. rest_method:: GET /v3/OS-EP-FILTER/projects/{project_id}/endpoints

Returns all the endpoints that are currently associated with ``project_id``.

Relationship: ``http://docs.openstack.org/api/openstack-identity/3/ext/OS-EP-FILTER/1.0/rel/project_endpoints``

Normal response codes: 200

Error response codes: 401

Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
   - endpoint_id: endpoint_id_path

Response
--------

Status: 200 OK

.. literalinclude:: samples/OS-EP-FILTER/list-endpoints-response.json
   :language: javascript

Get projects associated with endpoint
=====================================

.. rest_method:: GET /v3/OS-EP-FILTER/endpoints/{endpoint_id}/projects

Returns all projects that are currently associated with ``endpoint_id``.

Relationship: ``http://docs.openstack.org/api/openstack-identity/3/ext/OS-EP-FILTER/1.0/rel/endpoint_projects``

Normal response codes: 200

Error response codes: 401

Request
-------

.. rest_parameters:: parameters.yaml

   - endpoint_id: endpoint_id_path

Response
--------

Status: 200 OK

.. literalinclude:: samples/OS-EP-FILTER/get-projects-response.json
   :language: javascript

Create Endpoint Group
=====================

.. rest_method:: POST /v3/OS-EP-FILTER/endpoint_groups

Create a new endpoint group filter that represents a dynamic collection of
service endpoints having the same characteristics

Relationship: ``http://docs.openstack.org/api/openstack-identity/3/ext/OS-EP-FILTER/1.0/rel/endpoint_groups``

Normal response codes: 201

Error response codes: 401

Request
-------

.. rest_parameters:: parameters.yaml

   - name: eg_name
   - filters: eg_filters
   - description: eg_description

.. literalinclude:: samples/OS-EP-FILTER/create-endpoint-group-request.json
   :language: javascript

Response
--------

Status: 201 Created

.. literalinclude:: samples/OS-EP-FILTER/endpoint-group-response.json
   :language: javascript

Get Endpoint Group
==================

.. rest_method:: GET /v3/OS-EP-FILTER/endpoint_groups/{endpoint_group_id}

Show details of an endpoint group.

Relationship: ``http://docs.openstack.org/api/openstack-identity/3/ext/OS-EP-FILTER/1.0/rel/endpoint_group``

Normal response codes: 200

Error response codes: 401

Request
-------

.. rest_parameters: parameters.yaml

   - endpoint_group_id: endpoint_group_id_path

Response
--------

Status: 200 OK

.. literalinclude:: samples/OS-EP-FILTER/endpoint-group-response.json
   :language: javascript

Check Endpoint Group
====================

.. rest_method:: HEAD /v3/OS-EP-FILTER/endpoint_groups/{endpoint_group_id}

Determine if an endpoint group exists.

Relationship: ``http://docs.openstack.org/api/openstack-identity/3/ext/OS-EP-FILTER/1.0/rel/endpoint_group``

Normal response codes: 200

Error response codes: 401

Request
-------

.. rest_parameters:: parameters.yaml

   - endpoint_group_id: endpoint_group_id_path

Response
--------

Status: 200 OK

Update Endpoint Group
=====================

.. rest_method:: PATCH /v3/OS-EP-FILTER/endpoint_groups/{endpoint_group_id}

Modify attributes of an endpoint group.

Relationship: ``http://docs.openstack.org/api/openstack-identity/3/ext/OS-EP-FILTER/1.0/rel/endpoint_group``

Normal response codes: 200

Error response codes: 401

Request
-------

.. rest_parameters:: parameters.yaml

   - endpoint_group_id: endpoint_group_id_path
   - name: eg_name
   - filters: eg_filters
   - description: eg_description

.. literalinclude:: samples/OS-EP-FILTER/create-endpoint-group-request.json
   :language: javascript

Response
--------

Status: 200 OK

.. literalinclude:: samples/OS-EP-FILTER/endpoint-group-response.json
   :language: javascript

Delete Endpoint Group
=====================

.. rest_method::  DELETE /v3/OS-EP-FILTER/endpoint_groups/{endpoint_group_id}

Delete an endpoint group.

Relationship: ``http://docs.openstack.org/api/openstack-identity/3/ext/OS-EP-FILTER/1.0/rel/endpoint_group``

Normal response codes: 204

Error response codes: 401

Request
-------

.. rest_parameters:: parameters.yaml

   - endpoint_group_id: endpoint_group_id_path

Response
--------

Status: 204 No Content

List Endpoint Groups
====================

.. rest_method:: GET /v3/OS-EP-FILTER/endpoint_groups

List all available endpoint groups.

Relationship: ``http://docs.openstack.org/api/openstack-identity/3/ext/OS-EP-FILTER/1.0/rel/endpoint_groups``

Normal response codes: 200

Error response codes: 401

Response
--------

Status: 200 OK

.. literalinclude:: samples/OS-EP-FILTER/endpoint-groups-response.json
   :language: javascript

Create Endpoint Group to Project Association
============================================

.. rest_method:: PUT /v3/OS-EP-FILTER/endpoint_groups/{endpoint_group_id}/projects/{project_id}

Creates an associate between ``endpoint_group_id`` and ``project_id``.

Relationship: ``http://docs.openstack.org/api/openstack-identity/3/ext/OS-EP-FILTER/1.0/rel/endpoint_group_project``

Normal response codes: 204

Error response codes: 401

Request
-------

.. rest_parameters:: parameters.yaml

   - endpoint_group_id: endpoint_group_id_path
   - project_id: project_id_path

Response
--------

Status: 204 No Content

Get Endpoint Group to Project Association
=========================================

.. rest_method:: GET /v3/OS-EP-FILTER/endpoint_groups/{endpoint_group_id}/projects/{project_id}

Verifies the existence of an association between ``project_id`` and ``endpoint_group_id``.

Relationship: ``http://docs.openstack.org/api/openstack-identity/3/ext/OS-EP-FILTER/1.0/rel/endpoint_group_project``

Normal response codes: 200

Error response codes: 401

Request
-------

.. rest_parameters:: parameters.yaml

   - endpoint_group_id: endpoint_group_id_path
   - project_id: project_id_path

Response
--------

Status: 200 OK

.. literalinclude:: samples/OS-EP-FILTER/endpoint-project-response.json
   :language: javascript

Check Endpoint Group to Project Association
===========================================

.. rest_method:: HEAD /v3/OS-EP-FILTER/endpoint_groups/{endpoint_group_id}/projects/{project_id}

Verifies the existence of an association between ``project_id`` and ``endpoint_group_id``.

Relationship: ``http://docs.openstack.org/api/openstack-identity/3/ext/OS-EP-FILTER/1.0/rel/endpoint_group_project``

Normal response codes: 200

Error response codes: 401

Request
-------

.. rest_parameters:: parameters.yaml

   - endpoint_group_id: endpoint_group_id_path
   - project_id: project_id_path

Response
--------

Status: 200 OK

Delete Endpoint Group to Project Association
============================================

.. rest_method:: DELETE /v3/OS-EP-FILTER/endpoint_groups/{endpoint_group_id}/projects/{project_id}

Removes the association between ``project_id`` and ``endpoint_group_id``.

Relationship: ``http://docs.openstack.org/api/openstack-identity/3/ext/OS-EP-FILTER/1.0/rel/endpoint_group_project``

Normal response codes: 204

Error response codes: 401

Request
-------

.. rest_parameters:: parameters.yaml

   - endpoint_group_id: endpoint_group_id_path
   - project_id: project_id_path

Response
--------

Status: 204 No Content

List Projects Associated with Endpoint Group
============================================

.. rest_method:: GET /v3/OS-EP-FILTER/endpoint_groups/{endpoint_group_id}/projects

Returns all projects that are currently associated with ``endpoint_group_id``.

Relationship: ``http://docs.openstack.org/api/openstack-identity/3/ext/OS-EP-FILTER/1.0/rel/endpoint_group_projects``

Normal response codes: 200

Error response codes: 401

Request
-------

.. rest_parameters:: parameters.yaml

   - endpoint_group_id: endpoint_group_id_path

Response
--------

Status: 200 OK

.. literalinclude:: samples/OS-EP-FILTER/get-projects-response.json
   :language: javascript

List Endpoints Associated with Endpoint Group
=============================================

.. rest_method:: GET /v3/OS-EP-FILTER/endpoint_groups/{endpoint_group_id}/endpoints

Returns all the endpoints that are currently associated with ``endpoint_group_id``.

Relationship: ``http://docs.openstack.org/api/openstack-identity/3/ext/OS-EP-FILTER/1.0/rel/endpoint_group_endpoints``

Normal response codes: 200

Error response codes: 401

Request
-------

.. rest_parameters:: parameters.yaml

   - endpoint_group_id: endpoint_group_id_path

Response
--------

Status: 200 OK

.. literalinclude:: samples/OS-EP-FILTER/list-service-endpoints.json
   :language: javascript

List Endpoint Groups Associated with Project
============================================

.. rest_method:: GET /v3/OS-EP-FILTER/projects/{project_id}/endpoint_groups

Returns all the endpoints that are currently associated with ``project_id``.

Relationship: ``http://docs.openstack.org/api/openstack-identity/3/ext/OS-EP-FILTER/1.0/rel/project_endpoint_groups``

Normal response codes: 200

Error response codes: 401

Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path

Response
--------

Status: 200 OK

.. literalinclude:: samples/OS-EP-FILTER/endpoint-groups-response.json
   :language: javascript
