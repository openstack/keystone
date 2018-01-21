.. -*- rst -*-

================
OS-EP-FILTER API
================

This API enables the creation of custom catalogs using project scope. The
result is the ability to advertise specific endpoints based on the project in
use. The association can be done two different ways. The first is by building a
direct association between the project and the endpoint, which implies that
all tokens scoped to that particular project will receive a specific
endpoint, or set of endpoints, in the service catalog. The second is by
creating an endpoint group. An endpoint group is a filter that consists of at
least one endpoint attribute. By associating a project to an endpoint group,
all service catalogs scoped to that project will contain endpoints that match
the attributes defined in the endpoint group. Using endpoint groups is a way to
dynamically associate an endpoint, or a group of endpoints, to a specific
project.

API Resources
=============

Endpoint Group
--------------

An endpoint group represents a dynamic collection of service endpoints having
the same characteristics, such as ``service_id``, ``interface``, or
``region_id``. Any endpoint attribute could be used as part of a filter.

An example use case would be to give a particular project access to specific
service endpoints. When users authenticate for scoped tokens to that project,
they are presented with endpoints for the service because the association
matched attributes of the endpoints based on the filters. Continuing with this
example, let's assume we want a specific set of endpoints to be advertised in
the service catalog for a particular project. We can create an endpoint group
to explicitly filter endpoints based on their interface type and service ID.

.. literalinclude:: samples/OS-EP-FILTER/create-endpoint-group-request.json
   :language: javascript

This implies an Endpoint Group that will only return endpoints that have an
interface type of ``admin`` and correspond to a service with an ID
of ``1b501a``.

Create Endpoint Group
=====================

.. rest_method:: POST /v3/OS-EP-FILTER/endpoint_groups

Create a new endpoint group filter that represents a dynamic collection of
service endpoints having the same characteristics

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/ext/OS-EP-FILTER/1.0/rel/endpoint_groups``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - name: eg_name
   - filters: eg_filters
   - description: eg_description

Example
~~~~~~~

.. literalinclude:: samples/OS-EP-FILTER/create-endpoint-group-request.json
   :language: javascript

Response
--------

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success ../v3/status.yaml

   - 201

.. rest_status_code:: error ../v3/status.yaml

   - 401

Example
~~~~~~~

Status: 201 Created

.. literalinclude:: samples/OS-EP-FILTER/endpoint-group-response.json
   :language: javascript

Get Endpoint Group
==================

.. rest_method:: GET /v3/OS-EP-FILTER/endpoint_groups/{endpoint_group_id}

Show details of an endpoint group.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/ext/OS-EP-FILTER/1.0/rel/endpoint_group``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - endpoint_group_id: endpoint_group_id_path

Response
--------

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success ../v3/status.yaml

   - 200

.. rest_status_code:: error ../v3/status.yaml

   - 401

Example
~~~~~~~

Status: 200 OK

.. literalinclude:: samples/OS-EP-FILTER/endpoint-group-response.json
   :language: javascript

Check Endpoint Group
====================

.. rest_method:: HEAD /v3/OS-EP-FILTER/endpoint_groups/{endpoint_group_id}

Determine if an endpoint group exists.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/ext/OS-EP-FILTER/1.0/rel/endpoint_group``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - endpoint_group_id: endpoint_group_id_path

Response
--------

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success ../v3/status.yaml

   - 200

.. rest_status_code:: error ../v3/status.yaml

   - 401

Example
~~~~~~~

Status: 200 OK

Update Endpoint Group
=====================

.. rest_method:: PATCH /v3/OS-EP-FILTER/endpoint_groups/{endpoint_group_id}

Modify attributes of an endpoint group.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/ext/OS-EP-FILTER/1.0/rel/endpoint_group``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - endpoint_group_id: endpoint_group_id_path
   - name: eg_name
   - filters: eg_filters
   - description: eg_description

Example
~~~~~~~

.. literalinclude:: samples/OS-EP-FILTER/update-endpoint-group-request.json
   :language: javascript

Response
--------

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success ../v3/status.yaml

   - 200

.. rest_status_code:: error ../v3/status.yaml

   - 401

Example
~~~~~~~

Status: 200 OK

.. literalinclude:: samples/OS-EP-FILTER/update-endpoint-group-response.json
   :language: javascript

Delete Endpoint Group
=====================

.. rest_method::  DELETE /v3/OS-EP-FILTER/endpoint_groups/{endpoint_group_id}

Delete an endpoint group.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/ext/OS-EP-FILTER/1.0/rel/endpoint_group``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - endpoint_group_id: endpoint_group_id_path

Response
--------

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success ../v3/status.yaml

   - 204

.. rest_status_code:: error ../v3/status.yaml

   - 401


Status: 204 No Content

List Endpoint Groups
====================

.. rest_method:: GET /v3/OS-EP-FILTER/endpoint_groups

List all available endpoint groups.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/ext/OS-EP-FILTER/1.0/rel/endpoint_groups``

Response
--------

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success ../v3/status.yaml

   - 200

.. rest_status_code:: error ../v3/status.yaml

   - 401

Example
~~~~~~~

Status: 200 OK

.. literalinclude:: samples/OS-EP-FILTER/endpoint-groups-response.json
   :language: javascript

Project and Endpoint Associations
---------------------------------

As previously noted, projects can be associated with endpoints either directly
or by using endpoint groups. The following API calls describe how to associate
a project to a single endpoint and an endpoint group.

Create Association
==================

.. rest_method:: PUT /v3/OS-EP-FILTER/projects/{project_id}/endpoints/{endpoint_id}

Creates a direct association between ``project_id`` and ``endpoint_id``.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/ext/OS-EP-FILTER/1.0/rel/project_endpoint``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
   - endpoint_id: endpoint_id_path

Response
--------

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success ../v3/status.yaml

   - 204

.. rest_status_code:: error ../v3/status.yaml

   - 401

Example
~~~~~~~

Status: 204 No Content

Check Association
=================

.. rest_method:: HEAD /v3/OS-EP-FILTER/projects/{project_id}/endpoints/{endpoint_id}

Verifies the existence of an association between ``project_id`` and ``endpoint_id``.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/ext/OS-EP-FILTER/1.0/rel/project_endpoint``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
   - endpoint_id: endpoint_id_path

Response
--------

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success ../v3/status.yaml

   - 204

.. rest_status_code:: error ../v3/status.yaml

   - 401

Example
~~~~~~~

Status: 204 No Content

Delete Association
==================

.. rest_method:: DELETE /v3/OS-EP-FILTER/projects/{project_id}/endpoints/{endpoint_id}

Removes a direct association between ``project_id`` and ``endpoint_id``.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/ext/OS-EP-FILTER/1.0/rel/project_endpoint``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
   - endpoint_id: endpoint_id_path

Response
--------

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success ../v3/status.yaml

   - 204

.. rest_status_code:: error ../v3/status.yaml

   - 401

Example
~~~~~~~

Status: 204 No Content

List Associations by Project
=============================

.. rest_method:: GET /v3/OS-EP-FILTER/projects/{project_id}/endpoints

Returns all endpoints that are currently associated with ``project_id``.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/ext/OS-EP-FILTER/1.0/rel/project_endpoints``

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

.. rest_status_code:: success ../v3/status.yaml

   - 200

.. rest_status_code:: error ../v3/status.yaml

   - 401

Example
~~~~~~~

Status: 200 OK

.. literalinclude:: samples/OS-EP-FILTER/list-associations-by-project-response.json
   :language: javascript

List Associations by Endpoint
=============================

.. rest_method:: GET /v3/OS-EP-FILTER/endpoints/{endpoint_id}/projects

Returns all projects that are currently associated with ``endpoint_id``.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/ext/OS-EP-FILTER/1.0/rel/endpoint_projects``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - endpoint_id: endpoint_id_path

Response
--------

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success ../v3/status.yaml

   - 200

.. rest_status_code:: error ../v3/status.yaml

   - 401

Example
~~~~~~~

Status: 200 OK

.. literalinclude:: samples/OS-EP-FILTER/list-associations-by-endpoint-response.json
   :language: javascript

Project and Endpoint Group Associations
---------------------------------------

Projects can be associated to muliple endpoints by being associated to a single
endpoint group. All endpoints that match the filter in the endpoint group will
be associated with the project. The following API calls describe how to
associate a project to an endpoint group.

Create Endpoint Group to Project Association
============================================

.. rest_method:: PUT /v3/OS-EP-FILTER/endpoint_groups/{endpoint_group_id}/projects/{project_id}

Creates an association between ``endpoint_group_id`` and ``project_id``.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/ext/OS-EP-FILTER/1.0/rel/endpoint_group_project``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - endpoint_group_id: endpoint_group_id_path
   - project_id: project_id_path

Response
--------

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success ../v3/status.yaml

   - 204

.. rest_status_code:: error ../v3/status.yaml

   - 401

Example
~~~~~~~

Status: 204 No Content

Get Endpoint Group to Project Association
=========================================

.. rest_method:: GET /v3/OS-EP-FILTER/endpoint_groups/{endpoint_group_id}/projects/{project_id}

Verifies the existence of an association between ``project_id`` and ``endpoint_group_id``.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/ext/OS-EP-FILTER/1.0/rel/endpoint_group_project``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - endpoint_group_id: endpoint_group_id_path
   - project_id: project_id_path

Response
--------

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success ../v3/status.yaml

   - 200

.. rest_status_code:: error ../v3/status.yaml

   - 401

Example
~~~~~~~

Status: 200 OK

.. literalinclude:: samples/OS-EP-FILTER/endpoint-project-response.json
   :language: javascript

Check Endpoint Group to Project Association
===========================================

.. rest_method:: HEAD /v3/OS-EP-FILTER/endpoint_groups/{endpoint_group_id}/projects/{project_id}

Verifies the existence of an association between ``project_id`` and ``endpoint_group_id``.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/ext/OS-EP-FILTER/1.0/rel/endpoint_group_project``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - endpoint_group_id: endpoint_group_id_path
   - project_id: project_id_path

Response
--------

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success ../v3/status.yaml

   - 200

.. rest_status_code:: error ../v3/status.yaml

   - 401

Example
~~~~~~~

Status: 200 OK

Delete Endpoint Group to Project Association
============================================

.. rest_method:: DELETE /v3/OS-EP-FILTER/endpoint_groups/{endpoint_group_id}/projects/{project_id}

Removes the association between ``project_id`` and ``endpoint_group_id``.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/ext/OS-EP-FILTER/1.0/rel/endpoint_group_project``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - endpoint_group_id: endpoint_group_id_path
   - project_id: project_id_path

Response
--------

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success ../v3/status.yaml

   - 204

.. rest_status_code:: error ../v3/status.yaml

   - 401

Example
~~~~~~~

Status: 204 No Content

List Projects Associated with Endpoint Group
============================================

.. rest_method:: GET /v3/OS-EP-FILTER/endpoint_groups/{endpoint_group_id}/projects

Returns all projects that are currently associated with ``endpoint_group_id``.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/ext/OS-EP-FILTER/1.0/rel/endpoint_group_projects``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - endpoint_group_id: endpoint_group_id_path

Response
--------

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success ../v3/status.yaml

   - 200

.. rest_status_code:: error ../v3/status.yaml

   - 401

Example
~~~~~~~

Status: 200 OK

.. literalinclude:: samples/OS-EP-FILTER/list-associations-by-endpoint-response.json
   :language: javascript

List Endpoints Associated with Endpoint Group
=============================================

.. rest_method:: GET /v3/OS-EP-FILTER/endpoint_groups/{endpoint_group_id}/endpoints

Returns all the endpoints that are currently associated with ``endpoint_group_id``.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/ext/OS-EP-FILTER/1.0/rel/endpoint_group_endpoints``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - endpoint_group_id: endpoint_group_id_path

Response
--------

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success ../v3/status.yaml

   - 200

.. rest_status_code:: error ../v3/status.yaml

   - 401

Example
~~~~~~~

Status: 200 OK

.. literalinclude:: samples/OS-EP-FILTER/list-service-endpoints.json
   :language: javascript

List Endpoint Groups Associated with Project
============================================

.. rest_method:: GET /v3/OS-EP-FILTER/projects/{project_id}/endpoint_groups

Returns all the endpoint groups that are currently associated with ``project_id``.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/ext/OS-EP-FILTER/1.0/rel/project_endpoint_groups``

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

.. rest_status_code:: success ../v3/status.yaml

   - 200

.. rest_status_code:: error ../v3/status.yaml

   - 401

Example
~~~~~~~

Status: 200 OK

.. literalinclude:: samples/OS-EP-FILTER/endpoint-groups-response.json
   :language: javascript