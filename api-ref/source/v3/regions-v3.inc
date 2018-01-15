.. -*- rst -*-

=========
 Regions
=========

A region is a general division of an OpenStack deployment. You can
associate zero or more sub-regions with a region to create a tree-
like structured hierarchy.

Although a region does not have a geographical connotation, a
deployment can use a geographical name for a region ID, such as ``us-
east``.

You can list, create, update, show details for, and delete regions.


Show region details
===================

.. rest_method::  GET /v3/regions/{region_id}

Shows details for a region, by ID.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/regions``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - region_id: region_id_path

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - region: region_object
   - description: description_region_response_body
   - id: id_region_response_body
   - links: links_region
   - parent_region_id: parent_region_id_response_body

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

Example
~~~~~~~

.. literalinclude:: ./samples/admin/region-show-response.json
   :language: javascript


Update region
=============

.. rest_method::  PATCH /v3/regions/{region_id}

Updates a region.

You can update the description or parent region ID for a region.
You cannot update the region ID.

The following error might occur:

- ``Not Found (404)``. The parent region ID does not exist.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/region``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - region_id: region_id_path
   - region: region_object
   - description: description_region_request_body
   - parent_region_id: parent_region_id_request_body

Example
~~~~~~~

.. literalinclude:: ./samples/admin/region-update-request.json
   :language: javascript

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - region: region_object
   - description: description_region_response_body
   - id: id_region_response_body
   - links: links_region
   - parent_region_id: parent_region_id_response_body

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
   - 409
   - 413
   - 415
   - 503

Example
~~~~~~~

.. literalinclude:: ./samples/admin/region-update-response.json
   :language: javascript


Delete region
=============

.. rest_method::  DELETE /v3/regions/{region_id}

Deletes a region.

The following error might occur:

- ``Conflict (409)``. The region cannot be deleted because it has
  child regions.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/region``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - region_id: region_id_path

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
   - 405
   - 409
   - 413
   - 415
   - 503

List regions
============

.. rest_method::  GET /v3/regions

Lists regions.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/regions``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - parent_region_id: parent_region_id_query_not_required

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - regions: regions_object
   - description: description_region_response_body
   - id: id_region_response_body
   - links: links_region
   - parent_region_id: parent_region_id_response_body

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

Example
~~~~~~~

.. literalinclude:: ./samples/admin/regions-list-response.json
   :language: javascript


Create region
=============

.. rest_method::  POST /v3/regions

Creates a region.

When you create the region, you can optionally specify a region ID.
If you include characters in the region ID that are not allowed in
a URI, you must URL-encode the ID. If you omit an ID, the API
assigns an ID to the region.

The following errors might occur:

- ``Not Found (404)``. The parent region ID does not exist.

- ``Conflict (409)``. The parent region ID would form a circular
  relationship.

- ``Conflict (409)``. The user-defined region ID is not unique to
  the OpenStack deployment.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/regions``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - region: region_object
   - description: description_region_request_body
   - id: id_region_resquest_body
   - parent_region_id: parent_region_id_request_body

Example
~~~~~~~

.. literalinclude:: ./samples/admin/region-create-request.json
   :language: javascript

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - region: region_object
   - description: description_region_response_body
   - id: id_region_response_body
   - links: links_region
   - parent_region_id: parent_region_id_response_body

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success status.yaml

   - 201

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404
   - 405
   - 409
   - 413
   - 415
   - 503