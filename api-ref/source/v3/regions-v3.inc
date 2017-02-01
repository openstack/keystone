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

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/regions``

Shows details for a region, by ID.

Normal response codes: 200

Error response codes: 413,405,404,403,401,400,503

Request
-------

.. rest_parameters:: parameters.yaml

   - region_id: region_id_path

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - region: region_object
   - description: description_region_response_body
   - id: id_region_response_body
   - links: links_region
   - parent_region_id: parent_region_id_response_body

Response Example
----------------

.. literalinclude:: ./samples/admin/region-show-response.json
   :language: javascript


Update region
=============

.. rest_method::  PATCH /v3/regions/{region_id}

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/region``

Updates a region.

You can update the description or parent region ID for a region.
You cannot update the region ID.

The following error might occur:

- ``Not Found (404)``. The parent region ID does not exist.

Normal response codes: 200

Error response codes: 413,415,405,404,403,401,400,503,409

Request
-------

.. rest_parameters:: parameters.yaml

   - region_id: region_id_path
   - region: region_object
   - description: description_region_request_body
   - parent_region_id: parent_region_id_request_body

Request Example
---------------

.. literalinclude:: ./samples/admin/region-update-request.json
   :language: javascript

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - region: region_object
   - description: description_region_response_body
   - id: id_region_response_body
   - links: links_region
   - parent_region_id: parent_region_id_response_body

Response Example
----------------

.. literalinclude:: ./samples/admin/region-update-response.json
   :language: javascript


Delete region
=============

.. rest_method::  DELETE /v3/regions/{region_id}

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/region``

Deletes a region.

The following error might occur:

- ``Conflict (409)``. The region cannot be deleted because it has
  child regions.

Normal response codes: 204

Error response codes: 413,415,405,404,403,401,400,503,409

Request
-------

.. rest_parameters:: parameters.yaml

   - region_id: region_id_path


List regions
============

.. rest_method::  GET /v3/regions

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/regions``

Lists regions.

Normal response codes: 200

Error response codes: 413,405,404,403,401,400,503

Request
-------

.. rest_parameters:: parameters.yaml

   - parent_region_id: parent_region_id_query

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - regions: regions_object
   - description: description_region_response_body
   - id: id_region_response_body
   - links: links_region
   - parent_region_id: parent_region_id_response_body

Response Example
----------------

.. literalinclude:: ./samples/admin/regions-list-response.json
   :language: javascript


Create region
=============

.. rest_method::  POST /v3/regions

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/regions``

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

Normal response codes: 201

Error response codes: 413,415,405,404,403,401,400,503,409

Request
-------

.. rest_parameters:: parameters.yaml

   - region: region_object
   - description: description_region_request_body
   - id: id_region_resquest_body
   - parent_region_id: parent_region_id_request_body

Request Example
---------------

.. literalinclude:: ./samples/admin/region-create-request.json
   :language: javascript

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - region: region_object
   - description: description_region_response_body
   - id: id_region_response_body
   - links: links_region
   - parent_region_id: parent_region_id_response_body
