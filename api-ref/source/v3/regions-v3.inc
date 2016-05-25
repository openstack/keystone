.. -*- rst -*-

==============================
Regions (regions) (since v3.2)
==============================

A region is a general division of an OpenStack deployment. You can
associate zero or more sub-regions with a region to create a tree-
like structured hierarchy.

Although a region does not have a geographical connotation, a
deployment can use a geographical name for a region, such as ``us-
east``.

You can list, create, update, show details for, and delete regions.


Show region details
===================

.. rest_method::  GET /v3/regions/{region_id}

Shows details for a region, by ID.

Normal response codes: 200
Error response codes:413,405,404,403,401,400,503,

Request
-------

.. rest_parameters:: parameters.yaml

   - region_id: region_id

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - parent_region_id: parent_region_id
   - region: region
   - description: description
   - links: links
   - id: id

Response Example
----------------

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

Normal response codes: 200
Error response codes:413,415,405,404,403,401,400,503,409,

Request
-------

.. rest_parameters:: parameters.yaml

   - parent_region_id: parent_region_id
   - region: region
   - description: description
   - region_id: region_id

Request Example
---------------

.. literalinclude:: ./samples/admin/region-update-request.json
   :language: javascript

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - parent_region_id: parent_region_id
   - region: region
   - description: description
   - links: links
   - id: id

Response Example
----------------

.. literalinclude:: ./samples/admin/region-update-response.json
   :language: javascript


Delete region
=============

.. rest_method::  DELETE /v3/regions/{region_id}

Deletes a region.

The following error might occur:

- ``Conflict (409)``. The region cannot be deleted because it has
  child regions.

Error response codes:204,413,415,405,404,403,401,400,503,409,

Request
-------

.. rest_parameters:: parameters.yaml

   - region_id: region_id


List regions
============

.. rest_method::  GET /v3/regions

Lists regions.

Normal response codes: 200
Error response codes:413,405,404,403,401,400,503,

Request
-------

.. rest_parameters:: parameters.yaml

   - parent_region_id: parent_region_id

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - regions: regions
   - parent_region_id: parent_region_id
   - description: description
   - links: links
   - id: id

Response Example
----------------

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

Error response codes:201,413,415,405,404,403,401,400,503,409,

Request
-------

.. rest_parameters:: parameters.yaml

   - parent_region_id: parent_region_id
   - region: region
   - description: description
   - id: id

Request Example
---------------

.. literalinclude:: ./samples/admin/region-create-request.json
   :language: javascript

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - parent_region_id: parent_region_id
   - region: region
   - description: description
   - links: links
   - id: id
