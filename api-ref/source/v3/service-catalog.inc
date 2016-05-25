.. -*- rst -*-

===================================================
Service catalog and endpoints (services, endpoints)
===================================================

A service is an OpenStack web service that you can access through a
URL, or endpoint.

A service catalog lists the services that are available to the
caller based upon the current authorization.

You can create, list, show details for, update, and delete
services. When you create or update a service, you can enable the
service, which causes it and its endpoints to appear in the service
catalog.

You can create, list, show details for, update, and delete
endpoints.


List services
=============

.. rest_method::  GET /v3/services

Lists all services.

Normal response codes: 200
Error response codes:413,405,404,403,401,400,503,

Request
-------

.. rest_parameters:: parameters.yaml

   - type: type

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - name: name
   - links: links
   - enabled: enabled
   - services: services
   - type: type
   - id: id
   - description: description

Response Example
----------------

.. literalinclude:: ./samples/admin/services-list-response.json
   :language: javascript


Create service
==============

.. rest_method::  POST /v3/services

Creates a service.

Error response codes:201,413,415,405,404,403,401,400,503,409,

Request
-------

.. rest_parameters:: parameters.yaml

   - description: description
   - service: service
   - enabled: enabled
   - service_id: service_id
   - type: type
   - name: name

Request Example
---------------

.. literalinclude:: ./samples/admin/service-create-request.json
   :language: javascript

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - name: name
   - service: service
   - links: links
   - type: type
   - id: id
   - description: description


Show endpoint details
=====================

.. rest_method::  GET /v3/endpoints/{endpoint_id}

Shows details for an endpoint.

Normal response codes: 200
Error response codes:413,405,404,403,401,400,503,

Request
-------

.. rest_parameters:: parameters.yaml

   - endpoint_id: endpoint_id

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - endpoint: endpoint
   - name: name
   - links: links
   - url: url
   - region: region
   - interface: interface
   - service_id: service_id

Response Example
----------------

.. literalinclude:: ./samples/admin/endpoint-show-response.json
   :language: javascript


Update endpoint
===============

.. rest_method::  PATCH /v3/endpoints/{endpoint_id}

Updates an endpoint.

Normal response codes: 200
Error response codes:413,415,405,404,403,401,400,503,409,

Request
-------

.. rest_parameters:: parameters.yaml

   - endpoint: endpoint
   - name: name
   - url: url
   - region: region
   - interface: interface
   - service_id: service_id
   - endpoint_id: endpoint_id

Request Example
---------------

.. literalinclude:: ./samples/admin/endpoint-update-request.json
   :language: javascript

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - endpoint: endpoint
   - name: name
   - links: links
   - url: url
   - region: region
   - interface: interface
   - service_id: service_id

Response Example
----------------

.. literalinclude:: ./samples/admin/endpoint-update-response.json
   :language: javascript


Delete endpoint
===============

.. rest_method::  DELETE /v3/endpoints/{endpoint_id}

Deletes an endpoint.

Error response codes:204,413,415,405,404,403,401,400,503,409,

Request
-------

.. rest_parameters:: parameters.yaml

   - endpoint_id: endpoint_id


List endpoints
==============

.. rest_method::  GET /v3/endpoints

Lists all available endpoints.

Normal response codes: 200
Error response codes:413,405,404,403,401,400,503,

Request
-------

.. rest_parameters:: parameters.yaml

   - interface: interface
   - service_id: service_id

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - region_id: region_id
   - links: links
   - url: url
   - region: region
   - enabled: enabled
   - interface: interface
   - service_id: service_id
   - endpoints: endpoints
   - id: id

Response Example
----------------

.. literalinclude:: ./samples/admin/endpoints-list-response.json
   :language: javascript


Create endpoint
===============

.. rest_method::  POST /v3/endpoints

Creates an endpoint.

Error response codes:201,413,415,405,404,403,401,400,503,409,

Request
-------

.. rest_parameters:: parameters.yaml

   - endpoint: endpoint
   - name: name
   - url: url
   - enabled: enabled
   - interface: interface
   - service_id: service_id
   - region_id: region_id

Request Example
---------------

.. literalinclude:: ./samples/admin/endpoint-create-request.json
   :language: javascript

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - endpoint: endpoint
   - name: name
   - links: links
   - url: url
   - region: region
   - enabled: enabled
   - interface: interface
   - service_id: service_id
   - id: id
   - region_id: region_id


Show service details
====================

.. rest_method::  GET /v3/services/{service_id}

Shows details for a service.

Normal response codes: 200
Error response codes:413,405,404,403,401,400,503,

Request
-------

.. rest_parameters:: parameters.yaml

   - service_id: service_id

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - name: name
   - service: service
   - links: links
   - type: type
   - id: id
   - description: description

Response Example
----------------

.. literalinclude:: ./samples/admin/service-show-response.json
   :language: javascript


Update service
==============

.. rest_method::  PATCH /v3/services/{service_id}

Updates a service.

The request body is the same as the create service request body,
except that you include only those attributes that you want to
update.

Normal response codes: 200
Error response codes:413,415,405,404,403,401,400,503,409,

Request
-------

.. rest_parameters:: parameters.yaml

   - type: type
   - enabled: enabled
   - description: description
   - service: service
   - name: name
   - service_id: service_id

Request Example
---------------

.. literalinclude:: ./samples/admin/service-update-request.json
   :language: javascript

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - name: name
   - service: service
   - links: links
   - type: type
   - id: id
   - description: description

Response Example
----------------

.. literalinclude:: ./samples/admin/service-update-response.json
   :language: javascript


Delete service
==============

.. rest_method::  DELETE /v3/services/{service_id}

Deletes a service.

If you try to delete a service that still has associated endpoints,
this call either deletes all associated endpoints or fails until
all endpoints are deleted.

Error response codes:204,413,415,405,404,403,401,400,503,409,

Request
-------

.. rest_parameters:: parameters.yaml

   - service_id: service_id
