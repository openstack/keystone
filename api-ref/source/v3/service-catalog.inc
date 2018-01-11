.. -*- rst -*-

===============================
 Service catalog and endpoints
===============================

A service is an OpenStack web service that you can access through a
URL, i.e. an endpoint.

A service catalog lists the services that are available to the
caller based upon the current authorization.

You can create, list, show details for, update, and delete
services. When you create or update a service, you can enable the
service, which causes it and its endpoints to appear in the service
catalog.

You can create, list, show details for, update, and delete endpoints.


List services
=============

.. rest_method::  GET /v3/services

Lists all services.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/services``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - type: service_type_query

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - name: service_name
   - links: service_links
   - enabled: service_enabled
   - services: services
   - type: service_type
   - id: service_id
   - description: service_description

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

.. literalinclude:: ./samples/admin/services-list-response.json
   :language: javascript


Create service
==============

.. rest_method::  POST /v3/services

Creates a service.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/services``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - description: service_description
   - service: service
   - enabled: service_enabled
   - type: service_type
   - name: service_name

Example
~~~~~~~

.. literalinclude:: ./samples/admin/service-create-request.json
   :language: javascript

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - name: service_name
   - service: service
   - links: service_links
   - type: service_type
   - id: service_id
   - description: service_description

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success status.yaml

   - 201

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 409

Show service details
====================

.. rest_method::  GET /v3/services/{service_id}

Shows details for a service.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/service``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - service_id: service_id_path

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - name: service_name
   - service: service
   - links: service_links
   - type: service_type
   - id: service_id
   - description: service_description

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

.. literalinclude:: ./samples/admin/service-show-response.json
   :language: javascript


Update service
==============

.. rest_method::  PATCH /v3/services/{service_id}

Updates a service.

The request body is the same as the create service request body,
except that you include only those attributes that you want to
update.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/services``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - type: service_type
   - enabled: service_enabled_not_required
   - description: service_description_not_required
   - service: service
   - name: service_name
   - service_id: service_id_path

Example
~~~~~~~

.. literalinclude:: ./samples/admin/service-update-request.json
   :language: javascript

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - name: service_name
   - service: service
   - links: service_links
   - type: service_type
   - id: service_id
   - description: service_description

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

.. literalinclude:: ./samples/admin/service-update-response.json
   :language: javascript


Delete service
==============

.. rest_method::  DELETE /v3/services/{service_id}

Deletes a service.

If you try to delete a service that still has associated endpoints,
this call either deletes all associated endpoints or fails until
all endpoints are deleted.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/service``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - service_id: service_id_path

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


List endpoints
==============

.. rest_method::  GET /v3/endpoints

Lists all available endpoints.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/endpoints``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - interface: interface_query
   - service_id: service_id_query

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - region_id: region_id_required
   - links: endpoints_links
   - url: endpoint_url
   - region: endpoint_region
   - enabled: endpoint_enabled
   - interface: endpoint_region
   - service_id: service_id
   - endpoints: endpoints
   - id: endpoint_id

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

.. literalinclude:: ./samples/admin/endpoints-list-response.json
   :language: javascript


Create endpoint
===============

.. rest_method::  POST /v3/endpoints

Creates an endpoint.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/endpoints``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - endpoint: endpoint
   - url: endpoint_url
   - enabled: endpoint_enabled_not_required
   - interface: endpoint_interface
   - service_id: service_id
   - region_id: region_id_not_required

Example
~~~~~~~

.. literalinclude:: ./samples/admin/endpoint-create-request.json
   :language: javascript

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - endpoint: endpoint
   - links: endpoint_links
   - url: endpoint_url
   - region: endpoint_region
   - enabled: endpoint_enabled
   - interface: endpoint_interface
   - service_id: service_id
   - id: endpoint_id
   - region_id: region_id_required

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success status.yaml

   - 201

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 409


Show endpoint details
=====================

.. rest_method::  GET /v3/endpoints/{endpoint_id}

Shows details for an endpoint.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/endpoints``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - endpoint_id: endpoint_id_path

Response
--------

Parameters
~~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - endpoint: endpoint
   - name: endpoint_name
   - links: endpoint_links
   - url: endpoint_url
   - region: endpoint_region
   - interface: endpoint_interface
   - service_id: service_id

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

.. literalinclude:: ./samples/admin/endpoint-show-response.json
   :language: javascript


Update endpoint
===============

.. rest_method::  PATCH /v3/endpoints/{endpoint_id}

Updates an endpoint.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/endpoint``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - endpoint: endpoint
   - url: endpoint_url
   - region: endpoint_region
   - interface: endpoint_interface
   - service_id: service_id
   - endpoint_id: endpoint_id_path

Example
~~~~~~~

.. literalinclude:: ./samples/admin/endpoint-update-request.json
   :language: javascript

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - endpoint: endpoint
   - id: endpoint_id
   - links: endpoint_links
   - url: endpoint_url
   - region: endpoint_region
   - interface: endpoint_interface
   - service_id: service_id

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

.. literalinclude:: ./samples/admin/endpoint-update-response.json
   :language: javascript


Delete endpoint
===============

.. rest_method::  DELETE /v3/endpoints/{endpoint_id}

Deletes an endpoint.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/endpoint``

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

.. rest_status_code:: success status.yaml

   - 204

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404