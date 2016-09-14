.. -*- rst -*-

=========
Endpoints
=========


List endpoint templates
=======================

.. rest_method::  GET /v2.0/endpoints

Normal response codes: 200

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - endpoints: endpoints

Response Example
----------------

.. literalinclude:: samples/admin/endpoint-list-response.json
   :language: javascript


Create endpoint template
========================

.. rest_method::  POST /v2.0/endpoints

Normal response codes: 201

Request
-------

.. rest_parameters:: parameters.yaml

   - endpoint: endpoint
   - region: endpoint_region_request
   - service_id: service_id_request
   - publicurl: endpoint_publicurl_request
   - adminurl: endpoint_adminurl_request
   - internalurl: endpoint_internalurl_request

Request Example
---------------

.. literalinclude:: samples/admin/endpoint-create-request.json
   :language: javascript

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - endpoint: endpoint
   - id: endpoint_id
   - internalurl: endpoint_internalurl_response
   - publicurl: endpoint_publicurl_response
   - region: endpoint_region_response


Delete endpoint template
========================

.. rest_method::  DELETE /v2.0/endpoints/{endpointId}

Normal response codes: 204

Request
-------

.. rest_parameters:: parameters.yaml

   - endpointId: endpoint_id_path
