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

.. rest_parameters:: admin-endpoints_parameters.yaml

   - endpoints: endpoints_list

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

.. rest_parameters:: admin-endpoints_parameters.yaml

   - endpoint: endpoint_create
   - region: region
   - service_id: service_id
   - publicurl: publicurl
   - adminurl: adminurl
   - internalurl: internalurl

Request Example
---------------

.. literalinclude:: samples/admin/endpoint-create-request.json
   :language: javascript

Response Parameters
-------------------

.. rest_parameters:: admin-endpoints_parameters.yaml

   - adminurl: adminurl
   - id: id
   - internalurl: internalurl
   - publicurl: publicurl
   - region: region


Delete endpoint template
========================

.. rest_method::  DELETE /v2.0/endpoints/{endpointId}

Normal response codes: 204

Request
-------

.. rest_parameters:: admin-endpoints_parameters.yaml

   - endpointId: id_path
