.. -*- rst -*-

Register a Service Provider
===========================

.. rest_method::  PUT /v3/OS-FEDERATION/service_providers/{sp_id}

Normal response codes: 201
Error response codes: 400 Bad Request when registering a service provider with
invalid URLs for either `auth_url` or `sp_url`.

Request Example
---------------

.. literalinclude:: federation/service-provider/samples/register-request.json
   :language: javascript

Response Example
----------------

.. literalinclude:: federation/service-provider/samples/register-response.json
   :language: javascript


Listing Service Providers
=========================

.. rest_method::  GET /v3/OS-FEDERATION/service_providers

Normal response codes: 200

Response Example
----------------

.. literalinclude:: federation/service-provider/samples/list-response.json
   :language: javascript


Get Service Provider
====================

.. rest_method::  GET /v3/OS-FEDERATION/service_providers/{sp_id}

Normal response codes: 200

Response Example
----------------

.. literalinclude:: federation/service-provider/samples/get-response.json
   :language: javascript


Delete Service Provider
=======================

.. rest_method::  DELETE /v3/OS-FEDERATION/service_providers/{sp_id}

Normal response codes: 204


Update Service Provider
=======================

.. rest_method::  PATCH /v3/OS-FEDERATION/service_providers/{sp_id}

Normal response codes: 200
Error response codes: 400 Bad Request when updating a service provider with
invalid URLs for either `auth_url` or `sp_url`.

Request Example
---------------

.. literalinclude:: federation/service-provider/samples/update-request.json
   :language: javascript

Response Example
----------------

.. literalinclude:: federation/service-provider/samples/update-response.json
   :language: javascript
