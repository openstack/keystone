.. -*- rst -*-

Register a Service Provider
===========================

.. rest_method::  PUT /v3/OS-FEDERATION/service_providers/{id}

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/ext/OS-FEDERATION/1.0/rel/service_provider``

Normal response codes: 201
Error response codes: 400 Bad Request when registering a service provider with
invalid URLs for either `auth_url` or `sp_url`.

Request
-------

.. rest_parameters:: federation/service-provider/parameters.yaml

   - auth_url: auth_url
   - description: description
   - enabled: enabled
   - id: id_path
   - sp_url: sp_url

Request Example
---------------

.. literalinclude:: federation/service-provider/samples/register-request.json
   :language: javascript

Response
--------

.. rest_parameters:: federation/service-provider/parameters.yaml

   - auth_url: auth_url
   - description: description
   - enabled: enabled
   - id: id_body
   - links: links
   - relay_state_prefix: relay_state_prefix
   - sp_url: sp_url

Response Example
----------------

.. literalinclude:: federation/service-provider/samples/register-response.json
   :language: javascript


Listing Service Providers
=========================

.. rest_method::  GET /v3/OS-FEDERATION/service_providers

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/ext/OS-FEDERATION/1.0/rel/service_providers``

Normal response codes: 200

Response
--------

.. rest_parameters:: federation/service-provider/parameters.yaml

   - links: links_collection
   - service_providers: service_providers

Response Example
----------------

.. literalinclude:: federation/service-provider/samples/list-response.json
   :language: javascript


Get Service Provider
====================

.. rest_method::  GET /v3/OS-FEDERATION/service_providers/{id}

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/ext/OS-FEDERATION/1.0/rel/service_provider``

Normal response codes: 200

Request
-------

.. rest_parameters:: federation/service-provider/parameters.yaml

   - id: id_path

Response
--------

.. rest_parameters:: federation/service-provider/parameters.yaml

   - auth_url: auth_url
   - description: description
   - enabled: enabled
   - id: id_body
   - links: links
   - relay_state_prefix: relay_state_prefix
   - sp_url: sp_url

Response Example
----------------

.. literalinclude:: federation/service-provider/samples/get-response.json
   :language: javascript


Delete Service Provider
=======================

.. rest_method::  DELETE /v3/OS-FEDERATION/service_providers/{id}

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/ext/OS-FEDERATION/1.0/rel/service_provider``

Normal response codes: 204

Request
-------

.. rest_parameters:: federation/service-provider/parameters.yaml

   - id: id_path


Update Service Provider
=======================

.. rest_method::  PATCH /v3/OS-FEDERATION/service_providers/{id}

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/ext/OS-FEDERATION/1.0/rel/service_provider``

Normal response codes: 200
Error response codes: 400 Bad Request when updating a service provider with
invalid URLs for either `auth_url` or `sp_url`.

Request
-------

.. rest_parameters:: federation/service-provider/parameters.yaml

   - id: id_path
   - auth_url: auth_url
   - description: description
   - enabled: enabled
   - sp_url: sp_url

Request Example
---------------

.. literalinclude:: federation/service-provider/samples/update-request.json
   :language: javascript

Response
--------

.. rest_parameters:: federation/service-provider/parameters.yaml

   - auth_url: auth_url
   - description: description
   - enabled: enabled
   - id: id_body
   - links: links
   - relay_state_prefix: relay_state_prefix
   - sp_url: sp_url

Response Example
----------------

.. literalinclude:: federation/service-provider/samples/update-response.json
   :language: javascript
