.. -*- rst -*-

Register a service provider
===========================

.. rest_method::  PUT /v3/OS-FEDERATION/service_providers/{id}

Create a service provider entity.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/ext/OS-FEDERATION/1.0/rel/service_provider``

Request
-------

Parameters
~~~~~~~~~~
.. rest_parameters:: federation/service-provider/parameters.yaml

   - auth_url: auth_url
   - description: description
   - enabled: enabled
   - id: id_path
   - sp_url: sp_url

Example
~~~~~~~

.. literalinclude:: federation/service-provider/samples/register-request.json
   :language: javascript

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: federation/service-provider/parameters.yaml

   - auth_url: auth_url
   - description: description
   - enabled: enabled
   - id: id_body
   - links: links
   - relay_state_prefix: relay_state_prefix
   - sp_url: sp_url

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success ../v3/status.yaml

   - 201

Example
~~~~~~~

.. literalinclude:: federation/service-provider/samples/register-response.json
   :language: javascript


List service providers
======================

.. rest_method::  GET /v3/OS-FEDERATION/service_providers

List all service providers.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/ext/OS-FEDERATION/1.0/rel/service_providers``

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: federation/service-provider/parameters.yaml

   - links: links_collection
   - service_providers: service_providers

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success ../v3/status.yaml

   - 200

Example
~~~~~~~

.. literalinclude:: federation/service-provider/samples/list-response.json
   :language: javascript


Get service provider
====================

.. rest_method::  GET /v3/OS-FEDERATION/service_providers/{id}

Get a specific service provider reference.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/ext/OS-FEDERATION/1.0/rel/service_provider``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: federation/service-provider/parameters.yaml

   - id: id_path

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: federation/service-provider/parameters.yaml

   - auth_url: auth_url
   - description: description
   - enabled: enabled
   - id: id_body
   - links: links
   - relay_state_prefix: relay_state_prefix
   - sp_url: sp_url

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success ../v3/status.yaml

   - 200

Example
~~~~~~~

.. literalinclude:: federation/service-provider/samples/get-response.json
   :language: javascript


Delete service provider
=======================

.. rest_method::  DELETE /v3/OS-FEDERATION/service_providers/{id}

Delete a service provider.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/ext/OS-FEDERATION/1.0/rel/service_provider``

Request
-------

Parameters
~~~~~~~~~~~

.. rest_parameters:: federation/service-provider/parameters.yaml

   - id: id_path

Response
--------

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success ../v3/status.yaml

   - 204

Update service provider
=======================

.. rest_method::  PATCH /v3/OS-FEDERATION/service_providers/{id}

Update a service provider's attributes.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/ext/OS-FEDERATION/1.0/rel/service_provider``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: federation/service-provider/parameters.yaml

   - id: id_path
   - auth_url: auth_url
   - description: description
   - enabled: enabled
   - sp_url: sp_url

Example
~~~~~~~

.. literalinclude:: federation/service-provider/samples/update-request.json
   :language: javascript

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: federation/service-provider/parameters.yaml

   - auth_url: auth_url
   - description: description
   - enabled: enabled
   - id: id_body
   - links: links
   - relay_state_prefix: relay_state_prefix
   - sp_url: sp_url

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success ../v3/status.yaml

   - 200

Example
~~~~~~~~

.. literalinclude:: federation/service-provider/samples/update-response.json
   :language: javascript