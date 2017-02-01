.. -*- rst -*-

Create a mapping
================

.. rest_method::  PUT /v3/OS-FEDERATION/mappings/{id}

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/ext/OS-FEDERATION/1.0/rel/mapping``

Normal response codes: 201

Request
-------

.. rest_parameters:: federation/mapping/parameters.yaml

   - id: id_path
   - rules: rules

Request Example
---------------

.. literalinclude:: federation/mapping/samples/create-request.json
   :language: javascript

Response
--------

.. rest_parameters:: federation/mapping/parameters.yaml

   - id: id_body
   - links: links
   - rules: rules

Response Example
----------------

.. literalinclude:: federation/mapping/samples/create-response.json
   :language: javascript


Get a mapping
=============

.. rest_method::  GET /v3/OS-FEDERATION/mappings/{id}

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/ext/OS-FEDERATION/1.0/rel/mapping``

Normal response codes: 200

Request
-------

.. rest_parameters:: federation/mapping/parameters.yaml

   - id: id_path

Response
--------

.. rest_parameters:: federation/mapping/parameters.yaml

   - id: id_body
   - links: links
   - rules: rules

Response Example
----------------

.. literalinclude:: federation/mapping/samples/get-response.json
   :language: javascript


Update a mapping
================

.. rest_method::  PATCH /v3/OS-FEDERATION/mappings/{id}

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/ext/OS-FEDERATION/1.0/rel/mapping``

Normal response codes: 200

Request
-------

.. rest_parameters:: federation/mapping/parameters.yaml

   - id: id_path
   - rules: rules

Request Example
---------------

.. literalinclude:: federation/mapping/samples/update-request.json
   :language: javascript

Response
--------

.. rest_parameters:: federation/mapping/parameters.yaml

   - id: id_body
   - links: links
   - rules: rules

Response Example
----------------

.. literalinclude:: federation/mapping/samples/update-response.json
   :language: javascript


List all mappings
=================

.. rest_method::  GET /v3/OS-FEDERATION/mappings

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/ext/OS-FEDERATION/1.0/rel/mappings``

Normal response codes: 200

Response
--------

.. rest_parameters:: federation/mapping/parameters.yaml

   - links: links_collection
   - mappings: mappings

Response Example
----------------

.. literalinclude:: federation/mapping/samples/list-response.json
   :language: javascript


Delete a mapping
================

.. rest_method::  DELETE /v3/OS-FEDERATION/mappings/{id}

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/ext/OS-FEDERATION/1.0/rel/mapping``

Normal response codes: 204

Request
-------

.. rest_parameters:: federation/mapping/parameters.yaml

   - id: id_path
