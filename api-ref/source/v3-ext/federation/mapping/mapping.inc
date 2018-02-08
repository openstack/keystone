.. -*- rst -*-

Create a mapping
================

.. rest_method::  PUT /v3/OS-FEDERATION/mappings/{id}

Create a federated mapping.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/ext/OS-FEDERATION/1.0/rel/mapping``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: federation/mapping/parameters.yaml

   - id: id_path
   - rules: rules

Example
~~~~~~~

.. literalinclude:: federation/mapping/samples/create-request.json
   :language: javascript

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: federation/mapping/parameters.yaml

   - id: id_body
   - links: links
   - rules: rules

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success ../v3/status.yaml

   - 201

Example
~~~~~~~

.. literalinclude:: federation/mapping/samples/create-response.json
   :language: javascript


Get a mapping
=============

.. rest_method::  GET /v3/OS-FEDERATION/mappings/{id}

Get a specific federated mapping.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/ext/OS-FEDERATION/1.0/rel/mapping``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: federation/mapping/parameters.yaml

   - id: id_path

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: federation/mapping/parameters.yaml

   - id: id_body
   - links: links
   - rules: rules

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success ../v3/status.yaml

   - 200

Example
~~~~~~~

.. literalinclude:: federation/mapping/samples/get-response.json
   :language: javascript


Update a mapping
================

.. rest_method::  PATCH /v3/OS-FEDERATION/mappings/{id}

Update a federated mapping.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/ext/OS-FEDERATION/1.0/rel/mapping``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: federation/mapping/parameters.yaml

   - id: id_path
   - rules: rules

Example
~~~~~~~

.. literalinclude:: federation/mapping/samples/update-request.json
   :language: javascript

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: federation/mapping/parameters.yaml

   - id: id_body
   - links: links
   - rules: rules

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success ../v3/status.yaml

   - 200

Example
~~~~~~~

.. literalinclude:: federation/mapping/samples/update-response.json
   :language: javascript


List mappings
=============

.. rest_method::  GET /v3/OS-FEDERATION/mappings

List all federated mappings.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/ext/OS-FEDERATION/1.0/rel/mappings``

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: federation/mapping/parameters.yaml

   - links: links_collection
   - mappings: mappings

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success ../v3/status.yaml

   - 200

Example
~~~~~~~

.. literalinclude:: federation/mapping/samples/list-response.json
   :language: javascript


Delete a mapping
================

.. rest_method::  DELETE /v3/OS-FEDERATION/mappings/{id}

Remove a specific federated mapping.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/ext/OS-FEDERATION/1.0/rel/mapping``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: federation/mapping/parameters.yaml

   - id: id_path

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success ../v3/status.yaml

   - 204