.. -*- rst -*-

Create a mapping
================

.. rest_method::  PUT /v3/OS-FEDERATION/mappings/{mapping_id}

Normal response codes: 201

Request Example
---------------

.. literalinclude:: federation/mapping/samples/create-request.json
   :language: javascript

Response Example
----------------

.. literalinclude:: federation/mapping/samples/create-response.json
   :language: javascript


Get a mapping
=============

.. rest_method::  GET /v3/OS-FEDERATION/mappings/{mapping_id}

Normal response codes: 200

Response Example
----------------

.. literalinclude:: federation/mapping/samples/get-response.json
   :language: javascript


Update a mapping
================

.. rest_method::  PATCH /v3/OS-FEDERATION/mappings/{mapping_id}

Normal response codes: 200

Request Example
---------------

.. literalinclude:: federation/mapping/samples/update-request.json
   :language: javascript

Response Example
----------------

.. literalinclude:: federation/mapping/samples/update-response.json
   :language: javascript


List all mappings
=================

.. rest_method::  GET /v3/OS-FEDERATION/mappings

Normal response codes: 200

Response Example
----------------

.. literalinclude:: federation/mapping/samples/list-response.json
   :language: javascript


Delete a mapping
================

.. rest_method::  DELETE /v3/OS-FEDERATION/mappings/{mapping_id}

Normal response codes: 204
