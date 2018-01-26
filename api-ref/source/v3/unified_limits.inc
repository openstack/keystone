.. -*- rst -*-

==============
Unified Limits
==============

In OpenStack, a quota system mainly contains two parts: ``limit`` and
``usage``. The Unified limits in Keystone is a replacement of the ``limit``
part. It contains two kinds of resouces: ``Registered Limit`` and ``Limit``. A
``registered limit`` is a default limit. It is usually created by the services
which are registered in Keystone. A ``limit`` is the limit that override the
registered limit for each project.

List Registered Limits
======================

.. rest_method::  GET /v3/registered_limits

Lists Registered Limits.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/registered_limits``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - service_id: service_id_query
   - region_id: region_id_query
   - resource_name: resource_name_query


Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - links: link_collection
   - registered_limits: registered_limits
   - id: registered_limit_id
   - service_id: service_id_registered_limit
   - region_id: region_id_response_body
   - resource_name: resource_name
   - default_limit: default_limit
   - links: link_response_body


Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success status.yaml

   - 200

.. rest_status_code:: error status.yaml

   - 401
   - 403

Example
~~~~~~~

.. literalinclude:: ./samples/admin/registered-limits-list-response.json
   :language: javascript


Create Registered Limits
========================

.. rest_method::  POST /v3/registered_limits

Creates registered limits. It supports to create more than one registered limit
in one request.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/registered_limits``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - registered_limits: registered_limits
   - service_id: service_id_registered_limit
   - region_id: region_id_request_body
   - resource_name: resource_name
   - default_limit: default_limit

Examples
~~~~~~~~


.. literalinclude:: ./samples/admin/registered-limits-create-request.json
   :language: javascript


Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - registered_limits: registered_limits
   - id: registered_limit_id
   - service_id: service_id_registered_limit
   - region_id: region_id_response_body
   - resource_name: resource_name
   - default_limit: default_limit
   - links: link_response_body

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success status.yaml

   - 201

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 409

Examples
~~~~~~~~


.. literalinclude:: ./samples/admin/registered-limits-create-response.json
   :language: javascript


Update Registered Limits
========================

.. rest_method::  PUT /v3/registered_limits

Updates registered limits. It supports to update more than one registered limit
in one request.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/registered_limits``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - registered_limits: registered_limits
   - id: registered_limit_id
   - service_id: service_id_registered_limit
   - region_id: region_id_request_body
   - resource_name: resource_name
   - default_limit: default_limit

Example
~~~~~~~

.. literalinclude:: ./samples/admin/registered-limits-update-request.json
   :language: javascript

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - registered_limits: registered_limits
   - id: registered_limit_id
   - service_id: service_id_registered_limit
   - region_id: region_id_response_body
   - resource_name: resource_name
   - default_limit: default_limit
   - links: link_response_body


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

.. literalinclude:: ./samples/admin/registered-limits-update-response.json
   :language: javascript


Show Registered Limit Details
=============================

.. rest_method::  GET /v3/registered_limits/{registered_limit_id}

Shows details for a registered limit.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/registered_limit``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - registered_limit_id: registered_limit_id_path

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - registered_limit: registered_limit
   - id: registered_limit_id
   - service_id: service_id_registered_limit
   - region_id: region_id_response_body
   - resource_name: resource_name
   - default_limit: default_limit
   - links: link_response_body

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success status.yaml

   - 200

.. rest_status_code:: error status.yaml

   - 401
   - 403
   - 404

Example
~~~~~~~

.. literalinclude:: ./samples/admin/registered-limit-show-response.json
   :language: javascript


Delete Registered Limit
=======================

.. rest_method::  DELETE /v3/registered_limits/{registered_limit_id}

Deletes a registered limit.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/registered_limit``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - registered_limit_id: registered_limit_id_path

Response
--------

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success status.yaml

   - 204

.. rest_status_code:: error status.yaml

   - 401
   - 403
   - 404


List Limits
===========

.. rest_method::  GET /v3/limits

Lists Limits.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/limits``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - service_id: service_id_query
   - region_id: region_id_query
   - resource_name: resource_name_query


Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - links: link_collection
   - limits: limits
   - id: limit_id
   - project_id: project_id
   - service_id: service_id_limit
   - region_id: region_id_response_body
   - resource_name: resource_name
   - resource_limit: resource_limit
   - links: link_response_body


Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success status.yaml

   - 200

.. rest_status_code:: error status.yaml

   - 401
   - 403

Example
~~~~~~~

.. literalinclude:: ./samples/admin/limits-list-response.json
   :language: javascript


Create Limits
=============

.. rest_method::  POST /v3/limits

Creates limits. It supports to create more than one limit in one request.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/limits``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - limits: limits
   - service_id: service_id_limit
   - region_id: region_id_request_body
   - resource_name: resource_name
   - resource_limit: resource_limit

Examples
~~~~~~~~


.. literalinclude:: ./samples/admin/limits-create-request.json
   :language: javascript


Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - limits: limits
   - id: limit_id
   - service_id: service_id_limit
   - region_id: region_id_response_body
   - resource_name: resource_name
   - resource_limit: resource_limit
   - links: link_response_body

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success status.yaml

   - 201

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 409

Examples
~~~~~~~~


.. literalinclude:: ./samples/admin/limits-create-response.json
   :language: javascript


Update Limits
=============

.. rest_method::  PUT /v3/limits

Updates limits. It supports to update more than one limit in one request. It
only supports to update ``resource_limit`` for limits. It will return all the
limits for the project.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/limits``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - limits: limits
   - resource_limit: resource_limit

Example
~~~~~~~

.. literalinclude:: ./samples/admin/limits-update-request.json
   :language: javascript

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - limits: limits
   - id: limit_id
   - service_id: service_id_limit
   - region_id: region_id_response_body
   - resource_name: resource_name
   - resource_limit: resource_limit
   - links: link_response_body


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

.. literalinclude:: ./samples/admin/limits-update-response.json
   :language: javascript


Show Limit Details
==================

.. rest_method::  GET /v3/limits/{limit_id}

Shows details for a limit.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/limit``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - limit_id: limit_id_path

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - limits: limits
   - id: limit_id
   - project_id: project_id
   - service_id: service_id_limit
   - region_id: region_id_response_body
   - resource_name: resource_name
   - resource_limit: resource_limit
   - links: link_response_body

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success status.yaml

   - 200

.. rest_status_code:: error status.yaml

   - 401
   - 403
   - 404

Example
~~~~~~~

.. literalinclude:: ./samples/admin/limit-show-response.json
   :language: javascript


Delete Registered Limit
=======================

.. rest_method::  DELETE /v3/limits/{limit_id}

Deletes a limit.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/limit``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - limit_id: limit_id_path

Response
--------

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success status.yaml

   - 204

.. rest_status_code:: error status.yaml

   - 401
   - 403
   - 404
