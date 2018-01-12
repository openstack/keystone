.. -*- rst -*-

==========
 Policies
==========

.. warning::

    The ``policies`` API is deprecated. Keystone is not a policy management
    service. Do not use this.

A policy is an arbitrarily serialized policy engine rule set to be
consumed by a remote service.

You encode policy rule sets into a blob that remote services can
consume. To do so, set ``type`` to ``application/json`` and specify
policy rules as JSON strings in a ``blob``. For example:

::

   {
       "blob":{
           "foobar_user":[
               "role:compute-user"
           ]
       }
   }


Create policy
=============

.. rest_method::  POST /v3/policies

Creates a policy.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/policies``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - policy: policy
   - type: policy_type
   - blob: policy_blob_str

Example
~~~~~~~

.. literalinclude:: ./samples/admin/policy-create-request.json
   :language: javascript

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - links: policy_links
   - blob: policy_blob_str
   - policy: policy
   - type: policy_type
   - id: policy_id

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success status.yaml

   - 201

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404
   - 405
   - 409
   - 413
   - 415
   - 503

List policies
=============

.. rest_method::  GET /v3/policies

Lists policies.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/policies``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - type: policy_type_query

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - links: policy_links
   - blob: policy_blob_obj
   - policies: policies
   - type: policy_type
   - id: policy_id

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success status.yaml

   - 200

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404
   - 405
   - 413
   - 503

Example
~~~~~~~

.. literalinclude:: ./samples/admin/policies-list-response.json
   :language: javascript


Show policy details
===================

.. rest_method::  GET /v3/policies/{policy_id}

Shows details for a policy.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/policy``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - policy_id: policy_id_path

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - links: policy_links
   - blob: policy_blob_obj
   - policy: policy
   - type: policy_type
   - id: policy_id

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success status.yaml

   - 200

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404
   - 405
   - 413
   - 503

Example
~~~~~~~

.. literalinclude:: ./samples/admin/policy-show-response.json
   :language: javascript


Update policy
=============

.. rest_method::  PATCH /v3/policies/{policy_id}

Updates a policy.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/policy``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - policy_id: policy_id_path
   - policy: policy
   - type: policy_type
   - blob: policy_blob_obj

Example
~~~~~~~

.. literalinclude:: ./samples/admin/policy-update-request.json
   :language: javascript

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - links: policy_links
   - blob: policy_blob_obj
   - policy: policy
   - type: policy_type
   - id: policy_id

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success status.yaml

   - 200

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404
   - 405
   - 409
   - 413
   - 415
   - 503

Example
~~~~~~~

.. literalinclude:: ./samples/admin/policy-update-response.json
   :language: javascript


Delete policy
=============

.. rest_method::  DELETE /v3/policies/{policy_id}

Deletes a policy.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/policy``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - policy_id: policy_id_path

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
   - 405
   - 409
   - 413
   - 415
   - 503