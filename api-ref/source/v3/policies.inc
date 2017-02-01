.. -*- rst -*-

==========
 Policies
==========

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

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/policies``

Creates a policy.

Normal response codes: 201

Error response codes: 413,415,405,404,403,401,400,503,409

Request
-------

.. rest_parameters:: parameters.yaml

   - policy: policy
   - type: policy_type
   - blob: policy_blob_str

Request Example
---------------

.. literalinclude:: ./samples/admin/policy-create-request.json
   :language: javascript

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - links: policy_links
   - blob: policy_blob_str
   - policy: policy
   - type: policy_type
   - id: policy_id


List policies
=============

.. rest_method::  GET /v3/policies

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/policies``

Lists policies.

Normal response codes: 200

Error response codes: 413,405,404,403,401,400,503

Request
-------

.. rest_parameters:: parameters.yaml

   - type: policy_type_query

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - links: policy_links
   - blob: policy_blob_obj
   - policies: policies
   - type: policy_type
   - id: policy_id

Response Example
----------------

.. literalinclude:: ./samples/admin/policies-list-response.json
   :language: javascript


Show policy details
===================

.. rest_method::  GET /v3/policies/{policy_id}

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/policy``

Shows details for a policy.

Normal response codes: 200

Error response codes: 413,405,404,403,401,400,503

Request
-------

.. rest_parameters:: parameters.yaml

   - policy_id: policy_id_path

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - links: policy_links
   - blob: policy_blob_obj
   - policy: policy
   - type: policy_type
   - id: policy_id

Response Example
----------------

.. literalinclude:: ./samples/admin/policy-show-response.json
   :language: javascript


Update policy
=============

.. rest_method::  PATCH /v3/policies/{policy_id}

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/policy``

Updates a policy.

Normal response codes: 200

Error response codes: 413,415,405,404,403,401,400,503,409

Request
-------

.. rest_parameters:: parameters.yaml

   - policy_id: policy_id_path
   - policy: policy
   - type: policy_type
   - blob: policy_blob_obj

Request Example
---------------

.. literalinclude:: ./samples/admin/policy-update-request.json
   :language: javascript

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - links: policy_links
   - blob: policy_blob_obj
   - policy: policy
   - type: policy_type
   - id: policy_id

Response Example
----------------

.. literalinclude:: ./samples/admin/policy-update-response.json
   :language: javascript


Delete policy
=============

.. rest_method::  DELETE /v3/policies/{policy_id}

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/policy``

Deletes a policy.

Normal response codes: 204

Error response codes: 413,415,405,404,403,401,400,503,409

Request
-------

.. rest_parameters:: parameters.yaml

   - policy_id: policy_id_path
