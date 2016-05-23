.. -*- rst -*-

===================
Policies (policies)
===================

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

Error response codes:201,413,415,405,404,403,401,400,503,409,

Request
-------

.. rest_parameters:: parameters.yaml

   - policy: policy
   - user_id: user_id
   - project_id: project_id
   - type: type
   - blob: blob

Request Example
---------------

.. literalinclude:: ./samples/admin/policy-create-request.json
   :language: javascript

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - user_id: user_id
   - links: links
   - blob: blob
   - policy: policy
   - project_id: project_id
   - type: type
   - id: id


List policies
=============

.. rest_method::  GET /v3/policies

Lists policies.

Normal response codes: 200
Error response codes:413,405,404,403,401,400,503,

Request
-------

.. rest_parameters:: parameters.yaml

   - type: type

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - user_id: user_id
   - links: links
   - blob: blob
   - policies: policies
   - project_id: project_id
   - type: type
   - id: id

Response Example
----------------

.. literalinclude:: ./samples/admin/policies-list-response.json
   :language: javascript


Show policy details
===================

.. rest_method::  GET /v3/policies/{policy_id}

Shows details for a policy.

Normal response codes: 200
Error response codes:413,405,404,403,401,400,503,

Request
-------

.. rest_parameters:: parameters.yaml

   - policy_id: policy_id

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - user_id: user_id
   - links: links
   - blob: blob
   - policy: policy
   - project_id: project_id
   - type: type
   - id: id

Response Example
----------------

.. literalinclude:: ./samples/admin/policy-show-response.json
   :language: javascript


Update policy
=============

.. rest_method::  PATCH /v3/policies/{policy_id}

Updates a policy.

Normal response codes: 200
Error response codes:413,415,405,404,403,401,400,503,409,

Request
-------

.. rest_parameters:: parameters.yaml

   - policy: policy
   - user_id: user_id
   - project_id: project_id
   - type: type
   - blob: blob
   - policy_id: policy_id

Request Example
---------------

.. literalinclude:: ./samples/admin/policy-update-request.json
   :language: javascript

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - user_id: user_id
   - links: links
   - blob: blob
   - policy: policy
   - project_id: project_id
   - type: type
   - id: id

Response Example
----------------

.. literalinclude:: ./samples/admin/policy-update-response.json
   :language: javascript


Delete policy
=============

.. rest_method::  DELETE /v3/policies/{policy_id}

Deletes a policy.

Error response codes:204,413,415,405,404,403,401,400,503,409,

Request
-------

.. rest_parameters:: parameters.yaml

   - policy_id: policy_id
