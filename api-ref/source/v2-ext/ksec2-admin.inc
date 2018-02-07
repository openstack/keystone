.. -*- rst -*-

========================
OS-KSEC2 admin extension
========================

Supports Amazon Elastic Compute (EC2) style authentication.

EC2 Authentication
==================

.. rest_method::  POST /v2.0/ec2tokens

Authenticate for token.

Request
-------

Example
~~~~~~~

.. literalinclude:: samples/OS-KSEC2/authenticate-request.json
   :language: javascript

Parameters
~~~~~~~~~~

Response
--------

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success ../v3/status.yaml

  - 200

.. rest_status_code:: error ../v3/status.yaml

  - 400
  - 401

Example
~~~~~~~

.. literalinclude:: samples/OS-KSEC2/authenticate-response.json
   :language: javascript

Grant credential to user
========================

.. rest_method::  POST /v2.0/users/{userId}/credentials/OS-EC2

Grants a credential to a user.

Request
-------

.. rest_parameters:: parameters.yaml

   - userId: user_id_path


Example
~~~~~~~

.. literalinclude:: samples/OS-KSEC2/ec2Credentials-create-request.json
   :language: javascript


Response
--------

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success ../v3/status.yaml

  - 201

.. rest_status_code:: error ../v3/status.yaml

  - 400
  - 401
  - 403
  - 404
  - 405
  - 409
  - 413
  - 415
  - 503

List credentials (EC2 extension)
================================

.. rest_method::  GET /v2.0/users/{userId}/credentials/OS-EC2

Lists credentials.

Request
-------

.. rest_parameters:: parameters.yaml

   - userId: user_id_path

Response
--------

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success ../v3/status.yaml

  - 200

.. rest_status_code:: error ../v3/status.yaml

  - 400
  - 401
  - 403
  - 404
  - 405
  - 413
  - 503

Example
~~~~~~~

.. literalinclude:: samples/OS-KSEC2/credentialswithec2-list-response.json
   :language: javascript


Delete user credentials
=======================

.. rest_method::  DELETE /v2.0/users/{userId}/credentials/OS-EC2/{credentialId}

Deletes user credentials.

Request
-------

.. rest_parameters:: parameters.yaml

   - userId: user_id_path
   - credentialId: credential_id

Response
--------

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success ../v3/status.yaml

  - 204

.. rest_status_code:: error ../v3/status.yaml

  - 400
  - 401
  - 403
  - 404
  - 405
  - 409
  - 413
  - 415
  - 503

Get user credentials
====================

.. rest_method::  GET /v2.0/users/{userId}/credentials/OS-EC2/{credentialId}

Gets user credentials.

Request
-------

.. rest_parameters:: parameters.yaml

   - userId: user_id_path
   - credentialId: credential_id

Response
--------

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success ../v3/status.yaml

  - 200

.. rest_status_code:: error ../v3/status.yaml

  - 400
  - 401
  - 403
  - 404
  - 405
  - 413
  - 503

Example
~~~~~~~

.. literalinclude:: samples/OS-KSEC2/ec2Credentials-show-response.json
   :language: javascript
