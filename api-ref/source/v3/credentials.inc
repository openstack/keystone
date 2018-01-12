.. -*- rst -*-

=============
 Credentials
=============

In exchange for a set of authentication credentials that the user
submits, the Identity service generates and returns a token. A
token represents the authenticated identity of a user and,
optionally, grants authorization on a specific project or domain.

You can list all credentials, and create, show details for, update,
and delete a credential.


Create credential
=================

.. rest_method::  POST /v3/credentials

Creates a credential.

The following example shows how to create an EC2-style credential.
The credential blob is a string that contains a JSON-serialized
dictionary with the ``access`` and ``secret`` keys. This format is
required when you specify the ``ec2`` type. To specify other
credentials, such as ``access_key``, change the type and contents
of the data blob.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/credentials``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - credential: credential
   - project_id: project_id
   - type: credential_type
   - blob: credential_blob
   - user_id: credential_user_id

Example
~~~~~~~

.. literalinclude:: ./samples/admin/credential-create-request.json
   :language: javascript

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - credential: credential
   - user_id: credential_user_id
   - links: credential_links
   - blob: credential_blob
   - project_id: project_id
   - type: credential_type
   - id: credential_id

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

Example
~~~~~~~

.. literalinclude:: ./samples/admin/credential-create-response.json
   :language: javascript


List credentials
================

.. rest_method::  GET /v3/credentials

Lists all credentials.

Optionally, you can include the ``user_id`` or ``type`` query parameter in the
URI to filter the response by a user or credential type.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/credentials``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - user_id: user_id_query
   - type: credential_type_not_required

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - user_id: credential_user_id
   - links: credentials_links
   - blob: credential_blob
   - credentials: credentials
   - project_id: project_id
   - type: credential_type
   - id: credential_id

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

.. literalinclude:: ./samples/admin/credentials-list-response.json
   :language: javascript


Show credential details
=======================

.. rest_method::  GET /v3/credentials/{credential_id}

Shows details for a credential.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/credential``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - credential_id: credential_id_path

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - credential: credential
   - user_id: credential_user_id
   - links: credential_links
   - blob: credential_blob
   - project_id: project_id
   - type: credential_type
   - id: credential_id

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

.. literalinclude:: ./samples/admin/credential-show-response.json
   :language: javascript


Update credential
=================

.. rest_method::  PATCH /v3/credentials/{credential_id}

Updates a credential.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/credential``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - credential_id: credential_id_path
   - credential: credential
   - project_id: project_id
   - type: credential_type_not_required
   - blob: credential_blob_not_required
   - user_id: credential_user_id_not_required

Example
~~~~~~~

.. literalinclude:: ./samples/admin/credential-update-request.json
   :language: javascript

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - credential: credential
   - user_id: credential_user_id
   - links: credential_links
   - blob: credential_blob
   - project_id: project_id
   - type: credential_type
   - id: credential_id

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

.. literalinclude:: ./samples/admin/credential-update-response.json
   :language: javascript


Delete credential
=================

.. rest_method::  DELETE /v3/credentials/{credential_id}

Deletes a credential.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/credential``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - credential_id: credential_id_path

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
