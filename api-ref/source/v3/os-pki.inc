.. -*- rst -*-

==========
OS-PKI
==========

List revoked tokens
===================

.. rest_method:: GET /v3/auth/tokens/OS-PKI/revoked

Lists revoked PKI tokens.

Relationship:
``https://docs.openstack.org/api/openstack-identity/3/rel/tokens/OS-PKI/revoked``

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - signed: signed

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success status.yaml

   - 200

.. rest_status_code:: error status.yaml

   - 413
   - 415
   - 405
   - 404
   - 403
   - 401
   - 400
   - 503
   - 409

Example
~~~~~~~

.. literalinclude:: samples/admin/get-pki-revoked-response.json
   :language: javascript