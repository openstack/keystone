.. -*- rst -*-

==========
OS-PKI API
==========

List revoked tokens
===================

.. rest_method:: GET /v3/auth/tokens/OS-PKI/revoked

Relationship:
``https://docs.openstack.org/api/openstack-identity/3/rel/tokens/OS-PKI/revoked``

Lists revoked PKI tokens.

Normal response codes: 200

Error response codes: 413,415,405,404,403,401,400,503,409

Response
--------

.. rest_parameters:: parameters.yaml

   - signed: signed

Response Example
----------------

.. literalinclude:: samples/admin/get-pki-revoked-response.json
   :language: javascript
