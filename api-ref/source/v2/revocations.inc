.. -*- rst -*-

=============
 Revocations
=============

Allows the retrieval of revoked tokens.

List Revoked Tokens (v2)
========================

.. rest_method:: GET /v2.0/tokens/revoked

List the revoked tokens.

Normal response codes: 200

Error response codes: 400,401,403,404,405,413,503


Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

    - signed: signed

Response Example
----------------

.. literalinclude:: ./samples/admin/revoked-tokens-response.json
   :language: javascript
