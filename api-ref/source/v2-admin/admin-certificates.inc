.. -*- rst -*-

============
Certificates
============

Allows the retrieval of information for Certificate Authorities and certificates.

Show CA Certificate (v2)
========================

.. rest_method:: GET /v2.0/certificates/ca

Show the available CA certificate.

Normal response codes: 200

Error response codes: 401, 500

Response Example
----------------

.. literalinclude:: ./samples/admin/show-ca-certificate-v2-response.txt
   :language: text

Show Signing Certificate (v2)
=============================

.. rest_method:: GET /v2.0/certificates/signing

Show the available signing certificate.

Normal response codes: 200

Error response codes: 401, 500

Response Example
----------------

.. literalinclude:: ./samples/admin/show-signing-certificate-v2-response.txt
   :language: text
