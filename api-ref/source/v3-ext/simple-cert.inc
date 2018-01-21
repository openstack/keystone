.. -*- rst -*-

====================
 OS-SIMPLE-CERT API
====================

Allows the retrieval of information for Certificate Authorities and certificates.
Requires v3.0+ of the Identity API.

Show CA Certificate
===================

.. rest_method:: GET /v3/OS-SIMPLE-CERT/ca

Show the availbable CA certificate.

Response
--------

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success ../v3/status.yaml

   - 200

.. rest_status_code:: error ../v3/status.yaml

   - 401
   - 500

Example
~~~~~~~

.. literalinclude:: ./samples/OS-SIMPLE-CERT/show-ca-certificate-response.txt
   :language: text

Show Signing Certificate
========================

.. rest_method:: GET /v3/OS-SIMPLE-CERT/certificates

Show the available signing certificate.

Response
--------

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success ../v3/status.yaml

   - 200

.. rest_status_code:: error ../v3/status.yaml

   - 401
   - 500

Example
~~~~~~~

.. literalinclude:: ./samples/OS-SIMPLE-CERT/show-signing-certificate-response.txt
   :language: text