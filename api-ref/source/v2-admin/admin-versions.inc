.. -*- rst -*-

========
Versions
========


Get version details
===================

.. rest_method::  GET /v2.0

Gets detailed information about a version of the Identity API.

Normal response codes: 200,203
Error response codes: 413,405,404,403,401,400,503

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - location: location

Response Example
----------------

.. literalinclude:: ../v2/samples/admin/version-show-response.json
   :language: javascript
