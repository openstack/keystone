.. -*- rst -*-

============
API versions
============


Show version details
====================

.. rest_method::  GET /v2.0

Shows details for the Identity API v2.0.

Normal response codes: 200,203
Error response codes: 413,405,404,403,401,400,503

Response Example
----------------

.. literalinclude:: samples/admin/version-show-response.json
   :language: javascript


List versions
=============

.. rest_method::  GET /

Lists information about all Identity API versions.

Normal response codes: 200,300
Error response codes: 413,405,404,403,401,400,503

Response Example
----------------

.. literalinclude:: samples/admin/versions-list-response.json
   :language: javascript
