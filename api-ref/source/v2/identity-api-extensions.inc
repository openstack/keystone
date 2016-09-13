.. -*- rst -*-

==========
Extensions
==========


Show extension details
======================

.. rest_method::  GET /v2.0/extensions/{alias}

Shows details for an extension, by alias.

Normal response codes: 200,203

Error response codes: 413,405,404,403,401,400,503

Request
-------

.. rest_parameters:: parameters.yaml

   - alias: alias

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - x-openstack-request-id: x-openstack-request-id
   - alias: alias
   - updated: updated
   - description: api_ext_description
   - name: api_ext_name

Response Example
----------------

.. literalinclude:: samples/admin/extension-show-response.json
   :language: javascript


List extensions
===============

.. rest_method::  GET /v2.0/extensions

Lists available extensions.

Normal response codes: 200,203

Error response codes: 413,405,404,403,401,400,503

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - x-openstack-request-id: x-openstack-request-id
   - alias: alias
   - updated: updated
   - description: api_ext_description
   - name: api_ext_name

Response Example
----------------

.. literalinclude:: samples/admin/extensions-list-response.json
   :language: javascript
