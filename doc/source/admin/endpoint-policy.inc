.. -*- rst -*-

Endpoint Policy
===============

The Endpoint Policy feature provides associations between service endpoints
and policies that are already stored in the Identity server and referenced
by a policy ID.

Configure the endpoint policy backend driver in the ``[endpoint_policy]``
section. For example:

.. code-block:: ini

    [endpoint_policy]
    driver = sql

See `API Specification for Endpoint Policy <https://docs.openstack.org/
api-ref/identity/v3-ext/index.html#os-endpoint-policy-api>`_
for the details of API definition.
