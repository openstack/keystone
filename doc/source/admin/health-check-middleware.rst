Health Check middleware
=======================

This health check middleware allows an operator to configure the endpoint URL
that will provide information to a load balancer if the given API endpoint at
the node should be available or not.

To enable the health check middleware, it must occur in the beginning of the
application pipeline.

The health check middleware should be placed in your
``keystone-paste.ini`` in a section titled ``[filter:healthcheck]``.
It should look like this::

  [filter:healthcheck]
  use = egg:oslo.middleware#healthcheck

Desired keystone application pipelines have been defined with this filter,
looking like so::

  [pipeline:public_version_api]
  pipeline = healthcheck cors sizelimit osprofiler url_normalize public_version_service

It's important that the healthcheck go to the front of the pipeline for the
most efficient checks.

For more information and configuration options for the middleware see
`oslo.middleware <https://docs.openstack.org/oslo.middleware/latest/reference/healthcheck_plugins.html>`_.