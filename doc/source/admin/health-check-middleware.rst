Health Check
============

Health check mechanism allows an operator to configure the endpoint URL that
will provide information to a load balancer if the given API endpoint at the
node should be available or not.

It's enabled by default in Keystone using the functions from `oslo.middleware`.
And the URL is ``/healthcheck``.

For more information and configuration options for the middleware see
`oslo.middleware <https://docs.openstack.org/oslo.middleware/latest/reference/healthcheck_plugins.html>`_.
