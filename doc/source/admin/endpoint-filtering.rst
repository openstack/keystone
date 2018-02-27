Endpoint Filtering
==================

Endpoint Filtering enables creation of ad-hoc catalogs for each project-scoped
token request.

Configure the endpoint filter catalog driver in the ``[catalog]`` section.
For example:

.. code-block:: ini

    [catalog]
    driver = catalog_sql

In the ``[endpoint_filter]`` section, set ``return_all_endpoints_if_no_filter``
to ``False`` to return an empty catalog if no associations are made.
For example:

.. code-block:: ini

    [endpoint_filter]
    return_all_endpoints_if_no_filter = False

See `API Specification for Endpoint Filtering <https://developer.openstack.org/
api-ref/identity/v3-ext/#os-ep-filter-api>`_ for the details of API definition.
