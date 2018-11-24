
Service Catalog
===============

Keystone provides two configuration options for managing a service catalog.

SQL-based Service Catalog (``sql.Catalog``)
-------------------------------------------

A dynamic database-backed driver fully supporting persistent configuration.

``keystone.conf`` example:

.. code-block:: ini

    [catalog]
    driver = sql

.. NOTE::

    A `template_file` does not need to be defined for the sql based catalog.

To build your service catalog using this driver, see the built-in help:

.. code-block:: bash

    $ openstack --help
    $ openstack service create --help
    $ openstack endpoint create --help

File-based Service Catalog (``templated.Catalog``)
--------------------------------------------------

The templated catalog is an in-memory backend initialized from a read-only
``template_file``. Choose this option only if you know that your service
catalog will not change very much over time.

.. NOTE::

    Attempting to change your service catalog against this driver will result
    in ``HTTP 501 Not Implemented`` errors. This is the expected behavior. If
    you want to use these commands, you must instead use the SQL-based Service
    Catalog driver.

``keystone.conf`` example:

.. code-block:: ini

    [catalog]
    driver = templated
    template_file = /opt/stack/keystone/etc/default_catalog.templates

The value of ``template_file`` is expected to be an absolute path to your
service catalog configuration. An example ``template_file`` is included in
keystone, however you should create your own to reflect your deployment.