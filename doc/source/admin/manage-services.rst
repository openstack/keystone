.. _manage_services:

============================================
Create and manage services and service users
============================================

Service Catalog
===============

OpenStack services can be discovered when registered in keystone's service
catalog. The service catalog can be managed as either a static file template or
as a dynamic database table.

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

Create a service
~~~~~~~~~~~~~~~~

#. List the available services:

   .. code-block:: console

      $ openstack service list
      +----------------------------------+----------+------------+
      | ID                               | Name     | Type       |
      +----------------------------------+----------+------------+
      | 9816f1faaa7c4842b90fb4821cd09223 | cinder   | volume     |
      | 1250f64f31e34dcd9a93d35a075ddbe1 | cinderv2 | volumev2   |
      | da8cf9f8546b4a428c43d5e032fe4afc | ec2      | ec2        |
      | 5f105eeb55924b7290c8675ad7e294ae | glance   | image      |
      | dcaa566e912e4c0e900dc86804e3dde0 | keystone | identity   |
      | 4a715cfbc3664e9ebf388534ff2be76a | nova     | compute    |
      | 1aed4a6cf7274297ba4026cf5d5e96c5 | novav21  | computev21 |
      | bed063c790634c979778551f66c8ede9 | neutron  | network    |
      | 6feb2e0b98874d88bee221974770e372 |    s3    |    s3      |
      +----------------------------------+----------+------------+

#. To create a service, run this command:

   .. code-block:: console

      $ openstack service create --name SERVICE_NAME --description SERVICE_DESCRIPTION SERVICE_TYPE

   The arguments are:
      - ``service_name``: the unique name of the new service.
      - ``service_type``: the service type, such as ``identity``,
        ``compute``, ``network``, ``image``, ``object-store``
        or any other service identifier string.
      - ``service_description``: the description of the service.

   For example, to create a ``swift`` service of type
   ``object-store``, run this command:

   .. code-block:: console

      $ openstack service create --name swift --description "object store service" object-store
      +-------------+----------------------------------+
      | Field       | Value                            |
      +-------------+----------------------------------+
      | description | object store service             |
      | enabled     | True                             |
      | id          | 84c23f4b942c44c38b9c42c5e517cd9a |
      | name        | swift                            |
      | type        | object-store                     |
      +-------------+----------------------------------+

#. To get details for a service, run this command:

   .. code-block:: console

      $ openstack service show SERVICE_TYPE|SERVICE_NAME|SERVICE_ID

   For example:

   .. code-block:: console

      $ openstack service show object-store
      +-------------+----------------------------------+
      | Field       | Value                            |
      +-------------+----------------------------------+
      | description | object store service             |
      | enabled     | True                             |
      | id          | 84c23f4b942c44c38b9c42c5e517cd9a |
      | name        | swift                            |
      | type        | object-store                     |
      +-------------+----------------------------------+

Create an endpoint
~~~~~~~~~~~~~~~~~~

#. Once a service is created, register it at an endpoint:

   .. code-block:: console

      $ openstack endpoint create nova public http://example.com/compute/v2.1
      +--------------+----------------------------------+
      | Field        | Value                            |
      +--------------+----------------------------------+
      | enabled      | True                             |
      | id           | c219aa779e90403eb4a78cf0aa7d38b1 |
      | interface    | public                           |
      | region       | None                             |
      | region_id    | None                             |
      | service_id   | 0f5da035b8e94629bf35e7ec1703a8eb |
      | service_name | nova                             |
      | service_type | compute                          |
      | url          | http://example.com/compute/v2.1  |
      +--------------+----------------------------------+

Delete a service
~~~~~~~~~~~~~~~~

To delete a specified service, specify its ID.

.. code-block:: console

   $ openstack service delete SERVICE_TYPE|SERVICE_NAME|SERVICE_ID

For example:

.. code-block:: console

   $ openstack service delete object-store

Service users
=============

To authenticate users against the Identity service, you must
create a service user for each OpenStack service. For example,
create a service user for the Compute, Block Storage, and
Networking services.

To configure the OpenStack services with service users,
create a project for all services and create users for each
service. Assign the admin role to each service user and
project pair. This role enables users to validate tokens and
authenticate and authorize other user requests.

Create service users
--------------------

#. Create a project for the service users.
   Typically, this project is named ``service``,
   but choose any name you like:

   .. code-block:: console

      $ openstack project create service --domain default
      +-------------+----------------------------------+
      | Field       | Value                            |
      +-------------+----------------------------------+
      | description | None                             |
      | domain_id   | e601210181f54843b51b3edff41d4980 |
      | enabled     | True                             |
      | id          | 3e9f3f5399624b2db548d7f871bd5322 |
      | is_domain   | False                            |
      | name        | service                          |
      | parent_id   | e601210181f54843b51b3edff41d4980 |
      +-------------+----------------------------------+

#. Create service users for the relevant services for your
   deployment. For example:

   .. code-block:: console

    $ openstack user create nova --password Sekr3tPass
    +---------------------+----------------------------------+
    | Field               | Value                            |
    +---------------------+----------------------------------+
    | domain_id           | default                          |
    | enabled             | True                             |
    | id                  | 95ec3e1d5dd747f5a512d261731d29c7 |
    | name                | nova                             |
    | options             | {}                               |
    | password_expires_at | None                             |
    +---------------------+----------------------------------+

#. Assign the admin role to the user-project pair.

   .. code-block:: console

      $ openstack role add --project service --user nova admin
      +-------+----------------------------------+
      | Field | Value                            |
      +-------+----------------------------------+
      | id    | 233109e756c1465292f31e7662b429b1 |
      | name  | admin                            |
      +-------+----------------------------------+

Configuring service tokens
--------------------------

A lot of operations in OpenStack require communication between multiple
services on behalf of the user. For example, the Image service storing the
user's images in the Object Storage service. If the image is significantly
large, the operation might fail due to the user's token having expired
during upload.

In the above scenarios, the Image service will attach both the user's token
and its own token (called the service token), as per the diagram below.

.. code-block:: console

      +----------------+
      |      User      |
      +-------+--------+
              | Access Image Data Request
              | X-AUTH-TOKEN: <end user token>
              |
      +-------v---------+
      |     Glance      |
      +-------+---------+
              | Access Image Data Request
              | X-AUTH-TOKEN: <original end user token>
              | X-SERVICE-TOKEN: <glance service user token>
              |
      +-------v---------+
      |      Swift      |
      +-----------------+


When a service receives a call from another service, it validates that the
token has the appropriate roles for a service user. This is configured in each
individual service configuration, under the section ``[keystone_authtoken]``.

If the service token is valid, the operation will be allowed even if the
user's token has expired.

The ``service_token_roles`` option is the list of roles that the service
token must contain to be a valid service token. In the previous steps, we have
assigned the `admin` role to service users, so set the option to that and set
``service_token_roles_required`` to ``true``.

.. code-block:: ini

    [keystone_authtoken]
    service_token_roles = admin
    service_token_roles_required = true

For more information regarding service tokens, please see the
``keystonemiddleware`` `release notes
<https://docs.openstack.org/releasenotes/keystonemiddleware/ocata.html>`_.
