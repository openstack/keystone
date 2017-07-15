============================================
Create and manage services and service users
============================================

The Identity service enables you to define services, as
follows:

- Service catalog template. The Identity service acts
  as a service catalog of endpoints for other OpenStack
  services. The ``/etc/keystone/default_catalog.templates``
  template file defines the endpoints for services. When
  the Identity service uses a template file back end,
  any changes that are made to the endpoints are cached.
  These changes do not persist when you restart the
  service or reboot the machine.
- An SQL back end for the catalog service. When the
  Identity service is online, you must add the services
  to the catalog. When you deploy a system for
  production, use the SQL back end.

The ``auth_token`` middleware supports the
use of either a shared secret or users for each
service.

To authenticate users against the Identity service, you must
create a service user for each OpenStack service. For example,
create a service user for the Compute, Block Storage, and
Networking services.

To configure the OpenStack services with service users,
create a project for all services and create users for each
service. Assign the admin role to each service user and
project pair. This role enables users to validate tokens and
authenticate and authorize other user requests.

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

Create service users
~~~~~~~~~~~~~~~~~~~~

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
   deployment.

#. Assign the admin role to the user-project pair.

   .. code-block:: console

      $ openstack role add --project service --user SERVICE_USER_NAME admin
      +-------+----------------------------------+
      | Field | Value                            |
      +-------+----------------------------------+
      | id    | 233109e756c1465292f31e7662b429b1 |
      | name  | admin                            |
      +-------+----------------------------------+

Delete a service
~~~~~~~~~~~~~~~~

To delete a specified service, specify its ID.

.. code-block:: console

   $ openstack service delete SERVICE_TYPE|SERVICE_NAME|SERVICE_ID

For example:

.. code-block:: console

   $ openstack service delete object-store
