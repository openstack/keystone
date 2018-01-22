======================
Bootstrapping Identity
======================

After keystone is deployed and configured, it must be pre-populated with some
initial data before it can be used. This process is known as bootstrapping and
it typically involves creating the system's first user, project, domain,
service, and endpoint, among other things. The goal of bootstrapping is to put
enough information into the system such that it can function solely through the
API using normal authentication flows. After the first user is created, which
must be an administrator, you can use that account to interact with keystone
via the API.

Keystone provides two separate ways to bootstrap a deployment. The first is
with the ``keystone-manage bootstrap`` command. This is the preferred and
recommended way to bootstrap new installations. The second, and original way of
bootstrapping involves configuring a secret and deploying special middleware in
front of the identity service. The secret is known as the ``ADMIN_TOKEN``. Any
requests made to the identity API with the ``ADMIN_TOKEN`` will completely
bypass authentication allowing access to the entire API.

Using the CLI
=============

The process requires access to an environment with keystone binaries
installed, typically on the service host.

The ``keystone-manage bootstrap`` command will create a user, project and role,
and will assign the newly created role to the newly created user on the newly
created project. By default, the names of these new resources will be called
``admin``.

The defaults may be overridden by calling ``--bootstrap-username``,
``--bootstrap-project-name`` and ``--bootstrap-role-name``. Each of these have
an environment variable equivalent: ``OS_BOOTSTRAP_USERNAME``,
``OS_BOOTSTRAP_PROJECT_NAME`` and ``OS_BOOTSTRAP_ROLE_NAME``.

A user password must also be supplied. This can be passed in as either
``--bootstrap-password``, or set as an environment variable using
``OS_BOOTSTRAP_PASSWORD``.

Optionally, if specified by ``--bootstrap-public-url``,
``--bootstrap-admin-url`` and/or ``--bootstrap-internal-url`` or the equivalent
environment variables, the command will create an identity service with the
specified endpoint information. You may also configure the
``--bootstrap-region-id`` and ``--bootstrap-service-name`` for the endpoints to
your deployment's requirements.

.. NOTE::

    We strongly recommend that you configure the identity service and its
    endpoints while bootstrapping keystone.

Minimally, keystone can be bootstrapped with:

.. code-block:: bash

    $ keystone-manage bootstrap --bootstrap-password s3cr3t

Verbosely, keystone can be bootstrapped with:

.. code-block:: bash

    $ keystone-manage bootstrap \
        --bootstrap-password s3cr3t \
        --bootstrap-username admin \
        --bootstrap-project-name admin \
        --bootstrap-role-name admin \
        --bootstrap-service-name keystone \
        --bootstrap-region-id RegionOne \
        --bootstrap-admin-url http://localhost:35357 \
        --bootstrap-public-url http://localhost:5000 \
        --bootstrap-internal-url http://localhost:5000

This will create an ``admin`` user with the ``admin`` role on the ``admin``
project. The user will have the password specified in the command. Note that
both the user and the project will be created in the ``default`` domain. By not
creating an endpoint in the catalog users will need to provide endpoint
overrides to perform additional identity operations.

By creating an ``admin`` user and an identity endpoint you may
authenticate to keystone and perform identity operations like creating
additional services and endpoints using the ``admin`` user. This will preclude
the need to ever use or configure the ``admin_token`` (described below). It is
also, by design, more secure.

To test a proper configuration, a user can use OpenStackClient CLI:

.. code-block:: bash

    $ openstack project list --os-username admin --os-project-name admin \
        --os-user-domain-id default --os-project-domain-id default \
        --os-identity-api-version 3 --os-auth-url http://localhost:5000 \
        --os-password s3cr3t

Using a shared secret
=====================

.. NOTE::

    We strongly recommended that you configure the identity service with the
    ``keystone-manage bootstrap`` command and not the ``ADMIN_TOKEN``. The
    ``ADMIN_TOKEN`` can leave your deployment vulnerable by exposing
    administrator functionality through the API based solely on a single
    secret. You shouldn't have to use ``ADMIN_TOKEN`` at all, unless you have
    some special case bootstrapping requirements.


Before you can use the identity API, you need to configure keystone with a
shared secret. Requests made with this secret will bypass authentication and
grant administrative access to the identity API. The following configuration
snippet shows the shared secret as being ``ADMIN``:

.. code-block:: bash

    [DEFAULT]
    admin_token = ADMIN

You can use the shared secret, or ``admin_token``, to make API request to
keystone that bootstrap the rest of the deployment.  You must create a project,
user, and role in order to use normal user authentication through the API.

The ``admin_token`` does not represent a user or explicit authorization of any
kind. After bootstrapping, failure to remove this functionality exposes an
additional attack vector and security risk.
