.. -*- rst -*-

Create OpenStack client environment scripts
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The previous sections used a combination of environment variables and
command options to interact with the Identity service via the
``openstack`` client. To increase efficiency of client operations,
OpenStack supports simple client environment scripts also known as
OpenRC files. These scripts typically contain common options for
all clients, but also support unique options. For more information, see the
`OpenStack End User Guide <https://docs.openstack.org/user-guide/common/
cli_set_environment_variables_using_openstack_rc.html>`_.

Creating the scripts
--------------------

Create client environment scripts for the ``admin`` and ``demo``
projects and users. Future portions of this guide reference these
scripts to load appropriate credentials for client operations.

.. note::

   The paths of the client environment scripts are unrestricted.
   For convenience, you can place the scripts in any location,
   however ensure that they are accessible and located in a secure
   place appropriate for your deployment, as they do contain sensitive
   credentials.

#. Create and edit the ``admin-openrc`` file and add the following content:

   .. note::

      The OpenStack client also supports using a ``clouds.yaml`` file.
      For more information, see
      the `os-client-config <http://docs.openstack.org/os-client-config/latest>`_.

   .. code-block:: bash

      export OS_PROJECT_DOMAIN_NAME=Default
      export OS_USER_DOMAIN_NAME=Default
      export OS_PROJECT_NAME=admin
      export OS_USERNAME=admin
      export OS_PASSWORD=ADMIN_PASS
      export OS_AUTH_URL=http://controller:5000/v3
      export OS_IDENTITY_API_VERSION=3
      export OS_IMAGE_API_VERSION=2

   .. end

   Replace ``ADMIN_PASS`` with the password you chose
   for the ``admin`` user in the Identity service.

#. Create and edit the ``demo-openrc`` file and add the following content:

   .. code-block:: bash

      export OS_PROJECT_DOMAIN_NAME=Default
      export OS_USER_DOMAIN_NAME=Default
      export OS_PROJECT_NAME=myproject
      export OS_USERNAME=myuser
      export OS_PASSWORD=MYUSER_PASS
      export OS_AUTH_URL=http://controller:5000/v3
      export OS_IDENTITY_API_VERSION=3
      export OS_IMAGE_API_VERSION=2

   .. end

   Replace ``DEMO_PASS`` with the password you chose
   for the ``demo`` user in the Identity service.

Using the scripts
-----------------

To run clients as a specific project and user, you can simply load
the associated client environment script prior to running them.
For example:

#. Load the ``admin-openrc`` file to populate
   environment variables with the location of the Identity service
   and the ``admin`` project and user credentials:

   .. code-block:: console

      $ . admin-openrc

   .. end

#. Request an authentication token:

   .. code-block:: console

      $ openstack token issue

      +------------+-----------------------------------------------------------------+
      | Field      | Value                                                           |
      +------------+-----------------------------------------------------------------+
      | expires    | 2016-02-12T20:44:35.659723Z                                     |
      | id         | gAAAAABWvjYj-Zjfg8WXFaQnUd1DMYTBVrKw4h3fIagi5NoEmh21U72SrRv2trl |
      |            | JWFYhLi2_uPR31Igf6A8mH2Rw9kv_bxNo1jbLNPLGzW_u5FC7InFqx0yYtTwa1e |
      |            | eq2b0f6-18KZyQhs7F3teAta143kJEWuNEYET-y7u29y0be1_64KYkM7E       |
      | project_id | 343d245e850143a096806dfaefa9afdc                                |
      | user_id    | ac3377633149401296f6c0d92d79dc16                                |
      +------------+-----------------------------------------------------------------+

   .. end
