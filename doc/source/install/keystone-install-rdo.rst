Install and configure
~~~~~~~~~~~~~~~~~~~~~

This section describes how to install and configure the OpenStack
Identity service, code-named keystone, on the controller node. For
scalability purposes, this configuration deploys Fernet tokens and
the Apache HTTP server to handle requests.

.. note::

   Ensure that you have completed the prerequisite installation steps in the
   `Openstack Install Guide
   <https://docs.openstack.org/install-guide/environment-packages-rdo.html#finalize-the-installation>`_
   before proceeding.

Prerequisites
-------------

Before you install and configure the Identity service, you must
create a database.

#. Use the database access client to connect to the database
   server as the ``root`` user:

   .. code-block:: console

      $ mysql -u root -p

   .. end

2. Create the ``keystone`` database:

   .. code-block:: console

      MariaDB [(none)]> CREATE DATABASE keystone;

   .. end

#. Grant proper access to the ``keystone`` database:

   .. code-block:: console

      MariaDB [(none)]> GRANT ALL PRIVILEGES ON keystone.* TO 'keystone'@'localhost' \
      IDENTIFIED BY 'KEYSTONE_DBPASS';
      MariaDB [(none)]> GRANT ALL PRIVILEGES ON keystone.* TO 'keystone'@'%' \
      IDENTIFIED BY 'KEYSTONE_DBPASS';

   .. end

   Replace ``KEYSTONE_DBPASS`` with a suitable password.

#. Exit the database access client.

.. _keystone-install-configure-rdo:

Install and configure components
--------------------------------

.. include:: shared/note_configuration_vary_by_distribution.rst

#. Run the following command to install the packages:

   .. code-block:: console

      # yum install openstack-keystone httpd mod_wsgi

   .. end

2. Edit the ``/etc/keystone/keystone.conf`` file and complete the following
   actions:

   * In the ``[database]`` section, configure database access:

     .. path /etc/keystone/keystone.conf
     .. code-block:: ini

        [database]
        # ...
        connection = mysql+pymysql://keystone:KEYSTONE_DBPASS@controller/keystone

     .. end

     Replace ``KEYSTONE_DBPASS`` with the password you chose for the database.

     .. note::

        Comment out or remove any other ``connection`` options in the
        ``[database]`` section.

     .. note::

        The host, ``controller`` in this example, must be resolvable.

   * In the ``[token]`` section, configure the Fernet token provider:

     .. path /etc/keystone/keystone.conf
     .. code-block:: ini

        [token]
        # ...
        provider = fernet

     .. end

3. Populate the Identity service database:

   .. code-block:: console

      # su -s /bin/sh -c "keystone-manage db_sync" keystone

   .. end

4. Initialize Fernet key repositories:

   .. code-block:: console

      # keystone-manage fernet_setup --keystone-user keystone --keystone-group keystone
      # keystone-manage credential_setup --keystone-user keystone --keystone-group keystone

   .. end

5. Bootstrap the Identity service:

   .. note::

      Before the Queens release, keystone needed to be run on two separate ports to
      accommodate the Identity v2 API which ran a separate admin-only service
      commonly on port 35357. With the removal of the v2 API, keystone can be run
      on the same port for all interfaces.

   .. code-block:: console

      # keystone-manage bootstrap --bootstrap-password ADMIN_PASS \
        --bootstrap-admin-url http://controller:5000/v3/ \
        --bootstrap-internal-url http://controller:5000/v3/ \
        --bootstrap-public-url http://controller:5000/v3/ \
        --bootstrap-region-id RegionOne

   .. end

   Replace ``ADMIN_PASS`` with a suitable password for an administrative user.

Configure the Apache HTTP server
--------------------------------

#. Edit the ``/etc/httpd/conf/httpd.conf`` file and configure the
   ``ServerName`` option to reference the controller node:

   .. path /etc/httpd/conf/httpd
   .. code-block:: apache

      ServerName controller

   .. end

#. Create a link to the ``/usr/share/keystone/wsgi-keystone.conf`` file:

   .. code-block:: console

      # ln -s /usr/share/keystone/wsgi-keystone.conf /etc/httpd/conf.d/

   .. end

Finalize the installation
-------------------------

#. Start the Apache HTTP service and configure it to start when the system
   boots:

   .. code-block:: console

      # systemctl enable httpd.service
      # systemctl start httpd.service

   .. end

2. Configure the administrative account

   .. code-block:: console

      $ export OS_USERNAME=admin
      $ export OS_PASSWORD=ADMIN_PASS
      $ export OS_PROJECT_NAME=admin
      $ export OS_USER_DOMAIN_NAME=Default
      $ export OS_PROJECT_DOMAIN_NAME=Default
      $ export OS_AUTH_URL=http://controller:5000/v3
      $ export OS_IDENTITY_API_VERSION=3

   .. end

   Replace ``ADMIN_PASS`` with the password used in the
   ``keystone-manage bootstrap`` command in `keystone-install-configure-rdo`_.
