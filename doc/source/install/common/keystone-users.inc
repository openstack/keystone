.. -*- rst -*-

Create a domain, projects, users, and roles
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The Identity service provides authentication services for each OpenStack
service. The authentication service uses a combination of domains,
projects, users, and roles.

#. This guide uses a service project that contains a unique user for each
   service that you add to your environment. Create the ``service``
   project:

   .. code-block:: console

      $ openstack project create --domain default \
        --description "Service Project" service

      +-------------+----------------------------------+
      | Field       | Value                            |
      +-------------+----------------------------------+
      | description | Service Project                  |
      | domain_id   | default                          |
      | enabled     | True                             |
      | id          | 24ac7f19cd944f4cba1d77469b2a73ed |
      | is_domain   | False                            |
      | name        | service                          |
      | parent_id   | default                          |
      +-------------+----------------------------------+

   .. end

#. Regular (non-admin) tasks should use an unprivileged project and user.
   As an example, this guide creates the ``demo`` project and user.

   * Create the ``demo`` project:

     .. code-block:: console

        $ openstack project create --domain default \
          --description "Demo Project" demo

        +-------------+----------------------------------+
        | Field       | Value                            |
        +-------------+----------------------------------+
        | description | Demo Project                     |
        | domain_id   | default                          |
        | enabled     | True                             |
        | id          | 231ad6e7ebba47d6a1e57e1cc07ae446 |
        | is_domain   | False                            |
        | name        | demo                             |
        | parent_id   | default                          |
        +-------------+----------------------------------+

     .. end

     .. note::

         Do not repeat this step when creating additional users for this
         project.

   * Create the ``demo`` user:

     .. code-block:: console

        $ openstack user create --domain default \
          --password-prompt demo

        User Password:
        Repeat User Password:
        +---------------------+----------------------------------+
        | Field               | Value                            |
        +---------------------+----------------------------------+
        | domain_id           | default                          |
        | enabled             | True                             |
        | id                  | aeda23aa78f44e859900e22c24817832 |
        | name                | demo                             |
        | options             | {}                               |
        | password_expires_at | None                             |
        +---------------------+----------------------------------+

     .. end

   * Create the ``user`` role:

     .. code-block:: console

        $ openstack role create user

        +-----------+----------------------------------+
        | Field     | Value                            |
        +-----------+----------------------------------+
        | domain_id | None                             |
        | id        | 997ce8d05fc143ac97d83fdfb5998552 |
        | name      | user                             |
        +-----------+----------------------------------+

     .. end

   * Add the ``user`` role to the ``demo`` project and user:

     .. code-block:: console

        $ openstack role add --project demo --user demo user

     .. end

     .. note::

        This command provides no output.

.. note::

   You can repeat this procedure to create additional projects and
   users.
