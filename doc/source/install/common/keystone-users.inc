.. -*- rst -*-

Create a domain, projects, users, and roles
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The Identity service provides authentication services for each OpenStack
service. The authentication service uses a combination of domains,
projects, users, and roles.

#. Although the "default" domain already exists from the `keystone-manage
   bootstrap` step in this guide, a formal way to create a new domain would be:

   .. code-block:: console

      $ openstack domain create --description "An Example Domain" example

      +-------------+----------------------------------+
      | Field       | Value                            |
      +-------------+----------------------------------+
      | description | An Example Domain                |
      | enabled     | True                             |
      | id          | 2f4f80574fd84fe6ba9067228ae0a50c |
      | name        | example                          |
      | tags        | []                               |
      +-------------+----------------------------------+

   .. end

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
      | tags        | []                               |
      +-------------+----------------------------------+

   .. end

#. Regular (non-admin) tasks should use an unprivileged project and user.
   As an example, this guide creates the ``myproject`` project and ``myuser``
   user.

   * Create the ``myproject`` project:

     .. code-block:: console

        $ openstack project create --domain default \
          --description "Demo Project" myproject

        +-------------+----------------------------------+
        | Field       | Value                            |
        +-------------+----------------------------------+
        | description | Demo Project                     |
        | domain_id   | default                          |
        | enabled     | True                             |
        | id          | 231ad6e7ebba47d6a1e57e1cc07ae446 |
        | is_domain   | False                            |
        | name        | myproject                        |
        | parent_id   | default                          |
        | tags        | []                               |
        +-------------+----------------------------------+

     .. end

     .. note::

         Do not repeat this step when creating additional users for this
         project.

   * Create the ``myuser`` user:

     .. code-block:: console

        $ openstack user create --domain default \
          --password-prompt myuser

        User Password:
        Repeat User Password:
        +---------------------+----------------------------------+
        | Field               | Value                            |
        +---------------------+----------------------------------+
        | domain_id           | default                          |
        | enabled             | True                             |
        | id                  | aeda23aa78f44e859900e22c24817832 |
        | name                | myuser                           |
        | options             | {}                               |
        | password_expires_at | None                             |
        +---------------------+----------------------------------+

     .. end

   * Create the ``myrole`` role:

     .. code-block:: console

        $ openstack role create myrole

        +-----------+----------------------------------+
        | Field     | Value                            |
        +-----------+----------------------------------+
        | domain_id | None                             |
        | id        | 997ce8d05fc143ac97d83fdfb5998552 |
        | name      | myrole                           |
        +-----------+----------------------------------+

     .. end

   * Add the ``myrole`` role to the ``myproject`` project and ``myuser`` user:

     .. code-block:: console

        $ openstack role add --project myproject --user myuser myrole

     .. end

     .. note::

        This command provides no output.

.. note::

   You can repeat this procedure to create additional projects and
   users.
