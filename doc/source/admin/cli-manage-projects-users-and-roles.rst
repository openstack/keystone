=================================
Manage projects, users, and roles
=================================

As an administrator, you manage projects, users, and
roles. Projects are organizational units in the cloud to which
you can assign users. Projects are also known as *tenants* or
*accounts*. Users can be members of one or more projects. Roles
define which actions users can perform. You assign roles to
user-project pairs.

You can define actions for OpenStack service roles in the
``/etc/PROJECT/policy.yaml`` files. For example, define actions for
Compute service roles in the ``/etc/nova/policy.yaml`` file.

You can manage projects, users, and roles independently from each other.

During cloud set up, the operator defines at least one project, user,
and role.

You can add, update, and delete projects and users, assign users to
one or more projects, and change or remove the assignment. To enable or
temporarily disable a project or user, update that project or user.
You can also change quotas at the project level.

Before you can delete a user account, you must remove the user account
from its primary project.

Before you can run client commands, you need to have a cloud config
file or you can download and
source an OpenStack RC file. See the
:python-openstackclient-doc:`Configuration <configuration/index.html>`
documentation from the python-openstackclient project for more details.


Projects
~~~~~~~~

A project is a group of zero or more users. In Compute, a project owns
virtual machines. In Object Storage, a project owns containers. Users
can be associated with more than one project. Each project and user
pairing can have a role associated with it.

List projects
-------------

List all projects with their ID, name, and whether they are
enabled or disabled:

.. code-block:: console

   $ openstack project list
   +----------------------------------+--------------------+
   | ID                               | Name               |
   +----------------------------------+--------------------+
   | f7ac731cc11f40efbc03a9f9e1d1d21f | admin              |
   | c150ab41f0d9443f8874e32e725a4cc8 | alt_demo           |
   | a9debfe41a6d4d09a677da737b907d5e | demo               |
   | 9208739195a34c628c58c95d157917d7 | invisible_to_admin |
   | 3943a53dc92a49b2827fae94363851e1 | service            |
   | 80cab5e1f02045abad92a2864cfd76cb | test_project       |
   +----------------------------------+--------------------+

Create a project
----------------

Create a project named ``new-project``:

.. code-block:: console

   $ openstack project create --description 'my new project' new-project \
     --domain default
   +-------------+----------------------------------+
   | Field       | Value                            |
   +-------------+----------------------------------+
   | description | my new project                   |
   | domain_id   | e601210181f54843b51b3edff41d4980 |
   | enabled     | True                             |
   | id          | 1a4a0618b306462c9830f876b0bd6af2 |
   | is_domain   | False                            |
   | name        | new-project                      |
   | parent_id   | e601210181f54843b51b3edff41d4980 |
   | tags        | []                               |
   +-------------+----------------------------------+

-  Creating a project without using a domain scoped token, i.e. using a project
   scoped token or a system scoped token, and also without specifying a domain
   or domain_id, the project will automatically be created on the default domain.

Update a project
----------------

Specify the project ID to update a project. You can update the name,
description, and enabled status of a project.

-  To temporarily disable a project:

   .. code-block:: console

      $ openstack project set PROJECT_ID --disable

-  To enable a disabled project:

   .. code-block:: console

      $ openstack project set PROJECT_ID --enable

-  To update the name of a project:

   .. code-block:: console

      $ openstack project set PROJECT_ID --name project-new

-  To verify your changes, show information for the updated project:

   .. code-block:: console

      $ openstack project show PROJECT_ID
      +-------------+----------------------------------+
      | Field       | Value                            |
      +-------------+----------------------------------+
      | description | my new project                   |
      | domain_id   | e601210181f54843b51b3edff41d4980 |
      | enabled     | True                             |
      | id          | 0b0b995694234521bf93c792ed44247f |
      | is_domain   | False                            |
      | name        | new-project                      |
      | parent_id   | e601210181f54843b51b3edff41d4980 |
      | tags        | []                               |
      +-------------+----------------------------------+

Delete a project
----------------

Specify the project ID to delete a project:

.. code-block:: console

   $ openstack project delete PROJECT_ID

Users
~~~~~

List users
----------

List all users:

.. code-block:: console

   $ openstack user list
   +----------------------------------+----------+
   | ID                               | Name     |
   +----------------------------------+----------+
   | 352b37f5c89144d4ad0534139266d51f | admin    |
   | 86c0de739bcb4802b8dc786921355813 | demo     |
   | 32ec34aae8ea432e8af560a1cec0e881 | glance   |
   | 7047fcb7908e420cb36e13bbd72c972c | nova     |
   +----------------------------------+----------+

Create a user
-------------

To create a user, you must specify a name. Optionally, you can
specify a project ID, password, and email address. It is recommended
that you include the project ID and password because the user cannot
log in to the dashboard without this information.

Create the ``new-user`` user:

.. code-block:: console

   $ openstack user create --project new-project --password PASSWORD new-user
   +------------+----------------------------------+
   | Field      | Value                            |
   +------------+----------------------------------+
   | email      | None                             |
   | enabled    | True                             |
   | id         | 6322872d9c7e445dbbb49c1f9ca28adc |
   | name       | new-user                         |
   | project_id | 0b0b995694234521bf93c792ed44247f |
   | username   | new-user                         |
   +------------+----------------------------------+

Update a user
-------------

You can update the name, email address, and enabled status for a user.

-  To temporarily disable a user account:

   .. code-block:: console

      $ openstack user set USER_NAME --disable

   If you disable a user account, the user cannot log in to the
   dashboard. However, data for the user account is maintained, so you
   can enable the user at any time.

-  To enable a disabled user account:

   .. code-block:: console

      $ openstack user set USER_NAME --enable

-  To change the name and description for a user account:

   .. code-block:: console

      $ openstack user set USER_NAME --name user-new --email new-user@example.com
      User has been updated.

Delete a user
-------------

Delete a specified user account:

.. code-block:: console

   $ openstack user delete USER_NAME

Roles and role assignments
~~~~~~~~~~~~~~~~~~~~~~~~~~

List available roles
--------------------

List the available roles:

.. code-block:: console

   $ openstack role list
   +----------------------------------+---------------+
   | ID                               | Name          |
   +----------------------------------+---------------+
   | 71ccc37d41c8491c975ae72676db687f | member        |
   | 149f50a1fe684bfa88dae76a48d26ef7 | ResellerAdmin |
   | 9fe2ff9ee4384b1894a90878d3e92bab | reader        |
   | 6ecf391421604da985db2f141e46a7c8 | admin         |
   | deb4fffd123c4d02a907c2c74559dccf | anotherrole   |
   +----------------------------------+---------------+

Create a role
-------------

Users can be members of multiple projects. To assign users to multiple
projects, define a role and assign that role to a user-project pair.

Create the ``new-role`` role:

.. code-block:: console

   $ openstack role create new-role
   +-------------+----------------------------------+
   | Field       | Value                            |
   +-------------+----------------------------------+
   | description | None                             |
   | domain_id   | None                             |
   | id          | a34425c884c74c8881496dc2c2e84ffc |
   | name        | new-role                         |
   +-------------+----------------------------------+

.. note::

   If you are using identity v3, you may need to use the
   ``--domain`` option with a specific domain name.

Assign a role
-------------

To assign a user to a project, you must assign the role to a
user-project pair.

#. Assign a role to a user-project pair:

   .. code-block:: console

      $ openstack role add --user USER_NAME --project PROJECT_NAME ROLE_NAME

   For example, assign the ``new-role`` role to the ``demo`` user and
   ``test-project`` project pair:

   .. code-block:: console

      $ openstack role add --user demo --project test-project new-role

#. Verify the role assignment:

   .. code-block:: console

      $ openstack role assignment list --user USER_NAME \
        --project PROJECT_NAME --names
      +-------------+--------------+-------+--------------+--------+--------+-----------+
      | Role        | User         | Group | Project      | Domain | System | Inherited |
      +-------------+--------------+-------+--------------+--------+--------+-----------+
      | new-role    | demo@Default |       | demo@Default |        |        | False     |
      | member      | demo@Default |       | demo@Default |        |        | False     |
      | anotherrole | demo@Default |       | demo@Default |        |        | False     |
      +-------------+--------------+-------+--------------+--------+--------+-----------+

.. note::

   Before the Newton release, users would run
   the :command:`openstack role list --user USER_NAME --project TENANT_ID` command to
   verify the role assignment.

View role details
-----------------

View details for a specified role:

.. code-block:: console

   $ openstack role show ROLE_NAME
   +-------------+----------------------------------+
   | Field       | Value                            |
   +-------------+----------------------------------+
   | description | None                             |
   | domain_id   | None                             |
   | id          | a34425c884c74c8881496dc2c2e84ffc |
   | name        | new-role                         |
   +-------------+----------------------------------+

Remove a role
-------------

Remove a role from a user-project pair:

#. Run the :command:`openstack role remove` command:

   .. code-block:: console

      $ openstack role remove --user USER_NAME --project PROJECT_NAME ROLE_NAME

#. Verify the role removal:

   .. code-block:: console

      $ openstack role assignment list --user USER_NAME --project PROJECT_NAME --names

   If the role was removed, the command output omits the removed role.

Creating implied roles
----------------------

It is possible to build role hierarchies by having roles imply other roles.
These are called implied roles, or role inference rules.

To illustrate the capability, let's have the ``admin`` role imply the
``member`` role. In this example, if a user was assigned the prior role,
which in this case is the ``admin`` role, they would also get the ``member``
role that it implies.

.. code-block:: console

    $ openstack implied role create admin --implied-role member
    +------------+----------------------------------+
    | Field      | Value                            |
    +------------+----------------------------------+
    | implies    | 71ccc37d41c8491c975ae72676db687f |
    | prior_role | 29c09e68e6f741afa952a837e29c700b |
    +------------+----------------------------------+

.. note::

    Role implications only go one way, from a "prior" role to an "implied"
    role. Therefore assigning a user the ``member`` will not grant them the
    ``admin`` role.

This makes it easy to break up large roles into smaller pieces, allowing for
fine grained permissions, while still having an easy way to assign all the
pieces as if they were a single one. For example, you can have a ``member``
role imply ``compute_member``, ``network_member``, and ``volume_member``,
and then assign either the full-blown ``member`` role to users or any one of
the subsets.

Listing implied roles
---------------------

To list implied roles:

.. code-block:: console

    $ openstack implied role list
    +----------------------------------+-----------------+----------------------------------+-------------------+
    | Prior Role ID                    | Prior Role Name | Implied Role ID                  | Implied Role Name |
    +----------------------------------+-----------------+----------------------------------+-------------------+
    | 29c09e68e6f741afa952a837e29c700b | admin           | 71ccc37d41c8491c975ae72676db687f | member            |
    +----------------------------------+-----------------+----------------------------------+-------------------+

Deleting implied roles
----------------------

To delete a role inference rule:

.. code-block:: console

    $ openstack implied role delete admin --implied-role member

.. note::

    Deleting an implied role removes the role inference rule. It does not
    delete the prior or implied role. Therefore if a user was assigned the
    prior role, they will no longer have the roles that it implied.
