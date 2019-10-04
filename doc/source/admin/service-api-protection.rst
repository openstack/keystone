=============
Default Roles
=============

------
Primer
------

Like most OpenStack services, keystone protects its API using role-based access
control (RBAC).

Users can access different APIs depending on the roles they have on a project,
domain, or system.

As of the Rocky release, keystone provides three roles called ``admin``,
``member``, and ``reader`` by default. Operators can grant these roles to any
actor (e.g., group or user) on any target (e.g., system, domain, or project).
If you need a refresher on authorization scopes and token types, please refer
to the `token guide`_. The following sections describe how each default role
behaves with keystone's API across different scopes.

Default roles and behaviors across scopes allow operators to delegate more
functionality to their team, auditors, customers, and users without maintaining
custom policies.

.. _`token guide`: https://docs.openstack.org/keystone/latest/admin/tokens-overview.html#authorization-scopes

-----------------
Roles Definitions
-----------------

The default roles imply one another. The ``admin`` role implies the ``member``
role, and the ``member`` role implies the ``reader`` role. This implication
means users with the ``admin`` role automatically have the ``member`` and
``reader`` roles. Additionally, users with the ``member`` role automatically
have the ``reader`` role. Implying roles reduces role assignments and forms a
natural hierarchy between the default roles. It also reduces the complexity of
default policies by making check strings short. For example, a policy that
requires ``reader`` can be expressed as:

.. code-block:: yaml

    "identity:list_foo": "role:reader"

Instead of:

.. code-block:: yaml

    "identity:list_foo": "role:admin or role:member or role:reader"

Reader
======

The ``reader`` role provides read-only access to resources within the system, a
domain, or a project. Depending on the assignment scope, two users with the
``reader`` role can expect different API behaviors. For example, a user with
the ``reader`` role on the system can list all projects within the deployment.
A user with the ``reader`` role on a domain can only list projects within their
domain.

By analyzing the scope of a role assignment, we increase the re-usability of
the ``reader`` role and provide greater functionality without introducing more
roles. For example, to accomplish this without analyzing assignment scope, you
would need ``system-reader``, ``domain-reader``, and ``project-reader`` roles
in addition to custom policies for each service.

Member
======

Within keystone, there isn't a distinct advantage to having the ``member`` role
instead of the ``reader`` role. The ``member`` role is more applicable to other
services.  The ``member`` role works nicely for introducing granularity between
``admin`` and ``reader`` roles. Other services might write default policies
that require the ``member`` role to create resources, but the ``admin`` role to
delete them. For example, users with ``reader`` on a project could list
instance, users with ``member`` on a project can list and create instances, and
users with ``admin`` on a project can list, create, and delete instances.
Service developers can use the ``member`` role to provide more flexibility
between ``admin`` and ``reader`` on different scopes.

Admin
=====

We reserve the ``admin`` role for the most privileged operations within a given
scope. It is important to note that having ``admin`` on a project, domain, or
the system carries separate authorization and are not transitive. For example,
users with ``admin`` on the system should be able to manage every aspect of the
deployment because they're operators. Users with ``admin`` on a project
shouldn't be able to manage things outside the project because it would violate
the tenancy of their role assignment (this doesn't apply consistently since
services are addressing this individually at their own pace).

.. note::

   As of the Train release, keystone applies the following personas
   consistently across its API.

---------------------
System Administrators
---------------------

*System administrators* are allowed to manage every resource in keystone.
System administrators are typically operators and cloud administrators. They
can control resources that ultimately affect the behavior of the deployment.
For example, they can add or remove services and endpoints in the catalog,
create new domains, add federated mappings, and clean up stale resources, like
a user's application credentials or trusts.

You can find *system administrators* in your deployment with the following
assignments:

.. code-block:: console

    $ openstack role assignment list --names --system all
    +-------+------------------+-----------------------+---------+--------+--------+-----------+
    | Role  | User             | Group                 | Project | Domain | System | Inherited |
    +-------+------------------+-----------------------+---------+--------+--------+-----------+
    | admin |                  | system-admins@Default |         |        | all    | False     |
    | admin | admin@Default    |                       |         |        | all    | False     |
    | admin | operator@Default |                       |         |        | all    | False     |
    +-------+------------------+-----------------------+---------+--------+--------+-----------+

-------------------------------
System Members & System Readers
-------------------------------

In keystone, *system members* and *system readers* are very similar and have
the same authorization. Users with these roles on the system can view all
resources within keystone. They can audit role assignments, users, projects,
and group memberships, among other resources.

The *system reader* persona is useful for auditors or members of a support
team. You can find *system members* and *system readers* in your deployment
with the following assignments:

.. code-block:: console

    $ openstack role assignment list --names --system all --role member --role reader
    +--------+------------------------+-------------------------+---------+--------+--------+-----------+
    | Role   | User                   | Group                   | Project | Domain | System | Inherited |
    +--------+------------------------+-------------------------+---------+--------+--------+-----------+
    | reader |                        | system-auditors@Default |         |        | all    | False     |
    | admin  | operator@Default       |                         |         |        | all    | False     |
    | member | system-support@Default |                         |         |        | all    | False     |
    +--------+------------------------+-------------------------+---------+--------+--------+-----------+

.. warning::

   Filtering system role assignments is currently broken and is being tracked
   as a `bug <https://bugs.launchpad.net/keystone/+bug/1846817>`_.

---------------------
Domain Administrators
---------------------

*Domain administrators* can manage most aspects of the domain or its contents.
These users can create new projects and users within their domain. They can
inspect the role assignments users have on projects within their domain.

*Domain administrators* aren't allowed to access system-specific resources or
resources outside their domain. Users that need control over project, group,
and user creation are a great fit for *domain administrators*.

You can find *domain administrators* in your deployment with the following role
assignment:

.. code-block:: console

    $ openstack role assignment list --names --domain foobar --role admin
    +-------+----------------+----------------------+---------+--------+--------+-----------+
    | Role  | User           | Group                | Project | Domain | System | Inherited |
    +-------+----------------+----------------------+---------+--------+--------+-----------+
    | admin | jsmith@Default |                      |         | foobar |        | False     |
    | admin |                | foobar-admins@foobar |         | foobar |        | False     |
    +-------+----------------+----------------------+---------+--------+--------+-----------+

-------------------------------
Domain Members & Domain Readers
-------------------------------

Domain members and domain readers have the same relationship as system members
and system readers. They're allowed to view resources and information about
their domain. They aren't allowed to access system-specific information or
information about projects, groups, and users outside their domain.

The domain member and domain reader use-cases are great for auditing, support,
or monitoring the details of an account. You can find domain members and domain
readers with the following role assignments:

.. code-block:: console

    $ openstack role assignment list --names --role member --domain foobar
    +--------+-------------+-------+---------+--------+--------+-----------+
    | Role   | User        | Group | Project | Domain | System | Inherited |
    +--------+-------------+-------+---------+--------+--------+-----------+
    | member | jdoe@foobar |       |         | foobar |        | False     |
    +--------+-------------+-------+---------+--------+--------+-----------+
    $ openstack role assignment list --names --role reader --domain foobar
    +--------+-----------------+-------+---------+--------+--------+-----------+
    | Role   | User            | Group | Project | Domain | System | Inherited |
    +--------+-----------------+-------+---------+--------+--------+-----------+
    | reader | auditor@Default |       |         | foobar |        | False     |
    +--------+-----------------+-------+---------+--------+--------+-----------+


----------------------
Project Administrators
----------------------

*Project administrators* can only view and modify data within the project in
their role assignment. They're able to view information about their projects
and set tags on their projects. They're not allowed to view system or domain
resources, as that would violate the tenancy of their role assignment. Since
the majority of the resources in keystone's API are system and domain-specific,
*project administrators* don't have much authorization.

You can find *project administrators* in your deployment with the following
role assignment:

.. code-block:: console

    $ openstack role assignment list --names --project production --role admin
    +-------+----------------+--------------------------+-------------------+--------+--------+-----------+
    | Role  | User           | Group                    | Project           | Domain | System | Inherited |
    +-------+----------------+--------------------------+-------------------+--------+--------+-----------+
    | admin | jsmith@Default |                          | production@foobar |        |        | False     |
    | admin |                | production-admins@foobar | production@foobar |        |        | False     |
    +-------+----------------+--------------------------+-------------------+--------+--------+-----------+

---------------------------------
Project Members & Project Readers
---------------------------------

*Project members* and *project readers* can discover information about their
projects. They can access important information like resource limits for their
project, but they're not allowed to view information outside their project or
view system-specific information.

You can find *project members* and *project readers* in your deployment with
the following role assignments:


.. code-block:: console

    $ openstack role assignment list --names --project production --role member
    +--------+------+--------------------------+-------------------+--------+--------+-----------+
    | Role   | User | Group                    | Project           | Domain | System | Inherited |
    +--------+------+--------------------------+-------------------+--------+--------+-----------+
    | member |      | foobar-operators@Default | production@foobar |        |        | False     |
    +--------+------+--------------------------+-------------------+--------+--------+-----------+
    $ openstack role assignment list --names --project production --role reader
    +--------+-----------------+----------------------------+-------------------+--------+--------+-----------+
    | Role   | User            | Group                      | Project           | Domain | System | Inherited |
    +--------+-----------------+----------------------------+-------------------+--------+--------+-----------+
    | reader | auditor@Default |                            | production@foobar |        |        | False     |
    | reader |                 | production-support@Default | production@foobar |        |        | False     |
    +--------+-----------------+----------------------------+-------------------+--------+--------+-----------+

----------------
Writing Policies
----------------

If the granularity provided above doesn't meet your specific use-case, you can
still override policies and maintain them manually. You can read more about how
to do that in oslo.policy usage `documentation`_.

.. _`documentation`: https://docs.openstack.org/oslo.policy/latest/admin/index.html
