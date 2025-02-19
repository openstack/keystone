.. _domain_manager_usage:

====================
Domain Manager Usage
====================

The following sections describe the actions available to Domain Manager users
that possess the **manager** role in domain scope. This role enables users
self-service capabilities within the domain, including user, project and group
management as well as role assignment. This functionality is available starting
with the 2024.2 release of Keystone.

Managing users within a domain
==============================

Creating a user within a domain:

.. code-block:: bash

    openstack user create --domain $DOMAIN $USER_NAME

.. note::

    Explicit domain-scoping is only required for the "``user create``" command,
    any other user-centric commands like "``user set``" or "``user delete``" do
    not require the "``--domain``" flag and are automatically scoped to the
    domain for Domain Managers.

Managing projects within a domain
=================================

Creating a project within a domain:

.. code-block:: bash

    openstack project create --domain $DOMAIN $PROJECT_NAME

.. note::

    Explicit domain-scoping is only required for the "``project create``"
    command, any other project-centric commands like "``project set``" or
    "``project delete`` do not require the "``--domain``" flag and are
    automatically scoped to the domain for Domain Managers.

Deleting projects
-----------------

Note that before deleting projects, make sure that all cloud resources
(servers, volumes etc.) belonging to that project have been removed beforehand.
Otherwise such resources might become orphaned and inaccessible without
involving an admin.

Managing groups within a domain
===============================

Creating a group within a domain:

.. code-block:: bash

    openstack group create --domain $DOMAIN $GROUP_NAME


.. note::

    Explicit domain-scoping is only required for the "``group create``"
    command, any other group-centric commands like "``group set``" or "``group
    delete``" do not require the "``--domain``" flag and are automatically
    scoped to the domain for Domain Managers.

Managing group membership
-------------------------

Adding a user to a group:

.. code-block:: bash

    openstack group add user $GROUP $USER


Removing a user from a group:

.. code-block:: bash

    openstack group remove user $GROUP $USER

Checking if a user is within a group:

.. code-block:: bash

    openstack group contains user $GROUP $USER

Managing role assignments within a domain
=========================================

.. caution::

    A Domain Manager is only able to manage assignments of a subset of all
    available roles. Per default this is limited to the **reader**,
    **member** and **manager** roles. However, this can be adjusted by an
    admin of the cloud.

Inspecting role assignments
---------------------------

Current role assignments within the domain can be inspected using the following
command:

.. code-block:: bash

    openstack role assignment list --names

.. tip::

    The parameter "``--names``" will show readable names of users, groups,
    projects, roles and domains instead of IDs. It can be omitted if the raw
    IDs are of interest.

Managing user role assignments
------------------------------

Assigning a role to a user within a project:

.. code-block:: bash

    openstack role add --project $PROJECT --user $USER $ROLE


Assigning a role to a user domain-wide:

.. code-block:: bash

    openstack role add --domain $DOMAIN --user $USER $ROLE

Revoking a project-level role assignment from a user:

.. code-block:: bash

    openstack role remove --project $PROJECT --user $USER $ROLE


Revoking a domain-wide role assignment from a user:

.. code-block:: bash

    openstack role remove --domain $DOMAIN --user $USER $ROLE


Managing group role assignments
-------------------------------

Assigning a role to a group within a project:

.. code-block:: bash

    openstack role add --project $PROJECT --group $GROUP $ROLE


Assigning a role to a group domain-wide:

.. code-block:: bash

    openstack role add --domain $DOMAIN --group $GROUP $ROLE


Revoking a project-level role assignment from a group:

.. code-block:: bash

    openstack role remove --project $PROJECT --group $GROUP $ROLE


Revoking a domain-wide role assignment from a group:

.. code-block:: bash

    openstack role remove --domain $DOMAIN --group $GROUP $ROLE

