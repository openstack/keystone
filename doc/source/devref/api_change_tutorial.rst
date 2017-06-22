..
      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

====================
Making an API Change
====================

This document will guide you through the process of proposing and submitting
an API change to keystone.

Prerequisites
-------------

In order to follow this tutorial, it is assumed that you have read our
:doc:`index` and
:doc:`../getting-started/architecture` documents.

Proposing a change
------------------

You need to create a blueprint, submit a specification against the
`keystone-specs`_ repository and bring it up to discussion with the
`keystone core team`_ for agreement.

.. _`keystone-specs`: https://git.openstack.org/cgit/openstack/keystone-specs/
.. _`keystone core team`: https://review.openstack.org/#/admin/groups/9,members

Create
~~~~~~

#. `Create a blueprint`_ in launchpad;
#. git clone https://git.openstack.org/openstack/keystone-specs;
#. cp `specs/template.rst` `specs/backlog/<feature>.rst`;
#. Write the spec based on the template. Ensure the BP link points to the one
   created in step 1;
#. Also update the documentation at `api/v3/identity-api-v3.rst` to reflect the
   proposed API changes;
#. Push to gerrit for review;
#. Propose agenda items to the `keystone meeting`_, and make sure someone
   who understands the subject can attend the meeting to answer questions.

.. _`Create a blueprint`: https://blueprints.launchpad.net/keystone/+addspec
.. _`template`: https://git.openstack.org/cgit/openstack/keystone-specs/tree/specs/template.rst
.. _`keystone meeting`: https://wiki.openstack.org/wiki/Meetings/KeystoneMeeting

Agreement
~~~~~~~~~

The `keystone core team`_ will evaluate the specification and vote on accepting
it or not. If accepted, the proposal will be targeted to a release; otherwise,
the specification will be abandoned.

As soon as there is an agreement on the specification, the change may start
rolling out.

Implementing a change
---------------------

In this section, let's assume that a specification proposing the addition of a
`description` field to the roles API was accepted. In the next subsections, you
will find a detailed explanation on the needed code changes to the keystone
code to implement such change.

Architectural Recapitulation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

As you saw in the :doc:`../getting-started/architecture` document, there are
four logical levels of code at which a successful request calls: router,
controller, manager and
driver.

For the role backend, they can be found in the directory `keystone/assignment`,
in the following paths, respectively: `routers.py`, `controllers.py`, `core.py`
and `role_backends/sql.py` (currently only the SQL driver is supported).

Changing the SQL Model and Driver
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

First, you need to change the role model to include the description attribute.
Go to `keystone/assignment/role_backends/sql.py` and update it like::

    class RoleTable(sql.ModelBase, sql.ModelDictMixin):

        attributes = ['id', 'name', 'domain_id', 'description']
        description = sql.Column(sql.String(255), nullable=True)
        ...

Now, when keystone runs, the table will be created with the new attribute.
However, what about existing deployments which already have the role table
created? You need to migrate their database schema!

The directory `keystone/common/sql/migrate_repo/versions` owns all the
migrations since keystone day 1. Create a new file there with the next
migration number. For example, if the latest migration number there is `101`,
create yours as `102_add_role_description.py`, which will look like::

    def upgrade(migrate_engine):
        meta = sql.MetaData()
        meta.bind = migrate_engine

        role_table = sql.Table('role', meta, autoload=True)
        description = sql.Column('description', sql.String(255),
                                 nullable=True)
        role_table.create_column(description)

Do not forget to add tests for your migration at
`keystone/tests/unit/test_sql_upgrade.py`, you may take other tests as example
and learn how to develop yours. In this case, you would need to upgrade to
`102` check the migration has added the `description` column to the role table.

Changing the role driver itself in `keystone/assignment/role_backends/sql.py`
will not be necessary, because the driver handles the role entities as Python
dictionaries, thus the new attribute will be handled automatically.

Changing the Manager
~~~~~~~~~~~~~~~~~~~~

Managers handle the business logic. Keystone provides the basic CRUD for role
entities, that means that the role manager simply calls the driver with the
arguments received from the controller, and then returns the driver's result
back to controller. Additionally, it handles the cache management.

Thus, there is no manager change needed to make it able to operate role
entities with the new `description` attribute.

However, you should add tests for the role CRUD operations with the new
attribute to `keystone/tests/unit/assignment/test_core.py`.

When trying to determine whether a change goes in the driver or in the manager,
the test is whether the code is business logic and/or needs to be executed for
each driver. Both common and business logics go in the manager, while backend
specific logic goes in the drivers.

Changing the Controller and Router
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Business logic should not go in the controller. The controller should be viewed
as a binding between the business logic and the HTTP protocol. Thus, it is in
charge of calling the appropriate manager call and wrapping responses into HTTP
format.

Controllers use JSON schemas do determine whether a provided role is a valid
representation or not. Role create and role update schemas are available at
`keystone/assignment/schema.py`.

You will need to update their properties to include a `description` attribute::

    _role_properties = {
        'name': parameter_types.name,
        'description': parameter_types.description
    }

Besides doing the entity validation using such schemas, controllers pass and
accept all the attributes to and from the manager. Thus, there is no further
change needed at the controller level.

Furthermore, as role entities are passed in the request body to keystone calls,
the role routes do not need to be changed; i.e the routes still are::

      POST /v3/roles
      GET /v3/roles/{id}
      HEAD /v3/roles/{id}
      PATCH /v3/roles/{id}
      DELETE /v3/roles/{id}

Conclusion
----------

At this point, keystone role entities contain a `description` attribute. In
order to make it happen, you have learned how the keystone architecture is,
what is the responsibility of each layer, how database migrations occur and the
way entities are represented into tables.

The pattern of the change made in this tutorial applies to other keystone
subsystems as well, such as `resource` and `identity`.
