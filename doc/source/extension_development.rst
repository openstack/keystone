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

=====================================
Keystone Extensions Development Guide
=====================================

General
=======

This Extension Development Guide provides some mocked code to use as an
Extension code base in the ``keystone/contrib/example`` folder.

- All Extensions must be created in the ``keystone/contrib`` folder.
- The new Extension code must be contained in a new folder under ``contrib``.
- Whenever possible an Extension should follow the following directory
  structure convention::

      keystone/contrib/
      └── my_extension
          ├── backends (optional)
          │   ├── __init__.py (mandatory)
          │   └── sql.py (optional)
          │   └── kvs.py (optional)
          ├── migrate_repo (optional)
          │   ├── __init__.py (mandatory)
          │   ├── migrate.cfg (mandatory)
          │   └── versions (mandatory)
          │       ├── 001_create_tables.py (mandatory)
          │       └── __init__.py (mandatory)
          ├── __init__.py (mandatory)
          ├── core.py (mandatory)
          ├── controllers.py (mandatory for API Extension)
          └── routers.py (mandatory for API Extension)

- If the Extension implements an API Extension the ``controllers.py`` and
  ``routers.py`` must be present and correctly handle the API Extension
  requests and responses.
- If the Extension implements backends a ``backends`` folder should exist.
  Backends are defined to store data persistently and can use a variety of
  technologies. Please see the Backends section in this document for more info.
- If the Extension adds data structures, then a ``migrate_repo`` folder should
  exist.
- If configuration changes are required/introduced in the
  ``keystone.conf.sample`` file, these should be kept disabled as default and
  have their own section.
- If configuration changes are required/introduced in the
  ``keystone-paste.ini``, the new filter must be declared.
- The module may register to listen to events by declaring the corresponding
  callbacks in the ``core.py`` file.
- The new extension should be disabled by default (it should not affect the
  default application pipelines).

Modifying the `keystone.conf.sample` File
=========================================

In the case an Extension needs to change the ``keystone.conf.sample`` file, it
must follow the config file conventions and introduce a dedicated section.

Example::

    [example]
    driver = sql

    [my_other_extension]
    extension_flag = False

The Extension parameters expressed should be commented out since, by default,
extensions are disabled.

Example::

    [example]
    #driver = sql

    [my_other_extension]
    #extension_flag = False

In case the Extension is overriding or re-implementing an existing portion of
Keystone, the required change should be commented in the ``configuration.rst``
but not placed in the `keystone.conf.sample` file to avoid unnecessary
confusion.

Modifying the ``keystone-paste.ini`` File
=========================================

In the case an Extension is augmenting a pipeline introducing a new ``filter``
and/or APIs in the ``OS`` namespace, a corresponding ``filter:`` section is
necessary to be introduced in the ``keystone-paste.ini`` file. The Extension
should declare the filter factory constructor in the ``ini`` file.

Example::

    [filter:example]
    paste.filter_factory = keystone.contrib.example.routers:ExampleRouter.
    factory

The ``filter`` must not be placed in the ``pipeline`` and treated as optional.
How to add the extension in the pipeline should be specified in detail in the
``configuration.rst`` file.

Package Constructor File
========================

The ``__init__.py`` file represents the package constructor. Extension needs to
import what is necessary from the ``core.py`` module.

Example:

.. code-block:: python

   from keystone.contrib.example.core import *

Core
====

The ``core.py`` file represents the main module defining the data structure and
interface. In the ``Model View Control`` (MVC) model it represents the
``Model`` part and it delegates to the ``Backends`` the data layer
implementation.

In case the ``core.py`` file contains a ``Manager`` and a ``Driver`` it must
provide the dependency injections for the ``Controllers`` and/or other modules
using the ``Manager``. A good practice is to call the dependency
``extension_name_api``.

Example:

.. code-block:: python

    @dependency.provider('example_api')
    class Manager(manager.Manager):

Routers
=======

``routers.py`` have the objective of routing the HTTP requests and direct them to
the correct method within the ``Controllers``. Extension routers are extending
the ``wsgi.ExtensionRouter``.

Example:

.. code-block:: python

    from keystone.common import wsgi
    from keystone.contrib.example import controllers


    class ExampleRouter(wsgi.ExtensionRouter):

        PATH_PREFIX = '/OS-EXAMPLE'

        def add_routes(self, mapper):
            example_controller = controllers.ExampleV3Controller()
            mapper.connect(self.PATH_PREFIX + '/example',
                           controller=example_controller,
                           action='do_something',
                           conditions=dict(method=['GET']))

Controllers
===========

``controllers.py`` have the objective of handing requests and implement the
Extension logic. Controllers are consumers of 'Managers' API and must have all
the dependency injections required. ``Controllers`` are extending the
``V3Controller`` class.

Example:

.. code-block:: python

    @dependency.requires('identity_api', 'example_api')
    class ExampleV3Controller(controller.V3Controller):
        pass

Backends
========

The ``backends`` folder provides the model implementations for the different
backends supported by the Extension. See General above for an example directory
structure.

If a SQL backend is provided, in the ``sql.py`` backend implementation it is
mandatory to define the new table(s) that the Extension introduces and the
attributes they are composed of.

For more information on backends, refer to the `Keystone Architecture
<http://docs.openstack.org/developer/keystone/architecture.html>`_
documentation.

Example:

.. code-block:: python

    class ExampleSQLBackend(sql.ModelBase, sql.DictBase):
        """example table description."""
        __tablename__ = 'example_table'
        attributes = ['id', 'type', 'extra']

        example_id = sql.Column(sql.String(64),
                                primary_key=True,
                                nullable=False)
        ...

SQL Migration Repository
========================

In case the Extension is adding SQL data structures, these must be stored in
separate tables and must not be included in the ``migrate_repo`` of the core
Keystone. Please refer to the ``migrate.cfg`` file to configure the Extension
repository.

In order to create the Extension tables and their attributes, a ``db_sync``
command must be executed.

Example:

.. code-block:: bash

     $ ./bin/keystone-manage db_sync --extension example

Event Callbacks
---------------

Extensions may provide callbacks to Keystone (Identity) events.
Extensions must provide the list of events of interest and the corresponding
callbacks. Events are issued upon successful creation, modification, and
deletion of the following Keystone resources:

- ``group``
- ``project``
- ``role``
- ``user``

The extension's ``Manager`` class must contain the
``event_callbacks`` attribute. It is a dictionary listing as keys
those events that are of interest and the values should be the respective
callbacks. Event callback registration is done via the
dependency injection mechanism. During dependency provider registration, the
``dependency.provider`` decorator looks for the ``event_callbacks``
class attribute. If it exists the event callbacks are registered
accordingly. In order to enable event callbacks, the extension's ``Manager``
class must also be a dependency provider.

Example:

.. code-block:: python

    # Since this is a dependency provider. Any code module using this or any
    # other dependency provider (uses the dependency.provider decorator)
    # will be enabled for the attribute based notification

    @dependency.provider('example_api')
    class ExampleManager(manager.Manager):
        """Example Manager.

        See :mod:`keystone.common.manager.Manager` for more details on
        how this dynamically calls the backend.

        """

        def __init__(self):
            self.event_callbacks = {
                # Here we add the event_callbacks class attribute that
                # calls project_deleted_callback when a project is deleted.
                'deleted': {
                    'project': [
                        self.project_deleted_callback]}}
            super(ExampleManager, self).__init__(
                'keystone.contrib.example.core.ExampleDriver')

        def project_deleted_callback(self, context, message):
            # cleanup data related to the deleted project here

A callback must accept the following parameters:

- ``service`` - the service information (e.g. identity)
- ``resource_type`` - the resource type (e.g. project)
- ``operation`` - the operation (updated, created, deleted)
- ``payload`` - the actual payload info of the resource that was acted on

Current callback operations:

- ``created``
- ``deleted``
- ``updated``

Example:

.. code-block:: python

      def project_deleted_callback(self, service, resource_type, operation,
                                   payload):
