..
      Copyright 2011-2012 OpenStack, LLC
      All Rights Reserved.

      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

========================
Developing with Keystone
========================

Contributing Code
=================

To contribute code, sign up for a Launchpad account and sign a contributor
license agreement, available on the `<http://wiki.openstack.org/CLA>`_. Once
the CLA is signed you can contribute code through the Gerrit version control
system which is related to your Launchpad account.


To contribute tests, docs, code, etc, refer to our `Gerrit-Jenkins-Github Workflow`_.

.. _`Gerrit-Jenkins-Github Workflow`: http://wiki.openstack.org/GerritJenkinsGithub

Setup
-----

Get your development environment set up according to :doc:`setup`. The
instructions from here will assume that you have installed keystone into a
virtualenv. If you chose not to, simply exclude "tools/with_venv.sh" from the
example commands below.


Running Keystone
----------------

To run the keystone Admin and API server instances, use::

    $ tools/with_venv.sh bin/keystone-all

this runs keystone with the configuration the etc/ directory of the project.
See :doc:`configuration` for details on how Keystone is configured. By default,
keystone is configured with KVS backends, so any data entered into keystone run
in this fashion will not persist across restarts.


Interacting with Keystone
-------------------------

You can interact with Keystone through the command line using
:doc:`man/keystone-manage` which allows you to establish tenants, users, etc.


You can also interact with Keystone through its REST API. There is a python
keystone client library `python-keystoneclient`_ which interacts exclusively
through the REST API, and which keystone itself uses to provide its
command-line interface.

When initially getting set up, after you've configured which databases to use,
you're probably going to need to run the following to your database schema in
place::

    $ bin/keystone-manage db_sync

.. _`python-keystoneclient`: https://github.com/openstack/python-keystoneclient

Running Tests
=============

To run the full suites of tests maintained within Keystone, run::

    $ ./run_tests.sh

This shows realtime feedback during test execution, iterates over
multiple configuration variations, and uses external projects to do
light integration testing to verify the keystone API against other projects.

Test Structure
--------------

``./run_test.sh`` uses its python cohort (``run_tests.py``) to iterate
through the ``tests`` directory, using Nosetest to collect the tests and
invoke them using an OpenStack custom test running that displays the tests
as well as the time taken to
run those tests.

Within the tests directory, the general structure of the tests is a basic
set of tests represented under a test class, and then subclasses of those
tests under other classes with different configurations to drive different
backends through the APIs.

For example, ``test_backend.py`` has a sequence of tests under the class
``IdentityTests`` that will work with the default drivers as configured in
this projects etc/ directory. ``test_backend_sql.py`` subclasses those tests,
changing the configuration by overriding with configuration files stored in
the tests directory aimed at enabling the SQL backend for the Identity module.

Likewise, ``test_cli.py`` takes advantage of the tests written aainst
``test_keystoneclient`` to verify the same tests function through different
drivers.

Testing Schema Migrations
-------------------------

The application of schema migrations can be tested using SQLAlchemy Migrate’s
built-in test runner, one migration at a time.

.. WARNING::

    This may leave your database in an inconsistent state; attempt this in non-production environments only!

This is useful for testing the *next* migration in sequence (both forward &
backward) in a database under version control::


    python keystone/common/sql/migrate_repo/manage.py test \
    --url=sqlite:///test.db \
    --repository=keystone/common/sql/migrate_repo/

This command references to a SQLite database (test.db) to be used. Depending on
the migration, this command alone does not make assertions as to the integrity
of your data during migration.


Writing Tests
-------------

To add tests covering all drivers, update the base test class
(``test_backend.py``, ``test_legacy_compat.py``, and
``test_keystoneclient.py``).

To add new drivers, subclass the ``test_backend.py`` (look towards
``test_backend_sql.py`` or ``test_backend_kvs.py`` for examples) and update the
configuration of the test class in ``setUp()``.


Further Testing
---------------

devstack_ is the *best* way to quickly deploy keystone with the rest of the
OpenStack universe and should be critical step in your development workflow!

You may also be interested in either the
`OpenStack Continuous Integration Project`_ or the
`OpenStack Integration Testing Project`_.

.. _devstack: http://devstack.org/
.. _OpenStack Continuous Integration Project: https://github.com/openstack/openstack-ci
.. _OpenStack Integration Testing Project: https://github.com/openstack/tempest

Building the Documentation
==========================

The documentation is all generated with Sphinx from within the docs directory.
To generate the full set of HTML documentation:

    cd docs
    make autodoc
    make html
    make man

the results are in the docs/build/html and docs/build/man directories
respectively.
