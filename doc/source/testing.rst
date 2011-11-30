================
Testing Keystone
================

Keystone uses a number of testing methodologies to ensure correctness.

Running Built-In Tests
======================

To run the full suites of tests maintained within Keystone, run::

    $ ./run_tests.sh --with-progress

This shows realtime feedback during test execution, and iterates over
multiple configuration variations.

This differs from how tests are executed from the continuous integration
environment. Specifically, Jenkins doesn't care about realtime progress,
and aborts after the first test failure (a fail-fast behavior)::

    $ ./run_tests.sh

Testing Schema Migrations
=========================

The application of schema migrations can be tested using SQLAlchemy Migrate’s built-in test runner, one migration at a time.

.. WARNING::

    This may leave your database in an inconsistent state; attempt this in non-production environments only!

This is useful for testing the *next* migration in sequence (both forward & backward) in a database under version control::

    $ python keystone/backends/sqlalchemy/migrate_repo/manage.py test --url=sqlite:///test.db --repository=keystone/backends/sqlalchemy/migrate_repo/

This command refers to a SQLite database used for testing purposes. Depending on the migration, this command alone does not make assertions as to the integrity of your data during migration.

Writing Tests
=============

Tests are maintained in the ``keystone.test`` module. Unit tests are
isolated from functional tests.

Functional Tests
----------------

The ``keystone.test.functional.common`` module provides a ``unittest``-based
``httplib`` client which you can extend and use for your own tests.
Generally, functional tests should serve to illustrate intended use cases
and API behaviors. To help make your tests easier to read, the test client:

- Authenticates with a known user name and password combination
- Asserts 2xx HTTP status codes (unless told otherwise)
- Abstracts keystone REST verbs & resources into single function calls

Testing Multiple Configurations
-------------------------------

Several variations of the default configuration are iterated over to
ensure test coverage of mutually exclusive featuresets, such as the
various backend options.

These configuration templates are maintained in ``keystone/test/etc`` and
are iterated over by ``run_tests.py``.

Further Testing
===============

devstack_ is the *best* way to quickly deploy keystone with the rest of the
OpenStack universe and should be critical step in your development workflow!

You may also be interested in either the `OpenStack Continuous Integration Project`_
or the `OpenStack Integration Testing Project`_.

.. _devstack: http://devstack.org/
.. _OpenStack Continuous Integration Project: https://github.com/openstack/openstack-ci
.. _OpenStack Integration Testing Project: https://github.com/openstack/openstack-integration-tests
