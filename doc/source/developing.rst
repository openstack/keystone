..
      Copyright 2011-2012 OpenStack Foundation
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

Setup
-----

Get your development environment set up according to :doc:`setup`. The
instructions from here will assume that you have installed keystone into a
virtualenv. If you chose not to, simply exclude "tools/with_venv.sh" from the
example commands below.


Configuring Keystone
--------------------

keystone requires a configuration file.  There is a sample configuration file
that can be used to get started::

    $ cp etc/keystone.conf.sample etc/keystone.conf

The defaults are enough to get you going, but you can make any changes if
needed.


Running Keystone
----------------

To run the keystone Admin and API server instances, use::

    $ tools/with_venv.sh bin/keystone-all

this runs keystone with the configuration the etc/ directory of the project.
See :doc:`configuration` for details on how Keystone is configured. By default,
keystone is configured with SQL backends.


Interacting with Keystone
-------------------------

You can interact with Keystone through the command line using
:doc:`man/keystone-manage` which allows you to initialize keystone, etc.

You can also interact with Keystone through its REST API. There is a python
keystone client library `python-keystoneclient`_ which interacts exclusively
through the REST API, and which keystone itself uses to provide its
command-line interface.

When initially getting set up, after you've configured which databases to use,
you're probably going to need to run the following to your database schema in
place::

    $ bin/keystone-manage db_sync

.. _`python-keystoneclient`: https://github.com/openstack/python-keystoneclient

Database Schema Migrations
--------------------------

Keystone uses SQLAlchemy-migrate_ to migrate
the SQL database between revisions. For core components, the migrations are
kept in a central repository under ``keystone/common/sql/migrate_repo``.

.. _SQLAlchemy-migrate: http://code.google.com/p/sqlalchemy-migrate/

Extensions should be created as directories under ``keystone/contrib``. An
extension that requires SQL migrations should not change the common repository,
but should instead have its own repository. This repository must be in the
extension's directory in ``keystone/contrib/<extension>/migrate_repo``. In
addition, it needs a subdirectory named ``versions``. For example, if the
extension name is ``my_extension`` then the directory structure would be
``keystone/contrib/my_extension/migrate_repo/versions/``. For the migration to
work, both the ``migrate_repo`` and ``versions`` subdirectories must have
``__init__.py`` files. SQLAlchemy-migrate will look for a configuration file in
the ``migrate_repo`` named ``migrate.cfg``. This conforms to a key/value `ini`
file format. A sample configuration file with the minimal set of values is::

    [db_settings]
    repository_id=my_extension
    version_table=migrate_version
    required_dbs=[]

The directory ``keystone/contrib/example`` contains a sample extension
migration.

Migrations must be explicitly run for each extension individually. To run a
migration for a specific extension, run ``keystone-manage --extension <name>
db_sync``.

Initial Sample Data
-------------------

There is an included script which is helpful in setting up some initial sample
data for use with keystone::

    $ OS_SERVICE_TOKEN=ADMIN tools/with_venv.sh tools/sample_data.sh

Notice it requires a service token read from an environment variable for
authentication.  The default value "ADMIN" is from the ``admin_token``
option in the ``[DEFAULT]`` section in ``etc/keystone.conf``.

Once run, you can see the sample data that has been created by using the
`python-keystoneclient`_ command-line interface::

    $ tools/with_venv.sh keystone --os-token ADMIN --os-endpoint http://127.0.0.1:35357/v2.0/ user-list

Running Tests
=============

Before running tests, you should have ``tox`` installed and available in your
environment (in addition to the other external dependencies in :doc:`setup`)::

    $ pip install tox

.. NOTE::

    You may need to perform both the above operation and the next inside a
    python virtualenv, or prefix the above command with ``sudo``, depending on
    your preference.

To execute the full suite of tests maintained within Keystone, simply run::

    $ tox

This iterates over multiple configuration variations, and uses external
projects to do light integration testing to verify the Identity API against
other projects.

.. NOTE::

    The first time you run ``tox``, it will take additional time to build
    virtualenvs. You can later use the ``-r`` option with ``tox`` to rebuild
    your virtualenv in a similar manner.

To run tests for one or more specific test environments (for example, the most
common configuration of Python 2.7 and PEP-8), list the environments with the
``-e`` option, separated by spaces::

    $ tox -e py27,pep8

See ``tox.ini`` for the full list of available test environments.

Test Structure
--------------

Not all of the tests in the tests directory are strictly unit tests. Keystone
intentionally includes tests that run the service locally and drives the entire
configuration to achieve basic functional testing.

For the functional tests, an in-memory key-value store is used to keep the
tests fast.

Within the tests directory, the general structure of the tests is a basic
set of tests represented under a test class, and then subclasses of those
tests under other classes with different configurations to drive different
backends through the APIs.

For example, ``test_backend.py`` has a sequence of tests under the class
``IdentityTests`` that will work with the default drivers as configured in
this projects etc/ directory. ``test_backend_sql.py`` subclasses those tests,
changing the configuration by overriding with configuration files stored in
the tests directory aimed at enabling the SQL backend for the Identity module.

Likewise, ``test_keystoneclient.py`` takes advantage of the tests written
against ``KeystoneClientTests`` to verify the same tests function through
different drivers and releases of the Keystone client.

The class ``CompatTestCase`` does the work of checking out a specific version
of python-keystoneclient, and then verifying it against a temporarily running
local instance to explicitly verify basic functional testing across the API.

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

To add tests covering all drivers, update the relevant base test class
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


LDAP
----
LDAP has a fake backend that performs rudimentary operations.  If you
are building more significant LDAP functionality, you should test against
a live LDAP server.  Devstack has an option to set up a directory server for
Keystone to use.  Add ldap to the ``ENABLED_SERVICES`` environment variable,
and set environment variables ``KEYSTONE_IDENTITY_BACKEND=ldap`` and
``KEYSTONE_CLEAR_LDAP=yes`` in your ``localrc`` file.

The unit tests can be run against a live server with
``keystone/tests/_ldap_livetest.py``.  The default password is ``test`` but if you have
installed devstack with a different LDAP password, modify the file
``keystone/tests/backend_liveldap.conf`` to reflect your password.


Translated responses
--------------------

The Keystone server can provide error responses translated into the language in
the ``Accept-Language`` header of the request. In order to test this in your
development environment, there's a couple of things you need to do.

1. Build the message files. Run the following command in your keystone
   directory::

 $ python setup.py compile_catalog

This will generate .mo files like keystone/locale/[lang]/LC_MESSAGES/[lang].mo

2. When running Keystone, set the ``KEYSTONE_LOCALEDIR`` environment variable
   to the keystone/locale directory. For example::

  $ KEYSTONE_LOCALEDIR=/opt/stack/keystone/keystone/locale keystone-all

Now you can get a translated error response::

 $ curl -s -H "Accept-Language: zh" http://localhost:5000/notapath | python -mjson.tool
 {
     "error": {
         "code": 404,
         "message": "\u627e\u4e0d\u5230\u8cc7\u6e90\u3002",
         "title": "Not Found"
     }
 }


Caching Layer
-------------

The caching layer is designed to be applied to any ``manager`` object within Keystone
via the use of the ``on_arguments`` decorator provided in the ``keystone.common.cache``
module.  This decorator leverages `dogpile.cache`_ caching system to provide a flexible
caching backend.

It is recommended that each of the managers have an independent toggle within the config
file to enable caching.  The easiest method to utilize the toggle within the
configuration file is to define a ``caching`` boolean option within that manager's
configuration section (e.g. ``identity``).  Once that option is defined you can
pass function to the ``on_arguments`` decorator with the named argument ``should_cache_fn``.
In the ``keystone.common.cache`` module, there is a function called ``should_cache_fn``,
which will provide a reference, to a function, that will consult the global cache
``enabled`` option as well as the specific manager's caching enable toggle.

    .. NOTE::
        If a section-specific boolean option is not defined in the config section specified when
        calling ``should_cache_fn``, the returned function reference will default to enabling
        caching for that ``manager``.

Example use of cache and ``should_cache_fn`` (in this example, ``token`` is the manager)::

    from keystone.common import cache
    SHOULD_CACHE = cache.should_cache_fn('token')

    @cache.on_arguments(should_cache_fn=SHOULD_CACHE)
    def cacheable_function(arg1, arg2, arg3):
        ...
        return some_value

With the above example, each call to the ``cacheable_function`` would check to see if
the arguments passed to it matched a currently valid cached item.  If the return value
was cached, the caching layer would return the cached value; if the return value was
not cached, the caching layer would call the function, pass the value to the ``SHOULD_CACHE``
function reference, which would then determine if caching was globally enabled and enabled
for the ``token`` manager.  If either caching toggle is disabled, the value is returned but
not cached.

It is recommended that each of the managers have an independent configurable time-to-live (TTL).
If a configurable TTL has been defined for the manager configuration section, it is possible to
pass it to the ``cache.on_arguments`` decorator with the named-argument ``expiration_time``.  For
consistency, it is recommended that this option be called ``cache_time`` and default to ``None``.
If the ``expiration_time`` argument passed to the decorator is set to ``None``, the expiration
time will be set to the global default (``expiration_time`` option in the ``[cache]``
configuration section.

Example of using a section specific ``cache_time`` (in this example, ``identity`` is the manager)::

    from keystone.common import cache
    SHOULD_CACHE = cache.should_cache_fn('identity')

    @cache.on_arguments(should_cache_fn=SHOULD_CACHE,
                        expiration_time=CONF.identity.cache_time)
    def cachable_function(arg1, arg2, arg3):
        ...
        return some_value

For cache invalidation, the ``on_arguments`` decorator will add an ``invalidate`` method
(attribute) to your decorated function.  To invalidate the cache, you pass the same arguments
to the ``invalidate`` method as you would the normal function.

Example (using the above cacheable_function)::

    def invalidate_cache(arg1, arg2, arg3):
        cacheable_function.invalidate(arg1, arg2, arg3)

.. WARNING::
    The ``on_arguments`` decorator does not accept keyword-arguments/named arguments.  An
    exception will be raised if keyword arguments are passed to a caching-decorated function.

.. NOTE::
    In all cases methods work the same as functions except if you are attempting to invalidate
    the cache on a decorated bound-method, you need to pass  ``self`` to the ``invalidate``
    method as the first argument before the arguments.

.. _`dogpile.cache`: http://dogpilecache.readthedocs.org/


Building the Documentation
==========================

The documentation is all generated with Sphinx from within the docs directory.
To generate the full set of HTML documentation::

    cd docs
    make autodoc
    make html
    make man

the results are in the docs/build/html and docs/build/man directories
respectively.
