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
migration for a specific extension, simply run::

    $ keystone-manage db_sync --extension <name>

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

Filtering responsibilities between controllers and drivers
----------------------------------------------------------

Keystone supports the specification of filtering on list queries as part of the
v3 identity API. By default these queries are satisfied in the controller
class when a controller calls the ``wrap_collection`` method at the end of a
``list_{entity}`` method.  However, to enable optimum performance, any driver
can implement some or all of the specified filters (for example, by adding
filtering to the generated SQL statements to generate the list).

The communication of the filter details between the controller level and its
drivers is handled by the passing of a reference to a Hints object,
which is a list of dicts describing the filters. A driver that satisfies a
filter must delete the filter from the Hints object so that when it is returned
back to the controller level, it knows to only execute any unsatisfied
filters.

The contract for a driver for ``list_{entity}`` methods is therefore:

* It MUST return a list of entities of the specified type
* It MAY either just return all such entities, or alternatively reduce the
  list by filtering for one or more of the specified filters in the passed
  Hints reference, and removing any such satisfied filters.

Entity list truncation by drivers
---------------------------------

Keystone supports the ability for a deployment to restrict the number of
entries returned from ``list_{entity}`` methods, typically to prevent poorly
formed searches (e.g. without sufficient filters) from becoming a performance
issue.

These limits are set in the configuration file, either for a specific driver or
across all drivers.  These limits are read at the Manager level and passed into
individual drivers as part of the Hints list object. A driver should try and
honor any such limit if possible, but if it is unable to do so then it may
ignore it (and the truncation of the returned list of entities will happen at
the controller level).

Testing
-------

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

Running with PDB
~~~~~~~~~~~~~~~~

Using PDB breakpoints with tox and testr normally doesn't work since the tests
just fail with a BdbQuit exception rather than stopping at the breakpoint.

To run with PDB breakpoints during testing, use the ``debug`` tox environment
rather than ``py27``. Here's an example, passing the name of a test since
you'll normally only want to run the test that hits your breakpoint::

    $ tox -e debug keystone.tests.test_auth.AuthWithToken.test_belongs_to

For reference, the ``debug`` tox environment implements the instructions
here: https://wiki.openstack.org/wiki/Testr#Debugging_.28pdb.29_Tests

Test Structure
==============

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
=========================

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
=============

To add tests covering all drivers, update the relevant base test class
(``test_backend.py``, ``test_legacy_compat.py``, and
``test_keystoneclient.py``).

To add new drivers, subclass the ``test_backend.py`` (look towards
``test_backend_sql.py`` or ``test_backend_kvs.py`` for examples) and update the
configuration of the test class in ``setUp()``.


Further Testing
===============

devstack_ is the *best* way to quickly deploy keystone with the rest of the
OpenStack universe and should be critical step in your development workflow!

You may also be interested in either the
`OpenStack Continuous Integration Infrastructure`_ or the
`OpenStack Integration Testing Project`_.

.. _devstack: http://devstack.org/
.. _OpenStack Continuous Integration Infrastructure: http://ci.openstack.org
.. _OpenStack Integration Testing Project: https://github.com/openstack/tempest


LDAP Tests
==========

LDAP has a fake backend that performs rudimentary operations.  If you
are building more significant LDAP functionality, you should test against
a live LDAP server.  Devstack has an option to set up a directory server for
Keystone to use.  Add ldap to the ``ENABLED_SERVICES`` environment variable,
and set environment variables ``KEYSTONE_IDENTITY_BACKEND=ldap`` and
``KEYSTONE_CLEAR_LDAP=yes`` in your ``localrc`` file.

The unit tests can be run against a live server with
``keystone/tests/test_ldap_livetest.py``.  The default password is ``test`` but if you have
installed devstack with a different LDAP password, modify the file
``keystone/tests/backend_liveldap.conf`` to reflect your password.

.. NOTE::
    To run the live tests you need to set the environment variable ``ENABLE_LDAP_LIVE_TEST``
    to a non-negative value.


Generating Updated Sample Config File
-------------------------------------

Keystone's sample configuration file ``etc/keystone.conf.sample`` is automatically
generated based upon all of the options available within Keystone. These options
are sourced from the many files around Keystone as well as some external libraries.

If new options are added, primarily located in ``keystone.common.config``, a new
sample configuration file needs to be generated. Generating a new sample configuration
to be included in a commit run::

    $ tox -esample_config -r

The tox command will place an updated sample config in ``etc/keystone.conf.sample``.

If there is a new external library (e.g. ``oslo.messaging``) that utilizes the
``oslo.config`` package for configuration, it can be added to the list of libraries
found in ``tools/config/oslo.config.generator.rc``.


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

Example use of cache and ``should_cache_fn`` (in this example, ``token`` is the manager):

.. code:: python

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

Example of using a section specific ``cache_time`` (in this example, ``identity`` is the manager):

.. code:: python

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

Example (using the above cacheable_function):

.. code:: python

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


dogpile.cache based Key-Value-Store (KVS)
-----------------------------------------
The ``dogpile.cache`` based KVS system has been designed to allow for flexible stores for the
backend of the KVS system. The implementation allows for the use of any normal ``dogpile.cache``
cache backends to be used as a store. All interfacing to the KVS system happens via the
``KeyValueStore`` object located at ``keystone.common.kvs.KeyValueStore``.

To utilize the KVS system an instantiation of the ``KeyValueStore`` class is needed. To accquire
a KeyValueStore instantiation use the ``keystone.common.kvs.get_key_value_store`` factory
function. This factory will either create a new ``KeyValueStore`` object or retrieve the
already instantiated ``KeyValueStore`` object by the name passed as an argument. The object must
be configured before use. The KVS object will only be retrievable with the
``get_key_value_store`` function while there is an active reference outside of the registry.
Once all references have been removed the object is gone (the registry uses a ``weakref`` to
match the object to the name).

Example Instantiation and Configuration:

.. code:: python

    kvs_store = kvs.get_key_value_store('TestKVSRegion')
    kvs_store.configure('openstack.kvs.Memory', ...)

Any keyword arguments passed to the configure method that are not defined as part of the
KeyValueStore object configuration are passed to the backend for further configuration (e.g.
memcached servers, lock_timeout, etc).

The memcached backend uses the Keystone manager mechanism to support the use of any of the
provided memcached backends (``bmemcached``, ``pylibmc``, and basic ``memcached``).
By default the ``memcached`` backend is used.  Currently the Memcache URLs come from the
``servers`` option in the ``[memcache]`` configuration section of the Keystone config.

The following is an example showing how to configure the KVS system to use a
KeyValueStore object named "TestKVSRegion" and a specific Memcached driver:

.. code:: python

    kvs_store = kvs.get_key_value_store('TestKVSRegion')
    kvs_store.configure('openstack.kvs.Memcached', memcached_backend='Memcached')

The memcached backend supports a mechanism to supply an explicit TTL (in seconds) to all keys
set via the KVS object. This is accomplished by passing the argument ``memcached_expire_time``
as a keyword argument to the ``configure`` method. Passing the ``memcache_expire_time`` argument
will cause the ``time`` argument to be added to all ``set`` and ``set_multi`` calls performed by
the memcached client. ``memcached_expire_time`` is an argument exclusive to the memcached dogpile
backend, and will be ignored if passed to another backend:

.. code:: python

    kvs_store.configure('openstack.kvs.Memcached', memcached_backend='Memcached',
                        memcached_expire_time=86400)

If an explicit TTL is configured via the ``memcached_expire_time`` argument, it is possible to
exempt specific keys from receiving the TTL by passing the argument ``no_expiry_keys`` (list)
as a keyword argument to the ``configure`` method. ``no_expiry_keys`` should be supported by
all OpenStack-specific dogpile backends (memcached) that have the ability to set an explicit TTL:

.. code:: python

    kvs_store.configure('openstack.kvs.Memcached', memcached_backend='Memcached',
                    memcached_expire_time=86400, no_expiry_keys=['key', 'second_key', ...])


.. NOTE::
    For the non-expiring keys functionality to work, the backend must support the ability for
    the region to set the key_mangler on it and have the attribute ``raw_no_expiry_keys``.
    In most cases, support for setting the key_mangler on the backend is handled by allowing
    the region object to set the ``key_mangler`` attribute on the backend.

    The ``raw_no_expiry_keys`` attribute is expected to be used to hold the values of the
    keyword argument ``no_expiry_keys`` prior to hashing. It is the responsibility of the
    backend to use these raw values to determine if a key should be exempt from expiring
    and not set the TTL on the non-expiring keys when the ``set`` or ``set_multi`` methods are
    called.

    Typically the key will be hashed by the region using its key_mangler method
    before being passed to the backend to set the value in the KeyValueStore. This
    means that in most cases, the backend will need to either pre-compute the hashed versions
    of the keys (when the key_mangler is set) and store a cached copy, or hash each item in
    the ``raw_no_expiry_keys`` attribute on each call to ``.set()`` and ``.set_multi()``. The
    ``memcached`` backend handles this hashing and caching of the keys by utilizing an
    ``@property`` method for the ``.key_mangler`` attribute on the backend and utilizing the
    associated ``.settr()`` method to front-load the hashing work at attribute set time.

Once a KVS object has been instantiated the method of interacting is the same as most memcache
implementations:

.. code:: python

    kvs_store = kvs.get_key_value_store('TestKVSRegion')
    kvs_store.configure(...)
    # Set a Value
    kvs_store.set(<Key>, <Value>)
    # Retrieve a value:
    retrieved_value = kvs_store.get(<key>)
    # Delete a key/value pair:
    kvs_store.delete(<key>)
    # multi-get:
    kvs_store.get_multi([<key>, <key>, ...])
    # multi-set:
    kvs_store.set_multi(dict(<key>=<value>, <key>=<value>, ...))
    # multi-delete
    kvs_store.delete_multi([<key>, <key>, ...])


There is a global configuration option to be aware of (that can be set in the ``[kvs]`` section of
the Keystone configuration file): ``enable_key_mangler`` can be set top false, disabling the use of
key_manglers (modification of the key when saving to the backend to help prevent
collisions or exceeding key size limits with memcached).

.. NOTE::
    The ``enable_key_mangler`` option in the ``[kvs]`` section of the Keystone configuration file
    is not the same option (and does not affect the cache-layer key manglers) from the option in the
    ``[cache]`` section of the configuration file. Similarly the ``[cache]`` section options
    relating to key manglers has no bearing on the ``[kvs]`` objects.

.. WARNING::
    Setting the ``enable_key_mangler`` option to False can have detrimental effects on the
    KeyValueStore backend. It is recommended that this value is not set to False except for
    debugging issues with the ``dogpile.cache`` backend itself.

Any backends that are to be used with the ``KeyValueStore`` system need to be registered with
dogpile. For in-tree/provided backends, the registration should occur in
``keystone/common/kvs/__init__.py``. For backends that are developed out of tree, the location
should be added to the ``backends`` option in the ``[kvs]`` section of the Keystone configuration::

    [kvs]
    backends = backend_module1.backend_class1,backend_module2.backend_class2

All registered backends will receive the "short name" of "openstack.kvs.<class name>" for use in the
``configure`` method on the ``KeyValueStore`` object.  The ``<class name>`` of a backend must be
globally unique.

dogpile.cache based MongoDB (NoSQL) backend
--------------------------------------------

The ``dogpile.cache`` based MongoDB backend implementation allows for various MongoDB
configurations, e.g., standalone, a replica set, sharded replicas, with or without SSL,
use of TTL type collections, etc.

Example of typical configuration for MongoDB backend:

.. code:: python

    from dogpile.cache import region

    arguments = {
        'db_hosts': 'localhost:27017',
        'db_name': 'ks_cache',
        'cache_collection': 'cache',
        'username': 'test_user',
        'password': 'test_password',

        # optional arguments
        'son_manipulator': 'my_son_manipulator_impl'
    }

    region.make_region().configure('keystone.cache.mongo',
                                   arguments=arguments)

The optional `son_manipulator` is used to manipulate custom data type while its saved in
or retrieved from MongoDB. If the dogpile cached values contain built-in data types and no
custom classes, then the provided implementation class is sufficient. For further details, refer
http://api.mongodb.org/python/current/examples/custom_type.html#automatic-encoding-and-decoding

Similar to other backends, this backend can be added via keystone configuration in
``keystone.conf``::

    [cache]
    # Global cache functionality toggle.
    enabled = True

    # Referring to specific cache backend
    backend = keystone.cache.mongo

    # Backend specific configuration arguments
    backend_argument = db_hosts:localhost:27017
    backend_argument = db_name:ks_cache
    backend_argument = cache_collection:cache
    backend_argument = username:test_user
    backend_argument = password:test_password

This backend is registered in ``keystone.common.cache.core`` module. So, its usage
is similar to other dogpile caching backends as it implements the same dogpile APIs.


Building the Documentation
--------------------------

The documentation is generated with Sphinx uning the tox command.  To create HTML docs and man pages::

    $ tox -e docs

The results are in the docs/build/html and docs/build/man directories respectively.
