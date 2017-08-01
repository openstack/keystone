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

=============
Caching Layer
=============

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

.. code-block:: python

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

.. code-block:: python

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

.. code-block:: python

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


dogpile.cache based MongoDB (NoSQL) backend
-------------------------------------------

The ``dogpile.cache`` based MongoDB backend implementation allows for various MongoDB
configurations, e.g., standalone, a replica set, sharded replicas, with or without SSL,
use of TTL type collections, etc.

Example of typical configuration for MongoDB backend:

.. code-block:: python

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

Similar to other backends, this backend can be added via Keystone configuration in
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
