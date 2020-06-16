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
via the use of ``keystone.common.cache`` module. This leverages `oslo.cache`_ caching
system to provide a flexible caching backend.

.. _oslo.cache: https://opendev.org/openstack/oslo.cache

The caching can be setup for all or some subsystems. It is recommended that each of the
managers have an independent toggle within the config file to enable caching. The easiest
method to utilize the toggle within the configuration file is to define a ``caching``
boolean option within that manager's configuration section (e.g. ``identity``). Enable the
global cache ``enabled`` option as well as the specific manager's caching enable toggle in
order to cache that subsystem.

The `oslo.cache`_ is simple and easy to adopt by any system. See the `usage guide`_ of
it. There are various cache :ref:`backends <caching_layer>` supported by it. Example use of
`oslo.cache`_ in keystone (in this example, ``token`` is the manager):

.. code-block:: python

    from keystone.common import cache

    TOKENS_REGION = cache.create_region(name='tokens')
    MEMOIZE_TOKENS = cache.get_memoization_decorator(
        group='token',
        region=TOKENS_REGION)

    @MEMOIZE_TOKENS
    def _validate_token(self, token_id):
        ...
        return token

.. _usage guide: https://docs.openstack.org/oslo.cache/latest/user/usage.html

With the above example, each call to the ``cacheable_function`` would check to see if
the arguments passed to it matched a currently valid cached item.  If the return value
was cached, the caching layer would return the cached value; if the return value was
not cached, the caching layer would call the function, pass the value to the
``MEMOIZE_TOKEN`` decorator, which would then determine if caching was globally enabled
and enabled for the ``token`` manager.  If either caching toggle is disabled, the value
is returned but not cached.

It is recommended that each of the managers have an independent configurable time-to-live
(TTL). The option ``cache_time`` is to be set for every manager under its section in
keystone.conf file. If the ``cache_time`` is set to ``None``, the expiration time will be
set to the global default ``expiration_time`` option in the ``[cache]`` configuration section.
These options are passed to and handled by oslo.cache.

:ref:`Cache invalidation <cache_invalidation>` can be done if specific cache entries are changed.
Example of invalidating a cache (in this example, ``token`` is the manager):

.. code-block:: python

    def invalidate_individual_token_cache(self, token_id):
        ...
        self._validate_token.invalidate(self, token_id)

For cache invalidation, there is an ``invalidate`` method (attribute) on the decorated function.
To invalidate the cache, pass the same arguments to the ``invalidate`` method as you would the
normal function. This means you need to pass ``self`` as the first argument.

