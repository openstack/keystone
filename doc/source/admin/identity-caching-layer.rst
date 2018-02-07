.. :orphan:

Caching layer
~~~~~~~~~~~~~

OpenStack Identity supports a caching layer that is above the configurable
subsystems (for example, token). This gives you the flexibility to setup
caching for all or some subsystems. OpenStack Identity uses the `oslo.cache
<https://docs.openstack.org/oslo.cache/latest/>`__ library which allows
flexible cache back ends. The majority of the caching configuration options are
set in the ``[cache]`` section of the ``/etc/keystone/keystone.conf`` file. The
``enabled`` option of the ``[cache]`` section must be set to ``True`` in order
for any subsystem to cache responses. Each section that has the capability to
be cached will have a ``caching`` boolean value that toggles caching behavior
of that particular subsystem.

So to enable only the token back end caching, set the values as follows:

.. code-block:: ini

   [cache]
   enabled=true

   [catalog]
   caching=false

   [domain_config]
   caching=false

   [federation]
   caching=false

   [resource]
   caching=false

   [revoke]
   caching=false

   [role]
   caching=false

   [token]
   caching=true

.. note::

   Each subsystem is configured to cache by default. However, the global
   toggle for caching defaults to ``False``. A subsystem is only able to cache
   responses if the global toggle is enabled.

Current functional back ends are:

``dogpile.cache.null``
   A "null" backend that effectively disables all cache operations.(Default)

``dogpile.cache.memcached``
   Memcached back end using the standard ``python-memcached`` library.

``dogpile.cache.pylibmc``
   Memcached back end using the ``pylibmc`` library.

``dogpile.cache.bmemcached``
   Memcached using the ``python-binary-memcached`` library.

``dogpile.cache.redis``
   Redis back end.

``dogpile.cache.dbm``
   Local DBM file back end.

``dogpile.cache.memory``
   In-memory cache, not suitable for use outside of testing as it does not
   cleanup its internal cache on cache expiration and does not share cache
   between processes. This means that caching and cache invalidation will not
   be consistent or reliable.

``dogpile.cache.memory_pickle``
   In-memory cache, but serializes objects with pickle lib. It's not suitable
   for use outside of testing. The reason is the same with
   ``dogpile.cache.memory``

``oslo_cache.mongo``
   MongoDB as caching back end.

``oslo_cache.memcache_pool``
   Memcached backend that does connection pooling.

``oslo_cache.etcd3gw``
   Uses etcd 3.x for storage.

``oslo_cache.dict``
   A DictCacheBackend based on dictionary, not suitable for use outside of
   testing as it does not share cache between processes.This means that caching
   and cache invalidation will not be consistent or reliable.

Caching for tokens and tokens validation
----------------------------------------

The token subsystem is OpenStack Identity's most heavily used API. As a result,
all types of tokens benefit from caching, including Fernet tokens. Although
Fernet tokens do not need to be persisted, they should still be cached for
optimal token validation performance.

The token system has a separate ``cache_time`` configuration option,
that can be set to a value above or below the global ``expiration_time``
default, allowing for different caching behavior from the other systems
in OpenStack Identity. This option is set in the ``[token]`` section of
the configuration file.

The token revocation list cache time is handled by the configuration
option ``revocation_cache_time`` in the ``[token]`` section. The
revocation list is refreshed whenever a token is revoked. It typically
sees significantly more requests than specific token retrievals or token
validation calls.

Here is a list of actions that are affected by the cached time:

* getting a new token
* revoking tokens
* validating tokens
* checking v3 tokens

The delete token API calls invalidate the cache for the tokens being
acted upon, as well as invalidating the cache for the revoked token list
and the validate/check token calls.

Token caching is configurable independently of the ``revocation_list``
caching. Lifted expiration checks from the token drivers to the token
manager. This ensures that cached tokens will still raise a
``TokenNotFound`` flag when expired.

For cache consistency, all token IDs are transformed into the short
token hash at the provider and token driver level. Some methods have
access to the full ID (PKI Tokens), and some methods do not. Cache
invalidation is inconsistent without token ID normalization.

Caching for non-token resources
-------------------------------

Various other keystone components have a separate ``cache_time`` configuration
option, that can be set to a value above or below the global
``expiration_time`` default, allowing for different caching behavior
from the other systems in Identity service. This option can be set in various
sections (for example, ``[role]`` and ``[resource]``) of the configuration
file.
The create, update, and delete actions for domains, projects and roles
will perform proper invalidations of the cached methods listed above.

For more information about the different back ends (and configuration
options), see:

- `dogpile.cache.memory <https://dogpilecache.readthedocs.io/en/latest/api.html#memory-backends>`__

- `dogpile.cache.memcached <https://dogpilecache.readthedocs.io/en/latest/api.html#memcached-backends>`__

  .. note::

     The memory back end is not suitable for use in a production
     environment.

- `dogpile.cache.redis <https://dogpilecache.readthedocs.io/en/latest/api.html#redis-backends>`__

- `dogpile.cache.dbm <https://dogpilecache.readthedocs.io/en/latest/api.html#file-backends>`__

Cache invalidation
------------------

A common concern with caching is relaying inaccurate information after updating
or deleting a resource. Most subsystems within OpenStack Identity invalidate
specific cache entries once they have changed. In cases where a specific cache
entry cannot be invalidated from the cache, the cache region will be
invalidated instead. This invalidates all entries within the cache to prevent
returning stale or misleading data. A subsequent request for the resource will
be fully processed and cached.

.. WARNING::
    Be aware that if a read-only back end is in use for a particular subsystem,
    the cache will not immediately reflect changes performed through the back
    end. Any given change may take up to the ``cache_time`` (if set in the
    subsystem section of the configuration) or the global ``expiration_time``
    (set in the ``[cache]`` section of the configuration) before it is
    reflected. If this type of delay is an issue, we recommend disabling
    caching for that particular subsystem.

Configure the Memcached back end example
----------------------------------------

The following example shows how to configure the memcached back end:

.. code-block:: ini

   [cache]

   enabled = true
   backend = dogpile.cache.memcached
   backend_argument = url:127.0.0.1:11211

You need to specify the URL to reach the ``memcached`` instance with the
``backend_argument`` parameter.
