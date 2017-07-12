=============
Caching layer
=============

Identity supports a caching layer that is above the configurable subsystems,
such as token or assignment. The majority of the caching configuration options
are set in the ``[cache]`` section. However, each section that has the
capability to be cached usually has a ``caching`` option that will toggle
caching for that specific section. By default, caching is globally disabled.

Current functional back ends are:

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

``dogpile.cache.mongo``
    MongoDB as caching back end.
