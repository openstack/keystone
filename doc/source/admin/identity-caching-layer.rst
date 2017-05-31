.. :orphan:

Caching layer
~~~~~~~~~~~~~

OpenStack Identity supports a caching layer that is above the
configurable subsystems (for example, token). OpenStack Identity uses the
`oslo.cache <https://docs.openstack.org/developer/oslo.cache/>`__
library which allows flexible cache back ends. The majority of the
caching configuration options are set in the ``[cache]`` section of the
``/etc/keystone/keystone.conf`` file. However, each section that has
the capability to be cached usually has a caching boolean value that
toggles caching.

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

   Since the Newton release, the default setting is enabled for subsystem
   caching and the global toggle. As a result, all subsystems that support
   caching are doing this by default.

Caching for tokens and tokens validation
----------------------------------------

All types of tokens benefit from caching, including Fernet tokens. Although
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

Here is a list of actions that are affected by the cached time: getting
a new token, revoking tokens, validating tokens, checking v2 tokens, and
checking v3 tokens.

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

- `dogpile.cache.memory <https://dogpilecache.readthedocs.io/en/latest/api.html#memory-backend>`__

- `dogpile.cache.memcached <https://dogpilecache.readthedocs.io/en/latest/api.html#memcached-backends>`__

  .. note::

     The memory back end is not suitable for use in a production
     environment.

- `dogpile.cache.redis <https://dogpilecache.readthedocs.io/en/latest/api.html#redis-backends>`__

- `dogpile.cache.dbm <https://dogpilecache.readthedocs.io/en/latest/api.html#file-backends>`__

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
