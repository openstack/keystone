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

=======================
Performance and scaling
=======================

Before you begin tuning Keystone for performance and scalability, you should
first know that Keystone is just a two tier horizontally-scalable web
application, and the most effective methods for scaling it are going to be the
same as for any other similarly designed web application: give it more
processes, more memory, scale horizontally, and load balance the result.

With that said, there are many opportunities for tuning the performance of
Keystone, many of which are actually trade-offs between performance and
security that you need to judge for yourself, and tune accordingly.

Pruning expired tokens from backend storage
===========================================

Using a persistent token format will result in an ever-growing backend store.
Keystone will not remove, or prune, tokens from the backend even after they are
expired. This can be managed manually using ``keystone-manage token_flush``,
which will purge expired tokens from the data store in batches. Diligently
pruning expired tokens will prevent token bloat.

.. note::

    This optimization is not necessary for deployments leveraging Fernet
    tokens, which are non-persistent in nature.

Keystone configuration options that affect performance
======================================================

These are all of the options in ``keystone.conf`` that have a direct impact on
performance. See the help descriptions for these options for more specific
details on how and why you might want to tune these options for yourself.

* ``[DEFAULT] crypt_strength``: Reduce this number to increase performance,
  increase this number to make SQL managed password checking more secure.

* ``[DEFAULT] max_project_tree_depth``: Reduce this number to increase
  performance, increase this number to cater to more complicated hierarchical
  multitenancy use cases.

* ``[DEFAULT] max_password_length``: Reduce this number to increase
  performance, increase this number to allow for more secure passwords.

* ``[cache] enable``: Enable this option to increase performance, but you also
  need to configure other options in the ``[cache]`` section to actually
  utilize caching.

* ``[token] provider``: All supported token providers have been primarily
  driven by performance considerations. UUID and Fernet both require online
  validation (cacheable HTTP calls back to keystone to validate tokens).
  Fernet has the highest scalability characteristics overall, but requires more
  work to validate, and therefore enabling caching (``[cache] enable``) is
  absolutely critical.

* ``[fernet] max_active_keys``: If you're using Fernet tokens, decrease this
  option to improve performance, increase this option to support more advanced
  key rotation strategies.

Keystonemiddleware configuration options that affect performance
================================================================

This configuration actually lives in the Paste pipelines of services consuming
token validation from keystone (i.e.: nova, cinder, swift, etc.).

* ``cache``: When keystone's `auth_token` middleware is deployed with a
  swift cache, use this option to have `auth_token` middleware share a caching
  backend with swift. Otherwise, use the ``memcached_servers`` option instead.

* ``memcached_servers``: Set this option to share a cache across
  ``keystonemiddleware.auth_token`` processes.

* ``token_cache_time``: Increase this option to improve performance, decrease
  this option to respond to token revocation events more quickly (thereby
  increasing security).

* ``revocation_cache_time``: Increase this option to improve performance,
  decrease this option to respond to token revocation events more quickly
  (thereby increasing security).

* ``memcache_security_strategy``: Do not set this option to improve
  performance, but set it to improve security where you're sharing memcached
  with other processes.

* ``include_service_catalog``: Disable this option to improve performance, if
  the protected service does not require a service catalog.
