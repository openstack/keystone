.. -*- rst -*-

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

.. _password_hashing:

Password hashing
================

Keystone stores local user passwords as hashes in the SQL identity backend.
The algorithm is selected with ``[identity] password_hash_algorithm``. Supported
values are ``bcrypt`` (the default), ``bcrypt_sha256``, ``scrypt``, and
``pbkdf2_sha512``. Work-factor options such as
``[identity] password_hash_rounds``, ``[identity] scrypt_block_size``, and
``[identity] scrypt_parallelism`` apply to newly created hashes.

Transparent rehash on authentication
------------------------------------

When a user authenticates successfully against the SQL identity backend,
Keystone upgrades the stored hash in place if either of the following is true:

* The stored hash uses a different algorithm than
  ``[identity] password_hash_algorithm``.
* The stored hash uses a weaker work factor than the currently configured
  value for that algorithm (for example fewer bcrypt rounds, a lower scrypt
  ``n``/``r``/``p``, or fewer PBKDF2 iterations).

The rehash updates only the hash string. Password metadata (``created_at``,
``expires_at``, and password history) is left unchanged. The write is skipped
if another session changed the stored hash after the authentication read, so
an administrative password reset cannot be overwritten.

This applies to every supported hasher, not only PBKDF2-SHA512. Operators can
raise ``password_hash_rounds`` or switch ``password_hash_algorithm`` without
forcing users to reset their passwords. Existing hashes are upgraded on the
next successful login. Lowering the work factor does not downgrade hashes that
already use a stronger value.

LDAP and other non-SQL identity backends are not affected; they keep their own
password storage.

Example
-------

Raise the bcrypt cost and let existing users pick up the new value on login:

.. code-block:: ini

   [identity]
   password_hash_algorithm = bcrypt
   password_hash_rounds = 12
