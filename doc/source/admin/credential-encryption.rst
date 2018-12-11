=====================
Credential Encryption
=====================

As of the Newton release, keystone encrypts all credentials stored in the
default ``sql`` backend. Credentials are encrypted with the same mechanism used
to encrypt Fernet tokens, ``fernet``. Keystone provides only one type of
credential encryption but the encryption provider is pluggable in the event
you wish to supply a custom implementation.

This document details how credential encryption works, how to migrate existing
credentials in a deployment, and how to manage encryption keys for credentials.

Configuring credential encryption
---------------------------------

The configuration for credential encryption is straightforward. There are only
two configuration options needed:

.. code-block:: ini

    [credential]
    provider = fernet
    key_repository = /etc/keystone/credential-keys/

``[credential] provider`` defaults to the only option supplied by keystone,
``fernet``. There is no reason to change this option unless you wish to provide
a custom credential encryption implementation. The ``[credential]
key_repository`` location is a requirement of using ``fernet`` but will default
to the ``/etc/keystone/credential-keys/`` directory. Both ``[credential]
key_repository`` and ``[fernet_tokens] key_repository`` define locations for
keys used to encrypt things. One holds the keys to encrypt and decrypt
credentials and the other holds keys to encrypt and decrypt tokens. It is
imperative that these repositories are managed separately and they must not
share keys. Meaning they cannot share the same directory path. The
``[credential] key_repository`` is only allowed to have three keys. This is not
configurable and allows for credentials to be re-encrypted periodically with a
new encryption key for the sake of security.

How credential encryption works
-------------------------------

The implementation of this feature did not change any existing credential API
contracts. All changes are transparent to the user unless you're inspecting the
credential backend directly.

When creating a credential, keystone will encrypt the ``blob`` attribute before
persisting it to the backend. Keystone will also store a hash of the key that
was used to encrypt the information in that credential. Since Fernet is used to
encrypt credentials, a key repository consists of multiple keys. Keeping track
of which key was used to encrypt each credential is an important part of
encryption key management. Why this is important is detailed later in the
`Encryption key management` section.

When updating an existing credential's ``blob`` attribute, keystone will encrypt
the new ``blob`` and update the key hash.

When listing or showing credentials, all ``blob`` attributes are decrypted in
the response. Neither the cipher text, nor the hash of the key used to encrypt
the ``blob`` are exposed through the API. Furthermore, the key is only used
internally to keystone.

Encrypting existing credentials
-------------------------------

When upgrading a Mitaka deployment to Newton, three database migrations will
ensure all credentials are encrypted. The process is as follows:

1. An additive schema change is made to create the new ``encrypted_blob`` and
   ``key_hash`` columns in the existing ``credential`` table using
   ``keystone-manage db_sync --expand``.
2. A data migration will loop through all existing credentials, encrypt each
   ``blob`` and store the result in the new ``encrypted_blob`` column. The hash
   of the key used is also written to the ``key_hash`` column for that specific
   credential. This step is done using ``keystone-manage db_sync --migrate``.
3. A contractive schema will remove the ``blob`` column that held the plain
   text representations of the credential using ``keystone-manage db_sync
   --contract``. This should only be done after all nodes in the deployment are
   running Newton. If any Mitaka nodes are running after the database is
   contracted, they won't be able to read credentials since they are looking
   for the ``blob`` column that no longer exists.

.. NOTE::

    You may also use ``keystone-manage db_sync --check`` in order to check the
    current status of your rolling upgrades.

If performing a rolling upgrade, please note that a limited service outage will
take affect during this migration. When the migration is in place, credentials
will become read-only until the database is contracted. After the contract
phase is complete, credentials will be writeable to the backend. A
``[credential] key_repository`` location must be specified through
configuration and bootstrapped with keys using ``keystone-manage
credential_setup`` prior to migrating any existing credentials. If a new key
repository isn't setup using ``keystone-manage credential_setup`` keystone will
assume a null key to encrypt and decrypt credentials until a proper key
repository is present. The null key is a key consisting of all null bytes and
its only purpose is to ease the upgrade process from Mitaka to Newton. It is
highly recommended that the null key isn't used. It is no more secure than
storing credentials in plain text. If the null key is used, you should migrate
to a proper key repository using ``keystone-manage credential_setup`` and
``keystone-manage credential_migrate``.

Encryption key management
-------------------------

Key management of ``[credential] key_repository`` is handled with three
``keystone-manage`` commands:

1. ``keystone-manage credential_setup``
2. ``keystone-manage credential_rotate``
3. ``keystone-manage credential_migrate``

``keystone-manage credential_setup`` will populate ``[credential]
key_repository`` with new encryption keys. This must be done in order for
proper credential encryption to work, with the exception of the null key. This
step should only be done once.

``keystone-manage credential_rotate`` will create and rotate a new encryption
key in the ``[credential] key_repository``. This will only be done if all
credential key hashes match the hash of the current primary key. If any
credential has been encrypted with an older key, or secondary key, the rotation
will fail. Failing the rotation is necessary to prevent overrotation, which
would leave some credentials indecipherable since the key used to encrypt it
no longer exists. If this step fails, it is possible to forcibly re-key all
credentials using the same primary key with ``keystone-manage
credential_migrate``.

``keystone-manage credential_migrate`` will check the backend for credentials
whose key hash doesn't match the hash of the current primary key. Any
credentials with a key hash mismatching the current primary key will be
re-encrypted with the current primary key. The new cipher text and key hash
will be updated in the backend.
