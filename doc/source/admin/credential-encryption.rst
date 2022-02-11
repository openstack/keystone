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
