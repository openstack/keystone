================
JWS key rotation
================

The JWS token provider issues tokens using asymmetric signing. This document
attempts to describe how to manage key pairs in a deployment of keystone nodes
that need to validate tokens issued by one another.

The inherent benefit of using asymmetric keys is that each keystone server
generates it's own key pair. The private key is used to sign tokens. Anyone
with access to the public key has the ability to verify the token signature.
This is a critical step in validating tokens across a cluster of keystone
nodes.

It is necessary for operators to sync public keys across all keystone nodes in
the deployment. Each keystone server will need a corresponding public key for
every node. This only applies to public keys. Private keys should never leave
the server they are generated from.

Initial setup
-------------

Before a deployment of keystone servers can issue JWT tokens, each server must
set ``keystone.conf [token] provider = jws``. Additionally, each API server
must have its own asymmetric key pair either generated manually or using
``keystone-manage create_jws_keypair``. If you're generating the key pairs
manually, they must be usable with the ``ES256`` JSON Web Algorithm (`JWA`_). It
is worth noting that the ``keystone-manage create_jws_keypair`` command line
utility will create an appropriate key pair, but it will not automatically
deploy it to the key repository locations defined in ``keystone.conf
[jwt_tokens]``. It is up to operators to move these files accordingly and
resolve possible file name conflicts.

After generating a key pair, the public key from each API server must be shared
with every other API server in the deployment. Ensure the private key used to
sign JWS tokens is readable by the process running keystone and available in
the ``keystone.conf [jwt_tokens] jws_private_key_repository`` location.
Keystone will automatically use a key named ``private.pem`` to sign tokens and
ignore all other keys in the repository. To validate tokens, keystone will
iterate all available public keys in ``keystone.conf [jwt_tokens]
jws_public_key_repository``.  At a minimum, this repository needs to have the
corresponding public key to the ``private.pem`` key found in ``keystone.conf
[jwt_tokens] jws_private_key_repository``.

.. _`JWA`: https://tools.ietf.org/html/rfc7518

Continued operations
--------------------

Depending on the security requirements for your deployment, you might need to
rotate out an existing key pair. To do so without prematurely invalidating
tokens, follow these steps:

1. Generate a new asymmetric key pair for a given keystone API server (see
   ``keystone-manage create_jws_keypair`` for more details)
2. Copy or sync the newly generated public key to the public key repositories
   of all other keystone API servers, the public key should be placed in
   ``keystone.conf [jwt_tokens] jws_public_key_repository``
3. Copy the new private key to the private key repository on the API server
   you're performing the rotation on and make sure it's named ``private.pem``,
   at this point the server will start signing tokens with the new private key
   and all other keystone API servers will be able to validate those tokens
   since they already have a copy of the public key from step #2
4. At this point, you must wait until the last tokens signed with the old
   private key have expired before you can remove the old corresponding public
   keys from each keystone API server, note this should be a minimum of
   ``keystone.conf [token] expiration``
5. Once you're confident all tokens signed with the old private key are
   expired, it is safe to remove the old corresponding public key from each API
   server in the deployment, which is important in case the original private
   key was compromised and prevents attackers from using it craft their own
   tokens
