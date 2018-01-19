===================================
Fernet - Frequently Asked Questions
===================================

The following questions have been asked periodically since the initial release
of the fernet token format in Kilo.

What is a fernet token?
~~~~~~~~~~~~~~~~~~~~~~~

A fernet token is a bearer token that represents user authentication. Fernet
tokens contain a limited amount of identity and authorization data in a
`MessagePacked <https://msgpack.org/>`_ payload. The payload is then wrapped as
a `Fernet <https://github.com/fernet/spec>`_ message for transport, where
Fernet provides the required web safe characteristics for use in URLs and
headers. The data inside a fernet token is protected using symmetric encryption
keys, or fernet keys.

What is a fernet key?
~~~~~~~~~~~~~~~~~~~~~

A fernet key is used to encrypt and decrypt fernet tokens. Each key is actually
composed of two smaller keys: a 128-bit AES encryption key and a 128-bit SHA256
HMAC signing key. The keys are held in a key repository that keystone passes to
a library that handles the encryption and decryption of tokens.

What are the different types of keys?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A key repository is required by keystone in order to create fernet tokens.
These keys are used to encrypt and decrypt the information that makes up the
payload of the token. Each key in the repository can have one of three states.
The state of the key determines how keystone uses a key with fernet tokens. The
different types are as follows:

Primary key:
  There is only ever one primary key in a key repository. The primary key is
  allowed to encrypt and decrypt tokens. This key is always named as the
  highest index in the repository.
Secondary key:
  A secondary key was at one point a primary key, but has been demoted in place
  of another primary key. It is only allowed to decrypt tokens. Since it was
  the primary at some point in time, its existence in the key repository is
  justified. Keystone needs to be able to decrypt tokens that were created with
  old primary keys.
Staged key:
  The staged key is a special key that shares some similarities with secondary
  keys. There can only ever be one staged key in a repository and it must
  exist. Just like secondary keys, staged keys have the ability to decrypt
  tokens. Unlike secondary keys, staged keys have never been a primary key. In
  fact, they are opposites since the staged key will always be the next primary
  key. This helps clarify the name because they are the next key staged to be
  the primary key. This key is always named as ``0`` in the key repository.

So, how does a staged key help me and why do I care about it?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The fernet keys have a natural lifecycle. Each key starts as a staged key, is
promoted to be the primary key, and then demoted to be a secondary key. New
tokens can only be encrypted with a primary key. Secondary and staged keys are
never used to encrypt token. The staged key is a special key given the order of
events and the attributes of each type of key. The staged key is the only key
in the repository that has not had a chance to encrypt any tokens yet, but it
is still allowed to decrypt tokens. As an operator, this gives you the chance
to perform a key rotation on one keystone node, and distribute the new key set
over a span of time. This does not require the distribution to take place in an
ultra short period of time. Tokens encrypted with a primary key can be
decrypted, and validated, on other nodes where that key is still staged.

Where do I put my key repository?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The key repository is specified using the ``key_repository`` option in the
keystone configuration file. The keystone process should be able to read and
write to this location but it should be kept secret otherwise. Currently,
keystone only supports file-backed key repositories.

.. code-block:: ini

   [fernet_tokens]
   key_repository = /etc/keystone/fernet-keys/

What is the recommended way to rotate and distribute keys?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The :command:`keystone-manage` command line utility includes a key rotation
mechanism. This mechanism will initialize and rotate keys but does not make
an effort to distribute keys across keystone nodes. The distribution of keys
across a keystone deployment is best handled through configuration management
tooling. Use :command:`keystone-manage fernet_rotate` to rotate the key
repository.

Do fernet tokens still expire?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Yes, fernet tokens can expire just like any other keystone token formats.

Why should I choose fernet tokens over UUID tokens?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Even though fernet tokens operate very similarly to UUID tokens, they do not
require persistence or leverage the configured token persistence driver in any
way. The keystone token database no longer suffers bloat as a side effect of
authentication. Pruning expired tokens from the token database is no longer
required when using fernet tokens. Because fernet tokens do not require
persistence, they do not have to be replicated. As long as each keystone node
shares the same key repository, fernet tokens can be created and validated
instantly across nodes.

Why should I choose fernet tokens over PKI or PKIZ tokens?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The arguments for using fernet over PKI and PKIZ remain the same as UUID, in
addition to the fact that fernet tokens are much smaller than PKI and PKIZ
tokens. PKI and PKIZ tokens still require persistent storage and can sometimes
cause issues due to their size. This issue is mitigated when switching to
fernet because fernet tokens are kept under a 250 byte limit. PKI and PKIZ
tokens typically exceed 1600 bytes in length. The length of a PKI or PKIZ token
is dependent on the size of the deployment. Bigger service catalogs will result
in longer token lengths. This pattern does not exist with fernet tokens because
the contents of the encrypted payload is kept to a minimum.

Should I rotate and distribute keys from the same keystone node every rotation?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

No, but the relationship between rotation and distribution should be lock-step.
Once you rotate keys on one keystone node, the key repository from that node
should be distributed to the rest of the cluster. Once you confirm that each
node has the same key repository state, you could rotate and distribute from
any other node in the cluster.

If the rotation and distribution are not lock-step, a single keystone node in
the deployment will create tokens with a primary key that no other node has as
a staged key. This will cause tokens generated from one keystone node to fail
validation on other keystone nodes.

How do I add new keystone nodes to a deployment?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The keys used to create fernet tokens should be treated like super secret
configuration files, similar to an SSL secret key. Before a node is allowed to
join an existing cluster, issuing and validating tokens, it should have the
same key repository as the rest of the nodes in the cluster.

How should I approach key distribution?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Remember that key distribution is only required in multi-node keystone
deployments. If you only have one keystone node serving requests in your
deployment, key distribution is unnecessary.

Key distribution is a problem best approached from the deployment's current
configuration management system. Since not all deployments use the same
configuration management systems, it makes sense to explore options around what
is already available for managing keys, while keeping the secrecy of the keys
in mind. Many configuration management tools can leverage something like
``rsync`` to manage key distribution.

Key rotation is a single operation that promotes the current staged key to
primary, creates a new staged key, and prunes old secondary keys. It is easiest
to do this on a single node and verify the rotation took place properly before
distributing the key repository to the rest of the cluster. The concept behind
the staged key breaks the expectation that key rotation and key distribution
have to be done in a single step. With the staged key, we have time to inspect
the new key repository before syncing state with the rest of the cluster. Key
distribution should be an operation that can run in succession until it
succeeds. The following might help illustrate the isolation between key
rotation and key distribution.

#. Ensure all keystone nodes in the deployment have the same key repository.
#. Pick a keystone node in the cluster to rotate from.
#. Rotate keys.

   #. Was it successful?

      #.  If no, investigate issues with the particular keystone node you
          rotated keys on. Fernet keys are small and the operation for
          rotation is trivial. There should not be much room for error in key
          rotation. It is possible that the user does not have the ability to
          write new keys to the key repository. Log output from
          ``keystone-manage fernet_rotate`` should give more information into
          specific failures.

      #.  If yes, you should see a new staged key. The old staged key should
          be the new primary. Depending on the ``max_active_keys`` limit you
          might have secondary keys that were pruned. At this point, the node
          that you rotated on will be creating fernet tokens with a primary
          key that all other nodes should have as the staged key. This is why
          we checked the state of all key repositories in Step one. All other
          nodes in the cluster should be able to decrypt tokens created with
          the new primary key. At this point, we are ready to distribute the
          new key set.

#. Distribute the new key repository.

   #. Was it successful?

      #.  If yes, you should be able to confirm that all nodes in the cluster
          have the same key repository that was introduced in Step 3.  All
          nodes in the cluster will be creating tokens with the primary key
          that was promoted in Step 3. No further action is required until the
          next schedule key rotation.

      #.  If no, try distributing again. Remember that we already rotated the
          repository and performing another rotation at this point will
          result in tokens that cannot be validated across certain hosts.
          Specifically, the hosts that did not get the latest key set. You
          should be able to distribute keys until it is successful. If certain
          nodes have issues syncing, it could be permission or network issues
          and those should be resolved before subsequent rotations.

How long should I keep my keys around?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The fernet tokens that keystone creates are only secure as the keys creating
them. With staged keys the penalty of key rotation is low, allowing you to err
on the side of security and rotate weekly, daily, or even hourly.  Ultimately,
this should be less time than it takes an attacker to break a ``AES256`` key
and a ``SHA256 HMAC``.

Is a fernet token still a bearer token?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Yes, and they follow exactly the same validation path as UUID tokens, with the
exception of being written to, and read from, a back end. If someone
compromises your fernet token, they have the power to do all the operations you
are allowed to do.

What if I need to revoke all my tokens?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To invalidate every token issued from keystone and start fresh, remove the
current key repository, create a new key set, and redistribute it to all nodes
in the cluster. This will render every token issued from keystone as invalid
regardless if the token has actually expired. When a client goes to
re-authenticate, the new token will have been created with a new fernet key.

What can an attacker do if they compromise a fernet key in my deployment?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If any key used in the key repository is compromised, an attacker will be able
to build their own tokens. If they know the ID of an administrator on a
project, they could generate administrator tokens for the project. They will be
able to generate their own tokens until the compromised key has been removed
from from the repository.

I rotated keys and now tokens are invalidating early, what did I do?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Using fernet tokens requires some awareness around token expiration and the key
lifecycle. You do not want to rotate so often that secondary keys are removed
that might still be needed to decrypt unexpired tokens. If this happens, you
will not be able to decrypt the token because the key the was used to encrypt
it is now gone. Only remove keys that you know are not being used to encrypt or
decrypt tokens.

For example, your token is valid for 24 hours and we want to rotate keys every
six hours. We will need to make sure tokens that were created at 08:00 AM on
Monday are still valid at 07:00 AM on Tuesday, assuming they were not
prematurely revoked. To accomplish this, we will want to make sure we set
``max_active_keys=6`` in our keystone configuration file. This will allow us to
hold all keys that might still be required to validate a previous token, but
keeps the key repository limited to only the keys that are needed.

The number of ``max_active_keys`` for a deployment can be determined by
dividing the token lifetime, in hours, by the frequency of rotation in hours
and adding two. Better illustrated as::

    token_expiration = 24
    rotation_frequency = 6
    max_active_keys = (token_expiration / rotation_frequency) + 2

The reason for adding two additional keys to the count is to include the staged
key and a buffer key. This can be shown based on the previous example. We
initially setup the key repository at 6:00 AM on Monday, and the initial state
looks like:

.. code-block:: console

   $ ls -la /etc/keystone/fernet-keys/
   drwx------ 2 keystone keystone 4096 .
   drwxr-xr-x 3 keystone keystone 4096 ..
   -rw------- 1 keystone keystone   44 0    (staged key)
   -rw------- 1 keystone keystone   44 1    (primary key)

All tokens created after 6:00 AM are encrypted with key ``1``. At 12:00 PM we
will rotate keys again, resulting in,

.. code-block:: console

   $ ls -la /etc/keystone/fernet-keys/
   drwx------ 2 keystone keystone 4096 .
   drwxr-xr-x 3 keystone keystone 4096 ..
   -rw------- 1 keystone keystone   44 0    (staged key)
   -rw------- 1 keystone keystone   44 1    (secondary key)
   -rw------- 1 keystone keystone   44 2    (primary key)

We are still able to validate tokens created between 6:00 - 11:59 AM because
the ``1`` key still exists as a secondary key. All tokens issued after 12:00 PM
will be encrypted with key ``2``. At 6:00 PM we do our next rotation, resulting
in:

.. code-block:: console

   $ ls -la /etc/keystone/fernet-keys/
   drwx------ 2 keystone keystone 4096 .
   drwxr-xr-x 3 keystone keystone 4096 ..
   -rw------- 1 keystone keystone   44 0    (staged key)
   -rw------- 1 keystone keystone   44 1    (secondary key)
   -rw------- 1 keystone keystone   44 2    (secondary key)
   -rw------- 1 keystone keystone   44 3    (primary key)

It is still possible to validate tokens issued from 6:00 AM - 5:59 PM because
keys ``1`` and ``2`` exist as secondary keys. Every token issued until 11:59 PM
will be encrypted with key ``3``, and at 12:00 AM we do our next rotation:

.. code-block:: console

   $ ls -la /etc/keystone/fernet-keys/
   drwx------ 2 keystone keystone 4096 .
   drwxr-xr-x 3 keystone keystone 4096 ..
   -rw------- 1 keystone keystone   44 0    (staged key)
   -rw------- 1 keystone keystone   44 1    (secondary key)
   -rw------- 1 keystone keystone   44 2    (secondary key)
   -rw------- 1 keystone keystone   44 3    (secondary key)
   -rw------- 1 keystone keystone   44 4    (primary key)

Just like before, we can still validate tokens issued from 6:00 AM the previous
day until 5:59 AM today because keys ``1`` - ``4`` are present. At 6:00 AM,
tokens issued from the previous day will start to expire and we do our next
scheduled rotation:

.. code-block:: console

   $ ls -la /etc/keystone/fernet-keys/
   drwx------ 2 keystone keystone 4096 .
   drwxr-xr-x 3 keystone keystone 4096 ..
   -rw------- 1 keystone keystone   44 0    (staged key)
   -rw------- 1 keystone keystone   44 1    (secondary key)
   -rw------- 1 keystone keystone   44 2    (secondary key)
   -rw------- 1 keystone keystone   44 3    (secondary key)
   -rw------- 1 keystone keystone   44 4    (secondary key)
   -rw------- 1 keystone keystone   44 5    (primary key)

Tokens will naturally expire after 6:00 AM, but we will not be able to remove
key ``1`` until the next rotation because it encrypted all tokens from 6:00 AM
to 12:00 PM the day before. Once we do our next rotation, which is at 12:00 PM,
the ``1`` key will be pruned from the repository:

.. code-block:: console

   $ ls -la /etc/keystone/fernet-keys/
   drwx------ 2 keystone keystone 4096 .
   drwxr-xr-x 3 keystone keystone 4096 ..
   -rw------- 1 keystone keystone   44 0    (staged key)
   -rw------- 1 keystone keystone   44 2    (secondary key)
   -rw------- 1 keystone keystone   44 3    (secondary key)
   -rw------- 1 keystone keystone   44 4    (secondary key)
   -rw------- 1 keystone keystone   44 5    (secondary key)
   -rw------- 1 keystone keystone   44 6    (primary key)

If keystone were to receive a token that was created between 6:00 AM and 12:00
PM the day before, encrypted with the ``1`` key, it would not be valid because
it was already expired. This makes it possible for us to remove the ``1`` key
from the repository without negative validation side-effects.
