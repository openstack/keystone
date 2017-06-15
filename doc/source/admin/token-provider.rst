==============
Token provider
==============

OpenStack Identity supports customizable token providers. This is specified
in the ``[token]`` section of the configuration file. The token provider
controls the token construction, validation, and revocation operations.

You can register your own token provider by configuring the following property:

.. note::

   More commonly, you can use this option to change the token provider to one
   of the ones built in. Alternatively, you can use it to configure your own
   token provider.

* ``provider`` - token provider driver.
  Defaults to ``uuid``.
  Implemented by :class:`keystone.token.providers.uuid.Provider`. This is the
  entry point for the token provider in the ``keystone.token.provider``
  namespace.

Each token format uses different technologies to achieve various performance,
scaling, and architectural requirements. The Identity service includes
``fernet``, ``pkiz``, ``pki``, and ``uuid`` token providers.

Below is the detailed list of the token formats:

UUID
 ``uuid`` tokens must be persisted (using the back end specified in the
 ``[token] driver`` option), but do not require any extra configuration
 or setup.

PKI and PKIZ
 ``pki`` and ``pkiz`` tokens can be validated offline, without making HTTP
 calls to keystone. However, this format requires that certificates be
 installed and distributed to facilitate signing tokens and later validating
 those signatures.

Fernet
 ``fernet`` tokens do not need to be persisted at all, but require that you run
 ``keystone-manage fernet_setup`` (also see the
 ``keystone-manage fernet_rotate`` command).

.. warning::

    UUID, PKI, PKIZ, and Fernet tokens are all bearer tokens. They
    must be protected from unnecessary disclosure to prevent unauthorized
    access.
