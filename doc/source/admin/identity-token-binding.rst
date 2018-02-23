============================================
Configure Identity service for token binding
============================================

Token binding embeds information from an external authentication
mechanism, such as a Kerberos server or X.509 certificate, inside a
token. By using token binding, a client can enforce the use of a
specified external authentication mechanism with the token. This
additional security mechanism ensures that if a token is stolen, for
example, it is not usable without external authentication.

You configure the authentication types for a token binding in the
``/etc/keystone/keystone.conf`` file:

.. code-block:: ini

   [token]
   bind = kerberos

or

.. code-block:: ini

   [token]
   bind = x509

Currently ``kerberos`` and ``x509`` are supported.

To enforce checking of token binding, set the ``enforce_token_bind``
option to one of these modes:

- ``disabled``
    Disables token bind checking.

- ``permissive``
    Enables bind checking. If a token is bound to an unknown
    authentication mechanism, the server ignores it. The default is this
    mode.

- ``strict``
    Enables bind checking. If a token is bound to an unknown
    authentication mechanism, the server rejects it.

- ``required``
    Enables bind checking. Requires use of at least authentication
    mechanism for tokens.

- ``kerberos``
    Enables bind checking. Requires use of kerberos as the authentication
    mechanism for tokens:

    .. code-block:: ini

       [token]
       enforce_token_bind = kerberos

- ``x509``
    Enables bind checking. Requires use of X.509 as the authentication
    mechanism for tokens:

    .. code-block:: ini

       [token]
       enforce_token_bind = x509

*Do not* set ``enforce_token_bind = named`` as there is not an authentication
mechanism called ``named``.