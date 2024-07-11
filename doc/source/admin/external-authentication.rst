===========================================
Using external authentication with Keystone
===========================================

When Keystone is executed in a web server like Apache HTTPD,
it is possible to have the web server also handle authentication.
This enables support for additional methods of authentication that
are not provided by the identity store backend and
the authentication plugins that Keystone supports.

Having the web server handle authentication is not exclusive, and both
Keystone and the web server can provide different methods of authentication at
the same time. For example, the web server can provide support for X.509 or
Kerberos authentication, while Keystone provides support for password
authentication (with SQL or an identity store as the backend).

When the web server authenticates a user, it sets environment variables,
usually ``REMOTE_USER``, which can be used in the underlying application.
Keystone can be configured to use these environment variables to determine the
identity of the user.

Configuration
=============

In order to activate the external authentication mechanism for Identity API v3,
the ``external`` method must be in the list of enabled authentication methods.
By default it is enabled, so if you don't want to use external authentication,
remove it from the ``methods`` option in the ``auth`` section.

To configure the plugin that should be used set the ``external`` option again
in the ``auth`` section. There are two external authentication method plugins
provided by Keystone:

* ``DefaultDomain``: This plugin won't take into account the domain information
  that the external authentication method may pass down to Keystone and will
  always use the configured default domain. The ``REMOTE_USER`` variable is the
  username. This is the default if no plugin is given.

* ``Domain``: This plugin expects that the ``REMOTE_DOMAIN`` variable contains
  the domain for the user. If this variable is not present, the configured
  default domain will be used. The ``REMOTE_USER`` variable is the username.

.. CAUTION::

    You should disable the external auth method if you are currently using
    federation. External auth and federation both use the ``REMOTE_USER``
    variable. Since both the mapped and external plugin are being invoked to
    validate attributes in the request environment, it can cause conflicts.

    For example, imagine there are two distinct users with the same username
    `foo`, one in the `Default` domain while the other is in the `BAR` domain.
    The external Federation modules (i.e. mod_shib) sets the ``REMOTE_USER``
    attribute to `foo`. The external auth module also tries to set the
    ``REMOTE_USER`` attribute to `foo` for the `Default` domain. The
    federated mapping engine maps the incoming identity to `foo` in the `BAR`
    domain. This results in user_id conflict since both are using different
    user_ids to set `foo` in the `Default` domain and the `BAR` domain.

    To disable this, simply remove `external` from the `methods` option in
    `keystone.conf`::

       methods = external,password,token,oauth1

Using HTTPD authentication
==========================

Web servers like Apache HTTP support many methods of authentication. Keystone
can profit from this feature and let the authentication be done in the web
server, that will pass down the authenticated user to Keystone using the
``REMOTE_USER`` environment variable. This user must exist in advance in the
identity backend to get a token from the controller.

To use this method, Keystone should be running on HTTPD.

X.509 example
-------------

The following snippet for the Apache conf will authenticate the user based on
a valid X.509 certificate from a known CA::

    <VirtualHost _default_:5000>
        SSLEngine on
        SSLCertificateFile    /etc/ssl/certs/ssl.cert
        SSLCertificateKeyFile /etc/ssl/private/ssl.key

        SSLCACertificatePath /etc/ssl/allowed_cas
        SSLCARevocationPath  /etc/ssl/allowed_cas
        SSLUserName          SSL_CLIENT_S_DN_CN
        SSLVerifyClient      require
        SSLVerifyDepth       10

        (...)
    </VirtualHost>
