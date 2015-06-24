===========================================
Using external authentication with Keystone
===========================================
.. _external-auth:

When Keystone is executed in a web server like :doc:`Apache HTTPD
<apache-httpd>` it is possible to use external authentication methods different
from the authentication provided by the identity store backend or the different
authentication plugins. For example, this makes possible to use an SQL identity
backend together with, X.509 authentication or Kerberos, for example, instead
of using the username and password combination.

When a web server is in charge of authentication, it is normally possible to
set the ``REMOTE_USER`` environment variable so that it can be used in the
underlying application. Keystone can be configured to use that environment
variable if set, so that the authentication is handled by the web server.

Configuration
=============

In Identity API v2, there is no way to disable external authentication. In
order to activate the external authentication mechanism for Identity API v3,
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

Using HTTPD authentication
==========================

Web servers like Apache HTTP support many methods of authentication. Keystone
can profit from this feature and let the authentication be done in the web
server, that will pass down the authenticated user to Keystone using the
``REMOTE_USER`` environment variable. This user must exist in advance in the
identity backend to get a token from the controller.

To use this method, Keystone should be running on :doc:`HTTPD <apache-httpd>`.

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

Developing a WSGI middleware for authentication
===============================================

In addition to the method described above, it is possible to implement other
custom authentication mechanisms using the ``REMOTE_USER`` WSGI environment
variable.

.. ATTENTION::

    Please note that even if it is possible to develop a custom authentication
    module, it is preferable to use the modules in the HTTPD server. Such
    authentication modules in webservers like Apache have normally undergone
    years of development and use in production systems and are actively
    maintained upstream. Developing a custom authentication module that
    implements the same authentication as an existing Apache module likely
    introduces a higher security risk.

If you find you must implement a custom authentication mechanism, you will need
to develop a custom WSGI middleware pipeline component. This middleware should
set the environment variable ``REMOTE_USER`` to the authenticated username.
Keystone then will assume that the user has been already authenticated upstream
and will not try to authenticate it. However, as with HTTPD authentication, the
user must exist in advance in the identity backend so that a proper token can
be issued.

Your code should set the ``REMOTE_USER`` if the user is properly authenticated,
following the semantics below:

.. code-block:: python

    from keystone.common import wsgi
    from keystone import exception

    class MyMiddlewareAuth(wsgi.Middleware):
        def __init__(self, *args, **kwargs):
            super(MyMiddlewareAuth, self).__init__(*args, **kwargs)

        def process_request(self, request):
            if request.environ.get('REMOTE_USER', None) is not None:
                # Assume that it is authenticated upstream
                return self.application

            if not self.is_auth_applicable(request):
                # Not applicable
                return self.application

            username = self.do_auth(request)
            if username is not None:
                # User is authenticated
                request.environ['REMOTE_USER'] = username
            else:
                # User is not authenticated, render exception
                raise exception.Unauthorized("Invalid user")


Pipeline configuration
----------------------

Once you have your WSGI middleware component developed you have to add it to
your pipeline. The first step is to add the middleware to your configuration
file. Assuming that your middleware module is
``keystone.middleware.MyMiddlewareAuth``, you can configure it in your
``keystone-paste.ini`` as::

    [filter:my_auth]
    paste.filter_factory = keystone.middleware.MyMiddlewareAuth.factory

The second step is to add your middleware to the pipeline. The exact place
where you should place it will depend on your code (i.e. if you need for
example that the request body is converted from JSON before perform the
authentication you should place it after the ``json_body`` filter) but it
should be set before the ``public_service`` (for the ``public_api`` pipeline)
or ``admin_service`` (for the ``admin_api`` pipeline), since they consume
authentication.

For example, if the original pipeline looks like this::

    [pipeline:public_api]
    pipeline = url_normalize token_auth admin_token_auth json_body debug ec2_extension user_crud_extension public_service

Your modified pipeline might then look like this::

    [pipeline:public_api]
    pipeline = url_normalize token_auth admin_token_auth json_body my_auth debug ec2_extension user_crud_extension public_service
