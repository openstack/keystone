===========================================
Using external authentication with Keystone
===========================================

When Keystone is executed in :doc:`HTTPD <apache-httpd>` it is possible to
use external authentication methods different from the authentication
provided by the identity store backend. For example, this makes possible to
use a SQL identity backend together with X.509 authentication, Kerberos, etc.
instead of using the username/password combination.

Using HTTPD authentication
==========================

Webservers like Apache HTTP support many methods of authentication. Keystone can
profit from this feature and let the authentication be done in the webserver,
that will pass down the authenticated user to Keystone using the ``REMOTE_USER``
environment variable. This user must exist in advance in the identity backend
so as to get a token from the controller.

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
    years of development and use in production systems and are actively maintained
    upstream. Developing a custom authentication module that implements the same
    authentication as an existing Apache module likely introduces a higher
    security risk.

If you find you must implement a custom authentication mechanism, you will need
to develop a custom WSGI middleware pipeline component. This middleware should
set the environment variable ``REMOTE_USER`` to the authenticated username.
Keystone then will assume that the user has been already authenticated upstream
and will not try to authenticate it. However, as with HTTPD authentication, the
user must exist in advance in the identity backend so that a proper token can
be issued.

Your code should set the ``REMOTE_USER`` if the user is properly authenticated,
following the semantics below::

    from keystone.common import wsgi

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

            username = self.do_auth(request):
            if username is not None:
                # User is authenticated
                request.environ['REMOTE_USER'] = username
            else:
                # User is not authenticated, render exception
                raise exception.Unauthorized("Invalid user")


Pipeline configuration
----------------------

Once you have your WSGI middleware component developed you have to add it to
your pipeline. The first step is to add the middleware to your configuration file.
Assuming that your middleware module is ``keystone.middleware.MyMiddlewareAuth``,
you can configure it in your ``keystone-paste.ini`` as::

    [filter:my_auth]
    paste.filter_factory = keystone.middleware.MyMiddlewareAuth.factory

The second step is to add your middleware to the pipeline. The exact place where
you should place it will depend on your code (i.e. if you need for example that
the request body is converted from JSON before perform the authentication you
should place it after the ``json_body`` filter) but it should be set before the
``public_service`` (for the ``public_api`` pipeline) or ``admin_service`` (for
the ``admin_api`` pipeline), since they consume authentication.

For example, if the original pipeline looks like this::

    [pipeline:public_api]
    pipeline = stats_monitoring url_normalize token_auth admin_token_auth xml_body json_body debug ec2_extension user_crud_extension public_service

Your modified pipeline might then look like this::

    [pipeline:public_api]
    pipeline = stats_monitoring url_normalize token_auth admin_token_auth xml_body json_body my_auth debug ec2_extension user_crud_extension public_service
