=====================================
External authentication with Identity
=====================================

When Identity runs in ``apache-httpd``, you can use external
authentication methods that differ from the authentication provided by
the identity store back end. For example, you can use an SQL identity
back end together with X.509 authentication and Kerberos, instead of
using the user name and password combination.

Use HTTPD authentication
~~~~~~~~~~~~~~~~~~~~~~~~

Web servers, like Apache HTTP, support many methods of authentication.
Identity can allow the web server to perform the authentication. The web
server then passes the authenticated user to Identity by using the
``REMOTE_USER`` environment variable. This user must already exist in
the Identity back end to get a token from the controller. To use this
method, Identity should run on ``apache-httpd``.

Use X.509
~~~~~~~~~

The following Apache configuration snippet authenticates the user based
on a valid X.509 certificate from a known CA:

.. code-block:: none

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
