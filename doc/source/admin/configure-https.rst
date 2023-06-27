Configure HTTPS in Identity Service
-----------------------------------

The following part describes steps to enable both HTTP and HTTPS with a
self-signed certificate.

1. Generate an RSA private key.

.. code-block:: console

    stack@oauth2-0-server:/$ openssl genrsa -out keystone.key 2048
    Generating RSA private key, 2048 bit long modulus (2 primes)
    .........................................+++++
    .........................+++++
    e is 65537 (0x010001)

2. Create a certificate signing request.

.. code-block:: console

    stack@oauth2-0-server:/$ openssl req -new -key keystone.key -out keystone.csr
    You are about to be asked to enter information that will be incorporated
    into your certificate request.
    What you are about to enter is what is called a Distinguished Name or a DN.
    There are quite a few fields but you can leave some blank
    For some fields there will be a default value,
    If you enter '.', the field will be left blank.
    -----
    Country Name (2 letter code) [AU]:
    State or Province Name (full name) [Some-State]:
    Locality Name (eg, city) []:
    Organization Name (eg, company) [Internet Widgits Pty Ltd]:
    Organizational Unit Name (eg, section) []:
    Common Name (e.g. server FQDN or YOUR name) []:keystone.host
    Email Address []:

    Please enter the following 'extra' attributes
    to be sent with your certificate request
    A challenge password []:
    An optional company name []:

3. Generate a self-signed certificate.

.. code-block:: console

    stack@oauth2-0-server:/$ openssl x509 -req -days 365 -in keystone.csr \
    -signkey keystone.key -out keystone.host.crt
    Signature ok
    subject=C = , ST = , L = , O = , OU = , CN = keystone.host, emailAddress =
    Getting Private key

4. Append the configuration file for setting the HTTPS port service under the
   directory ``/etc/apache2/sites-enabled/``.

.. code-block:: console

    stack@oauth2-0-server:/$ sudo ln -s \
    /etc/apache2/sites-available/000-default.conf \
    /etc/apache2/sites-enabled/000-default.conf

5. Modify the apache configuration file and add proxy rules to implement HTTPS
   support for the Keystone service.

.. code-block:: console

    stack@oauth2-0-server:/$ vi 000-default.conf
    <VirtualHost *:443>
    DocumentRoot /var/www/html
    SSLCertificateFile /etc/ssl/certs/keystone.host.crt
    SSLCertificateKeyFile /etc/ssl/certs/keystone.key
    SSLEngine on
    SSLProtocol  all -SSLv2 -SSLv3
    SSLCipherSuite ECDH:AESGCM:HIGH:!RC4:!DH:!MD5:!aNULL:!eNULL
    SSLHonorCipherOrder on
    ProxyPass "/identity" "unix:/var/run/uwsgi/keystone-wsgi-public.socket|uwsgi://uwsgi-uds-keystone-wsgi-public" retry=0
    </VirtualHost>

6. Restart apache service so that the modified configuration information takes
   effect.

.. code-block:: console

    stack@oauth2-0-server:/$ systemctl restart apache2.service
    ==== AUTHENTICATING FOR org.freedesktop.systemd1.manage-units ===
    Authentication is required to restart 'apache2.service'.
    Authenticating as: Ubuntu (ubuntu)
    Password:
    ==== AUTHENTICATION COMPLETE ===

.. _RFC6749: https://datatracker.ietf.org/doc/html/rfc6749