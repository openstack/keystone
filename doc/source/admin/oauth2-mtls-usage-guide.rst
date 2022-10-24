===============================================
OAuth 2.0 Mutual-TLS Client Authentication Flow
===============================================
Overview
~~~~~~~~
OAuth 2.0 Mutual-TLS Client Authentication based on `RFC8705`_ is implemented
as an extension of Keystone. Users can use use_id as client_id to obtain the
OAuth 2.0 Certificate-Bound access token with TLS certificates. With the same
TLS certificates, the Certificate-Bound access token can then be used to access
the protected resources of the OpenStack API, which uses Keystone middleware
supporting the OAuth 2.0 Mutual-TLS Client Authentication. See the
`Identity API reference`_ for more information on generating OAuth 2.0 access
token.

Guide
~~~~~
Enable Keystone identity server to support OAuth 2.0 Mutual-TLS Client
Authentication by the following steps in this guide. In this example,
``keystone.host`` is the domain name used by the Keystone identity server.

.. _RFC8705: https://datatracker.ietf.org/doc/html/rfc8705
.. _`Identity API reference`: https://docs.openstack.org/api-ref/identity/v3/index.html#os-oauth2-api

Create a private/public Certificate Authority (CA)
--------------------------------------------------
In order to use mutual TLS, it is necessary to create a private/public
Certificate Authority (CA) as a root certificate that will be used to sign
client and keystone certificates.

1. Generate an RSA private key.

.. code-block:: console

    $ openssl genrsa -out root_a.key 4096
    Generating RSA private key, 4096 bit long modulus (2 primes)
    .++++
    .........................++++
    e is 65537 (0x010001)

2. Generate a self-signed certificate.

.. code-block:: console

    $ openssl req -new -x509 -key root_a.key -out root_a.pem -days 365
    You are about to be asked to enter information that will be incorporated
    into your certificate request.
    What you are about to enter is what is called a Distinguished Name or a DN.
    There are quite a few fields but you can leave some blank
    For some fields there will be a default value,
    If you enter '.', the field will be left blank.
    -----
    Country Name (2 letter code) [AU]: JP
    State or Province Name (full name) [Some-State]: Tokyo
    Locality Name (eg, city) []: Chiyoda-ku
    Organization Name (eg, company) [Internet Widgits Pty Ltd]: IssuingORG
    Organizational Unit Name (eg, section) []: CertDept
    Common Name (e.g. server FQDN or YOUR name) []: root_a.openstack.host
    Email Address []: root_a@issuing.org
    Please enter the following 'extra' attributes
    to be sent with your certificate request
    A challenge password []:
    An optional company name []:

3. If you need to support multiple root certificates, you can refer to step1
   and step2. Because of the needs of the server configuration, you need to
   merge these root certificates into a single file. Multiple root
   certificates are used in this guide, so another root certificate is
   created, the certificate is named root_b, and the CN of the certificate
   is "root_b.openstack.host".

.. code-block:: console

    $ cat root_a.pem >> multi_ca.pem
    $ cat root_b.pem >> multi_ca.pem
    $ cat multi_ca.pem
    -----BEGIN CERTIFICATE-----
    MIIF1TCCA72gAwIBAgIUN7d0MTiikDjDMLxUQ8SJcV97Nz8wDQYJKoZIhvcNAQEL
    BQAwejELMAkGA1UEBhMCSlAxEDAOBgNVBAgMB2ppYW5nc3UxDzANBgNVBAcMBnN1
    ...
    K/k00vZmrZXONglaf/OeMalhiRaOTsK2CzEvg6Xgu1zOjtNshm6qnSEXDYxzJue2
    FPLDGEMKSCLb
    -----END CERTIFICATE-----
    -----BEGIN CERTIFICATE-----
    MIIF1TCCA72gAwIBAgIUOiAEZWTheMS5wFA661G6bushkg4wDQYJKoZIhvcNAQEL
    BQAwejELMAkGA1UEBhMCY24xEDAOBgNVBAgMB2ppYW5nc3UxDzANBgNVBAcMBnN1
    ...
    UzvplIZcNZKzgOLLrSkk42/yqxdTZnc3BeBiVsA5T6aapNbY8D6ZpPU2cYYSxrfK
    VpOanJoJy22J
    -----END CERTIFICATE-----

Enable Keystone to support mutual TLS
-------------------------------------
The following parts describe steps to enable mutual TLS only for os-oauth2-api.

1. Generate an RSA private key.

.. code-block:: console

    $ openssl genrsa -out keystone_priv.key 4096
    Generating RSA private key, 4096 bit long modulus (2 primes)
    .........................................+++++
    .........................+++++
    e is 65537 (0x010001)

2. Create a certificate signing request.

.. code-block:: console

    $ openssl req -new -key keystone_priv.key -out keystone_csr.csr
    You are about to be asked to enter information that will be incorporated
    into your certificate request.
    What you are about to enter is what is called a Distinguished Name or a DN.
    There are quite a few fields but you can leave some blank
    For some fields there will be a default value,
    If you enter '.', the field will be left blank.
    -----
    Country Name (2 letter code) [AU]: JP
    State or Province Name (full name) [Some-State]: Tokyo
    Locality Name (eg, city) []: Chiyoda-ku
    Organization Name (eg, company) [Internet Widgits Pty Ltd]: OpenstackORG
    Organizational Unit Name (eg, section) []: DevDept
    Common Name (e.g. server FQDN or YOUR name) []:keystone.host
    Email Address []: dev@keystone.host
    Please enter the following 'extra' attributes
    to be sent with your certificate request
    A challenge password []:
    An optional company name []:

3. Use the root certificate to generate a self-signed certificate.

.. code-block:: console

    $ openssl x509 -req -in keystone_csr.csr \
    -CA root_a.pem -CAkey root_a.key -CAcreateserial \
    -out keystone_ca.pem -days 365 -sha384
    Signature ok
    subject=C = JP, ST = Tokyo, L = Chiyoda-ku, O = OpenstackORG, OU = DevDept, CN = keystone.host, emailAddress = dev@keystone.host
    Getting CA Private Key

4. Modify the apache configuration file and add options to implement mutual TLS
   support for the Keystone service.

.. note::

  Based on the server environment, this command may have to be run to enable
  SSL module in apache2 service when setting up HTTPS protocol for keystone
  server.

  .. code-block:: console

    $ sudo a2enmod ssl

.. code-block:: console

    $ sudo vi /etc/apache2/sites-enabled/keystone-wsgi-public.conf
    ProxyPass "/identity" "unix:/var/run/uwsgi/keystone-wsgi-public.socket|uwsgi://uwsgi-uds-keystone-wsgi-public" retry=0
    <IfModule mod_ssl.c>
    <VirtualHost _default_:443>
      ServerAdmin webmaster@localhost
      ErrorLog ${APACHE_LOG_DIR}/error.log
      CustomLog ${APACHE_LOG_DIR}/access.log combined
      SSLEngine on
      SSLCertificateFile      /etc/ssl/certs/keystone_ca.pem
      SSLCertificateKeyFile   /etc/ssl/private/keystone_priv.key
      SSLCACertificateFile    /etc/ssl/certs/multi_ca.pem
      <Location /identity/v3/OS-OAUTH2/token>
        SSLVerifyClient require
        SSLOptions +ExportCertData
        SSLOptions +StdEnvVars
        SSLRequireSSL
      </Location>
    </VirtualHost>
    </IfModule>

5. Restart apache service so that the modified configuration information takes
   effect.

.. code-block:: console

    $ systemctl restart apache2.service
    ==== AUTHENTICATING FOR org.freedesktop.systemd1.manage-units ===
    Authentication is required to restart 'apache2.service'.
    Authenticating as: Ubuntu (ubuntu)
    Password:
    ==== AUTHENTICATION COMPLETE ===

Create mapping rules for validating TLS certificates
----------------------------------------------------
Because different root certificates have different ways of authenticating TLS
certificates provided by client, the relevant mapping rules need to be set in
the system.

1. Create a mapping rule file. The mapping used below supports both root
   certificates. When the CN name of the issuer of the client certificate is
   "root_a.openstack.host", the client certificate must contain the 5 fields
   specified by Mapping, and these fields must match the user information in
   Keystone. When the CN name of the issuer of the client certificate is
   "root_b.openstack.host", only 2 fields need to be included to keep the
   user information consistent with the keystone. When using Subject
   Distinguished Names, the ``SSL_CLIENT_SUBJECT_DN_*`` format must be used.
   When using Issuer Distinguished Names, the ``SSL_CLIENT_ISSUER_DN_*`` format
   must be used. The ``*`` part is the key of the attribute for Distinguished
   Names converted to uppercase. For more information about the attribute
   types for Distinguished Names, see the relevant RFC documentation
   such as: `RFC1779`_, `RFC2985`_, `RFC4519`_, etc.

.. note::

  The short forms of attribute keys can be found in `RFC4514`_. For the key
  ``Email Address`` which is not listed in `RFC4514`_, you can use
  ``SSL_CLIENT_ISSUER_DN_EMAILADDRESS`` and
  ``SSL_CLIENT_SUBJECT_DN_EMAILADDRESS``


.. code-block:: console

    $ vi oauth2_mapping.json
    [
      {
        "local": [
          {
            "user": {
              "name": "{0}",
              "id": "{1}",
              "email": "{2}",
              "domain": {
                "name": "{3}",
                "id": "{4}"
              }
            }
          }
        ],
        "remote": [
          {
            "type": "SSL_CLIENT_SUBJECT_DN_CN"
          },
          {
            "type": "SSL_CLIENT_SUBJECT_DN_UID"
          },
          {
            "type": "SSL_CLIENT_SUBJECT_DN_EMAILADDRESS"
          },
          {
            "type": "SSL_CLIENT_SUBJECT_DN_O"
          },
          {
            "type": "SSL_CLIENT_SUBJECT_DN_DC"
          },
          {
            "type": "SSL_CLIENT_ISSUER_DN_CN",
            "any_one_of": [
                "root_a.openstack.host"
           ]
          }
        ]
      },
      {
        "local": [
          {
            "user": {
              "id": "{0}",
               "domain": {
                "id": "{1}"
              }
            }
          }
        ],
        "remote": [
          {
            "type": "SSL_CLIENT_SUBJECT_DN_UID"
          },
          {
            "type": "SSL_CLIENT_SUBJECT_DN_DC"
          },
          {
            "type": "SSL_CLIENT_ISSUER_DN_CN",
            "any_one_of": [
                "root_b.openstack.host"
           ]
          }
        ]
      }
    ]

2. Use the file to create the mapping rule in keystone.

.. code-block:: console

    $ openstack mapping create --rules oauth2_mapping.json oauth2_mapping

3. If it already exists, use the file to update the mapping rule in keystone.

.. code-block:: console

    openstack mapping set --rules oauth2_mapping.json oauth2_mapping

.. _RFC1779: https://www.rfc-editor.org/rfc/rfc1779.html
.. _RFC2985: https://www.rfc-editor.org/rfc/rfc2985.html
.. _RFC4519: https://www.rfc-editor.org/rfc/rfc4519.html
.. _RFC4514: https://www.rfc-editor.org/rfc/rfc4514.html#page-7

Enable keystone to support OAuth 2.0 Mutual-TLS Client Authentication
---------------------------------------------------------------------
Modify the relevant configuration to enable the os-oauth2-api to use TLS
certificates for user authentication.

1. Modify ``keystone.conf`` to OAuth 2.0 Mutual-TLS Client Authentication.

.. code-block:: console

    $ vi /etc/keystone/keystone.conf
    [oauth2]
    oauth2_authn_method = certificate
    oauth2_cert_dn_mapping_id=oauth2_mapping

2. Restart Keystone service so that the modified configuration information
   takes effect.

.. code-block:: console

    $ sudo systemctl restart devstack@keystone.service

Try to access the Keystone APIs
-------------------------------
At last, try to access the Keystone APIs to confirm that the server is working
properly.

1. Create an OAuth 2.0 Mutual-TLS Client Authentication user. Because some
OpenStack APIs require project information, it is recommended to specify the
project when creating a user.

.. code-block:: console

    $ openstack user create --domain default --email test@demo.com --project demo --project-domain default client01
    +---------------------+----------------------------------+
    | Field               | Value                            |
    +---------------------+----------------------------------+
    | default_project_id  | c5c07949e53a41da816f3c052b37dfe8 |
    | domain_id           | default                          |
    | email               | test@demo.com                    |
    | enabled             | True                             |
    | id                  | 88319190aca54383a38b96eb0e75266e |
    | name                | client01                         |
    | description         | None                             |
    | password_expires_at | None                             |
    +---------------------+----------------------------------+

2. Existing users can set the project information through the command.

.. code-block:: console

    $ openstack user show client02
    +---------------------+----------------------------------+
    | Field               | Value                            |
    +---------------------+----------------------------------+
    | default_project_id  | None                             |
    | domain_id           | default                          |
    | email               | test@demo.com                    |
    | enabled             | True                             |
    | id                  | dc8682953ad9443dbda5291d6f675def |
    | name                | client02                         |
    | description         | None                             |
    | password_expires_at | None                             |
    +---------------------+----------------------------------+
    $ openstack user set dc8682953ad9443dbda5291d6f675def --project demo --project-domain default
    $ openstack user show client02
    +---------------------+----------------------------------+
    | Field               | Value                            |
    +---------------------+----------------------------------+
    | default_project_id  | c5c07949e53a41da816f3c052b37dfe8 |
    | domain_id           | default                          |
    | email               | test@demo.com                    |
    | enabled             | True                             |
    | id                  | dc8682953ad9443dbda5291d6f675def |
    | name                | client02                         |
    | description         | None                             |
    | password_expires_at | None                             |
    +---------------------+----------------------------------+

3. Assign roles to the user.

.. code-block:: console

    $ openstack role add --project demo --user client01 admin
    $ openstack role assignment list --project demo --user client01
    +----------------------------------+----------------------------------+-------+----------------------------------+--------+--------+-----------+
    | Role                             | User                             | Group | Project                          | Domain | System | Inherited |
    +----------------------------------+----------------------------------+-------+----------------------------------+--------+--------+-----------+
    | 1684856368de4c31a7b6e8fefd6654ff | 88319190aca54383a38b96eb0e75266e |       | c5c07949e53a41da816f3c052b37dfe8 |        |        | False     |
    +----------------------------------+----------------------------------+-------+----------------------------------+--------+--------+-----------+
    $ openstack role add --project demo --user client02 admin
    $ openstack role assignment list --project demo --user client02
    +----------------------------------+----------------------------------+-------+----------------------------------+--------+--------+-----------+
    | Role                             | User                             | Group | Project                          | Domain | System | Inherited |
    +----------------------------------+----------------------------------+-------+----------------------------------+--------+--------+-----------+
    | 1684856368de4c31a7b6e8fefd6654ff | dc8682953ad9443dbda5291d6f675def |       | c5c07949e53a41da816f3c052b37dfe8 |        |        | False     |
    +----------------------------------+----------------------------------+-------+----------------------------------+--------+--------+-----------+

4. Generate an RSA private key for the user.

.. code-block:: console

    $ openssl genrsa -out client01_priv.key 4096
    Generating RSA private key, 4096 bit long modulus (2 primes)
    .........................................+++++
    .........................+++++
    e is 65537 (0x010001)
    $ openssl genrsa -out client02_priv.key 4096
    Generating RSA private key, 4096 bit long modulus (2 primes)
    .........................................+++++
    .........................+++++
    e is 65537 (0x010001)

5. Create a certificate signing request based on the mapping rule of the root
   certificate and on the user information. Because the client certificate is
   subsequently signed with root_a, five fields are specified when the request
   is created. If root_b is used to issue the client certificate, only two
   fields are required when creating the request.

.. code-block:: console

    $ openssl req -new -key client01_priv.key -out client01.csr \
    -subj "/UID=88319190aca54383a38b96eb0e75266e/O=Default/DC=default/emailAddress=test@demo.com/CN=client01"
    $ openssl req -new -key client02_priv.key -out client02.csr \
    -subj "/UID=dc8682953ad9443dbda5291d6f675def/DC=default/CN=client02"

6. Use the root certificate to generate a self-signed certificate for the user.

.. code-block:: console

    $ openssl x509 -req -in client01.csr \
    -CA root_a.pem -CAkey root_a.key -CAcreateserial -out \
    client01.pem -days 180 -sha256
    Signature ok
    subject=UID = 88319190aca54383a38b96eb0e75266e, O = Default, DC = default, emailAddress = test@demo.com, CN = client01
    Getting CA Private Key
    $ openssl x509 -req -in client02.csr \
    -CA root_b.pem -CAkey root_b.key -CAcreateserial -out \
    client02.pem -days 180 -sha256
    Signature ok
    subject=UID = dc8682953ad9443dbda5291d6f675def, DC = default, CN = client02
    Getting CA Private Key

7. Through the HTTP protocol, access the Keystone token API to confirm that the
   X-Auth-Token can be obtained normally.

.. code-block:: console

    $ curl -si -X POST http://keystone.local/identity/v3/auth/tokens?nocatalog \
    -d '{"auth":{"identity":{"methods":["password"],"password": {"user":{"domain":{"name":"Default"},"name":"username","password":"test_pwd"}}},"scope":{"project":{"domain":{"name":"Default"},"name":"admin"}}}}' \
    -H 'Content-type:application/json'
    HTTP/1.1 201 CREATED
    Date: Tue, 24 Dec 2024 16:21:22 GMT
    Server: Apache/2.4.52 (Ubuntu)
    Content-Type: application/json
    Content-Length: 711
    X-Subject-Token: gAAAAABnat-...
    Vary: X-Auth-Token
    x-openstack-request-id: req-37d6a755-a633-4ab1-aa1b-980553804546
    Connection: close

    {"token": {"methods": ["password"], "user": {"domain": {"id": "default", "name": "Default"}, "id": "3414be74f5df43549088db1d63d33a61", "name": "admin", "password_expires_at": null}, "audit_ids": ["wc7QBA2CSMilYrgxzsDLOw"], "expires_at": "2024-12-24T17:21:22.000000Z", "issued_at": "2024-12-24T16:21:22.000000Z", "project": {"domain": {"id": "default", "name": "Default"}, "id": "6a7d3fa72f7a42b39938e9b3c845d206", "name": "admin"}, "is_domain": false, "roles": [{"id": "241e9736dbd0449eb22b7f23289ca6f8", "name": "manager"}, {"id": "73eb16a56be74f6783f0f26a8cd0df36", "name": "member"}, {"id": "1684856368de4c31a7b6e8fefd6654ff", "name": "admin"}, {"id": "b36ac7b62c204727930f41df609a236a", "name": "reader"}]}}

8. Obtain OAuth 2.0 Certificate-Bound access tokens through OAuth 2.0
   Mutual-TLS Client Authentication.

.. code-block:: console

    $ curl -si -X POST https://keystone.local/identity/v3/OS-OAUTH2/token \
    -H "application/x-www-form-urlencoded" \
    -d "grant_type=client_credentials&client_id=88319190aca54383a38b96eb0e75266e" \
    --cacert root_a.pem \
    --key client01_priv.key --cert client01.pem
    HTTP/1.1 200 OK
    Date: Tue, 24 Dec 2024 16:19:14 GMT
    Server: Apache/2.4.52 (Ubuntu)
    Content-Type: application/json
    Content-Length: 307
    Vary: X-Auth-Token
    x-openstack-request-id: req-8ec8dff2-8c34-4799-aa4b-a855566111dc
    Connection: close

    {"access_token":"gAAAAABnat8...","expires_in":3600,"token_type":"Bearer"}

    $ curl -si -X POST https://keystone.local/identity/v3/OS-OAUTH2/token \
    -H "application/x-www-form-urlencoded" \
    -d "grant_type=client_credentials&client_id=dc8682953ad9443dbda5291d6f675def" \
    --cacert root_a.pem \
    --key client02_priv.key --cert client02.pem
    HTTP/1.1 200 OK
    Date: Tue, 24 Dec 2024 16:27:24 GMT
    Server: Apache/2.4.52 (Ubuntu)
    Content-Type: application/json
    Content-Length: 307
    Vary: X-Auth-Token
    x-openstack-request-id: req-9bf1ad0f-32b7-4e86-8f30-01292bbb49a5
    Connection: close

    {"access_token":"gAAAAABnauD...","expires_in":3600,"token_type":"Bearer"}


9. Confirm that the OAuth 2.0 Certificate-Bound access tokens contain
   information such as project, roles, thumbprint, etc.

.. code-block:: console

    $ curl -si -X GET http://keystone.local/identity/v3/auth/tokens?nocatalog -H "X-Auth-Token:$x_auth_token" -H "X-Subject-Token:$access_token"
    HTTP/1.1 200 OK
    Date: Tue, 24 Dec 2024 16:45:43 GMT
    Server: Apache/2.4.52 (Ubuntu)
    Content-Type: application/json
    Content-Length: 805
    X-Subject-Token: gAAAAABnauU...
    Vary: X-Auth-Token
    x-openstack-request-id: req-fca9bf15-80cc-42c6-9153-769b77ec1b00
    Connection: close

    {"token": {"methods": ["oauth2_credential"], "user": {"domain": {"id": "default", "name": "Default"}, "id": "88319190aca54383a38b96eb0e75266e", "name": "client01", "password_expires_at": null}, "audit_ids": ["yeIlaD7ETe6tJPN7QoJ2Bg"], "expires_at": "2024-12-24T17:45:39.000000Z", "issued_at": "2024-12-24T16:45:39.000000Z", "project": {"domain": {"id": "default", "name": "Default"}, "id": "c5c07949e53a41da816f3c052b37dfe8", "name": "demo"}, "is_domain": false, "roles": [{"id": "241e9736dbd0449eb22b7f23289ca6f8", "name": "manager"}, {"id": "73eb16a56be74f6783f0f26a8cd0df36", "name": "member"}, {"id": "1684856368de4c31a7b6e8fefd6654ff", "name": "admin"}, {"id": "b36ac7b62c204727930f41df609a236a", "name": "reader"}], "oauth2_credential": {"x5t#S256": "9gRzUFm9Qu5nwFsKr9nCwPZhNTXP4dlvG73GBj5UmwY="}}}
