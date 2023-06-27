======================================
OAuth2.0 Client Credentials Grant Flow
======================================

Overview
~~~~~~~~
OAuth2.0 Client Credentials Grant based on `RFC6749`_ is implemented as an
extension of Keystone. This extension uses the `application credentials`_ as
its back-end because they have some similar features. Users can use
``application_credentials_id`` and ``application_credentials_secret`` as
client credentials to obtain the OAuth2.0 access token. The access token can
then be used to access the protected resources of the OpenStack API, which
uses Keystone middleware supporting the OAuth2.0 Client Credentials Grant.
See the `Identity API reference`_ for more information on generating OAuth2.0
access token.

Guide
~~~~~
Enable Keystone identity server to support OAuth2.0 Client Credentials
Grant by the following steps in this guide. In this example,
``keystone.host`` is the domain name used by the Keystone identity server.

.. _application credentials: https://docs.openstack.org/api-ref/identity/v3/index.html#application-credentials
.. _`Identity API reference`: https://docs.openstack.org/api-ref/identity/v3/index.html#os-oauth2-api

Enable Keystone HTTPS Service
---------------------------------
The following part describes steps to enable both HTTP and HTTPS with a
self-signed certificate.

.. warning::

   According to `RFC6749`_ , HTTPS **must** be enabled in the authorization
   server since requests include sensitive information, e.g., a client secret,
   in plain text. Note that you might have to enable both HTTP and HTTPS as
   some other OpenStack services or third-party applications don't use
   OAuth2.0 and need HTTP for the authentication with the Keystone identity
   server.

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

Enable application credentials authentication
---------------------------------------------
Due to the design of the current implementation, the application credentials
must be enabled in Keystone as it is used for the management of OAuth2.0
client credentials.

1. Modify ``keystone.conf`` to support application credentials authentication.

.. code-block:: console

    stack@oauth2-0-server:/$ vi /etc/keystone/keystone.conf
    [auth]
    methods = external,password,token,application_credential

2. Restart Keystone service so that the modified configuration information takes
   effect.

.. code-block:: console

    stack@oauth2-0-server:/$ sudo systemctl restart devstack@keystone.service

Try to access the Keystone APIs
-------------------------------
At last, try to access the Keystone APIs to confirm that the server is working
properly.

1. Through the HTTP protocol, access the Keystone token API to confirm that the
   X-Auth-Token can be obtained normally.

.. code-block:: console

    stack@oauth2-0-server:/$ curl -si -X POST http://keystone.host/identity/v3/auth/tokens?nocatalog \
    -d '{"auth":{"identity":{"methods":["password"],"password": {"user":{"domain":{"name":"Default"},"name":"username","password":"test_pwd"}}},"scope":{"project":{"domain":{"name":"Default"},"name":"admin"}}}}' \
    -H 'Content-type:application/json'

    HTTP/1.1 201 CREATED
    Date: Mon, 28 Feb 2022 08:50:31 GMT
    Server: Apache/2.4.41 (Ubuntu)
    Content-Type: application/json
    Content-Length: 648
    X-Subject-Token: $x_auth_token
    Vary: X-Auth-Token
    x-openstack-request-id: req-e84d2387-10c7-4bb9-942e-61190e9186d9
    Connection: close

    {"token": {"methods": ["password"], "user": {"domain": {"id": "default", "name": "Default"}, "id": "eb98b8bbb2174aa5acd6cf57b0bf64c6", "name": "admin", "password_expires_at": null}, "audit_ids": ["RkU3ZQXuR7uKF2tEwgtkYg"], "expires_at": "2022-02-28T09:50:31.000000Z", "issued_at": "2022-02-28T08:50:31.000000Z", "project": {"domain": {"id": "default", "name": "Default"}, "id": "83808bea957a4ce1aa612aef63b24d1c", "name": "admin"}, "is_domain": false, "roles": [{"id": "c30201abb78848a6919f582d0cd74f84", "name": "admin"}, {"id": "459dcf48c6794731b700fc6aa1cad669", "name": "member"}, {"id": "54ee344bb009472c8223d4d76d9b1246", "name": "reader"}]}}

2. Through the HTTPS protocol, access the Keystone token API to confirm that the
   X-Auth-Token can be obtained normally.

.. code-block:: console

    stack@oauth2-0-server:/$ curl -sik -X POST https://keystone.host/identity/v3/auth/tokens?nocatalog \
    -d '{"auth":{"identity":{"methods":["password"],"password": {"user":{"domain":{"name":"Default"},"name":"username","password":"test_pwd"}}},"scope":{"project":{"domain":{"name":"Default"},"name":"admin"}}}}' \
    -H 'Content-type:application/json'

    HTTP/1.1 201 CREATED
    Date: Tue, 01 Mar 2022 00:38:48 GMT
    Server: Apache/2.4.41 (Ubuntu)
    Content-Type: application/json
    Content-Length: 648
    X-Subject-Token: $x_auth_token
    Vary: X-Auth-Token
    x-openstack-request-id: req-324f20e2-16d6-4f26-aefc-e2913b76e36f
    Connection: close

    {"token": {"methods": ["password"], "user": {"domain": {"id": "default", "name": "Default"}, "id": "eb98b8bbb2174aa5acd6cf57b0bf64c6", "name": "admin", "password_expires_at": null}, "audit_ids": ["XFEM4-V4QQiA9v3JVLUeWw"], "expires_at": "2022-03-01T01:38:48.000000Z", "issued_at": "2022-03-01T00:38:48.000000Z", "project": {"domain": {"id": "default", "name": "Default"}, "id": "83808bea957a4ce1aa612aef63b24d1c", "name": "admin"}, "is_domain": false, "roles": [{"id": "c30201abb78848a6919f582d0cd74f84", "name": "admin"}, {"id": "459dcf48c6794731b700fc6aa1cad669", "name": "member"}, {"id": "54ee344bb009472c8223d4d76d9b1246", "name": "reader"}]}}

3. Create OAuth2.0 client credentials through the application credentials API.

.. code-block:: console

    stack@oauth2-0-server:/$ curl -sik -X POST https://keystone.host/identity/v3/users/eb98b8bbb2174aa5acd6cf57b0bf64c6/application_credentials \
    -H "X-Auth-Token: $x_auth_token" \
    -H "Content-Type: application/json" \
    -d '{"application_credential": {"name": "sample_001"}}'

    HTTP/1.1 201 CREATED
    Date: Tue, 01 Mar 2022 00:55:25 GMT
    Server: Apache/2.4.41 (Ubuntu)
    Content-Type: application/json
    Content-Length: 890
    Vary: X-Auth-Token
    x-openstack-request-id: req-e73ffa83-78df-4663-bccc-dd3ac582417f
    Connection: close

    {"application_credential": {"id": "$oauth2_client_id", "name": "sample_001", "description": null, "user_id": "eb98b8bbb2174aa5acd6cf57b0bf64c6", "project_id": "83808bea957a4ce1aa612aef63b24d1c", "system": null, "expires_at": null, "unrestricted": null, "roles": [{"id": "c30201abb78848a6919f582d0cd74f84", "name": "admin", "domain_id": null, "description": null, "options": {"immutable": true}}, {"id": "459dcf48c6794731b700fc6aa1cad669", "name": "member", "domain_id": null, "description": null, "options": {"immutable": true}}, {"id": "54ee344bb009472c8223d4d76d9b1246", "name": "reader", "domain_id": null, "description": null, "options": {"immutable": true}}], "secret": "$auth2_client_secret", "links": {"self": "https://keystone.host/identity/v3/application_credentials/f96a2fec117141a6b5fbaa0485632244"}}}

4. Obtain oauth2.0 access tokens through the "Basic" HTTP authentication with
   OAuth2.0 client credentials.

.. code-block:: console

    stack@oauth2-0-server:/$ curl -sik -u "$oauth2_client_id:$oauth2_client_secret" \
    -X POST https://keystone.host/identity/v3/OS-OAUTH2/token
    -H "application/x-www-form-urlencoded" -d "grant_type=client_credentials"
    HTTP/1.1 200 OK
    Date: Tue, 01 Mar 2022 00:56:59 GMT
    Server: Apache/2.4.41 (Ubuntu)
    Content-Type: application/json
    Content-Length: 264
    Vary: X-Auth-Token
    x-openstack-request-id: req-a8358f51-2e0f-45a7-bb1e-7d29c6a793f4
    Connection: close

    {"access_token":"gAAAAABhi1cMynG89h8t6TJrxNiZuNzjcIUIxNctoVfuqTw7BpUedLKxjPymClVEnj9GhIT5u2mpjaJATlEAtaa3D6_t8jk_fV-mqo2IUlsmTPTnMwkcjh5FSHQVRdqvDxgY3nSqLA_Hfv-zPmjS5KWX3hmyDE5YWO1ztX6QNVQb4wTPyNL1-7I","expires_in":3600,"token_type":"Bearer"}

