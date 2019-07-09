..
    Licensed under the Apache License, Version 2.0 (the "License"); you may not
    use this file except in compliance with the License. You may obtain a copy
    of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
    License for the specific language governing permissions and limitations
    under the License.

================================================
Configuring Keystone for Tokenless Authorization
================================================

-----------
Definitions
-----------

* `X.509 Tokenless Authorization`: Provides a means to authorize client
  operations within Keystone by using an X.509 SSL client certificate
  without having to issue a token.

  This feature is designed to reduce the complexity of user token validation
  in Keystone ``auth_token`` middleware by eliminating the need for service
  user token for authentication and authorization. Therefore, there's no need
  to having to create and maintain a service user account for the sole purpose
  of user token validation. Furthermore, this feature improves efficiency by
  avoiding service user token handling (i.e. request, cache, and renewal).
  By not having to deal with service user credentials in the configuration
  files, deployers are relieved of the burden of having to protect the
  server user passwords throughout the deployment lifecycle. This feature also
  improve security by using X.509 certificate instead of password for
  authentication.

  For details, please refer to the specs
  `Tokenless Authorization with X.509 Client SSL Certificate`_

* `Public Key Infrastructure or PKI`: a system which utilize public key
  cryptography to achieve authentication, authorization, confidentiality,
  integrity, non-repudiation. In this system, the identities are
  represented by public key certificates. Public key certificate handling
  is governed by the `X.509`_ standard.

  See `Public Key Infrastructure`_ and `X.509`_ for more information.

* `X.509 Certificate`: a time bound digital identity, which is
  certified or digitally signed by its issuer using cryptographic means as
  defined by the `X.509`_ standard. It contains information which can be
  used to uniquely identify its owner. For example, the owner of the
  certificate is identified by the ``Subject`` attribute while the issuer
  is identified by ``Issuer`` attribute.

  In operation, certificates are usually stored in
  `Privacy-Enhanced Mail`_ (PEM) format.

  Here's an example of what a certificate typically contains:

  .. code-block:: javascript

    Certificate:
        Data:
            Version: 3 (0x2)
            Serial Number: 4098 (0x1002)
        Signature Algorithm: sha256WithRSAEncryption
            Issuer: DC = com, DC = somedemo, O = openstack, OU = keystone, CN = Intermediate CA
            Validity
                Not Before: Jul  5 18:42:01 2019 GMT
                Not After : Jul  2 18:42:01 2029 GMT
            Subject: DC = com, DC = somedemo, O = Default, OU = keystone, CN = glance
            Subject Public Key Info:
                Public Key Algorithm: rsaEncryption
                    Public-Key: (2048 bit)
                    Modulus:
                        00:cf:35:8b:cd:4f:17:28:38:25:f7:e2:ac:ce:4e:
                        d7:05:74:2f:99:04:f8:c2:13:14:50:18:70:d6:b0:
                        53:62:15:60:59:99:90:47:e2:7e:bf:ca:30:4a:18:
                        f5:b8:29:1e:cc:d4:b8:49:9c:4a:aa:d9:10:b9:d7:
                        9f:55:85:cf:e3:44:d2:3c:95:42:5a:b0:53:3e:49:
                        9d:6b:b2:a0:9f:72:9d:76:96:55:8b:ee:c4:71:46:
                        ab:bd:12:71:42:a0:60:29:7a:66:16:e1:fd:03:17:
                        af:a3:c7:26:c3:c3:8b:a7:f9:c0:22:08:2d:e4:5c:
                        07:e1:44:58:c1:b1:88:ae:45:5e:03:10:bb:b4:c2:
                        42:52:da:4e:b5:1b:d6:6f:49:db:a4:5f:8f:e5:79:
                        9f:73:c2:37:de:99:a7:4d:6f:cb:b5:f9:7e:97:e0:
                        77:c8:40:21:40:ef:ab:d3:55:72:37:6c:28:0f:bd:
                        37:8c:3a:9c:e9:a0:21:6b:63:3f:7a:dd:1b:2c:90:
                        07:37:66:86:66:36:ef:21:bb:43:df:d5:37:a9:fa:
                        4b:74:9a:7c:4b:cd:8b:9d:3b:af:6d:50:fe:c9:0a:
                        25:35:c5:1d:40:35:1d:1f:f9:10:fd:b6:5c:45:11:
                        bb:67:11:81:3f:ed:d6:27:04:98:8f:9e:99:a1:c8:
                        c1:2d
                    Exponent: 65537 (0x10001)
            X509v3 extensions:
                X509v3 Basic Constraints:
                    CA:FALSE
                Netscape Cert Type:
                    SSL Client, S/MIME
                Netscape Comment:
                    OpenSSL Generated Client Certificate
                X509v3 Subject Key Identifier:
                    EE:38:FB:60:65:CD:81:CE:B2:01:E3:A5:99:1B:34:6C:1A:74:97:BB
                X509v3 Authority Key Identifier:
                    keyid:64:17:77:31:00:F2:ED:90:9A:A8:1D:B5:7D:75:06:03:B5:FD:B9:C0

                X509v3 Key Usage: critical
                    Digital Signature, Non Repudiation, Key Encipherment
                X509v3 Extended Key Usage:
                    TLS Web Client Authentication, E-mail Protection
        Signature Algorithm: sha256WithRSAEncryption
             82:8b:17:c6:f4:63:eb:8d:69:03:7a:bf:54:7f:37:02:eb:94:
             ef:57:fd:27:8f:f8:67:e9:0e:3b:0a:40:66:11:68:e6:04:1a:
             8a:da:47:ed:83:eb:54:34:3b:5b:70:18:cf:62:e2:6d:7c:74:
             4c:cf:14:b3:a9:70:b2:68:ed:19:19:71:6f:7d:87:22:38:8d:
             83:c6:59:15:74:19:5b:a2:64:6f:b9:9a:81:3d:0a:67:58:d1:
             e2:b2:9b:9b:8f:60:7a:8c:0e:61:d9:d7:04:63:cc:58:af:36:
             a4:61:86:44:1c:64:e2:9b:bd:f3:21:87:dd:18:81:80:af:0f:
             d6:4c:9f:ae:0f:01:e0:0e:38:4d:5d:71:da:0b:11:39:bd:c3:
             5d:0c:db:14:ca:bf:7f:07:37:c9:36:bd:22:a5:73:c6:e1:13:
             53:15:de:ac:4a:4b:dc:48:90:47:06:fa:d4:d2:5d:c6:d2:d4:
             3f:0f:49:0f:27:de:21:b0:bd:a3:92:c3:cb:69:b6:8d:94:e1:
             e3:40:b4:80:c7:e6:e2:df:0a:94:52:d1:16:41:0f:bc:29:a8:
             93:40:1b:77:28:a3:f2:cb:3c:7f:bb:ae:a6:0e:b3:01:78:09:
             d3:2b:cf:2f:47:83:91:36:37:43:34:6e:80:2b:81:10:27:95:
             95:ae:1e:93:42:94:a6:23:b8:07:c0:0f:38:23:70:b0:8e:79:
             14:cd:72:8a:90:bf:77:ad:74:3c:23:9e:67:5d:0e:26:15:6e:
             20:95:6d:d0:89:be:a3:6c:4a:13:1d:39:fb:21:e3:9c:9f:f3:
             ff:15:da:0a:28:29:4e:f4:7f:5e:0f:70:84:80:7c:09:5a:1c:
             f4:ac:c9:1b:9d:38:43:dd:27:00:95:ef:14:a0:57:3e:26:0b:
             d8:bb:40:d6:1f:91:92:f0:4e:5d:93:1c:b7:3d:bd:83:ef:79:
             ee:47:ca:61:04:00:e6:39:05:ab:f0:cd:47:e9:25:c8:3a:4c:
             e5:62:9f:aa:8a:ba:ea:46:10:ef:bd:1e:24:5f:0c:89:8a:21:
             bb:9d:c7:73:0f:b9:b5:72:1f:1f:1b:5b:ff:3a:cb:d8:51:bc:
             bb:9a:40:91:a9:d5:fe:95:ac:73:a5:12:6a:b2:e3:b1:b2:7d:
             bf:e7:db:cd:9f:24:63:6e:27:cf:d8:82:d9:ac:d8:c9:88:ea:
             4f:1c:ae:7d:b7:c7:81:b2:1c:f8:6b:6b:85:3b:f2:14:cb:c7:
             61:81:ad:64:e7:d9:90:a3:ea:69:7e:26:7a:0a:29:7b:1b:2a:
             e0:38:f7:58:d1:90:82:44:01:ab:05:fd:68:0c:ab:9e:c6:94:
             76:34:46:8b:66:bb:02:07

  See `public key certificate`_ for more information.

* `Issuer`: the issuer of a X.509 certificate. It is also known as
  `Certificate Authority (CA)`_ or Certification Authority. Issuer is
  typically represented in `RFC 2253`_ format. Throughout this document,
  ``issuer``, ``issuer DN``, ``CA``, and ``trusted issuer`` are used
  interchangeably.

.. _`Tokenless Authorization with X.509 Client SSL Certificate`: https://specs.openstack.org/openstack/keystone-specs/specs/liberty/keystone-tokenless-authz-with-x509-ssl-client-cert.html
.. _`Public Key Infrastructure`: https://en.wikipedia.org/wiki/Public_key_infrastructure
.. _`X.509`: https://en.wikipedia.org/wiki/X.509
.. _`public key certificate`: https://en.wikipedia.org/wiki/Public_key_certificate
.. _`Privacy-Enhanced Mail`: https://en.wikipedia.org/wiki/Public_key_certificate
.. _`RFC 2253`: https://tools.ietf.org/html/rfc2253
.. _`Certificate Authority (CA)`: https://en.wikipedia.org/wiki/Certificate_authority

Prerequisites
-------------

This feature requires Keystone API proxy SSL terminator to validate the
incoming X.509 SSL client certificate and pass the certificate information
(i.e. subject DN, issuer DN, etc) to the Keystone application as part of the
request environment. At the time of this writing the feature has been tested
with either HAProxy or Apache as Keystone API proxy SSL terminator only.

The rest of this document required readers to familiar with:

* `Public Key Infrastructure (PKI) and certificate management`_
* `SSL with client authentication`_, or commonly known as two-way SSL
* `Public Key Infrastructure (PKI) and certificate management`_
* `Apache SSL configuration`_
* `HAProxy SSL configuration`_

.. _`Public Key Infrastructure (PKI) and certificate management`: https://en.wikipedia.org/wiki/Public_key_infrastructure
.. _`SSL with client authentication`: https://tools.ietf.org/html/rfc5246#section-7.4.6
.. _`Apache SSL configuration`: https://httpd.apache.org/docs/trunk/mod/mod_ssl.html#ssloptions
.. _`HAProxy SSL configuration`: http://cbonte.github.io/haproxy-dconv/1.7/configuration.html#7.3.4

Configuring this feature requires `OpenSSL Command Line Tool (CLI)`_. Please refer
to the respective OS installation guide on how to install it.

.. _`OpenSSL Command Line Tool (CLI)`: https://www.openssl.org/docs/manmaster/man1/openssl.html

----------------------
Keystone Configuration
----------------------

This feature utilizes Keystone federation capability to determine the
authorization associated with the incoming X.509 SSL client certificate by
mapping the certificate attributes to a Keystone identity. Therefore, the
direct issuer or trusted Certification Authority (CA) of the client certificate
is the remote Identity Provider (IDP), and the hexadecimal output of the SHA256
hash of the issuer distinguished name (DN) is used as the IDP ID.

.. NOTE::

   Client certificate issuer DN may be formatted differently depending on the
   SSL terminator. For example, Apache mod_ssl may use `RFC 2253`_ while HAProxy
   may use the old format. The old format is used by applications that linked
   with an older version of OpenSSL where the string representation of the
   distinguished name has not yet become a de facto standard. For more
   information on the old formation, please see the `nameopt`_ in the
   OpenSSL CLI manual. Therefore, it is critically important to keep the
   format consistent throughout the configuration as Keystone does exact string
   match when comparing certificate attributes.

.. _`nameopt`: https://www.openssl.org/docs/manmaster/man1/x509.html
.. _`RFC 2253`: https://tools.ietf.org/html/rfc2253

How to obtain trusted issuer DN
-------------------------------
If SSL terminates at either HAProxy or Apache, the client certificate issuer
DN can be obtained by using the OpenSSL CLI.

Since version 2.3.11, Apache mod_ssl by default uses `RFC 2253`_ when handling
certificate distinguished names. However, deployer have the option to use
the old format by configuring the `LegacyDNStringFormat`_ option.

.. _`RFC 2253`: https://tools.ietf.org/html/rfc2253
.. _`LegacyDNStringFormat`: https://httpd.apache.org/docs/trunk/mod/mod_ssl.html#ssloptions

HAProxy, on the other hand, only supports the old format.

To obtain issuer DN in RFC 2253 format:

.. code-block:: bash

   $ openssl x509 -issuer -noout -in client_cert.pem -nameopt rfc2253 | sed 's/^\s*issuer=//'

To obtain issuer DN in old format:

.. code-block:: bash

   $ openssl x509 -issuer -noout -in client_cert.pem -nameopt compat | sed 's/^\s*issuer=//'

How to calculate the IDP ID from trusted issuer DN
--------------------------------------------------
The hexadecimal output of the SHA256 hash of the trusted issuer DN is being
used as the Identity Provider ID in Keystone. It can be obtained using
OpenSSL CLI.

To calculate the IDP ID for issuer DN in RFC 2253 format:

.. code-block:: bash

   $ openssl x509 -issuer -noout -in client_cert.pem -nameopt rfc2253 | tr -d '\n' | sed 's/^\s*issuer=//' | openssl dgst -sha256 -hex | awk '{print $2}'

To calculate the IDP ID for issuer DN in old format:

.. code-block:: bash

   $ openssl x509 -issuer -noout -in client_cert.pem -nameopt compat | tr -d '\n' | sed 's/^\s*issuer=//' | openssl dgst -sha256 -hex | awk '{print $2}'


Keystone Configuration File Changes
-----------------------------------

The following options in the ``tokenless_auth`` section of the Keystone
configuration file `keystone.conf` are used to enable the X.509 tokenless
authorization feature:

* ``trusted_issuer`` - A list of trusted issuers for the X.509 SSL client
  certificates. More specifically the list of trusted issuer DNs mentioned in
  the `How to obtain trusted issuer DN`_ section above.
  The format of the trusted issuer DNs must match exactly with what the SSL
  terminator passed into the request environment. For example, if SSL
  terminates in Apache mod_ssl, then the issuer DN should be in RFC 2253
  format. Whereas if SSL terminates in HAProxy, then the issuer DN
  is expected to be in the old format. This is a multi-string list option. The
  absence of any trusted issuers means the X.509 tokenless authorization
  feature is effectively disabled.
* ``protocol`` - The protocol name for the X.509 tokenless authorization
  along with the option `issuer_attribute` below can look up its
  corresponding mapping. It defaults to ``x509``.
* ``issuer_attribute`` - The issuer attribute that is served as an IdP ID for
  the X.509 tokenless authorization along with the protocol to look up its
  corresponding mapping. It is the environment variable in the WSGI
  environment that references to the Issuer of the client certificate. It
  defaults to ``SSL_CLIENT_I_DN``.

This is a sample configuration for two `trusted_issuer` and a `protocol` set
to ``x509``.

.. code-block:: ini

    [tokenless_auth]
    trusted_issuer = emailAddress=admin@foosigner.com,CN=Foo Signer,OU=eng,O=abc,L=San Jose,ST=California,C=US
    trusted_issuer = emailAddress=admin@openstack.com,CN=OpenStack Cert Signer,OU=keystone,O=openstack,L=Sunnyvale,ST=California,C=US
    protocol = x509

-------------
Setup Mapping
-------------

Like federation, X.509 tokenless authorization also utilizes the mapping
mechanism to formulate an identity. The identity provider must correspond
to the issuer of the X.509 SSL client certificate. The protocol for the
given identity is ``x509`` by default, but can be configurable.

Create an Identity Provider (IDP)
---------------------------------

As mentioned, the Identity Provider ID is the hexadecimal output of the SHA256
hash of the issuer distinguished name (DN).

.. NOTE::

   If there are multiple trusted issuers, there must be multiple IDP created,
   one for each trusted issuer.

To create an IDP for a given trusted issuer, follow the instructions in the
`How to calculate the IDP ID from trusted issuer DN`_ section to calculate
the IDP ID. Then use OpenStack CLI to create the IDP. i.e.

.. code-block:: bash

   $ openstack identity provider create --description 'IDP foo' <IDP ID>


Create a Map
------------

A mapping needs to be created to map the ``Subject DN`` in the client
certificate as a user to yield a valid local user if the user's ``type``
defined as ``local`` in the mapping. For example, the client certificate
has ``Subject DN`` as ``CN=alex,OU=eng,O=nice-network,L=Sunnyvale,
ST=California,C=US``, in the following examples, ``user_name`` will be
mapped to``alex`` and ``domain_name`` will be mapped to ``nice-network``.
And it has user's ``type`` set to ``local``. If user's ``type`` is not
defined, it defaults to ``ephemeral``.

Please refer to `mod_ssl`_ for the detailed mapping attributes.

.. _`mod_ssl`: http://httpd.apache.org/docs/current/mod/mod_ssl.html

.. code-block:: javascript

    [
        {
            "local": [
                {
                    "user": {
                        "name": "{0}",
                        "domain": {
                            "name": "{1}"
                        },
                        "type": "local"
                    }
                }
            ],
            "remote": [
                {
                    "type": "SSL_CLIENT_S_DN_CN",
                    "whitelist": ["glance", "nova", "swift", "neutron"]
                },
                {
                     "type": "SSL_CLIENT_S_DN_O",
                     "whitelist": ["Default"]
                }
            ]
        }
    ]

When user's ``type`` is not defined or set to ``ephemeral``, the mapped user
does not have to be a valid local user but the mapping must yield at least
one valid local group. For example:

.. code-block:: javascript

    [
        {
            "local": [
                {
                    "user": {
                        "name": "{0}",
                        "type": "ephemeral"
                    },
                    "group": {
                        "domain": {
                            "name": "{1}"
                        },
                        "name": "openstack_services"
                    }
                }
            ],
            "remote": [
                {
                    "type": "SSL_CLIENT_S_DN_CN",
                    "whitelist": ["glance", "nova", "swift", "neutron"]
                },
                {
                     "type": "SSL_CLIENT_S_DN_O",
                     "whitelist": ["Default"]
                }
            ]
        }
    ]

.. NOTE::

   The above mapping assume openstack_services group already exist and have
   the proper role assignments (i.e. allow token validation) If not, it will
   need to be created.

To create a mapping using OpenStack CLI, assuming the mapping is saved into
a file ``x509_tokenless_mapping.json``:

.. code-block:: bash

   $ openstack mapping create --rules x509_tokenless_mapping.json x509_tokenless

.. NOTE::

   The mapping ID is arbitrary and it can be any string as opposed to
   IDP ID.

Create a Protocol
-----------------

The name of the protocol must be the same as the one specified by the
``protocol`` option in ``tokenless_auth`` section of the Keystone
configuration file. The protocol name is user designed and it can be any
name as opposed to IDP ID.

A protocol name and an IDP ID will uniquely identify a mapping.

To create a protocol using OpenStack CLI:

.. code-block:: bash

   $ openstack federation protocol create --identity-provider <IDP ID>
     --mapping x509_tokenless x509


.. NOTE::

   If there are multiple trusted issuers, there must be multiple protocol
   created, one for each IDP. All IDP can share a same mapping but the
   combination of IDP ID and protocol must be unique.

----------------------------
SSL Terminator Configuration
----------------------------

Apache Configuration
--------------------

If SSL terminates at Apache mod_ssl, Apache must be configured to handle
two-way SSL and pass the SSL certificate information to the Keystone
application as part of the request environment.

The Client authentication attribute ``SSLVerifyClient`` should be set
as ``optional`` to allow other token authentication methods and
attribute ``SSLOptions`` needs to set as ``+StdEnvVars`` to allow certificate
attributes to be passed. For example,

.. code-block:: ini

    <VirtualHost *:443>
        WSGIScriptAlias / /var/www/cgi-bin/keystone/main
        ErrorLog /var/log/apache2/keystone.log
        CustomLog /var/log/apache2/access.log combined
        SSLEngine on
        SSLCertificateFile    /etc/apache2/ssl/apache.cer
        SSLCertificateKeyFile /etc/apache2/ssl/apache.key
        SSLCACertificatePath /etc/apache2/capath
        SSLOptions +StdEnvVars
        SSLVerifyClient optional
    </VirtualHost>

HAProxy and Apache Configuration
--------------------------------
If SSL terminates at HAProxy and Apache is the API proxy for the Keystone
application, HAProxy must configured to handle two-way SSL and convey
the SSL certificate information via the request headers. Apache in turn will
need to bring those request headers into the request environment.

Here's an example on how to configure HAProxy to handle two-way SSL and
pass the SSL certificate information via the request headers.

.. code-block:: ini

    frontend http-frontend
        mode http
        option forwardfor
        bind 10.1.1.1:5000 ssl crt /etc/keystone/ssl/keystone.pem ca-file /etc/keystone/ssl/ca.pem verify optional

        reqadd X-Forwarded-Proto:\ https if { ssl_fc }
        http-request set-header X-SSL                   %[ssl_fc]
        http-request set-header X-SSL-Client-Verify     %[ssl_c_verify]
        http-request set-header X-SSL-Client-SHA1       %{+Q}[ssl_c_sha1]
        http-request set-header X-SSL-Client-DN         %{+Q}[ssl_c_s_dn]
        http-request set-header X-SSL-Client-CN         %{+Q}[ssl_c_s_dn(cn)]
        http-request set-header X-SSL-Client-O          %{+Q}[ssl_c_s_dn(o)]
        http-request set-header X-SSL-Issuer            %{+Q}[ssl_c_i_dn]
        http-request set-header X-SSL-Issuer-CN         %{+Q}[ssl_c_i_dn(cn)]

When the request gets to the Apache Keystone API Proxy, Apache will need to
bring those SSL headers into the request environment. Here's an example on
how to configure Apache to achieve that.

.. code-block:: ini

    <VirtualHost 192.168.0.10:5000>
        WSGIScriptAlias / /var/www/cgi-bin/keystone/main

        # Bring the needed SSL certificate attributes from HAProxy into the
        # request environment
        SetEnvIf X-SSL-Issuer "^(.*)$" SSL_CLIENT_I_DN=$0
        SetEnvIf X-SSL-Issuer-CN "^(.*)$" SSL_CLIENT_I_DN_CN=$0
        SetEnvIf X-SSL-Client-CN "^(.*)$" SSL_CLIENT_S_DN_CN=$0
        SetEnvIf X-SSL-Client-O "^(.*)$" SSL_CLIENT_S_DN_O=$0
    </VirtualHost>


-------------------------------
Setup ``auth_token`` middleware
-------------------------------

In order to use ``auth_token`` middleware as the service client for X.509
tokenless authorization, both configurable options and scope information
will need to be setup.

Configurable Options
--------------------

The following configurable options in ``auth_token`` middleware
should set to the correct values:


* ``auth_type`` - Must set to ``v3tokenlessauth``.
* ``certfile`` - Set to the full path of the certificate file.
* ``keyfile`` - Set to the full path of the private key file.
* ``cafile`` - Set to the full path of the trusted CA certificate file.
* ``project_name`` or ``project_id`` - set to the scoped project.
* ``project_domain_name`` or ``project_domain_id`` - if ``project_name`` is
  specified.

Here's an example of ``auth_token`` middleware configuration using X.509
tokenless authorization for user token validation.

.. code-block:: ini

    [keystone_authtoken]
    memcached_servers = localhost:11211
    cafile = /etc/keystone/ca.pem
    project_domain_name = Default
    project_name = service
    auth_url = https://192.168.0.10/identity/v3
    auth_type = v3tokenlessauth
    certfile = /etc/glance/certs/glance.pem
    keyfile = /etc/glance/private/glance_private_key.pem

