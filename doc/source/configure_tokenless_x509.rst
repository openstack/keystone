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

.. NOTE::

    This feature is experimental and unsupported in Liberty.

-----------
Definitions
-----------

* `X.509 Tokenless Authorization`: Provides a means to authorize client
  operations within Keystone by using an X.509 SSL client certificate
  without having to issue a token. For details, please refer to the specs
  `Tokenless Authorization with X.509 Client SSL Certificate`_

.. _`Tokenless Authorization with X.509 Client SSL Certificate`: http://specs.openstack.org/openstack/keystone-specs/specs/liberty/keystone-tokenless-authz-with-x509-ssl-client-cert.html

Prerequisites
-------------

Keystone must be running in a web container with https enabled; tests have
been done with Apache/2.4.7 running on Ubuntu 14.04 . Please refer to
`running-keystone-in-httpd`_ and `apache-certificate-and-key-installation`_
as references for this setup.

.. _`running-keystone-in-httpd`: http://docs.openstack.org/developer/keystone/apache-httpd.html
.. _`apache-certificate-and-key-installation`: https://www.digitalocean.com/community/tutorials/how-to-create-a-ssl-certificate-on-apache-for-ubuntu-14-04

--------------------
Apache Configuration
--------------------

To enable X.509 tokenless authorization, SSL has to be enabled and configured
in the Apache virtual host file. The Client authentication attribute
``SSLVerifyClient`` should be set as ``optional`` to allow other token
authentication methods and attribute ``SSLOptions`` needs to set as
``+StdEnvVars`` to allow certificate attributes to be passed. The following
is the sample virtual host file used for the testing.

.. code-block:: ini

    <VirtualHost *:443>
        WSGIScriptAlias / /var/www/cgi-bin/keystone/main
        ErrorLog /var/log/apache2/keystone.log
        LogLevel debug
        CustomLog /var/log/apache2/access.log combined
        SSLEngine on
        SSLCertificateFile    /etc/apache2/ssl/apache.cer
        SSLCertificateKeyFile /etc/apache2/ssl/apache.key
        SSLCACertificatePath /etc/apache2/capath
        SSLOptions +StdEnvVars
        SSLVerifyClient optional
    </VirtualHost>

----------------------
Keystone Configuration
----------------------

The following options can be defined in `keystone.conf`:

* ``trusted_issuer`` - The multi-str list of trusted issuers to further
  filter the certificates that are allowed to participate in the X.509
  tokenless authorization. If the option is absent then no certificates
  will be allowed. The naming format for the attributes of a Distinguished
  Name(DN) must be separated by a comma and contain no spaces; however
  spaces are allowed for the value of an attribute, like 'L=San Jose' in
  the example below. This configuration option may be repeated for multiple
  values. Please look at the sample below.
* ``protocol`` - The protocol name for the X.509 tokenless authorization
  along with the option `issuer_attribute` below can look up its
  corresponding mapping. It defaults to ``x509``.
* ``issuer_attribute`` - The issuer attribute that is served as an IdP ID for
  the X.509 tokenless authorization along with the protocol to look up its
  corresponding mapping. It is the environment variable in the WSGI
  enviornment that references to the Issuer of the client certificate. It
  defaults to ``SSL_CLIENT_I_DN``.

This is a sample configuration for two `trusted_issuer` and a `protocol` set
to ``x509``.

.. code-block:: ini

    [tokenless_auth]
    trusted_issuer = emailAddress=mary@abc.com,CN=mary,OU=eng,O=abc,L=San Jose,ST=California,C=US
    trusted_issuer = emailAddress=john@openstack.com,CN=john,OU=keystone,O=openstack,L=Sunnyvale,ST=California,C=US
    protocol = x509

-------------
Setup Mapping
-------------

Like federation, X.509 tokenless authorization also utilizes the mapping
mechanism to formulate an identity. The identity provider must correspond
to the issuer of the X.509 SSL client certificate. The protocol for the
given identity is ``x509`` by default, but can be configurable.

Create an Identity Provider(IdP)
--------------------------------

In order to create an IdP, the issuer DN in the client certificate needs
to be provided. The following sample is what a generic issuer DN looks
like in a certificate.

.. code-block:: ini

    E=john@openstack.com
    CN=john
    OU=keystone
    O=openstack
    L=Sunnyvale
    S=California
    C=US

The issuer DN should be constructed as a string that contains no spaces
and have the right order seperated by commas like the example below.
Please be aware that ``emailAddress`` and ``ST`` should be used instead
of ``E`` and ``S`` that are shown in the above example. The following is
the sample Python code used to create the IdP ID.

.. code-block:: python

    import hashlib
    issuer_dn = 'emailAddress=john@openstack.com,CN=john,OU=keystone,
        O=openstack,L=Sunnyvale,ST=California,C=US'
    hashed_idp = hashlib.sha256(issuer_dn)
    idp_id = hashed_idp.hexdigest()
    print(idp_id)

The output of the above Python code will be the IdP ID and the following
sample curl command should be sent to keystone to create an IdP with the
newly generated IdP ID.

.. code-block:: bash

    curl -k -s -X PUT -H "X-Auth-Token: <TOKEN>" \
         -H "Content-Type: application/json" \
         -d '{"identity_provider": {"description": "Stores keystone IDP identities.","enabled": true}}' \
         https://<HOSTNAME>:<PORT>/v3/OS-FEDERATION/identity_providers/<IdP ID>

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

    {
         "mapping": {
             "rules": [
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
                            "type": "SSL_CLIENT_S_DN_CN"
                        },
                        {
                            "type": "SSL_CLIENT_S_DN_O"
                        }
                    ]
                }
            ]
        }
    }

When user's ``type`` is not defined or set to ``ephemeral``, the mapped user
does not have to be a valid local user but the mapping must yield at least
one valid local group. For example:

.. code-block:: javascript

    {
         "mapping": {
             "rules": [
                 {
                     "local": [
                         {
                            "user": {
                                "name": "{0}",
                                "type": "ephemeral"
                            }
                         },
                         {
                            "group": {
                                "id": "12345678"
                            }
                         }
                    ],
                    "remote": [
                        {
                            "type": "SSL_CLIENT_S_DN_CN"
                        }
                    ]
                }
            ]
        }
    }

The following sample curl command should be sent to keystone to create a
mapping with the provided mapping ID. The mapping ID is user designed and
it can be any string as opposed to IdP ID.

.. code-block:: bash

    curl -k -s -H "X-Auth-Token: <TOKEN>" \
         -H "Content-Type: application/json" \
         -d '{"mapping": {"rules": [{"local": [{"user": {"name": "{0}","type": "ephemeral"}},{"group": {"id": "<GROUPID>"}}],"remote": [{"type": "SSL_CLIENT_S_DN_CN"}]}]}}' \
         -X PUT https://<HOSTNAME>:<PORT>/v3/OS-FEDERATION/mappings/<MAPPING ID>


Create a Protocol
-----------------

The name of the protocol will be the one defined in `keystone.conf` as
``protocol`` which defaults to ``x509``. The protocol name is user designed
and it can be any name as opposed to IdP ID.

A protocol name and an IdP ID will uniquely identify a mapping.

The following sample curl command should be sent to keystone to create a
protocol with the provided protocol name that is defined in `keystone.conf`.

.. code-block:: bash

    curl -k -s -H "X-Auth-Token: <TOKEN>" \
         -H "Content-Type: application/json" \
         -d '{"protocol": {"mapping_id": "<MAPPING ID>"}}' \
         -X PUT https://<HOSTNAME>:<PORT>/v3/OS-FEDERATION/identity_providers/<IdP ID>/protocols/<PROTOCOL NAME>

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

* ``auth_protocol`` - Set to ``https``.
* ``certfile`` - Set to the full path of the certificate file.
* ``keyfile`` - Set to the full path of the private key file.
* ``cafile`` - Set to the full path of the trusted CA certificate file.

Scope Information
-----------------

The scope information will be passed from the headers with the following
header attributes to:

* ``X-Project-Id`` - If specified, its the project scope.
* ``X-Project-Name`` - If specified, its the project scope.
* ``X-Project-Domain-Id`` - If specified, its the domain of project scope.
* ``X-Project-Domain-Name`` - If specified, its the domain of project scope.
* ``X-Domain-Id`` - If specified, its the domain scope.
* ``X-Domain-Name`` - If specified, its the domain scope.

---------------------
Test It Out with cURL
---------------------

Once the above configurations have been setup, the following curl command can
be used for token validation.

.. code-block:: bash

    curl -v -k -s -X GET --cert /<PATH>/x509client.crt \
         --key /<PATH>/x509client.key \
         --cacert /<PATH>/ca.crt \
         -H "X-Project-Name: <PROJECT-NAME>" \
         -H "X-Project-Domain-Id: <PROJECT-DOMAIN-ID>" \
         -H "X-Subject-Token: <TOKEN>" \
         https://<HOST>:<PORT>/v3/auth/tokens | python -mjson.tool

Details of the Options
----------------------

* ``--cert`` - The client certificate that will be presented to Keystone.
  The ``Issuer`` in the certificate along with the defined ``protocol``
  in `keystone.conf` will uniquely identify the mapping. The ``Subject``
  in the certificate will be mapped to the valid local user from the
  identified mapping.
* ``--key`` - The corresponding client private key.
* ``--cacert`` - It can be the Apache server certificate or its issuer
  (signer) certificate.
* ``X-Project-Name`` - The project scope needs to be passed in the header.
* ``X-Project-Domain-Id`` - Its the domain of project scope.
* ``X-Subject-Token`` - The token to be validated.

