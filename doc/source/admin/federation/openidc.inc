.. -*- rst -*-

..
      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

.. _federation_openidc:

-------------------------
Setting Up OpenID Connect
-------------------------

See :ref:`keystone-as-sp` before proceeding with these OpenIDC-specific
instructions.

When using OpenID Connect, you must have a third party `OpenID Provider or
Identity Provider`_. Some examples of OpenID Connect Providers are Google,
Keycloak, Microsoft Entra, and GitLab. Keystone will use `mod_auth_openidc`_
to enable Keystone to act as an OpenID Connect Relying Party, which is
the name of an application that depends on an OpenID Connect Provider for
identity. You must add an OpenID Connect Client representing the Keystone
Service Provider in your OpenID Connect Provider.

Claims are pieces of user details or attributes provided by the OpenID
Connect Provider to the OpenID Connect Relying Party. Claims can be
retrieved from the ID token or from the UserInfo endpoint. Claims are
requested by specifying scopes, which map to sets of claims.

For the purposes of consistency with the rest of the Keystone documentation,
the term Service Provider will be used which means Keystone acting as
a Service Provider and is equivilent to OpenID Connect Relying Party.

These examples use Google as an OpenID Connect Provider. The Service
Provider must be added to the Identity Provider in the `Google API console`_.

.. _OpenID Provider or Identity Provider: https://openid.net/developers/how-connect-works/
.. _mod_auth_openidc: https://github.com/OpenIDC/mod_auth_openidc
.. _Google API console: https://console.developers.google.com/

Configuring Apache HTTPD for mod_auth_openidc
---------------------------------------------

.. note::

   You are advised to carefully examine the `mod_auth_openidc documentation`_.

.. _mod_auth_openidc documentation: https://github.com/zmartzone/mod_auth_openidc#how-to-use-it

Install the Module
~~~~~~~~~~~~~~~~~~

Install the Apache module package. For example, on Ubuntu:

.. code-block:: console

   # apt-get install libapache2-mod-auth-openidc

The package and module name will differ between distributions.

Configure mod_auth_openidc
~~~~~~~~~~~~~~~~~~~~~~~~~~

In the Apache configuration for the keystone VirtualHost, set the following OIDC
options:

.. code-block:: apache

   OIDCClaimPrefix "OIDC-"
   OIDCClaimDelimiter ";"
   OIDCResponseType "id_token"
   OIDCScope "openid email profile"
   OIDCProviderMetadataURL https://accounts.google.com/.well-known/openid-configuration
   OIDCOAuthVerifyJwksUri https://www.googleapis.com/oauth2/v3/certs
   OIDCClientID <openid_client_id>
   OIDCClientSecret <openid_client_secret>
   OIDCCryptoPassphrase <random string>
   OIDCRedirectURI https://sp.keystone.example.org/v3/redirect_uri

``OIDCClaimPrefix`` prefixes all claims with the value, which will then
be prefixed with ``HTTP_`` when presented to Keystone, with dashes ("-")
converted to underscores ("_") and uppercased. Resulting in the ``iss`` claim
being presented to Keystone as ``HTTP_OIDC_ISS`` using the ``OIDCClaimPrefix``
from above. Claims are pieces of JSON data but Apache only forwards on string
data to Keystone. So by default lists are converted to comma (",") separated
strings while Keystone's mapping code expects them to be semi-colon (";")
separated. To properly support this set the ``OIDCClaimDelimiter`` to utilize
semi-colons (";"). ``OIDCResponseType`` specifies the OpenID Connect Flow
which will be used. To use the Implicit Flow then specify the value ``id_token``
and to use the Authorization Code Flow, specify the value ``code``. Some OpenID
Connect Providers do not enable Implicit Flow by default.
``OIDCScope`` is the list of attributes or claims that the user will authorize the
Identity Provider to send to the Service Provider. ``OIDCClientID`` and
``OIDCClientSecret`` must be generated and obtained from the Identity Provider,
``OIDCProviderMetadataURL`` is a URL from which the Service Provider will fetch
the Identity Provider's metadata. ``OIDCOAuthVerifyJwksUri`` is a URL from
which the Service Provider will download the public key from the Identity
Provider to check if the user's access token is valid or not, this configuration
must be used while using the AuthType ``auth-openidc``, when using the AuthType
``openid-connect`` and the OIDCProviderMetadataURL is configured, this property
will not be necessary.
``OIDCRedirectURI`` is a vanity URL that must
point to a protected path that does not have any content, such as an extension
of the protected federated auth path. It should not match any Keystone API endpoints
or mod_auth_openidc will handle requests to the endpoint instead of Keystone. This
can lead to unusual errors and behaviors from Keystone.

.. note::

   If using a mod_wsgi version less than 4.3.0, then the `OIDCClaimPrefix` must
   be specified to have only alphanumerics or a dash ("-"). This is because
   `mod_wsgi blocks headers that do not fit this criteria`_.

.. _mod_wsgi blocks headers that do not fit this criteria: http://modwsgi.readthedocs.org/en/latest/release-notes/version-4.3.0.html#bugs-fixed

Configure Protected Endpoints
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Configure each protected path to use the ``openid-connect`` AuthType:

.. code-block:: apache

   <Location ~ "/redirect_uri">
       Require valid-user
       AuthType openid-connect
   </Location>
   <Location /v3/OS-FEDERATION/identity_providers/google/protocols/openid/auth>
       Require valid-user
       AuthType openid-connect
   </Location>

.. note::
  To add support to Bearer Access Token authentication flow that is used by
  applications that do not adopt the browser flow, such the OpenStack CLI, you
  will need to change the AuthType from ``openid-connect`` to
  ``auth-openidc``.

Do the same for the WebSSO auth paths if using horizon:

.. code-block:: apache

   <Location /v3/auth/OS-FEDERATION/websso/openid>
       Require valid-user
       AuthType openid-connect
   </Location>
   <Location /v3/auth/OS-FEDERATION/identity_providers/google/protocols/openid/websso>
       Require valid-user
       AuthType openid-connect
   </Location>

Remember to reload Apache after altering the VirtualHost:

.. code-block:: console

   # systemctl reload apache2

.. note::

   When creating :ref:`mapping rules <create_a_mapping>`, in keystone, note that the 'remote'
   attributes will be prefixed, with ``HTTP_``, so for instance, if you set
   ``OIDCClaimPrefix`` to ``OIDC-``, then a typical remote value to check for
   is: ``HTTP_OIDC_ISS``.

Configuring Multiple Identity Providers
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To configure multiples Identity Providers in your environment you will need to
set your OIDC options like the following options:

.. code-block:: apache

    OIDCClaimPrefix "OIDC-"
    OIDCClaimDelimiter ";"
    OIDCResponseType "id_token"
    OIDCScope "openid email profile"
    OIDCMetadataDir <IDP metadata directory>
    OIDCCryptoPassphrase <random string>
    OIDCRedirectURI https://sp.keystone.example.org/redirect_uri
    OIDCOAuthVerifyCertFiles <kid>#</path/to-cert.pem> <kid2>#</path/to-cert2.pem> <kidN>#</path/to-certN.pem>

The ``OIDCOAuthVerifyCertFiles`` is a tuple separated with `space`
containing the key-id (kid) of the Issuer's public key and a path to
the Issuer certificate. The separator ``#`` is used to split the (``kid``)
and the public certificate address

The metadata folder configured in the option ``OIDCMetadataDir`` must have all
your Identity Providers configurations, the name of the files will be
the name (with path) of the Issuers like:

.. code-block::

    - <IDP metadata directory>
      |
      - accounts.google.com.client
      |
      - accounts.google.com.conf
      |
      - accounts.google.com.provider
      |
      - keycloak.example.org%2Fauth%2Frealms%2Fidp.client
      |
      - keycloak.example.org%2Fauth%2Frealms%2Fidp.conf
      |
      - keycloak.example.org%2Fauth%2Frealms%2Fidp.provider

.. note::
  The name of the file must be url-encoded if needed, as the Apache2 mod_auth_openidc
  will get the raw value from the query parameter ``iss`` from the http request
  and check if there is a metadata with this name, as the query parameter is
  url-encoded, so the metadata file name need to be encoded too. For example, if you have an
  Issuer with ``/`` in the URL, then you need to escape it to ``%2F`` by
  applying a URL escape in the file name.

The content of these files must be a JSON like

``accounts.google.com.client``:

.. code-block:: json

    {
      "client_id":"<openid_client_id>",
      "client_secret":"<openid_client_secret>"
    }

The ``.client`` file handles the SP credentials in the Issuer.

``accounts.google.com.conf``:

This file will be a JSON that overrides some of OIDC options. The options
that are able to be overridden are listed in the
`OpenID Connect Apache2 plugin documentation`_.

.. _`OpenID Connect Apache2 plugin documentation`: https://github.com/zmartzone/mod_auth_openidc/wiki/Multiple-Providers#opclient-configuration

If you do not want to override the config values, you can leave this file as
an empty JSON like ``{}``.

``accounts.google.com.provider``:

This file will contain all specifications about the IdentityProvider. To
simplify, you can just use the JSON returned in the ``.well-known`` endpoint:

.. code-block:: json

  {
    "issuer": "https://accounts.google.com",
    "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
    "token_endpoint": "https://oauth2.googleapis.com/token",
    "userinfo_endpoint": "https://openidconnect.googleapis.com/v1/userinfo",
    "revocation_endpoint": "https://oauth2.googleapis.com/revoke",
    "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
    "response_types_supported": [
     "code",
     "token",
     "id_token",
     "code token",
     "code id_token",
     "token id_token",
     "code token id_token",
     "none"
    ],
    "subject_types_supported": [
     "public"
    ],
    "id_token_signing_alg_values_supported": [
     "RS256"
    ],
    "scopes_supported": [
     "openid",
     "email",
     "profile"
    ],
    "token_endpoint_auth_methods_supported": [
     "client_secret_post",
     "client_secret_basic"
    ],
    "claims_supported": [
     "aud",
     "email",
     "email_verified",
     "exp",
     "family_name",
     "given_name",
     "iat",
     "iss",
     "locale",
     "name",
     "picture",
     "sub"
    ],
    "code_challenge_methods_supported": [
     "plain",
     "S256"
    ]
  }

Continue configuring keystone
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

:ref:`Continue configuring keystone <federation_configuring_keystone>`
