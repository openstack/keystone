:orphan:

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

====================
Setup OpenID Connect
====================

Configuring mod_auth_openidc
============================

Federate Keystone (SP) and an external IdP using OpenID Connect (`mod_auth_openidc`_)

.. _`mod_auth_openidc`: https://github.com/pingidentity/mod_auth_openidc

To install `mod_auth_openidc` on Ubuntu, perform the following:

.. code-block:: bash

  sudo apt-get install libapache2-mod-auth-openidc

This module is available for other distributions (Fedora/CentOS/Red Hat) from:
https://github.com/pingidentity/mod_auth_openidc/releases

In the keystone Apache site file, add the following as a top level option, to
load the `mod_auth_openidc` module:

.. code-block:: xml

  LoadModule auth_openidc_module /usr/lib/apache2/modules/mod_auth_openidc.so

Also within the same file, locate the virtual host entry and add the following
entries for OpenID Connect:

.. code-block:: xml

  <VirtualHost *:5000>

      ...

      OIDCClaimPrefix "OIDC-"
      OIDCResponseType "id_token"
      OIDCScope "openid email profile"
      OIDCProviderMetadataURL <url_of_provider_metadata>
      OIDCClientID <openid_client_id>
      OIDCClientSecret <openid_client_secret>
      OIDCCryptoPassphrase openstack
      OIDCRedirectURI http://localhost:5000/v3/OS-FEDERATION/identity_providers/<idp_id>/protocols/oidc/auth/redirect

      <LocationMatch /v3/OS-FEDERATION/identity_providers/.*?/protocols/oidc/auth>
        AuthType openid-connect
        Require valid-user
        LogLevel debug
      </LocationMatch>
  </VirtualHost>

Note an example of an `OIDCProviderMetadataURL` instance is: https://accounts.google.com/.well-known/openid-configuration
If not using `OIDCProviderMetadataURL`, then the following attributes
must be specified: `OIDCProviderIssuer`, `OIDCProviderAuthorizationEndpoint`,
`OIDCProviderTokenEndpoint`, `OIDCProviderTokenEndpointAuth`,
`OIDCProviderUserInfoEndpoint`, and `OIDCProviderJwksUri`

Note, if using a mod_wsgi version less than 4.3.0, then the `OIDCClaimPrefix`
must be specified to have only alphanumerics or a dash ("-"). This is because
mod_wsgi blocks headers that do not fit this criteria. See http://modwsgi.readthedocs.org/en/latest/release-notes/version-4.3.0.html#bugs-fixed
for more details

Once you are done, restart your Apache daemon:

.. code-block:: bash

    $ service apache2 restart

Tips
====

1. When creating a mapping, note that the 'remote' attributes will be prefixed,
   with `HTTP_`, so for instance, if you set OIDCClaimPrefix to `OIDC-`, then a
   typical remote value to check for is: `HTTP_OIDC_ISS`.

2. Don't forget to add oidc as an [auth] plugin in keystone.conf, see `Step 2`_

.. _`Step 2`: federation/federation.html
