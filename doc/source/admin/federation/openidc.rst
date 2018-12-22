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

-------------------------
Setting Up OpenID Connect
-------------------------

See :ref:`keystone-as-sp` before proceeding with these OpenIDC-specific
instructions.

These examples use Google as an OpenID Connect Identity Provider. The Service
Provider must be added to the Identity Provider in the `Google API console`_.

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
   OIDCResponseType "id_token"
   OIDCScope "openid email profile"
   OIDCProviderMetadataURL https://accounts.google.com/.well-known/openid-configuration
   OIDCClientID <openid_client_id>
   OIDCClientSecret <openid_client_secret>
   OIDCCryptoPassphrase <random string>
   OIDCRedirectURI https://sp.keystone.example.org/v3/OS-FEDERATION/identity_providers/google/protocols/openid/auth

``OIDCScope`` is the list of attributes that the user will authorize the
Identity Provider to send to the Service Provider. ``OIDCClientID`` and
``OIDCClientSecret`` must be generated and obtained from the Identity Provider.
``OIDCProviderMetadataURL`` is a URL from which the Service Provider will fetch
the Identity Provider's metadata. ``OIDCRedirectURI`` is a vanity URL that must
point to a protected path that does not have any content, such as an extension
of the protected federated auth path.

.. note::

   If using a mod_wsgi version less than 4.3.0, then the `OIDCClaimPrefix` must
   be specified to have only alphanumerics or a dash ("-"). This is because
   `mod_wsgi blocks headers that do not fit this criteria`_.

.. _mod_wsgi blocks headers that do not fit this criteria: http://modwsgi.readthedocs.org/en/latest/release-notes/version-4.3.0.html#bugs-fixed

Configure Protected Endpoints
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Configure each protected path to use the ``openid-connect`` AuthType:

.. code-block:: apache

   <Location /v3/OS-FEDERATION/identity_providers/google/protocols/openid/auth>
       Require valid-user
       AuthType openid-connect
   </Location>

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

   When creating `mapping rules`_, in keystone, note that the 'remote'
   attributes will be prefixed, with ``HTTP_``, so for instance, if you set
   ``OIDCClaimPrefix`` to ``OIDC-``, then a typical remote value to check for
   is: ``HTTP_OIDC_ISS``.

.. _`mapping rules`: configure_federation.html#mapping

Continue configuring keystone
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

`Continue configuring keystone`_

.. _Continue configuring keystone: configure_federation.html#configuring-keystone
