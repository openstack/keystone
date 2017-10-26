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

Setup Web Single Sign-On (SSO)
==============================

----------------
Keystone Changes
----------------

1. Update `trusted_dashboard` in keystone.conf.

Specify URLs of trusted horizon servers. This value may be repeated
multiple times. This setting ensures that keystone only sends token data back
to trusted servers. This is performed as a precaution, specifically to
prevent man-in-the-middle (MITM) attacks.

.. code-block:: ini

  [federation]
  trusted_dashboard = http://acme.horizon.com/auth/websso/
  trusted_dashboard = http://beta.horizon.com/auth/websso/

2. Update httpd vhost file with websso information.

The `/v3/auth/OS-FEDERATION/websso/<protocol>` and
`/v3/auth/OS-FEDERATION/identity_providers/{idp_id}/protocols/{protocol_id}/websso`
routes must be protected by the chosen httpd module. This is performed so the
request that originates from horizon will use the same identity provider that
is configured in keystone.

.. WARNING::
    By using the IdP specific route, a user will no longer leverage the Remote
    ID of a specific Identity Provider, and will be unable to verify that the
    Identity Provider is trusted, the mapping will remain as the only means to
    controlling authorization.

If `mod_shib` is used, then use the following as an example:

.. code-block:: none

  <VirtualHost *:5000>

      ...

      <Location ~ "/v3/auth/OS-FEDERATION/websso/saml2">
        AuthType shibboleth
        Require valid-user
        ShibRequestSetting requireSession 1
        ShibRequireSession On
        ShibExportAssertion Off
      </Location>
      <Location ~ "/v3/auth/OS-FEDERATION/identity_providers/myidp/protocols/saml2/websso">
        AuthType shibboleth
        Require valid-user
      </Location>
  </VirtualHost>

If `mod_auth_openidc` is used, then use the following as an example:

.. code-block:: none

  <VirtualHost *:5000>

      OIDCRedirectURI http://localhost:5000/v3/auth/OS-FEDERATION/websso
      OIDCRedirectURI http://localhost:5000/v3/auth/OS-FEDERATION/identity_providers/myidp/protocols/openid/websso

      ...

      <Location ~ "/v3/auth/OS-FEDERATION/websso/openid">
        AuthType openid-connect
        Require valid-user
        ...
      </Location>
      <Location ~ "/v3/auth/OS-FEDERATION/identity_providers/myidp/protocols/openid/websso">
        AuthType openid-connect
        Require valid-user
        ...
      </Location>
  </VirtualHost>

If `mod_auth_kerb` is used, then use the following as an example:

.. code-block:: none

  <VirtualHost *:5000>

      ...

      <Location ~ "/v3/auth/OS-FEDERATION/websso/kerberos">
        AuthType Kerberos
        AuthName "Acme Corporation"
        KrbMethodNegotiate on
        KrbMethodK5Passwd off
        Krb5Keytab /etc/apache2/http.keytab
        ...
      </Location>
      <Location ~ "/v3/auth/OS-FEDERATION/identity_providers/myidp/protocols/kerberos/websso">
        AuthType Kerberos
        AuthName "Acme Corporation"
        KrbMethodNegotiate on
        KrbMethodK5Passwd off
        Krb5Keytab /etc/apache2/http.keytab
        ...
      </Location>
  </VirtualHost>

If `mod_auth_mellon` is used, then use the following as an example:

.. code-block:: none

  <VirtualHost *:5000>

      ...

      <Location ~ "/v3/auth/OS-FEDERATION/websso/saml2">
        AuthType Mellon
        MellonEnable auth
        Require valid-user
        ...
      </Location>
      <Location ~ "/v3/auth/OS-FEDERATION/identity_providers/myidp/protocols/saml2/websso">
        AuthType Mellon
        MellonEnable auth
        Require valid-user
        ...
      </Location>
  </VirtualHost>

.. NOTE::
    If you are also using SSO via the API, don't forget to make the Location
    settings match your configuration used for the keystone identity provider
    location:
    `/v3/OS-FEDERATION/identity_providers/<idp>/protocols/<protocol>/auth`

3. Update `remote_id_attribute` in keystone.conf.

A remote id attribute indicates the header to retrieve from the WSGI
environment. This header contains information about the identity
of the identity provider. For `mod_shib` this would be
``Shib-Identity-Provider``, for `mod_auth_openidc`, this could be
``HTTP_OIDC_ISS``.  For `mod_auth_mellon`, this could be ``MELLON_IDP``.

It is recommended that this option be set on a per-protocol basis.

.. code-block:: ini

  [saml2]
  remote_id_attribute = Shib-Identity-Provider
  [openid]
  remote_id_attribute = HTTP_OIDC_ISS

Alternatively, a generic option may be set at the `[federation]` level.

.. code-block:: ini

  [federation]
  remote_id_attribute = HTTP_OIDC_ISS

4. Copy the `sso_callback_template.html
<https://git.openstack.org/cgit/openstack/keystone/plain/etc/sso_callback_template.html>`__
template into the location specified by `[federation]/sso_callback_template`.

---------------
Horizon Changes
---------------

.. NOTE::

    Django OpenStack Auth version 1.2.0 or higher is required for these steps.

    Identity provider and federation protocol specific webSSO is only available
    in Django OpenStack Auth version 2.0.0 or higher.

1. Set the `WEBSSO_ENABLED` option.

Ensure the `WEBSSO_ENABLED` option is set to True in horizon's local_settings.py file,
this will provide users with an updated login screen for horizon.

.. code-block:: python

  WEBSSO_ENABLED = True

2. (Optional) Create a list of authentication methods with the
   `WEBSSO_CHOICES` option.

Within horizon's settings.py file, a list of supported authentication methods can be
specified. The list includes Keystone federation protocols such as OpenID Connect and
SAML, and also keys that map to specific identity provider and federation protocol
combinations (as defined in `WEBSSO_IDP_MAPPING`). With the exception of ``credentials``
which is reserved by horizon, and maps to the user name and password used by keystone's
identity backend.

.. code-block:: python

  WEBSSO_CHOICES = (
        ("credentials", _("Keystone Credentials")),
        ("openid", _("OpenID Connect")),
        ("saml2", _("Security Assertion Markup Language")),
        ("myidp_openid", "Acme Corporation - OpenID Connect"),
        ("myidp_saml2", "Acme Corporation - SAML2")
      )

3. (Optional) Create a dictionary of specific identity provider and federation
   protocol combinations.

A dictionary of specific identity provider and federation protocol combinations.
From the selected authentication mechanism, the value will be looked up as keys
in the dictionary. If a match is found, it will redirect the user to a identity
provider and federation protocol specific WebSSO endpoint in keystone, otherwise
it will use the value as the protocol_id when redirecting to the WebSSO by
protocol endpoint.

.. code-block:: python

  WEBSSO_IDP_MAPPING = {
        "myidp_openid": ("myidp", "openid"),
        "myidp_saml2": ("myidp", "saml2")
      }

.. NOTE::

    The value is expected to be a tuple formatted as: (<idp_id>, <protocol_id>).

6. (Optional) Specify an initial choice with the `WEBSSO_INITIAL_CHOICE`
   option.

The list set by the `WEBSSO_CHOICES` option will be generated in a drop-down
menu in the login screen. The setting `WEBSSO_INITIAL_CHOICE` will
automatically set that choice to be highlighted by default.

.. code-block:: python

  WEBSSO_INITIAL_CHOICE = "credentials"

7. Restart your web server:

.. code-block:: bash

   $ sudo service apache2 restart
