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

===============================
Keystone Federation and Horizon
===============================

Keystone Changes
================

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

.. code-block:: xml

  <VirtualHost *:5000>

      ...

      <Location ~ "/v3/auth/OS-FEDERATION/websso/saml2">
        AuthType shibboleth
        Require valid-user
        ...
      </Location>
      <Location ~ "/v3/auth/OS-FEDERATION/identity_providers/idp_1/protocols/saml2/websso">
        AuthType shibboleth
        Require valid-user
        ...
      </Location>
  </VirtualHost>

If `mod_auth_openidc` is used, then use the following as an example:

.. code-block:: xml

  <VirtualHost *:5000>

      OIDCRedirectURI http://localhost:5000/v3/auth/OS-FEDERATION/websso/redirect
      OIDCRedirectURI http://localhost:5000/v3/auth/OS-FEDERATION/identity_providers/idp_1/protocol/oidc/websso/redirect

      ...

      <Location ~ "/v3/auth/OS-FEDERATION/websso/oidc">
        AuthType openid-connect
        Require valid-user
        ...
      </Location>
      <Location ~ "/v3/auth/OS-FEDERATION/identity_providers/idp_1/protocols/oidc/websso">
        AuthType openid-connect
        Require valid-user
        ...
      </Location>
  </VirtualHost>

If `mod_auth_kerb` is used, then use the following as an example:

.. code-block:: xml

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
      <Location ~ "/v3/auth/OS-FEDERATION/identity_providers/idp_1/protocols/kerberos/websso">
        AuthType Kerberos
        AuthName "Acme Corporation"
        KrbMethodNegotiate on
        KrbMethodK5Passwd off
        Krb5Keytab /etc/apache2/http.keytab
        ...
      </Location>
  </VirtualHost>

If `mod_auth_mellon` is used, then use the following as an example:

.. code-block:: xml

  <VirtualHost *:5000>

      ...

      <Location ~ "/v3/auth/OS-FEDERATION/websso/saml2">
        AuthType Mellon
        MellonEnable auth
        Require valid-user
        ...
      </Location>
      <Location ~ "/v3/auth/OS-FEDERATION/identity_providers/idp_1/protocols/saml2/websso">
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
  [oidc]
  remote_id_attribute = HTTP_OIDC_ISS

Alternatively, a generic option may be set at the `[federation]` level.

.. code-block:: ini

  [federation]
  remote_id_attribute = HTTP_OIDC_ISS

4. Set `remote_ids` for a keystone identity provider using the API or CLI.

A keystone identity provider may have multiple `remote_ids` specified, this
allows the same *keystone* identity provider resource to be used with multiple
external identity providers. For example, an identity provider resource
``university-idp``, may have the following `remote_ids`:
``['university-x', 'university-y', 'university-z']``.
This removes the need to configure N identity providers in keystone.

This can be performed using the `OS-FEDERATION API`_:
``PATCH /OS-FEDERATION/identity_providers/{idp_id}``

Or by using the `OpenStackClient CLI`_:

.. code-block:: bash

    $ openstack identity provider set --remote-id <remote-id>  <idp-id>

.. NOTE::

    Remote IDs are globally unique. Two identity providers cannot be
    associated with the same remote ID. Once authenticated with the external
    identity provider, keystone will determine which identity provider
    and mapping to use based on the protocol and the value returned from the
    `remote_id_attribute` key.

    For example, if our identity provider is ``google``, the mapping used is
    ``google_mapping`` and the protocol is ``oidc``. The identity provider's
    remote IDs  would be: [``accounts.google.com``].
    The `remote_id_attribute` value may be set to ``HTTP_OIDC_ISS``, since
    this value will always be ``accounts.google.com``.

    The motivation for this approach is that there will always be some data
    sent by the identity provider (in the assertion or claim) that uniquely
    identifies the identity provider. This removes the requirement for horizon
    to list all the identity providers that are trusted by keystone.

.. _`OpenStackClient CLI`: http://docs.openstack.org/developer/python-openstackclient/command-objects/identity-provider.html#identity-provider-set
.. _`OS-FEDERATION API`: http://specs.openstack.org/openstack/keystone-specs/api/v3/identity-api-v3-os-federation-ext.html#update-identity-provider

Horizon Changes
===============

.. NOTE::

    Django OpenStack Auth version 1.2.0 or higher is required for these steps.

    Identity provider and federation protocol specific webSSO is only available
    in Django OpenStack Auth version 2.0.0 or higher.

1. Set the Identity Service version to 3

Ensure the `OPENSTACK_API_VERSIONS` option in horizon's local_settings.py has
been updated to indicate that the `identity` version to use is `3`.

.. code-block:: python

  OPENSTACK_API_VERSIONS = {
    "identity": 3,
  }

2. Authenticate against Identity Server v3.

Ensure the `OPENSTACK_KEYSTONE_URL` option in horizon's local_settings.py has
been updated to point to a v3 URL.

.. code-block:: python

  OPENSTACK_KEYSTONE_URL = "http://localhost:5000/v3"

3. Set the `WEBSSO_ENABLED` option.

Ensure the `WEBSSO_ENABLED` option is set to True in horizon's local_settings.py file,
this will provide users with an updated login screen for horizon.

.. code-block:: python

  WEBSSO_ENABLED = True

4. (Optional) Create a list of authentication methods with the
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
        ("oidc", _("OpenID Connect")),
        ("saml2", _("Security Assertion Markup Language")),
        ("idp_1_oidc", "Acme Corporation - OpenID Connect"),
        ("idp_1_saml2", "Acme Corporation - SAML2")
      )

5. (Optional) Create a dictionary of specific identity provider and federation
   protocol combinations.

A dictionary of specific identity provider and federation protocol combinations.
From the selected authentication mechanism, the value will be looked up as keys
in the dictionary. If a match is found, it will redirect the user to a identity
provider and federation protocol specific WebSSO endpoint in keystone, otherwise
it will use the value as the protocol_id when redirecting to the WebSSO by
protocol endpoint.

.. code-block:: python

  WEBSSO_IDP_MAPPING = {
        "idp_1_oidc": ("idp_1", "oidc"),
        "idp_1_saml2": ("idp_1", "saml2")
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
