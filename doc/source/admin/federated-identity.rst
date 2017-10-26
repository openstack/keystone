==================
Federated Identity
==================

You can use federation for the Identity service (keystone) in two ways:

* Supporting keystone as a :abbr:`SP (Service Provider)`: consuming identity
  assertions issued by an external Identity Provider, such as SAML
  assertions or OpenID Connect claims.
* Supporting keystone as an :abbr:`IdP (Identity Provider)`: fulfilling
  authentication requests on behalf of Service Providers.

  .. note::

      It is also possible to have one keystone act as an SP that
      consumes Identity from another keystone acting as an IdP.

There is currently support for two major federation protocols:

* `SAML <https://en.wikipedia.org/wiki/SAML_2.0>`_
* `OpenID Connect <https://en.wikipedia.org/wiki/OpenID_Connect>`_

.. figure:: figures/keystone-federation.png
   :width: 100%

   Keystone federation

To enable federation:

#. Run keystone under Apache. See `Configure the Apache HTTP server
   <https://docs.openstack.org/ocata/install-guide-obs/keystone-install.html>`_
   for more information.

   .. note::

      Other application servers, such as `nginx <https://www.nginx.com/resources/wiki>`_,
      have support for federation extensions that may work but are not tested
      by the community.

#. Configure Apache to use a federation capable module.
   We recommend Shibboleth, see :doc:`the Shibboleth documentation<../advanced-topics/federation/shibboleth>` for more information.

   .. note::

      Another option is ``mod_auth_melon``, see `the mod's github repo <https://github.com/UNINETT/mod_auth_mellon>`_
      for more information.

#. Configure federation in keystone.

.. note::

   The external IdP is responsible for authenticating users and communicates
   the result of authentication to keystone using authentication assertions.
   Keystone maps these values to keystone user groups and assignments
   created in keystone.

Supporting keystone as a SP
~~~~~~~~~~~~~~~~~~~~~~~~~~~

To have keystone as an SP, you will need to configure
keystone to accept assertions from external IdPs. Examples of external
IdPs are:

* :abbr:`ADFS (Active Directory Federation Services)`
* FreeIPA
* Tivoli Access Manager
* Keystone

Configuring federation in keystone
----------------------------------

#. Configure authentication drivers in ``keystone.conf`` by adding the
   authentication methods to the ``[auth]`` section in ``keystone.conf``.
   Ensure the names are the same as to the protocol names added via Identity
   API v3.

   For example:

   .. code-block:: ini

      [auth]
      methods = external,password,token,saml2,openid

   .. note::

      ``saml2`` and ``openid`` are instances of the ``mapped`` plugin. These
      must match the name of the of the federation protocol created via the
      Identity API. The other names in the example are not related to
      federation.

#. Create local keystone groups and assign roles.

   .. important::

      The keystone requires group-based role assignments to authorize
      federated users. The federation mapping engine maps federated users into
      local user groups, which are the actors in keystone's role assignments.

#. Create an IdP object in keystone. The object must represent the
   IdP you will use to authenticate end users:

   .. code:: ini

      PUT /OS-FEDERATION/identity_providers/{idp_id}

   More configuration information for IdPs can be found `Register an Identity Provider <https://developer.openstack.org/api-ref/identity/v3-ext/index.html#register-an-identity-provider>`_.

#. Add mapping rules:

   .. code:: ini

      PUT /OS-FEDERATION/mappings/{mapping_id}

   More configuration information for mapping rules can be found `Create a mapping <https://developer.openstack.org/api-ref/identity/v3-ext/index.html#create-a-mapping>`_.

   .. note::

       The only keystone API objects that support mapping are groups and users.

#. Add a protocol object and specify the mapping ID you want to use with the
   combination of the IdP and protocol:

   .. code:: ini

      PUT /OS-FEDERATION/identity_providers/{idp_id}/protocols/{protocol_id}

   More configuration information for protocols can be found `Add a protocol and attribute mapping to an identity provider <https://developer.openstack.org/api-ref/identity/v3-ext/index.html#add-a-protocol-and-attribute-mapping-to-an-identity-provider>`_.

Performing federated authentication
-----------------------------------

#. Authenticate externally and generate an unscoped token in keystone:

   .. note::

      Unlike other authentication methods in keystone, the user does
      not issue an HTTP POST request with authentication data in the request body.
      To start federated authentication a user must access the dedicated URL with
      IdP's and protocol's identifiers stored within a protected URL.
      The URL has a format of:
      ``/v3/OS-FEDERATION/identity_providers/{idp_id}/protocols/{protocol_id}/auth``.

   .. code:: ini

      GET/POST /OS-FEDERATION/identity_providers/{identity_provider}/protocols/{protocol}/auth

#. Determine accessible resources. By using the previously returned token, the
   user can issue requests to the list projects and domains that are
   accessible.

   * List projects a federated user can access: GET /OS-FEDERATION/projects
   * List domains a federated user can access: GET /OS-FEDERATION/domains

   .. code:: ini

      GET /OS-FEDERATION/projects

#. Get a scoped token. A federated user can request a scoped token using
   the unscoped token. A project or domain can be specified by either ID or
   name. An ID is sufficient to uniquely identify a project or domain.

   .. code:: ini

      POST /auth/tokens

Supporting keystone as an IdP
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When acting as an IdP, the primary role of keystone is
to issue assertions about users owned by keystone. This is done using PySAML2.

Configuring federation in keystone
----------------------------------

There are certain settings in ``keystone.conf`` that must be set up, prior
to attempting to federate multiple keystone deployments.

#. Within ``keystone.conf``, assign values to the ``[saml]``
   related fields, for example:

   .. code:: ini

      [saml]
      certfile=/etc/keystone/ssl/certs/ca.pem
      keyfile=/etc/keystone/ssl/private/cakey.pem
      idp_entity_id=https://keystone.example.com/v3/OS-FEDERATION/saml2/idp
      idp_sso_endpoint=https://keystone.example.com/v3/OS-FEDERATION/saml2/sso
      idp_metadata_path=/etc/keystone/saml2_idp_metadata.xml

#. We recommend the following `Organization` configuration options.
   Ensure these values contain not special characters that may cause
   problems as part of a URL:

   .. code:: ini

      idp_organization_name=example_company
      idp_organization_display_name=Example Corp.
      idp_organization_url=example.com

#. As with the `Organization` options, the `Contact` options are not
   necessary, but it is advisable to set these values:

   .. code:: ini

      idp_contact_company=example_company
      idp_contact_name=John
      idp_contact_surname=Smith
      idp_contact_email=jsmith@example.com
      idp_contact_telephone=555-55-5555
      idp_contact_type=technical

Generate metadata
-----------------

Metadata must be exchanged to create a trust between the IdP and the SP.

#. Create metadata for your keystone IdP, run the ``keystone-manage`` command
   and pipe the output to a file. For example:

   .. code:: console

      $ keystone-manage saml_idp_metadata > /etc/keystone/saml2_idp_metadata.xml

   .. note::

      The file location must match the value of the ``idp_metadata_path``
      configuration option assigned previously.

Create a SP
-----------

To setup keystone-as-a-Service-Provider properly, you will need to
understand what protocols are supported by external IdPs.
For example, keystone as an SP can allow identities to federate in from a
ADFS IdP but it must be configured to understand the SAML v2.0 protocol.
ADFS issues assertions using SAML v2.0. Some examples
of federated protocols include:

* SAML v2.0
* OpenID Connect

The following instructions are an example of how you can configure
keystone as an SP.

#. Create a new SP with an ID of BETA.

#. Create a ``sp_url`` of `<http://beta.example.com/Shibboleth.sso/SAML2/ECP>`_.

#. Create a ``auth_url`` of `<http://beta.example.com:5000/v3/OS-FEDERATION/identity_providers/beta/protocols/saml2/auth>`_.

   .. note::

      Use the ``sp_url`` when creating a SAML assertion for BETA and signed by
      the current keystone IdP. Use the ``auth_url`` when retrieving the token
      for BETA once the SAML assertion is sent.

#. Set the ``enabled`` field to ``true``. It is set to
   ``false`` by default.

#. Your output should reflect the following example:

   .. code:: console

      $ curl -s -X PUT \
     -H "X-Auth-Token: $OS_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"service_provider": {"auth_url": "http://beta.example.com:5000/v3/OS-FEDERATION/identity_providers/beta/protocols/saml2/auth", "sp_url": "https://example.com:5000/Shibboleth.sso/SAML2/ECP", "enabled": true}}' \
     http://localhost:5000/v3/OS-FEDERATION/service_providers/BETA | python -mjson.tool

keystone-to-keystone
~~~~~~~~~~~~~~~~~~~~

Keystone acting as an IdP is known as :abbr:`k2k (keystone-2-keystone)`
or k2k federation, where a keystone somewhere is acting as the SP
and another keystone is acting as the IdP. All IdPs issue
assertions about the identities it owns using a `Protocol`.

Mapping rules
~~~~~~~~~~~~~

Mapping adds a set of rules to map federation attributes to keystone users
or groups. An IdP has exactly one mapping specified per protocol.

A mapping is a translation between assertions provided from an IdP and
the permission and roles applied by an SP. Given an assertion from an IdP, an
SP applies a mapping to translate attributes from the
IdP to known roles. A mapping is typically
owned by an SP.

Mapping objects can be used multiple times by different combinations
of IdP and protocol.

A rule hierarchy is as follows:

.. code:: ini

   {
        "rules": [
           {
               "local": [
                  {
                       "<user> or <group>"
                   }
               ],
               "remote": [
                   {
                       "<condition>"
                   }
               ]
           }
       ]
   }

* ``rules``: top-level list of rules.
* ``local``: a rule containing information on what local attributes
  will be mapped.
* ``remote``: a rule containing information on what remote attributes will
  be mapped.
* ``condition``: contains information on conditions that allow a rule, can
  only be set in a remote rule.

For more information on mapping rules, see `Mapping Rules
<https://docs.openstack.org/keystone/latest/advanced-topics/federation/federated_identity.html#mapping-rules>`_.

Mapping creation
----------------

Mapping creation starts with the communication between the IdP and SP.
The IdP usually provides a set of assertions that their users
have in their assertion document. The SP will have to map
those assertions to known groups and roles.
For example:

.. code:: ini

   Identity Provider 1:
     name: jsmith
     groups: hacker
     other: <assertion information>
   The Service Provider may have 3 groups:
     Admin Group
     Developer Group
     User Group

   The mapping created by the Service Provider might look like:
     Local:
     Group: Developer Group
   Remote:
     Groups: hackers

The ``Developer Group`` may have a role assignment on the
``Developer Project``. When `jsmith` authenticates against IdP 1, it
presents that assertion to the SP.The SP maps the `jsmith` user to the
``Developer Group`` because the assertion says `jsmith` is a member of
the ``hacker`` group.

Mapping examples
----------------

A bare bones mapping is sufficient if you would like all federated users to
have the same authorization in the SP cloud. However, mapping is
quite powerful and flexible. You can map different remote
users into different user groups in keystone, limited only by the number of
assertions your IdP makes about each user.

A mapping is composed of a list of rules, and each rule is further composed of
a list of remote attributes and a list of local attributes. If a rule is
matched, all of the local attributes are applied in the SP. For a
rule to match, all of the remote attributes it defines must match.

In the base case, a federated user simply needs an assertion containing
an email address to be identified in the SP cloud. To achieve that, only
one rule is needed that requires the presence of one remote attribute:

.. code:: javascript

    {
        "rules": [
            {
                "remote": [
                    {
                        "type": "Email"
                    }
                ],
                "local": [
                    {
                        "user": {
                            "name": "{0}"
                        }
                    }
                ]
            }
        ]
    }

However, that is not particularly useful as the federated user would receive no
authorization. To rectify it, you can map all federated users with email
addresses into a ``federated-users`` group in the ``default`` domain. All
federated users will then be able to consume whatever role assignments that
user group has already received in keystone:

.. note::

   In this example, there is only one rule requiring one remote attribute.

.. code:: javascript

    {
        "rules": [
            {
                "remote": [
                    {
                        "type": "Email"
                    }
                ],
                "local": [
                    {
                        "user": {
                            "name": "{0}"
                        }
                    },
                    {
                        "group": {
                            "domain": {
                                "id": "0cd5e9"
                            },
                            "name": "federated-users"
                        }
                    }
                ]
            }
        ]
    }

This example can be expanded by adding a second rule that conveys
additional authorization to only a subset of federated users. Federated users
with a `title` attribute that matches either ``Manager`` or
``Supervisor`` are granted the hypothetical ``observer`` role, which would
allow them to perform any read-only API call in the cloud:

.. code:: javascript

    {
        "rules": [
            {
                "remote": [
                    {
                        "type": "Email"
                    },
                ],
                "local": [
                    {
                        "user": {
                            "name": "{0}"
                        }
                    },
                    {
                        "group": {
                            "domain": {
                                "id": "default"
                            },
                            "name": "federated-users"
                        }
                    }
                ]
            },
            {
                "remote": [
                    {
                        "type": "Title",
                        "any_one_of": [".*Manager$", "Supervisor"],
                        "regex": "true"
                    },
                ],
                "local": [
                    {
                        "group": {
                            "domain": {
                                "id": "default"
                            },
                            "name": "observers"
                        }
                    }
                ]
            }
        ]
    }

.. note::

   ``any_one_of`` and ``regex`` in the rule above map federated users into
   the ``observers`` group when a user's ``Title`` assertion matches any of
   the regular expressions specified in the ``any_one_of`` attribute.

Keystone also supports the following:

* ``not_any_of``, matches any assertion that does not include one of
  the specified values
* ``blacklist``, matches all assertions of the specified type except
  those included in the specified value
* ``whitelist`` does not match any assertion except those listed in the
  specified value.
