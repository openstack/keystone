:orphan:

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

Configuring Keystone for Federation
===================================

-----------
Definitions
-----------
* `Service Provider (SP)`: provides a service to an end-user.
* `Identity Provider (IdP)`: service that stores information about users and
  groups.
* `SAML assertion`: contains information about a user as provided by an IdP.

-----------------------------------
Keystone as a Service Provider (SP)
-----------------------------------

.. NOTE::

    This feature is considered stable and supported as of the Juno release.

Prerequisites
-------------

This approach to federation supports keystone as a Service Provider, consuming
identity properties issued by an external Identity Provider, such as SAML
assertions or OpenID Connect claims, or by using
`Keystone as an Identity Provider (IdP)`_.

Federated users are not mirrored in the keystone identity backend
(for example, using the SQL driver). The external Identity Provider is
responsible for authenticating users, and communicates the result of
authentication to keystone using identity properties. Keystone maps these
values to keystone user groups and assignments created in keystone.

The following configuration steps were performed on a machine running
Ubuntu 14.04 and Apache 2.4.7.

To enable federation, you'll need to:

1. Run keystone under Apache for `SUSE`_, `RedHat`_ or `Ubuntu`_, rather than
   using uwsgi command.
2. `Configure Apache to use a federation capable authentication method`_.
3. `Configure Federation in Keystone`_.

.. _`SUSE`: ../../install/keystone-install-obs.html#configure-the-apache-http-server
.. _`RedHat`: ../../install/keystone-install-rdo.html#configure-the-apache-http-server
.. _`Ubuntu`: ../../install/keystone-install-ubuntu.html#configure-the-apache-http-server

Configure Apache to use a federation capable authentication method
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

There is currently support for two major federation protocols:

* SAML - Keystone supports the following implementations:

  * Shibboleth - see `Setup Shibboleth`_.
  * Mellon - see `Setup Mellon`_.

* OpenID Connect - see `Setup OpenID Connect`_.

.. _`Setup Shibboleth`: shibboleth.html
.. _`Setup OpenID Connect`: openidc.html
.. _`Setup Mellon`: mellon.html

Configure keystone and Horizon for Single Sign-On
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* To configure horizon to access a federated keystone,
  follow the steps outlined at: `Keystone Federation and Horizon`_.

.. _`Keystone Federation and Horizon`: websso.html

Configure Federation in Keystone
--------------------------------

Now that the Identity Provider and keystone are communicating we can start to
configure ``federation``.

1. `Configure authentication drivers in keystone.conf`_
2. `Create keystone groups and assign roles`_
3. `Add Identity Provider(s), Mapping(s), and Protocol(s)`_

Configure authentication drivers in keystone.conf
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Add the authentication methods to the ``[auth]`` section in ``keystone.conf``.
Names should be equal to protocol names added via Identity API v3. Here we use
examples ``saml2`` and ``openid``.

.. code-block:: bash

       [auth]
       methods = external,password,token,saml2,openid

Create keystone groups and assign roles
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

As mentioned earlier, no new users will be added to the Identity backend, but
the Identity Service requires group-based role assignments to authorize
federated users. The federation mapping function will map the user into local
Identity Service groups objects, and hence to local role assignments.

Thus, it is required to create the necessary Identity Service groups that
correspond to the Identity Provider's groups; additionally, these groups should
be assigned roles on one or more projects or domains.

You may be interested in more information on `group management
<https://developer.openstack.org/api-ref/identity/v3/#create-group>`_
and `role assignments
<https://developer.openstack.org/api-ref/identity/v3/#assign-role-to-group-on-project>`_,
both of which are exposed to the CLI via `python-openstackclient
<https://pypi.org/project/python-openstackclient/>`_.

For example, create a new domain and project like this:

.. code-block:: bash

    $ openstack domain create federated_domain
    $ openstack project create federated_project --domain federated_domain

And a new group like this:

.. code-block:: bash

    $ openstack group create federated_users

Add the group to the domain and project:

.. code-block:: bash

    $ openstack role add --group federated_users --domain federated_domain Member
    $ openstack role add --group federated_users --project federated_project Member

We'll later add a mapping that makes all federated users a part of this group
and therefore members of the new domain.

Add Identity Provider(s), Mapping(s), and Protocol(s)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To utilize federation the following must be created in the Identity Service:

* `Identity Provider`_
* `Mapping`_
* `Protocol`_

Read more about `federation in keystone
<https://developer.openstack.org/api-ref/identity/v3-ext/#os-federation-api>`__.

~~~~~~~~~~~~~~~~~
Identity Provider
~~~~~~~~~~~~~~~~~

Create an Identity Provider object in keystone, which represents the Identity
Provider we will use to authenticate end users:

.. code-block:: bash

    $ openstack identity provider create --remote-id https://myidp.example.com/v3/OS-FEDERATION/saml2/idp myidp

The value for the ``remote-id`` option is the unique identifier provided by the
IdP. For a SAML IdP it can found as the EntityDescriptor entityID in the IdP's
provided metadata. If the IdP is a keystone IdP, it is the value set in that
keystone's ``[saml]/idp_entity_id`` option. For an OpenID Connect IdP, it is
the IdP's Issuer Identifier. It will usually appear as a URI but there is no
requirement for it to resolve to anything and may be arbitrarily decided by the
administrator of the IdP. The local name, here called 'myidp', is decided by
you and will be used by the mapping and protocol, and later for authentication.

A keystone identity provider may have multiple `remote_ids` specified, this
allows the same *keystone* identity provider resource to be used with multiple
external identity providers. For example, an identity provider resource
``university-idp``, may have the following `remote_ids`:
``['university-x', 'university-y', 'university-z']``.
This removes the need to configure N identity providers in keystone.

.. NOTE::

    Remote IDs are globally unique. Two identity providers cannot be
    associated with the same remote ID. Once authenticated with the external
    identity provider, keystone will determine which identity provider
    and mapping to use based on the protocol and the value returned from the
    `remote_id_attribute` key.

    For example, if our identity provider is ``google``, the mapping used is
    ``google_mapping`` and the protocol is ``openid``. The identity provider's
    remote IDs  would be: [``https://accounts.google.com``].
    The `remote_id_attribute` value may be set to ``HTTP_OIDC_ISS``, since
    this value will always be ``https://accounts.google.com``.

    The motivation for this approach is that there will always be some data
    sent by the identity provider (in the assertion or claim) that uniquely
    identifies the identity provider. This removes the requirement for horizon
    to list all the identity providers that are trusted by keystone.

Read more about `identity providers
<https://developer.openstack.org/api-ref/identity/v3-ext/#identity-providers>`__.

~~~~~~~
Mapping
~~~~~~~
A mapping is a list of rules. The only Identity API objects that will support mapping are groups
and users.

Mapping adds a set of rules to map federation protocol attributes to Identity API objects.
There are many different ways to setup as well as combine these rules. More information on
rules can be found on the :doc:`mapping_combinations` page.

An Identity Provider has exactly one mapping specified per protocol.
Mapping objects can be used multiple times by different combinations of Identity Provider and Protocol.

As a simple example, if keystone is your IdP, you can map a few known remote
users to the group you already created:

.. code-block:: bash

    $ cat > rules.json <<EOF
    [
        {
            "local": [
                {
                    "user": {
                        "name": "{0}"
                    },
                    "group": {
                        "domain": {
                            "name": "Default"
                        },
                        "name": "federated_users"
                    }
                }
            ],
            "remote": [
                {
                    "type": "openstack_user"
                },
                {
                    "type": "openstack_user",
                    "any_one_of": [
                        "demo",
                        "alt_demo"
                    ]
                }
            ]
        }
    ]
    EOF
    $ openstack mapping create --rules rules.json myidp_mapping

As another example, if Shibboleth is your IdP, the remote section should use REMOTE_USER as the remote type:

.. code-block:: bash

    $ cat > rules.json <<EOF
    [
        {
            "local": [
                {
                    "user": {
                        "name": "{0}"
                    },
                    "group": {
                        "domain": {
                            "name": "Default"
                        },
                        "name": "federated_users"
                    }
                }
            ],
            "remote": [
                {
                    "type": "REMOTE_USER"
                }
            ]
        }
    ]
    EOF
    $ openstack mapping create --rules rules.json myidp_mapping

Read more about `mapping
<https://developer.openstack.org/api-ref/identity/v3-ext/#mappings>`__.

~~~~~~~~
Protocol
~~~~~~~~

A protocol contains information that dictates which Mapping rules to use for an incoming
request made by an IdP. An IdP may have multiple supported protocols.

You can create a protocol like this:

.. code-block:: bash

    $ openstack federation protocol create saml2 --mapping myidp_mapping --identity-provider myidp

The name you give the protocol is not arbitrary. It must match the method name
you gave in the ``[auth]/methods`` config option. When authenticating it will be
referred to as the ``protocol_id``.

Read more about `federation protocols
<https://developer.openstack.org/api-ref/identity/v3-ext/#protocols>`__

Performing federated authentication
-----------------------------------

.. NOTE::

    Authentication with keystone-to-keystone federation does not follow these steps.
    See `Testing it all out`_ to authenticate with keystone-to-keystone.

1. Authenticate externally and generate an unscoped token in keystone
2. Determine accessible resources
3. Get a scoped token

Get an unscoped token
~~~~~~~~~~~~~~~~~~~~~

Unlike other authentication methods in the Identity Service, the user does not
issue an HTTP POST request with authentication data in the request body. To
start federated authentication a user must access the dedicated URL with
Identity Provider's and Protocol's identifiers stored within a protected URL.
The URL has a format of:
``/v3/OS-FEDERATION/identity_providers/{idp_id}/protocols/{protocol_id}/auth``.

In this instance we follow a standard SAML2 authentication procedure, that is,
the user will be redirected to the Identity Provider's authentication webpage
and be prompted for credentials. After successfully authenticating the user
will be redirected to the Service Provider's endpoint. If using a web browser,
a token will be returned in JSON format, with the ID in the X-Subject-Token
header.

In the returned unscoped token, a list of Identity Service groups the user
belongs to will be included.

Read more about `getting an unscoped token
<https://developer.openstack.org/api-ref/identity/v3-ext/#request-an-unscoped-os-federation-token>`__.

~~~~~~~~~~~~
Example cURL
~~~~~~~~~~~~

Note that the request does not include a body. The following url would be
considered protected by ``mod_shib`` and Apache, as such a request made
to the URL would be redirected to the Identity Provider, to start the
SAML authentication procedure.

.. code-block:: bash

    $ curl -X GET -D - http://localhost:5000/v3/OS-FEDERATION/identity_providers/{idp_id}/protocols/{protocol_id}/auth

Determine accessible resources
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

By using the previously returned token, the user can issue requests to the list
projects and domains that are accessible.

* List projects a federated user can access: ``GET /OS-FEDERATION/projects``
* List domains a federated user can access: ``GET /OS-FEDERATION/domains``

Read more about `listing resources
<https://developer.openstack.org/api-ref/identity/v3-ext/#list-projects-a-federated-user-can-access>`__.

~~~~~~~
Example
~~~~~~~

.. code-block:: bash

    $ export OS_IDENTITY_API_VERSION=3
    $ export OS_TOKEN=<unscoped token>
    $ export OS_URL=http://localhost:5000/v3
    $ openstack federation project list

or

.. code-block:: bash

    $ export OS_IDENTITY_API_VERSION=3
    $ export OS_TOKEN=<unscoped token>
    $ export OS_URL=http://localhost:5000/v3
    $ openstack federation domain list

Get a scoped token
~~~~~~~~~~~~~~~~~~

A federated user may request a scoped token, by using the unscoped token. A
project or domain may be specified by either ``id`` or ``name``. An ``id`` is
sufficient to uniquely identify a project or domain.

Read more about `getting a scoped token
<https://developer.openstack.org/api-ref/identity/v3-ext/#request-a-scoped-os-federation-token>`__.

~~~~~~~
Example
~~~~~~~

.. code-block:: bash

    $ export OS_AUTH_TYPE=token
    $ export OS_IDENTITY_API_VERSION=3
    $ export OS_TOKEN=<unscoped token>
    $ export OS_AUTH_URL=http://localhost:5000/v3
    $ export OS_PROJECT_DOMAIN_NAME=federated_domain
    $ export OS_PROJECT_NAME=federated_project
    $ openstack token issue

--------------------------------------
Keystone as an Identity Provider (IdP)
--------------------------------------

.. NOTE::

    This feature is experimental and unsupported in Juno (with several issues
    that will not be backported). These issues have been fixed and this feature
    is considered stable and supported as of the Kilo release.

.. NOTE::

    This feature requires installation of the xmlsec1 tool via your
    distribution packaging system (for instance apt or yum)

    Example for apt:

    .. code-block:: bash

            $ apt-get install xmlsec1

Configuration Options
---------------------

There are certain settings in ``keystone.conf`` that must be setup, prior to
attempting to federate multiple keystone deployments.

Within ``keystone.conf``, assign values to the ``[saml]`` related fields, for
example:

.. code-block:: ini

    [saml]
    idp_entity_id=https://myidp.example.com/v3/OS-FEDERATION/saml2/idp
    idp_sso_endpoint=https://myidp.example.com/v3/OS-FEDERATION/saml2/sso

``idp_entity_id`` is the unique identifier for the Identity Provider. It
usually takes the form of a URI but it does not have to resolve to anything.
``idp_sso_endpoint`` is required to generate valid metadata but its value is
not important, though it may be in the future.

Note the ``certfile``, ``keyfile``, and ``idp_metadata_path`` settings and adjust them if
necessary:

.. code-block:: ini

    certfile=/etc/keystone/ssl/certs/signing_cert.pem
    keyfile=/etc/keystone/ssl/private/signing_key.pem
    idp_metadata_path=/etc/keystone/saml2_idp_metadata.xml

Though not necessary, the follow Organization configuration options should
also be setup. It is recommended that these values be URL safe.

.. code-block:: ini

    idp_organization_name=example_company
    idp_organization_display_name=Example Corp.
    idp_organization_url=example.com

As with the Organization options, the Contact options, are not necessary, but
it's advisable to set these values too.

.. code-block:: ini

    idp_contact_company=example_company
    idp_contact_name=John
    idp_contact_surname=Smith
    idp_contact_email=jsmith@example.com
    idp_contact_telephone=555-555-5555
    idp_contact_type=technical

Generate Metadata
-----------------

In order to create a trust between the IdP and SP, metadata must be exchanged.

First, if you haven't already generated a PKI key pair, you need to do so and
copy those files the locations designated by ``certfile`` and ``keyfile``
options that were assigned in the previous section. Ensure that your apache
vhost has SSL enabled and is using that keypair by adding the following to the
vhost::

    SSLEngine on
    SSLCertificateFile /etc/keystone/ssl/certs/signing_cert.pem
    SSLCertificateKeyFile /etc/keystone/ssl/private/signing_key.pem

To create metadata for your keystone IdP, run the ``keystone-manage`` command
and redirect the output to a file. For example:

.. code-block:: bash

    $ keystone-manage saml_idp_metadata > /etc/keystone/saml2_idp_metadata.xml

.. NOTE::
    The file location should match the value of the configuration option
    ``idp_metadata_path`` that was assigned in the previous section.

Finally, restart apache.

Create a Service Provider (SP)
------------------------------

In this example we are creating a new Service Provider with an ID of ``mysp``,
a ``sp_url`` of ``http://mysp.example.com/Shibboleth.sso/SAML2/ECP`` and a
``auth_url`` of ``http://mysp.example.com:5000/v3/OS-FEDERATION/identity_providers/myidp/protocols/saml2/auth``
. The ``sp_url`` will be used when creating a SAML assertion for ``mysp`` and
signed by the current keystone IdP. The ``auth_url`` is used to retrieve the
token for ``mysp`` once the SAML assertion is sent. The auth_url has the format
described in `Get an unscoped token`_.

.. code-block:: bash

    $ openstack service provider create --service-provider-url 'http://mysp.example.com/Shibboleth.sso/SAML2/ECP' --auth-url http://mysp.example.com:5000/v3/OS-FEDERATION/identity_providers/myidp/protocols/saml2/auth mysp

Testing it all out
------------------

Use keystoneauth to create a password session with the IdP, then use the
session to authenticate with the SP, and get a scoped token from the SP.

.. NOTE::
    ECP stands for Enhanced Client or Proxy, an extension from the SAML2
    protocol used in non-browser interfaces, like in the following example.

.. code-block:: python

    import os

    from keystoneauth1 import session
    from keystoneauth1.identity import v3
    from keystoneauth1.identity.v3 import k2k

    auth = v3.Password(auth_url=os.environ.get('OS_AUTH_URL'),
                       username=os.environ.get('OS_USERNAME'),
                       password=os.environ.get('OS_PASSWORD'),
                       user_domain_name=os.environ.get('OS_USER_DOMAIN_NAME'),
                       project_name=os.environ.get('OS_PROJECT_NAME'),
                       project_domain_name=os.environ.get('OS_PROJECT_DOMAIN_NAME'))
    password_session = session.Session(auth=auth)
    k2ksession = k2k.Keystone2Keystone(password_session.auth, 'mysp',
                                       domain_name='federated_domain')
    auth_ref = k2ksession.get_auth_ref(password_session)
    scoped_token_id = auth_ref.auth_token
    print('Scoped token id: %s' % scoped_token_id)
