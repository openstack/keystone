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

-----------------------------------
Keystone as a Service Provider (SP)
-----------------------------------

Prerequisites
-------------

If you are not familiar with the idea of federated identity, see the
`introduction`_ first.

In this section, we will configure keystone as a Service Provider, consuming
identity properties issued by an external Identity Provider, such as SAML
assertions or OpenID Connect claims. For testing purposes, we recommend using
`samltest.id`_  as a SAML Identity Provider, or Google as an OpenID Connect
Identity Provider, and the examples here will references those providers. If you
plan to set up `Keystone as an Identity Provider (IdP)`_, it is easiest to set
up keystone with a dummy SAML provider first and then reconfigure it to point to
the keystone Identity Provider later.

The following configuration steps were performed on a machine running
Ubuntu 16.04 and Apache 2.4.18.

To enable federation, you'll need to run keystone behind a web server such as
Apache rather than running the WSGI application directly with uWSGI or Gunicorn.
See the installation guide for `SUSE`_, `RedHat`_ or `Ubuntu`_ to configure
the Apache web server for keystone.

Throughout the rest of the guide, you will need to decide on three pieces of
information and use them consistently throughout your configuration:

1. The protocol name. This must be a valid keystone auth method and must match
   one of: ``saml2``, ``openid``, ``mapped`` or a `custom auth method`_ for which
   you must `register as an external driver`_.

2. The identity provider name. This can be arbitrary.

3. The entity ID of the service provider. This should be a URN but need not
   resolve to anything.

You will also need to decide what HTTPD module to use as a Service Provider.
This guide provides examples for ``mod_shib`` and ``mod_auth_mellon`` as SAML
service providers, and ``mod_auth_openidc`` as an OpenID Connect Service
Provider.

.. note::

   In this guide, the keystone Service Provider is configured on a host called
   sp.keystone.example.org listening on the standard HTTPS port. All keystone
   paths will start with the keystone version prefix, ``/v3``. If you have
   configured keystone to listen on port 5000, or to respond on the path
   ``/identity`` (for example), take this into account in your own
   configuration.

.. _introduction: introduction
.. _samltest.id: https://samltest.id
.. _SUSE: ../../install/keystone-install-obs.html#configure-the-apache-http-server
.. _RedHat: ../../install/keystone-install-rdo.html#configure-the-apache-http-server
.. _Ubuntu: ../../install/keystone-install-ubuntu.html#configure-the-apache-http-server
.. _custom auth method: ../../contributor/auth-plugins
.. _register as an external driver: ../../contributor/developing-drivers

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

.. code-block:: ini

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

.. code-block:: console

   $ openstack domain create federated_domain
   $ openstack project create federated_project --domain federated_domain

And a new group like this:

.. code-block:: console

   $ openstack group create federated_users

Add the group to the domain and project:

.. code-block:: console

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

.. code-block:: console

   $ openstack identity provider create --remote-id https://samltest.id/saml/idp samltest

The value for the ``remote-id`` option is the unique identifier provided by the
IdP. For a SAML IdP it can found as the EntityDescriptor entityID in the IdP's
provided metadata. If the IdP is a keystone IdP, it is the value set in that
keystone's ``[saml]/idp_entity_id`` option. For an OpenID Connect IdP, it is
the IdP's Issuer Identifier. It will usually appear as a URI but there is no
requirement for it to resolve to anything and may be arbitrarily decided by the
administrator of the IdP. The local name, here called 'samltest', is decided by
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

.. code-block:: console

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
   $ openstack mapping create --rules rules.json samltest_mapping

As another example, if Shibboleth is your IdP, the remote section should use REMOTE_USER as the remote type:

.. code-block:: console

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
   $ openstack mapping create --rules rules.json samltest_mapping

Read more about `mapping
<https://developer.openstack.org/api-ref/identity/v3-ext/#mappings>`__.

~~~~~~~~
Protocol
~~~~~~~~

A protocol contains information that dictates which Mapping rules to use for an incoming
request made by an IdP. An IdP may have multiple supported protocols.

You can create a protocol like this:

.. code-block:: console

   $ openstack federation protocol create saml2 --mapping samltest_mapping --identity-provider samltest

The name you give the protocol is not arbitrary. It must match the method name
you gave in the ``[auth]/methods`` config option. When authenticating it will be
referred to as the ``protocol_id``.

Read more about `federation protocols
<https://developer.openstack.org/api-ref/identity/v3-ext/#protocols>`__

Authenticating
--------------

Use the CLI to authenticate with a SAML2.0 Identity Provider
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. FIXME(cmurphy): Include examples for OpenID Connect authentication with the CLI

The ``python-openstackclient`` can be used to authenticate a federated user in a
SAML Identity Provider to keystone.

.. note::

   The SAML Identity Provider must be configured to support the ECP
   authentication profile.

To use the CLI tool, you must have the name of the Identity Provider
resource in keystone, the name of the federation protocol configured in
keystone, and the ECP endpoint for the Identity Provider. If you are the cloud
administrator, the name of the Identity Provider and protocol was configured in
`Identity Provider`_ and `Protocol`_ respectively. If you are not the
administrator, you must obtain this information from the administrator.

The ECP endpoint for the Identity Provider can be obtained from its metadata
without involving an administrator. This endpoint is the
``urn:oasis:names:tc:SAML:2.0:bindings:SOAP`` binding in the metadata document:

.. code-block:: console

   $ curl -s https://samltest.id/saml/idp | grep urn:oasis:names:tc:SAML:2.0:bindings:SOAP
        <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="https://samltest.id/idp/profile/SAML2/SOAP/ECP"/>

~~~~~~~~~~~~~~~~~~~~~
Find available scopes
~~~~~~~~~~~~~~~~~~~~~

If you are a new user and are not aware of what resources you have access to,
you can use an unscoped query to list the projects or domains you have been
granted a role assignment on:

.. code-block:: bash

   export OS_AUTH_TYPE=v3samlpassword
   export OS_IDENTITY_PROVIDER=samltest
   export OS_IDENTITY_PROVIDER_URL=https://samltest.id/idp/profile/SAML2/SOAP/ECP
   export OS_PROTOCOL=saml2
   export OS_USERNAME=morty
   export OS_PASSWORD=panic
   export OS_AUTH_URL=https://sp.keystone.example.org/v3
   export OS_IDENTITY_API_VERSION=3
   openstack federation project list
   openstack federation domain list

~~~~~~~~~~~~~~~~~~
Get a scoped token
~~~~~~~~~~~~~~~~~~

If you already know the project, domain or system you wish to scope to, you can
directly request a scoped token:

.. code-block:: bash

   export OS_AUTH_TYPE=v3samlpassword
   export OS_IDENTITY_PROVIDER=samltest
   export OS_IDENTITY_PROVIDER_URL=https://samltest.id/idp/profile/SAML2/SOAP/ECP
   export OS_PROTOCOL=saml2
   export OS_USERNAME=morty
   export OS_PASSWORD=panic
   export OS_AUTH_URL=https://sp.keystone.example.org/v3
   export OS_IDENTITY_API_VERSION=3
   export OS_PROJECT_NAME=federated_project
   export OS_PROJECT_DOMAIN_NAME=Default
   openstack token issue

Use horizon to authenticate with an external Identity Provider
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When horizon is configured to enable WebSSO, a dropdown menu will appear on the
login screen before the user has authenticated. Select an authentication method
from the menu to be redirected to your Identity Provider for authentication.

.. image:: ../../_static/horizon-login-sp.png
   :height: 400px
   :alt: Horizon login screen using external authentication

--------------------------------------
Keystone as an Identity Provider (IdP)
--------------------------------------

Prerequisites
-------------

When keystone is configured as an Identity Provider, it is often referred to as
`Keystone to Keystone`, because it enables federation between multiple OpenStack
clouds using the SAML2.0 protocol.

If you are not familiar with the idea of federated identity, see the
`introduction`_ first.

When setting up `Keystone to Keystone`, it is easiest to `configure a keystone
Service Provider`_ first with a sandbox Identity Provider such as
`samltest.id`_.

.. _configure a keystone Service Provider: :ref:`Keystone as a Service Provider (SP)`
.. _samltest.id: https://samltest.id

This feature requires installation of the xmlsec1 tool via your distribution
packaging system (for instance apt or yum)

.. code-block:: console

   # apt-get install xmlsec1

.. note::

   In this guide, the keystone Identity Provider is configured on a host called
   idp.keystone.example.org listening on the standard HTTPS port. All keystone
   paths will start with the keystone version prefix, ``/v3``. If you have
   configured keystone to listen on port 5000, or to respond on the path
   ``/identity`` (for example), take this into account in your own
   configuration.

Configuring Metadata
--------------------

Since keystone is acting as a SAML Identity Provider, its metadata must be
configured in the ``[saml]`` section of ``keystone.conf`` so that it can served
by the `metadata API`_.

.. _metadata API: https://developer.openstack.org/api-ref/identity/v3-ext/index.html#retrieve-metadata-properties

The two parameters that **must** be set in order for keystone to generate
metadata are ``idp_entity_id`` and ``idp_sso_endpoint``:

.. code-block:: ini

   [saml]
   idp_entity_id=https://idp.keystone.example.org/v3/OS-FEDERATION/saml2/idp
   idp_sso_endpoint=https://idp.keystone.example.org/v3/OS-FEDERATION/saml2/sso

``idp_entity_id`` sets the Identity Provider entity ID, which is a string of
your choosing that uniquely identifies the Identity Provider to any Service
Provider.

``idp_sso_endpoint`` is required to generate valid metadata, but its value is
currently not used because keystone as an Identity Provider does not support the
SAML2.0 WebSSO auth profile. This may change in the future which is why there is
no default value provided and must be set by the operator.

For completeness, the following Organization and Contact configuration options
should also be updated to reflect your organization and administrator contact
details.

.. code-block:: ini

   idp_organization_name=example_company
   idp_organization_display_name=Example Corp.
   idp_organization_url=example.com
   idp_contact_company=example_company
   idp_contact_name=John
   idp_contact_surname=Smith
   idp_contact_email=jsmith@example.com
   idp_contact_telephone=555-555-5555
   idp_contact_type=technical

It is important to take note of the default ``certfile`` and ``keyfile``
options, and adjust them if necessary:

.. code-block:: ini

   certfile=/etc/keystone/ssl/certs/signing_cert.pem
   keyfile=/etc/keystone/ssl/private/signing_key.pem

You must generate a PKI key pair and copy the files to these paths. You can use
the ``openssl`` tool to do so. Keystone does not provide a utility for this.

Check the ``idp_metadata_path`` setting and adjust it if necessary:

.. code-block:: ini

   idp_metadata_path=/etc/keystone/saml2_idp_metadata.xml

To create metadata for your keystone IdP, run the ``keystone-manage`` command
and redirect the output to a file. For example:

.. code-block:: console

   # keystone-manage saml_idp_metadata > /etc/keystone/saml2_idp_metadata.xml

Finally, restart the keystone WSGI service or the web server frontend:

.. code-block:: console

   # systemctl restart apache2

Creating a Service Provider Resource
------------------------------------

Create a Service Provider resource to represent your Service Provider as an
object in keystone:

.. code-block:: console

   $ openstack service provider create keystonesp \
   --service-provider-url https://sp.keystone.example.org/Shibboleth.sso/SAML2/ECP
   --auth-url https://sp.keystone.example.org/v3/OS-FEDERATION/identity_providers/keystoneidp/protocols/saml2/auth

The ``--auth-url`` is the `federated auth endpoint`_ for a specific Identity
Provider and protocol name, here named ``keystoneidp`` and ``saml2``.

The ``--service-provider-url`` is the
``urn:oasis:names:tc:SAML:2.0:bindings:PAOS`` binding for the Assertion Consumer
Service of the Service Provider. It can be obtained from the Service Provider
metadata:

.. code-block:: console

   $ curl -s https://sp.keystone.example.org/Shibboleth.sso/Metadata | grep urn:oasis:names:tc:SAML:2.0:bindings:PAOS
   <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:PAOS" Location="https://sp.keystone.example.org/Shibboleth.sso/SAML2/ECP" index="4"/>

.. _federated auth endpoint: https://developer.openstack.org/api-ref/identity/v3-ext/index.html#request-an-unscoped-os-federation-token

Authenticating
--------------

Use the CLI to authenticate with Keystone-to-Keystone
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Use ``python-openstackclient`` to authenticate with the IdP and then get a
scoped token from the SP.

.. code-block:: console

   export OS_USERNAME=demo
   export OS_PASSWORD=nomoresecret
   export OS_AUTH_URL=https://idp.keystone.example.org/v3
   export OS_IDENTITY_API_VERSION=3
   export OS_PROJECT_NAME=federated_project
   export OS_PROJECT_DOMAIN_NAME=Default
   export OS_SERVICE_PROVIDER=keystonesp
   export OS_REMOTE_PROJECT_NAME=federated_project
   export OS_REMOTE_PROJECT_DOMAIN_NAME=Default
   openstack token issue

Use Horizon to switch clouds
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

No additional configuration is necessary to enable horizon for
Keystone to Keystone. Log into the horizon instance for the Identity Provider
using your regular local keystone credentials. Once logged in, you will see a
Service Provider dropdown menu which you can use to switch your dashboard view
to another cloud.

.. image:: ../../_static/horizon-login-idp.png
   :height: 175px
   :alt: Horizon dropdown menu for switching between keystone providers

.. include:: openidc.rst
.. include:: mellon.rst
.. include:: shibboleth.rst
.. include:: websso.rst
