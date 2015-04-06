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

===================================
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

This approach to federation supports Keystone as a Service Provider, consuming
identity properties issued by an external Identity Provider, such as SAML
assertions or OpenID Connect claims.

Federated users are not mirrored in the Keystone identity backend
(for example, using the SQL driver). The external Identity Provider is
responsible for authenticating users, and communicates the result of
authentication to Keystone using identity properties. Keystone maps these
values to Keystone user groups and assignments created in Keystone.

The following configuration steps were performed on a machine running
Ubuntu 12.04 and Apache 2.2.22.

To enable federation, you'll need to:

1. Run Keystone under Apache, rather than using ``keystone-all``.
2. Configure Apache to use a federation capable authentication method.
3. Enable ``OS-FEDERATION`` extension.

Configure Apache to use a federation capable authentication method
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

There are many ways to configure Federation in the Apache HTTPD server.
Using Shibboleth and OpenID Connect are documented so far.

* To use Shibboleth, follow the steps outlined at: `Setup Shibboleth`_.
* To use OpenID Connect, follow the steps outlined at: `Setup OpenID Connect`_.

.. _`Setup Shibboleth`: extensions/shibboleth.html
.. _`Setup OpenID Connect`: extensions/openidc.html

Configure Keystone and Horizon for Single Sign-On
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* To configure horizon to access a federated keystone,
  follow the steps outlined at: `Keystone Federation and Horizon`_.

.. _`Keystone Federation and Horizon`: extensions/websso.html

Enable the ``OS-FEDERATION`` extension
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Follow the steps outlined at: `Enabling Federation Extension`_.

.. _`Enabling Federation Extension`: extensions/federation.html

Configuring Federation
----------------------

Now that the Identity Provider and Keystone are communicating we can start to
configure the ``OS-FEDERATION`` extension.

1. Add local Keystone groups and roles
2. Add Identity Provider(s), Mapping(s), and Protocol(s)

Create Keystone groups and assign roles
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

As mentioned earlier, no new users will be added to the Identity backend, but
the Identity Service requires group-based role assignments to authorize
federated users. The federation mapping function will map the user into local
Identity Service groups objects, and hence to local role assignments.

Thus, it is required to create the necessary Identity Service groups that
correspond to the Identity Provider's groups; additionally, these groups should
be assigned roles on one or more projects or domains.

You may be interested in more information on `group management
<http://specs.openstack.org/openstack/keystone-specs/api/v3/identity-api-v3.html#create-group>`_
and `role assignments
<http://specs.openstack.org/openstack/keystone-specs/api/v3/identity-api-v3.html#grant-role-to-group-on-project>`_,
both of which are exposed to the CLI via `python-openstackclient
<https://pypi.python.org/pypi/python-openstackclient/>`_.

Add Identity Provider(s), Mapping(s), and Protocol(s)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To utilize federation the following must be created in the Identity Service:

* Identity Provider
* Mapping
* Protocol

More information on ``OS-FEDERATION`` can be found `here
<http://specs.openstack.org/openstack/keystone-specs/api/v3/identity-api-v3-os-federation-ext.html>`__.

~~~~~~~~~~~~~~~~~
Identity Provider
~~~~~~~~~~~~~~~~~

Create an Identity Provider object in Keystone, which represents the Identity
Provider we will use to authenticate end users.

More information on identity providers can be found `here
<http://specs.openstack.org/openstack/keystone-specs/api/v3/identity-api-v3-os-federation-ext.html#register-an-identity-provider>`__.

~~~~~~~
Mapping
~~~~~~~
A mapping is a list of rules. The only Identity API objects that will support mapping are groups
and users.

Mapping adds a set of rules to map federation protocol attributes to Identity API objects.
An Identity Provider has exactly one mapping specified per protocol.

Mapping objects can be used multiple times by different combinations of Identity Provider and Protocol.

More information on mapping can be found `here
<http://specs.openstack.org/openstack/keystone-specs/api/v3/identity-api-v3-os-federation-ext.html#create-a-mapping>`__.

~~~~~~~~
Protocol
~~~~~~~~

A protocol contains information that dictates which Mapping rules to use for an incoming
request made by an IdP. An IdP may have multiple supported protocols.

Add `Protocol object
<http://specs.openstack.org/openstack/keystone-specs/api/v3/identity-api-v3-os-federation-ext.html#add-a-protocol-and-attribute-mapping-to-an-identity-provider>`__ and specify the mapping id
you want to use with the combination of the IdP and Protocol.

Performing federated authentication
-----------------------------------

1. Authenticate externally and generate an unscoped token in Keystone
2. Determine accessible resources
3. Get a scoped token

Get an unscoped token
~~~~~~~~~~~~~~~~~~~~~

Unlike other authentication methods in the Identity Service, the user does not
issue an HTTP POST request with authentication data in the request body. To
start federated authentication a user must access the dedicated URL with
Identity Provider's and Protocol's identifiers stored within a protected URL.
The URL has a format of:
``/v3/OS-FEDERATION/identity_providers/{identity_provider}/protocols/{protocol}/auth``.

In this instance we follow a standard SAML2 authentication procedure, that is,
the user will be redirected to the Identity Provider's authentication webpage
and be prompted for credentials. After successfully authenticating the user
will be redirected to the Service Provider's endpoint. If using a web browser,
a token will be returned in XML format.

In the returned unscoped token, a list of Identity Service groups the user
belongs to will be included.

More information on getting an unscoped token can be found `here
<http://specs.openstack.org/openstack/keystone-specs/api/v3/identity-api-v3-os-federation-ext.html#authenticating>`__.

~~~~~~~~~~~~
Example cURL
~~~~~~~~~~~~

Note that the request does not include a body. The following url would be
considered protected by ``mod_shib`` and Apache, as such a request made
to the URL would be redirected to the Identity Provider, to start the
SAML authentication procedure.

.. code-block:: bash

    $ curl -X GET -D - http://localhost:5000/v3/OS-FEDERATION/identity_providers/{identity_provider}/protocols/{protocol}/auth

Determine accessible resources
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

By using the previously returned token, the user can issue requests to the list
projects and domains that are accessible.

* List projects a federated user can access: ``GET /OS-FEDERATION/projects``
* List domains a federated user can access: ``GET /OS-FEDERATION/domains``

More information on listing resources can be found `here
<http://specs.openstack.org/openstack/keystone-specs/api/v3/identity-api-v3-os-federation-ext.html#listing-projects-and-domains>`__.

~~~~~~~~~~~~
Example cURL
~~~~~~~~~~~~

.. code-block:: bash

    $ curl -X GET -H "X-Auth-Token: <unscoped token>" http://localhost:5000/v3/OS-FEDERATION/projects

or

.. code-block:: bash

    $ curl -X GET -H "X-Auth-Token: <unscoped token>" http://localhost:5000/v3/OS-FEDERATION/domains

Get a scoped token
~~~~~~~~~~~~~~~~~~

A federated user may request a scoped token, by using the unscoped token. A
project or domain may be specified by either ``id`` or ``name``. An ``id`` is
sufficient to uniquely identify a project or domain.

More information on getting a scoped token can be found `here
<http://specs.openstack.org/openstack/keystone-specs/api/v3/identity-api-v3-os-federation-ext.html#request-a-scoped-os-federation-token>`__.

~~~~~~~~~~~~
Example cURL
~~~~~~~~~~~~

.. code-block:: bash

    $ curl -X POST -H "Content-Type: application/json" -d '{"auth":{"identity":{"methods":["saml2"],"saml2":{"id":"<unscoped_token_id>"}},"scope":{"project":{"domain": {"name": "Default"},"name":"service"}}}}' -D - http://localhost:5000/v3/auth/tokens

--------------------------------------
Keystone as an Identity Provider (IdP)
--------------------------------------

.. NOTE::

    This feature is experimental and unsupported in Juno (with several issues
    that will not be backported). These issues have been fixed and this feature
    is considered stable and supported as of the Kilo release.

Configuration Options
---------------------

There are certain settings in ``keystone.conf`` that must be setup, prior to
attempting to federate multiple Keystone deployments.

Within ``keystone.conf``, assign values to the ``[saml]`` related fields, for
example:

.. code-block:: ini

    [saml]
    certfile=/etc/keystone/ssl/certs/ca.pem
    keyfile=/etc/keystone/ssl/private/cakey.pem
    idp_entity_id=https://keystone.example.com/v3/OS-FEDERATION/saml2/idp
    idp_sso_endpoint=https://keystone.example.com/v3/OS-FEDERATION/saml2/sso
    idp_metadata_path=/etc/keystone/saml2_idp_metadata.xml

Though not necessary, the follow Organization configuration options should
also be setup. It is recommended that these values be URL safe.

.. code-block:: ini

    idp_organization_name=example_company
    idp_organization_display_name=Example Corp.
    idp_organization_url=example.com

As with the Organizaion options, the Contact options, are not necessary, but
it's advisable to set these values too.

.. code-block:: ini

    idp_contact_company=example_company
    idp_contact_name=John
    idp_contact_surname=Smith
    idp_contact_email=jsmith@example.com
    idp_contact_telephone=555-55-5555
    idp_contact_type=technical

Generate Metadata
-----------------

In order to create a trust between the IdP and SP, metadata must be exchanged.
To create metadata for your Keystone IdP, run the ``keystone-manage`` command
and pipe the output to a file. For example:

.. code-block:: bash

    $ keystone-manage saml_idp_metadata > /etc/keystone/saml2_idp_metadata.xml

.. NOTE::
    The file location should match the value of the configuration option
    ``idp_metadata_path`` that was assigned in the previous section.

Create a Service Provider (SP)
------------------------------

In this example we are creating a new Service Provider with an ID of ``BETA``,
a ``sp_url`` of ``http://beta.example.com/Shibboleth.sso/POST/ECP`` and a
``auth_url`` of ``http://beta.example.com:5000/v3/OS-FEDERATION/identity_providers/beta/protocols/saml2/auth``
. The ``sp_url`` will be used when creating a SAML assertion for ``BETA`` and
signed by the current Keystone IdP. The ``auth_url`` is used to retrieve the
token for ``BETA`` once the SAML assertion is sent.

.. code-block:: bash

    $ curl -s -X PUT \
      -H "X-Auth-Token: $OS_TOKEN" \
      -H "Content-Type: application/json" \
      -d '{"service_provider": {"auth_url": "http://beta.example.com:5000/v3/OS-FEDERATION/identity_providers/beta/protocols/saml2/auth", "sp_url": "https://example.com:5000/Shibboleth.sso/SAML2/ECP"}' \
      http://localhost:5000/v3/service_providers/BETA | python -mjson.tool

Testing it all out
------------------

Lastly, if a scoped token and a Service Provider region are presented to
Keystone, the result will be a full SAML Assertion, signed by the IdP
Keystone, specifically intended for the Service Provider Keystone.

.. code-block:: bash

    $ curl -s -X POST \
      -H "Content-Type: application/json" \
      -d '{"auth": {"scope": {"service_provider": {"id": "BETA"}}, "identity": {"token": {"id": "d793d935b9c343f783955cf39ee7dc3c"}, "methods": ["token"]}}}' \
      http://localhost:5000/v3/auth/OS-FEDERATION/saml2

At this point the SAML Assertion can be sent to the Service Provider Keystone
using the provided ``auth_url`` in the ``X-Auth-Url`` header present in the
response containing the SAML Assertion, and a valid OpenStack token, issued by
a Service Provider Keystone, will be returned.

