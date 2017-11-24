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

Setup Shibboleth
================

-----------------------------------------
Configure Apache HTTPD for mod_shibboleth
-----------------------------------------

Follow the steps outlined at: Running Keystone in HTTPD for `SUSE`_, `RedHat`_
or `Ubuntu`_.

.. _`SUSE`: ../../install/keystone-install-obs.html#configure-the-apache-http-server
.. _`RedHat`: ../../install/keystone-install-rdo.html#configure-the-apache-http-server
.. _`Ubuntu`: ../../install/keystone-install-ubuntu.html#configure-the-apache-http-server

You'll also need to install `Shibboleth <https://wiki.shibboleth.net/confluence/display/SHIB2/Home>`_, for
example:

.. code-block:: bash

    $ apt-get install libapache2-mod-shib2

Configure your Keystone virtual host and adjust the config to properly handle SAML2 workflow:

Add this *WSGIScriptAliasMatch* directive to your public vhost configuration::

    WSGIScriptAliasMatch ^(/v3/OS-FEDERATION/identity_providers/.*?/protocols/.*?/auth)$ /usr/local/bin/keystone-wsgi-public/$1

Make sure the *keystone.conf* vhost file contains a *<Location>* directive for the Shibboleth module and
a *<Location>* directive for each identity provider::

    <Location /Shibboleth.sso>
        SetHandler shib
    </Location>

    <Location /v3/OS-FEDERATION/identity_providers/myidp/protocols/saml2/auth>
        ShibRequestSetting requireSession 1
        AuthType shibboleth
        ShibExportAssertion Off
        Require valid-user

        <IfVersion < 2.4>
            ShibRequireSession On
            ShibRequireAll On
       </IfVersion>
    </Location>

.. NOTE::
    * ``saml2`` is the name of the `protocol that you will configure <configure_federation.html#protocol>`_
    * ``myidp`` is the name associated with the `IdP in Keystone <configure_federation.html#identity_provider>`_
    * The ``ShibRequireSession`` and ``ShibRequireAll`` rules are invalid in
      Apache 2.4+.
    * You are advised to carefully examine `Shibboleth Apache configuration
      documentation
      <https://wiki.shibboleth.net/confluence/display/SHIB2/NativeSPApacheConfig>`_

Enable the ``shib2`` module, for example:

.. code-block:: bash

    $ a2enmod shib2

Restart Apache, for example:

.. code-block:: bash

    $ service apache2 restart

---------------------------
Configuring shibboleth2.xml
---------------------------

Once you have your Keystone vhost (virtual host) ready, it's then time to
configure Shibboleth and upload your Metadata to the Identity Provider.

Create a new keypair for Shibboleth with:

.. code-block:: bash

    $ shib-keygen -y <number of years>

The newly created key file will be stored under ``/etc/shibboleth/sp-key.pem``.

Configure your Service Provider by editing ``/etc/shibboleth/shibboleth2.xml``
file. You will want to change five settings:

* Set the SP entity ID. This value usually has the form of a URI but it does not
  have to resolve to anything. It must uniquely identify your Service Provider
  to your Identity Provider.

.. code-block:: xml

    <ApplicationDefaults entityID="http://mysp.example.com/shibboleth">

* Set the IdP entity ID. This value is determined by the IdP. For example, if
  Keystone is the IdP:

.. code-block:: xml

    <SSO entityID="https://myidp.example.com/v3/OS-FEDERATION/saml2/idp">

Example if testshib.org is the IdP:

.. code-block:: xml

    <SSO entityID="https://idp.testshib.org/idp/shibboleth">

* Remove the discoveryURL lines unless you want to enable advanced IdP discovery.

* Add a MetadataProvider block. The URI given here is a real URL that Shibboleth
  will use to fetch metadata from the IdP. For example, if Keystone is the IdP:

.. code-block:: xml

    <MetadataProvider type="XML" uri="https://myidp.example.com:5000/v3/OS-FEDERATION/saml2/metadata"/>

Example if testshib.org is the IdP:

.. code-block:: xml

    <MetadataProvider type="XML" uri="http://www.testshib.org/metadata/testshib-providers.xml" />

You are advised to examine `Shibboleth Service Provider Configuration documentation <https://wiki.shibboleth.net/confluence/display/SHIB2/Configuration>`_

The result should look like (The example shown below is for reference only, not
to be used in a production environment):

.. code-block:: xml

    <SPConfig xmlns="urn:mace:shibboleth:2.0:native:sp:config"
        xmlns:conf="urn:mace:shibboleth:2.0:native:sp:config"
        xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
        xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
        xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
        clockSkew="180">

        <!--
        By default, in-memory StorageService, ReplayCache, ArtifactMap, and SessionCache
        are used. See example-shibboleth2.xml for samples of explicitly configuring them.
        -->

        <!--
        To customize behavior for specific resources on Apache, and to link vhosts or
        resources to ApplicationOverride settings below, use web server options/commands.
        See https://wiki.shibboleth.net/confluence/display/SHIB2/NativeSPConfigurationElements for help.

        For examples with the RequestMap XML syntax instead, see the example-shibboleth2.xml
        file, and the https://wiki.shibboleth.net/confluence/display/SHIB2/NativeSPRequestMapHowTo topic.
        -->

        <!-- The ApplicationDefaults element is where most of Shibboleth's SAML bits are defined. -->
        <ApplicationDefaults entityID="https://mysp.example.com/shibboleth">

            <!--
            Controls session lifetimes, address checks, cookie handling, and the protocol handlers.
            You MUST supply an effectively unique handlerURL value for each of your applications.
            The value defaults to /Shibboleth.sso, and should be a relative path, with the SP computing
            a relative value based on the virtual host. Using handlerSSL="true", the default, will force
            the protocol to be https. You should also set cookieProps to "https" for SSL-only sites.
            Note that while we default checkAddress to "false", this has a negative impact on the
            security of your site. Stealing sessions via cookie theft is much easier with this disabled.
            -->
            <Sessions lifetime="28800" timeout="3600" relayState="ss:mem"
                      checkAddress="false" handlerSSL="false" cookieProps="http">

                <!--
                Configures SSO for a default IdP. To allow for >1 IdP, remove
                entityID property and adjust discoveryURL to point to discovery service.
                (Set discoveryProtocol to "WAYF" for legacy Shibboleth WAYF support.)
                You can also override entityID on /Login query string, or in RequestMap/htaccess.
                -->
                <SSO entityID="https://myidp.example.com/v3/OS-FEDERATION/saml2/idp">
                  SAML2 SAML1
                </SSO>

                <!-- SAML and local-only logout. -->
                <Logout>SAML2 Local</Logout>

                <!-- Extension service that generates "approximate" metadata based on SP configuration. -->
                <Handler type="MetadataGenerator" Location="/Metadata" signing="false"/>

                <!-- Status reporting service. -->
                <Handler type="Status" Location="/Status" acl="127.0.0.1 ::1"/>

                <!-- Session diagnostic service. -->
                <Handler type="Session" Location="/Session" showAttributeValues="false"/>

                <!-- JSON feed of discovery information. -->
                <Handler type="DiscoveryFeed" Location="/DiscoFeed"/>
            </Sessions>
            <!--
            Allows overriding of error template information/filenames. You can
            also add attributes with values that can be plugged into the templates.
            -->
            <Errors supportContact="root@localhost"
                helpLocation="/about.html"
                styleSheet="/shibboleth-sp/main.css"/>

            <!-- Example of remotely supplied batch of signed metadata. -->
            <!--
            <MetadataProvider type="XML" uri="http://federation.org/federation-metadata.xml"
                  backingFilePath="federation-metadata.xml" reloadInterval="7200">
                <MetadataFilter type="RequireValidUntil" maxValidityInterval="2419200"/>
                <MetadataFilter type="Signature" certificate="fedsigner.pem"/>
            </MetadataProvider>
            -->

            <!-- Example of locally maintained metadata. -->
            <!--
            <MetadataProvider type="XML" file="partner-metadata.xml"/>
            -->
            <MetadataProvider type="XML" uri="https://myidp.example.com:5000/v3/OS-FEDERATION/saml2/metadata"/>

            <!-- Map to extract attributes from SAML assertions. -->
            <AttributeExtractor type="XML" validate="true" reloadChanges="false" path="attribute-map.xml"/>

            <!-- Use a SAML query if no attributes are supplied during SSO. -->
            <AttributeResolver type="Query" subjectMatch="true"/>

            <!-- Default filtering policy for recognized attributes, lets other data pass. -->
            <AttributeFilter type="XML" validate="true" path="attribute-policy.xml"/>

            <!-- Simple file-based resolver for using a single keypair. -->
            <CredentialResolver type="File" key="sp-key.pem" certificate="sp-cert.pem"/>

            <!--
            The default settings can be overridden by creating ApplicationOverride elements (see
            the https://wiki.shibboleth.net/confluence/display/SHIB2/NativeSPApplicationOverride topic).
            Resource requests are mapped by web server commands, or the RequestMapper, to an
            applicationId setting.
            Example of a second application (for a second vhost) that has a different entityID.
            Resources on the vhost would map to an applicationId of "admin":
            -->
            <!--
            <ApplicationOverride id="admin" entityID="https://admin.example.org/shibboleth"/>
            -->
        </ApplicationDefaults>

        <!-- Policies that determine how to process and authenticate runtime messages. -->
        <SecurityPolicyProvider type="XML" validate="true" path="security-policy.xml"/>

        <!-- Low-level configuration about protocols and bindings available for use. -->
        <ProtocolProvider type="XML" validate="true" reloadChanges="false" path="protocols.xml"/>

    </SPConfig>

If keystone is your IdP, you will need to examine your attributes map file
``/etc/shibboleth/attribute-map.xml`` and add the following attributes:

.. code-block:: xml

    <Attribute name="openstack_user" id="openstack_user"/>
    <Attribute name="openstack_roles" id="openstack_roles"/>
    <Attribute name="openstack_project" id="openstack_project"/>
    <Attribute name="openstack_user_domain" id="openstack_user_domain"/>
    <Attribute name="openstack_project_domain" id="openstack_project_domain"/>

For more information see the
`attributes documentation <https://wiki.shibboleth.net/confluence/display/SHIB2/NativeSPAddAttribute>`_

Once you are done, restart your Shibboleth daemon and apache:

.. _`external authentication`: ../external-auth.html

.. code-block:: bash

    $ service shibd restart
    $ service apache2 restart

Check ``/var/log/shibboleth/shibd_warn.log`` for any ERROR or CRIT notices and
correct them.

Upload your Service Provider's metadata file to your Identity Provider. You can
fetch it with:

.. code-block:: bash

    $ wget http://mysp.example.com/Shibboleth.sso/Metadata

This step depends on your Identity Provider choice and is not covered here.
If keystone is your Identity Provider you do not need to upload this file.
