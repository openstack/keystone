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

================
Setup Shibboleth
================

Configure Apache HTTPD for mod_shibboleth
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Follow the steps outlined at: `Running Keystone in HTTPD`_.

.. _`Running Keystone in HTTPD`: ../apache-httpd.html

You'll also need to install `Shibboleth <https://wiki.shibboleth.net/confluence/display/SHIB2/Home>`_, for
example:

.. code-block:: bash

    $ apt-get install libapache2-mod-shib2

Configure your Keystone virtual host and adjust the config to properly handle SAML2 workflow:

Add *WSGIScriptAlias* directive to your vhost configuration::

    WSGIScriptAliasMatch ^(/v3/OS-FEDERATION/identity_providers/.*?/protocols/.*?/auth)$ /var/www/keystone/main/$1

Make sure the *wsgi-keystone.conf* contains a *<Location>* directive for the Shibboleth module and
a *<Location>* directive for each identity provider::

    <Location /Shibboleth.sso>
        SetHandler shib
    </Location>

    <Location /v3/OS-FEDERATION/identity_providers/idp_1/protocols/saml2/auth>
        ShibRequestSetting requireSession 1
        ShibRequestSetting applicationId idp_1
        AuthType shibboleth
        ShibRequireAll On
        ShibRequireSession On
        ShibExportAssertion Off
        Require valid-user
    </Location>

.. NOTE::
    * ``saml2`` may be different in your deployment, but do not use a wildcard value.
      Otherwise *every* federated protocol will be handled by Shibboleth.
    * ``idp_1`` has to be replaced with the name associated with the idp in Keystone.
      The same name is used inside the shibboleth2.xml configuration file but they could
      be different.
    * The ``ShibRequireSession`` and ``ShibRequireAll`` rules are invalid in
      Apache 2.4+ and should be dropped in that specific setup.
    * You are advised to carefully examine `Shibboleth Apache configuration
      documentation
      <https://wiki.shibboleth.net/confluence/display/SHIB2/NativeSPApacheConfig>`_

Enable the Keystone virtual host, for example:

.. code-block:: bash

    $ a2ensite wsgi-keystone.conf

Enable the ``ssl`` and ``shib2`` modules, for example:

.. code-block:: bash

    $ a2enmod ssl
    $ a2enmod shib2

Restart Apache, for example:

.. code-block:: bash

    $ service apache2 restart

Configuring shibboleth2.xml
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Once you have your Keystone vhost (virtual host) ready, it's then time to
configure Shibboleth and upload your Metadata to the Identity Provider.

If new certificates are required, they can be easily created by executing:

.. code-block:: bash

    $ shib-keygen -y <number of years>

The newly created file will be stored under ``/etc/shibboleth/sp-key.pem``

You should fetch your Service Provider's Metadata file. Typically this can be
achieved by simply fetching a Metadata file, for example:

.. code-block:: bash

    $ wget --no-check-certificate -O <name of the file> https://service.example.org/Shibboleth.sso/Metadata

Upload your Service Provider's Metadata file to your Identity Provider.
This step depends on your Identity Provider choice and is not covered here.

Configure your Service Provider by editing ``/etc/shibboleth/shibboleth2.xml``
file. You are advised to examine `Shibboleth Service Provider Configuration documentation <https://wiki.shibboleth.net/confluence/display/SHIB2/Configuration>`_

An example of your ``/etc/shibboleth/shibboleth2.xml`` may look like
(The example shown below is for reference only, not to be used in a production
environment):

.. code-block:: xml

    <!--
    File configuration courtesy of http://testshib.org

    More  information:
    https://wiki.shibboleth.net/confluence/display/SHIB2/NativeSPConfiguration
    -->

    <SPConfig xmlns="urn:mace:shibboleth:2.0:native:sp:config"
    xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" clockSkew="1800 ">

        <!-- The entityID is the name TestShib made for your SP. -->
        <ApplicationDefaults entityID="https://<yourhosthere>/shibboleth">

            <!--
            You should use secure cookies if at all possible.
            See cookieProps in this Wiki article.
            -->
            <!-- https://wiki.shibboleth.net/confluence/display/SHIB2/NativeSPSessions  -->
            <Sessions lifetime="28800" timeout="3600" checkAddress="false"
            relayState="ss:mem" handlerSSL="false">

                <!-- Triggers a login request directly to the TestShib IdP. -->
                <!-- https://wiki.shibboleth.net/confluence/display/SHIB2/NativeSPServiceSSO -->
                <SSO entityID="https://<idp-url>/idp/shibboleth" ECP="true">
                    SAML2 SAML1
                </SSO>

                <!-- SAML and local-only logout. -->
                <!-- https://wiki.shibboleth.net/confluence/display/SHIB2/NativeSPServiceLogout -->
                <Logout>SAML2 Local</Logout>

                <!--
                Handlers allow you to interact with the SP and gather
                more information. Try them out!
                Attribute value s received by the SP through SAML
                will be visible at:
                http://<yourhosthere>/Shibboleth.sso/Session
                -->

                <!--
                Extension service that generates "approximate" metadata
                based on SP configuration.
                -->
                <Handler type="MetadataGenerator" Location="/Metadata"
                signing="false"/>

                <!-- Status reporting service. -->
                <Handler type="Status" Location="/Status"
                acl="127.0.0.1"/>

                <!-- Session diagnostic service. -->
                <Handler type="Session" Location="/Session"
                showAttributeValues="true"/>
                <!-- JSON feed of discovery information. -->
                <Handler type="DiscoveryFeed" Location="/DiscoFeed"/>
            </Sessions>

            <!--
            Error pages to display to yourself if
            something goes horribly wrong.
            -->
            <Errors supportContact  ="<admin_email_address>"
                logoLocation="/shibboleth-sp/logo.jpg"
                styleSheet="/shibboleth-sp/main.css"/>

            <!--
            Loads and trusts a metadata file that describes only one IdP
            and  how to communicate with it.
            -->
            <MetadataProvider type="XML" uri="<idp-metadata-file>"
                 backingFilePath="<local idp metadata>"
                 reloadInterval="180000" />

            <!-- Attribute and trust options you shouldn't need to change. -->
            <AttributeExtractor type="XML" validate="true"
            path="attribute-map.xml"/>
            <AttributeResolver type="Query" subjectMatch="true"/>
            <AttributeFilter type="XML" validate="true"
            path="attribute-policy.xml"/>

            <!--
            Your SP generated these credentials.
            They're used to talk to IdP's.
            -->
            <CredentialResolver type="File" key="sp-key.pem"
            certificate="sp-cert.pem"/>

            <ApplicationOverride id="idp_1" entityID="https://<yourhosthere>/shibboleth">
               <Sessions lifetime="28800" timeout="3600" checkAddress="false"
               relayState="ss:mem" handlerSSL="false">

                <!-- Triggers a login request directly to the TestShib IdP. -->
                <SSO entityID="https://<idp_1-url>/idp/shibboleth" ECP="true">
                    SAML2 SAML1
                </SSO>

                <Logout>SAML2 Local</Logout>
               </Sessions>

               <MetadataProvider type="XML" uri="<idp_1-metadata-file>"
                 backingFilePath="<local idp_1 metadata>"
                 reloadInterval="180000" />

            </ApplicationOverride>

            <ApplicationOverride id="idp_2" entityID="https://<yourhosthere>/shibboleth">
               <Sessions lifetime="28800" timeout="3600" checkAddress="false"
               relayState="ss:mem" handlerSSL="false">

                <!-- Triggers a login request directly to the TestShib IdP. -->
                <SSO entityID="https://<idp_2-url>/idp/shibboleth" ECP="true">
                    SAML2 SAML1
                </SSO>

                <Logout>SAML2 Local</Logout>
               </Sessions>

               <MetadataProvider type="XML" uri="<idp_2-metadata-file>"
                 backingFilePath="<local idp_2 metadata>"
                 reloadInterval="180000" />

            </ApplicationOverride>

        </ApplicationDefaults>

        <!--
        Security policies you shouldn't change unless you
        know what you're doing.
        -->
        <SecurityPolicyProvider type="XML" validate="true"
        path="security-policy.xml"/>

        <!--
        Low-level configuration about protocols and bindings
        available for use.
        -->
        <ProtocolProvider type="XML" validate="true" reloadChanges="false"
        path="protocols.xml"/>

    </SPConfig>

Keystone enforces `external authentication`_ when the ``REMOTE_USER``
environment variable is present so make sure Shibboleth doesn't set the
``REMOTE_USER`` environment variable.  To do so, scan through the
``/etc/shibboleth/shibboleth2.xml`` configuration file and remove the
``REMOTE_USER`` directives.

Examine your attributes map file ``/etc/shibboleth/attributes-map.xml`` and adjust
your requirements if needed. For more information see
`attributes documentation <https://wiki.shibboleth.net/confluence/display/SHIB2/NativeSPAddAttribute>`_

Once you are done, restart your Shibboleth daemon:

.. _`external authentication`: ../external-auth.html

.. code-block:: bash

    $ service shibd restart
    $ service apache2 restart
