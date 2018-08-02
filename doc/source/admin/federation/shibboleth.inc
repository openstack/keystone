.. -*- rst -*-

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

.. _shibboleth:

---------------------
Setting up Shibboleth
---------------------

See :ref:`keystone-as-sp` before proceeding with these Shibboleth-specific
instructions.

.. note::

   The examples below are for Ubuntu 16.04, for which only version 2 of the
   Shibboleth Service Provider is available. Version 3 is available for other
   distributions and the configuration should be identical to version 2.

Configuring Apache HTTPD for mod_shib
-------------------------------------

.. note::

   You are advised to carefully examine the `mod_shib Apache configuration
   documentation`_.

.. _mod_shib Apache configuration documentation: https://wiki.shibboleth.net/confluence/display/SHIB2/NativeSPApacheConfig

Configure keystone under Apache, following the steps in the install guide for
`SUSE`_, `RedHat`_ or `Ubuntu`_.

.. _`SUSE`: ../../install/keystone-install-obs.html#configure-the-apache-http-server
.. _`RedHat`: ../../install/keystone-install-rdo.html#configure-the-apache-http-server
.. _`Ubuntu`: ../../install/keystone-install-ubuntu.html#configure-the-apache-http-server

Install the Module
~~~~~~~~~~~~~~~~~~

Install the Apache module package. For example, on Ubuntu:

.. code-block:: console

   # apt-get install libapache2-mod-shib2

The package and module name will differ between distributions.

Configure Protected Endpoints
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In the Apache configuration for the keystone VirtualHost, set an additional
``<Location>`` which is not part of keystone's API:

.. code-block:: apache

   <Location /Shibboleth.sso>
       SetHandler shib
   </Location>

If you are using ``mod_proxy``, for example to proxy requests to the
``/identity`` path to keystone's UWSGI service, you must exempt this Shibboleth
endpoint from it:

.. code-block:: apache

   Proxypass Shibboleth.sso !

Configure each protected path to use the ``shibboleth`` AuthType:

.. code-block:: apache

   <Location /v3/OS-FEDERATION/identity_providers/samltest/protocols/saml2/auth>
       Require valid-user
       AuthType shibboleth
       ShibRequestSetting requireSession 1
       ShibExportAssertion off
       <IfVersion < 2.4>
           ShibRequireSession On
           ShibRequireAll On
       </IfVersion>
   </Location>

Do the same for the WebSSO auth paths if using horizon as a single sign-on
frontend:

.. code-block:: apache

   <Location /v3/auth/OS-FEDERATION/websso/saml2>
       Require valid-user
       AuthType shibboleth
       ShibRequestSetting requireSession 1
       ShibExportAssertion off
       <IfVersion < 2.4>
           ShibRequireSession On
           ShibRequireAll On
       </IfVersion>
   </Location>
   <Location /v3/auth/OS-FEDERATION/identity_providers/samltest/protocols/saml2/websso>
       Require valid-user
       AuthType shibboleth
       ShibRequestSetting requireSession 1
       ShibExportAssertion off
       <IfVersion < 2.4>
           ShibRequireSession On
           ShibRequireAll On
       </IfVersion>
   </Location>

Remember to reload Apache after altering the VirtualHost:

.. code-block:: console

   # systemctl reload apache2

Configuring mod_shib
--------------------

.. note::

   You are advised to examine `Shibboleth Service Provider Configuration
   documentation
   <https://wiki.shibboleth.net/confluence/display/SHIB2/Configuration>`_

Generate a keypair
~~~~~~~~~~~~~~~~~~

For all SAML Service Providers, a PKI key pair must be generated and exchanged
with the Identity Provider. The ``mod_shib`` package on the Ubuntu distribution
provides a utility to generate the key pair:

.. code-block:: console

   # shib-keygen -y <number of years>

which will generate a key pair under ``/etc/shibboleth``. In other cases, the
package might generate the key pair automatically upon installation.

Configure metadata
~~~~~~~~~~~~~~~~~~

``mod_shib`` also has its own configuration file at
``/etc/shibboleth/shibboleth2.xml`` that must be altered, as well
as its own daemon. First, give the Service Provider an entity ID. This is a URN
that you choose that must be globally unique to the Identity Provider:

.. code-block:: xml

   <ApplicationDefaults entityID="https://sp.keystone.example.org/shibboleth"
       REMOTE_USER="eppn persistent-id targeted-id">

Depending on your Identity Provider, you may also want to change the REMOTE_USER
setting, more on that in a moment.

Set the entity ID of the Identity Provider (this is the same as the value you
provided for ``--remote-id`` in `Identity Provider`):

.. code-block:: xml

   <SSO entityID="https://samltest.id/saml/idp">

Additionally, if you want to enable ECP (required for Keystone-to-Keystone),
the SSO tag for this entity must also have the ECP flag set:


.. code-block:: xml

   <SSO entityID="https://samltest.id/saml/idp" ECP="true">

Tell Shibboleth where to find the metadata of the Identity Provider. You could
either tell it to fetch it from a URI or point it to a local file. For example,
pointing to a local file:

.. code-block:: xml

   <MetadataProvider type="XML" file="/etc/shibboleth/samltest-metadata.xml" />

or pointing to a remote location:

.. code-block:: xml

   <MetadataProvider type="XML" url="https://samltest.id/saml/idp"
       backingFile="samltest-metadata.xml" />

When you are finished configuring ``shibboleth2.xml``, restart the ``shibd``
daemon:

.. code-block:: console

   # systemctl restart shibd

Check the ``shibd`` logs in ``/var/log/shibboleth/shibd.log`` and
``/var/log/shibboleth/shibd_warn.log`` for errors or warnings.

Configure allowed attributes
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. note::

   For more information see the `attributes documentation
   <https://wiki.shibboleth.net/confluence/display/SHIB2/NativeSPAddAttribute>`_

By default, ``mod_shib`` does not pass all attributes received from the Identity
Provider to keystone. If your Identity Provider does not use attributes known to
``shibd``, you must configure them. For example, `samltest.id` uses a custom UID
attribute.  It is not discoverable in the Identity Provider metadata, but the
attribute name and type is logged in the ``mod_shib`` logs when an
authentication attempt is made. To allow the attribute, add it to
``/etc/shibboleth/attribute-map.xml``:

.. code-block:: xml

   <Attribute name="urn:oid:0.9.2342.19200300.100.1.1" id="uid" />

You may also want to use that attribute as a value for the ``REMOTE_USER``
variable, which will make the ``REMOTE_USER`` variable usable as a parameter to
your mapping rules. To do so, add it to ``/etc/shibboleth/shibboleth2.xml``:

.. code-block:: xml

   <ApplicationDefaults entityID="https://sp.keystone.example.org/shibboleth"
       REMOTE_USER="uid">

Similarly, if using keystone as your Identity Provider, several custom
attributes will be needed in ``/etc/shibboleth/attribute-map.xml``:

.. code-block:: xml

    <Attribute name="openstack_user" id="openstack_user"/>
    <Attribute name="openstack_roles" id="openstack_roles"/>
    <Attribute name="openstack_project" id="openstack_project"/>
    <Attribute name="openstack_user_domain" id="openstack_user_domain"/>
    <Attribute name="openstack_project_domain" id="openstack_project_domain"/>
    <Attribute name="openstack_groups" id="openstack_groups"/>

And update the ``REMOTE_USER`` variable in ``/etc/shibboleth/shibboleth2.xml``
if desired:

.. code-block:: xml

   <ApplicationDefaults entityID="https://sp.keystone.example.org/shibboleth"
       REMOTE_USER="openstack_user">

Restart the ``shibd`` daemon after making these changes:

.. code-block:: console

   # systemctl restart shibd

Exchange Metadata
~~~~~~~~~~~~~~~~~

Once configured, the Service Provider metadata is available to download:

.. code-block:: console

   # wget https://sp.keystone.example.org/Shibboleth.sso/Metadata

Upload your Service Provider's metadata to your Identity Provider. This step
depends on your Identity Provider choice and is not covered here. If keystone
is your Identity Provider you do not need to upload this file.

Continue configuring keystone
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

:ref:`Continue configuring keystone <federation_configuring_keystone>`
