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

.. _mellon:

-----------------
Setting Up Mellon
-----------------

See :ref:`keystone-as-sp` before proceeding with these Mellon-specific
instructions.

Configuring Apache HTTPD for mod_auth_mellon
--------------------------------------------

.. note::

   You are advised to carefully examine the `mod_auth_mellon documentation`_.

.. _mod_auth_mellon documentation: https://github.com/Uninett/mod_auth_mellon/blob/master/doc/user_guide/mellon_user_guide.adoc#installing-configuring-mellon

Follow the steps outlined at: Keystone install guide for `SUSE`_, `RedHat`_ or
`Ubuntu`_.

.. _`SUSE`: ../../install/keystone-install-obs.html#configure-the-apache-http-server
.. _`RedHat`: ../../install/keystone-install-rdo.html#configure-the-apache-http-server
.. _`Ubuntu`: ../../install/keystone-install-ubuntu.html#configure-the-apache-http-server

Install the Module
~~~~~~~~~~~~~~~~~~

Install the Apache module package. For example, on Ubuntu:

.. code-block:: console

   # apt-get install libapache2-mod-auth-mellon

The package and module name will differ between distributions.

Configure mod_auth_mellon
~~~~~~~~~~~~~~~~~~~~~~~~~

Unlike ``mod_shib``, all of ``mod_auth_mellon``'s configuration is done in
Apache, not in a separate config file. Set up the shared settings in a single
``<Location>`` directive near the top in your keystone VirtualHost file, before
your protected endpoints:

.. code-block:: apache

   <Location /v3>
       MellonEnable "info"
       MellonSPPrivateKeyFile /etc/apache2/mellon/sp.keystone.example.org.key
       MellonSPCertFile /etc/apache2/mellon/sp.keystone.example.org.cert
       MellonSPMetadataFile /etc/apache2/mellon/sp-metadata.xml
       MellonIdPMetadataFile /etc/apache2/mellon/idp-metadata.xml
       MellonEndpointPath /v3/mellon
       MellonIdP "IDP"
   </Location>

Configure Protected Endpoints
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Configure each protected path to use the ``Mellon`` AuthType:

.. code-block:: apache

   <Location /v3/OS-FEDERATION/identity_providers/samltest/protocols/saml2/auth>
      Require valid-user
      AuthType Mellon
      MellonEnable auth
   </Location>

Do the same for the WebSSO auth paths if using horizon as a single sign-on
frontend:

.. code-block:: apache

   <Location /v3/auth/OS-FEDERATION/websso/saml2>
      Require valid-user
      AuthType Mellon
      MellonEnable auth
   </Location>
   <Location /v3/auth/OS-FEDERATION/identity_providers/samltest/protocols/saml2/websso>
      Require valid-user
      AuthType Mellon
      MellonEnable auth
   </Location>

Configure the Mellon Service Provider Metadata
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Mellon provides a script called ``mellon_create_metadata.sh``_ which generates
the values for the config directives ``MellonSPPrivateKeyFile``,
``MellonSPCertFile``, and ``MellonSPMetadataFile``. Run the script:

.. code-block:: console

   $ ./mellon_create_metadata.sh \
   https://sp.keystone.example.org/mellon \
   http://sp.keystone.example.org/v3/OS-FEDERATION/identity_providers/samltest/protocols/saml2/auth/mellon

The first parameter is used as the entity ID, a URN of your choosing that must
uniquely identify the Service Provider to the Identity Provider. The second
parameter is the full URL for the endpoint path corresponding to the parameter
``MellonEndpointPath``.

After generating the keypair and metadata, copy the files to the locations
given by the ``MellonSPPrivateKeyFile`` and ``MellonSPCertFile`` settings in
your Apache configuration.

Upload the Service Provider's Metadata file which you just generated to your
Identity Provider. This is the file used as the value of the
`MellonSPMetadataFile` in the config. The IdP may provide a webpage where you
can upload the file, or you may be required to submit the file using `wget` or
`curl`. Please check your IdP documentation for details.

Exchange Metadata
~~~~~~~~~~~~~~~~~

Fetch your Identity Provider's Metadata file and copy it to the path specified
by the ``MellonIdPMetadataFile`` setting in your Apache configuration.

.. code-block:: console

   $ wget -O /etc/apache2/mellon/idp-metadata.xml https://samltest.id/saml/idp

Remember to reload Apache after finishing configuring Mellon:

.. code-block:: console

   # systemctl reload apache2

.. _`mellon_create_metadata.sh`: https://github.com/UNINETT/mod_auth_mellon/blob/master/mellon_create_metadata.sh

Continue configuring keystone
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

:ref:`Continue configuring keystone <federation_configuring_keystone>`
