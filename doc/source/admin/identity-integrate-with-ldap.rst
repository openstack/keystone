.. _integrate-identity-with-ldap:

============================
Integrate Identity with LDAP
============================

The OpenStack Identity service supports integration with existing LDAP
directories for authentication and authorization services. LDAP back
ends require initialization before configuring the OpenStack Identity
service to work with it. For more information, see `Setting up LDAP
for use with Keystone <https://wiki.openstack.org/wiki/OpenLDAP>`__.

When the OpenStack Identity service is configured to use LDAP back ends,
you can split authentication (using the *identity* feature) and
authorization (using the *assignment* feature).

The *identity* feature enables administrators to manage users and groups
by each domain or the OpenStack Identity service entirely.

The *assignment* feature enables administrators to manage project role
authorization using the OpenStack Identity service SQL database, while
providing user authentication through the LDAP directory.

.. _identity_ldap_server_setup:

Identity LDAP server set up
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. important::

   For the OpenStack Identity service to access LDAP servers, you must
   enable the ``authlogin_nsswitch_use_ldap`` boolean value for SELinux
   on the server running the OpenStack Identity service. To enable and
   make the option persistent across reboots, set the following boolean
   value as the root user:

   .. code-block:: console

      # setsebool -P authlogin_nsswitch_use_ldap on

The Identity configuration is split into two separate back ends; identity
(back end for users and groups), and assignments (back end for domains,
projects, roles, role assignments). To configure Identity, set options
in the ``/etc/keystone/keystone.conf`` file. See
:ref:`integrate-identity-backend-ldap` for Identity back end configuration
examples. Modify these examples as needed.

**To define the destination LDAP server**

#. Define the destination LDAP server in the
   ``/etc/keystone/keystone.conf`` file:

   .. code-block:: ini

      [ldap]
      url = ldap://localhost
      user = dc=Manager,dc=example,dc=org
      password = samplepassword
      suffix = dc=example,dc=org

**Additional LDAP integration settings**

Set these options in the ``/etc/keystone/keystone.conf`` file for a
single LDAP server, or ``/etc/keystone/domains/keystone.DOMAIN_NAME.conf``
files for multiple back ends. Example configurations appear below each
setting summary:

**Query option**

.. hlist::
   :columns: 1

   * Use ``query_scope`` to control the scope level of data presented
     (search only the first level or search an entire sub-tree)
     through LDAP.
   * Use ``page_size`` to control the maximum results per page. A value
     of zero disables paging.
   * Use ``alias_dereferencing`` to control the LDAP dereferencing
     option for queries.

.. code-block:: ini

   [ldap]
   query_scope = sub
   page_size = 0
   alias_dereferencing = default
   chase_referrals =

**Debug**

Use ``debug_level`` to set the LDAP debugging level for LDAP calls.
A value of zero means that debugging is not enabled.

.. code-block:: ini

   [ldap]
   debug_level = 0

.. warning::

   This value is a bitmask, consult your LDAP documentation for
   possible values.

**Connection pooling**

Use ``use_pool`` to enable LDAP connection pooling. Configure the
connection pool size, maximum retry, reconnect trials, timeout (-1
indicates indefinite wait) and lifetime in seconds.

.. code-block:: ini

   [ldap]
   use_pool = true
   pool_size = 10
   pool_retry_max = 3
   pool_retry_delay = 0.1
   pool_connection_timeout = -1
   pool_connection_lifetime = 600

**Connection pooling for end user authentication**

Use ``use_auth_pool`` to enable LDAP connection pooling for end user
authentication. Configure the connection pool size and lifetime in
seconds.

.. code-block:: ini

   [ldap]
   use_auth_pool = false
   auth_pool_size = 100
   auth_pool_connection_lifetime = 60

When you have finished the configuration, restart the OpenStack Identity
service.

.. warning::

   During the service restart, authentication and authorization are
   unavailable.

.. _integrate-identity-backend-ldap:

Integrate Identity back end with LDAP
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The Identity back end contains information for users, groups, and group
member lists. Integrating the Identity back end with LDAP allows
administrators to use users and groups in LDAP.

.. important::

   For OpenStack Identity service to access LDAP servers, you must
   define the destination LDAP server in the
   ``/etc/keystone/keystone.conf`` file. For more information,
   see :ref:`identity_ldap_server_setup`.

**To integrate one Identity back end with LDAP**

#. Enable the LDAP Identity driver in the ``/etc/keystone/keystone.conf``
   file. This allows LDAP as an identity back end:

   .. code-block:: ini

      [identity]
      #driver = sql
      driver = ldap

#. Create the organizational units (OU) in the LDAP directory, and define
   the corresponding location in the ``/etc/keystone/keystone.conf``
   file:

   .. code-block:: ini

      [ldap]
      user_tree_dn = ou=Users,dc=example,dc=org
      user_objectclass = inetOrgPerson

      group_tree_dn = ou=Groups,dc=example,dc=org
      group_objectclass = groupOfNames

   .. note::

      These schema attributes are extensible for compatibility with
      various schemas. For example, this entry maps to the person
      attribute in Active Directory:

      .. code-block:: ini

         user_objectclass = person

#. A read-only implementation is recommended for LDAP integration. These
   permissions are applied to object types in the
   ``/etc/keystone/keystone.conf`` file:

   .. code-block:: ini

      [ldap]
      user_allow_create = False
      user_allow_update = False
      user_allow_delete = False

      group_allow_create = False
      group_allow_update = False
      group_allow_delete = False

   Restart the OpenStack Identity service.

   .. warning::

      During service restart, authentication and authorization are
      unavailable.

**To integrate multiple Identity back ends with LDAP**

#. Set the following options in the ``/etc/keystone/keystone.conf``
   file:

   #. Enable the LDAP driver:

      .. code-block:: ini

         [identity]
         #driver = sql
         driver = ldap

   #. Enable domain-specific drivers:

      .. code-block:: ini

         [identity]
         domain_specific_drivers_enabled = True
         domain_config_dir = /etc/keystone/domains

#. Restart the OpenStack Identity service.

   .. warning::

      During service restart, authentication and authorization are
      unavailable.

#. List the domains using the dashboard, or the OpenStackClient CLI. Refer
   to the `Command List
   <https://docs.openstack.org/developer/python-openstackclient/command-list.html>`__
   for a list of OpenStackClient commands.

#. Create domains using OpenStack dashboard, or the OpenStackClient CLI.

#. For each domain, create a domain-specific configuration file in the
   ``/etc/keystone/domains`` directory. Use the file naming convention
   ``keystone.DOMAIN_NAME.conf``, where DOMAIN\_NAME is the domain name
   assigned in the previous step.

   .. note::

      The options set in the
      ``/etc/keystone/domains/keystone.DOMAIN_NAME.conf`` file will
      override options in the ``/etc/keystone/keystone.conf`` file.

#. Define the destination LDAP server in the
   ``/etc/keystone/domains/keystone.DOMAIN_NAME.conf`` file. For example:

   .. code-block:: ini

      [ldap]
      url = ldap://localhost
      user = dc=Manager,dc=example,dc=org
      password = samplepassword
      suffix = dc=example,dc=org

#. Create the organizational units (OU) in the LDAP directories, and define
   their corresponding locations in the
   ``/etc/keystone/domains/keystone.DOMAIN_NAME.conf`` file. For example:

   .. code-block:: ini

      [ldap]
      user_tree_dn = ou=Users,dc=example,dc=org
      user_objectclass = inetOrgPerson

      group_tree_dn = ou=Groups,dc=example,dc=org
      group_objectclass = groupOfNames

   .. note::

      These schema attributes are extensible for compatibility with
      various schemas. For example, this entry maps to the person
      attribute in Active Directory:

      .. code-block:: ini

         user_objectclass = person

#. A read-only implementation is recommended for LDAP integration. These
   permissions are applied to object types in the
   ``/etc/keystone/domains/keystone.DOMAIN_NAME.conf`` file:

   .. code-block:: ini

      [ldap]
      user_allow_create = False
      user_allow_update = False
      user_allow_delete = False

      group_allow_create = False
      group_allow_update = False
      group_allow_delete = False

#. Restart the OpenStack Identity service.

   .. warning::

      During service restart, authentication and authorization are
      unavailable.

**Additional LDAP integration settings**

Set these options in the ``/etc/keystone/keystone.conf`` file for a
single LDAP server, or ``/etc/keystone/domains/keystone.DOMAIN_NAME.conf``
files for multiple back ends. Example configurations appear below each
setting summary:

Filters
   Use filters to control the scope of data presented through LDAP.

   .. code-block:: ini

      [ldap]
      user_filter = (memberof=cn=openstack-users,ou=workgroups,dc=example,dc=org)
      group_filter =

Identity attribute mapping
   Mask account status values (include any additional attribute
   mappings) for compatibility with various directory services.
   Superfluous accounts are filtered with ``user_filter``.

   Setting attribute ignore to list of attributes stripped off on
   update.

   For example, you can mask Active Directory account status attributes
   in the ``/etc/keystone/keystone.conf`` file:

   .. code-block:: ini

      [ldap]
      user_id_attribute      = cn
      user_name_attribute    = sn
      user_mail_attribute    = mail
      user_pass_attribute    = userPassword
      user_enabled_attribute = userAccountControl
      user_enabled_mask      = 2
      user_enabled_invert    = false
      user_enabled_default   = 512
      user_default_project_id_attribute =
      user_additional_attribute_mapping =

      group_id_attribute     = cn
      group_name_attribute   = ou
      group_member_attribute = member
      group_desc_attribute   = description
      group_additional_attribute_mapping =

Enabled emulation
   An alternative method to determine if a user is enabled or not is by
   checking if that user is a member of the emulation group.

   Use DN of the group entry to hold enabled user when using enabled
   emulation.

   .. code-block:: ini

      [ldap]
      user_enabled_emulation = false
      user_enabled_emulation_dn = false

When you have finished configuration, restart the OpenStack Identity
service.

.. warning::

   During service restart, authentication and authorization are
   unavailable.

Secure the OpenStack Identity service connection to an LDAP back end
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The Identity service supports the use of TLS to encrypt LDAP traffic.
Before configuring this, you must first verify where your certificate
authority file is located. For more information, see the
`OpenStack Security Guide SSL introduction <https://docs.openstack.org/
security-guide/secure-communication/introduction-to-ssl-and-tls.html>`_.

Once you verify the location of your certificate authority file:

**To configure TLS encryption on LDAP traffic**

#. Open the ``/etc/keystone/keystone.conf`` configuration file.

#. Find the ``[ldap]`` section.

#. In the ``[ldap]`` section, set the ``use_tls`` configuration key to
   ``True``. Doing so will enable TLS.

#. Configure the Identity service to use your certificate authorities file.
   To do so, set the ``tls_cacertfile`` configuration key in the ``ldap``
   section to the certificate authorities file's path.

   .. note::

      You can also set the ``tls_cacertdir`` (also in the ``ldap``
      section) to the directory where all certificate authorities files
      are kept. If both ``tls_cacertfile`` and ``tls_cacertdir`` are set,
      then the latter will be ignored.

#. Specify what client certificate checks to perform on incoming TLS
   sessions from the LDAP server. To do so, set the ``tls_req_cert``
   configuration key in the ``[ldap]`` section to ``demand``, ``allow``, or
   ``never``:

   .. hlist::
      :columns: 1

      * ``demand`` - The LDAP server always receives certificate
        requests. The session terminates if no certificate
        is provided, or if the certificate provided cannot be verified
        against the existing certificate authorities file.
      * ``allow`` - The LDAP server always receives certificate
        requests. The session will proceed as normal even if a certificate
        is not provided. If a certificate is provided but it cannot be
        verified against the existing certificate authorities file, the
        certificate will be ignored and the session will proceed as
        normal.
      * ``never`` - A certificate will never be requested.

On distributions that include openstack-config, you can configure TLS
encryption on LDAP traffic by running the following commands instead.

.. code-block:: console

   # openstack-config --set /etc/keystone/keystone.conf \
     ldap use_tls True
   # openstack-config --set /etc/keystone/keystone.conf \
     ldap tls_cacertfile ``CA_FILE``
   # openstack-config --set /etc/keystone/keystone.conf \
     ldap tls_req_cert ``CERT_BEHAVIOR``

Where:

- ``CA_FILE`` is the absolute path to the certificate authorities file
  that should be used to encrypt LDAP traffic.

- ``CERT_BEHAVIOR`` specifies what client certificate checks to perform
  on an incoming TLS session from the LDAP server (``demand``,
  ``allow``, or ``never``).
