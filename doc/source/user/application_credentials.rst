..
      Copyright 2018 SUSE Linux GmbH
      All Rights Reserved.

      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

=======================
Application Credentials
=======================

Users can create application credentials to allow their applications to
authenticate to keystone. Users can delegate a subset of their role assignments
on a project to an application credential, granting the application the same or
restricted authorization to a project. With application credentials,
applications authenticate with the application credential ID and a secret string
which is not the user's password. This way, the user's password is not embedded
in the application's configuration, which is especially important for users
whose identities are managed by an external system such as LDAP or a
single-signon system.

See the `Identity API reference`_ for more information on authenticating with
and managing application credentials.

.. _`Identity API reference`: https://developer.openstack.org/api-ref/identity/v3/index.html#application-credentials

Managing Application Credentials
================================

Create an application credential using python-keystoneclient:

.. code-block:: console

   $ openstack application credential create monitoring
   +--------------+----------------------------------------------------------------------------------------+
   | Field        | Value                                                                                  |
   +--------------+----------------------------------------------------------------------------------------+
   | description  | None                                                                                   |
   | expires_at   | None                                                                                   |
   | id           | 26bb287fd56a41f8a577c47f79221187                                                       |
   | name         | monitoring                                                                             |
   | project_id   | e99b6f4b9bf84a9da27e20c9cbfe887a                                                       |
   | roles        | Member anotherrole                                                                     |
   | secret       | PJXxBFGPOLwdl3PA6tSivJT9S4RpWhLcNZH2gXzCoxX1C2cnZsj2_Xmfw-LE7Wc-NwuJEYoHcG0gQ5bjWwe-bg |
   | unrestricted | False                                                                                  |
   +--------------+----------------------------------------------------------------------------------------+

The only required parameter is a name. The application credential is created for
the project to which the user is currently scoped with the same role assignments
the user has on that project. Keystone will automatically generate a secret
string that will be revealed once at creation time. You can also provide your
own secret, if desired:

.. code-block:: console

   $ openstack application credential create monitoring --secret securesecret
   +--------------+----------------------------------+
   | Field        | Value                            |
   +--------------+----------------------------------+
   | description  | None                             |
   | expires_at   | None                             |
   | id           | bc257241e21747768c83fb9806af392d |
   | name         | monitoring                       |
   | project_id   | e99b6f4b9bf84a9da27e20c9cbfe887a |
   | roles        | Member anotherrole               |
   | secret       | securesecret                     |
   | unrestricted | False                            |
   +--------------+----------------------------------+

The secret is hashed before it is stored, so the original secret is not
retrievable after creation. If the secret is lost, a new application credential
must be created.

If none are provided, the application credential is created with the same role
assignments on the project that the user has. You can find out what role
assignments you have on a project by examining your token or your keystoneauth
session:

.. code-block:: python

   >>> mysession.auth.auth_ref.role_names
   [u'anotherrole', u'Member']

If you have more than one role assignment on a project, you can grant your
application credential only a subset of your role assignments if desired. This
is useful if you have administrator privileges on a project but only want the
application to have basic membership privileges, or if you have basic membership
privileges but want the application to only have read-only privileges. You
cannot grant the application a role assignment that your user does not already
have; for instance, if you are an admin on a project, and you want your
application to have read-only access to the project, you must acquire a
read-only role assignment on that project yourself before you can delegate it to
the application credential. Removing a user's role assignment on a project will
invalidate the user's application credentials for that project.

.. code-block:: console

   $ openstack application credential create monitoring --role Member
   +--------------+----------------------------------------------------------------------------------------+
   | Field        | Value                                                                                  |
   +--------------+----------------------------------------------------------------------------------------+
   | description  | None                                                                                   |
   | expires_at   | None                                                                                   |
   | id           | 5d04e42491a54e83b313aa2625709411                                                       |
   | name         | monitoring                                                                             |
   | project_id   | e99b6f4b9bf84a9da27e20c9cbfe887a                                                       |
   | roles        | Member                                                                                 |
   | secret       | vALEOMENxB_QaKFZOA2XOd7stwrhTlqPKrOdrXXM5BORss9u3O6GT-w_HYCPaZbtg96sDPCdtzVARZLpgUOY_g |
   | unrestricted | False                                                                                  |
   +--------------+----------------------------------------------------------------------------------------+

You can provide an expiration date for application credentials:

.. code-block:: console

   $ openstack application credential create monitoring --expiration '2019-02-12T20:52:43'
   +--------------+----------------------------------------------------------------------------------------+
   | Field        | Value                                                                                  |
   +--------------+----------------------------------------------------------------------------------------+
   | description  | None                                                                                   |
   | expires_at   | 2019-02-12T20:52:43.000000                                                             |
   | id           | 4ea8c4a84f7b4c65a3d84460be9cd1f7                                                       |
   | name         | monitoring                                                                             |
   | project_id   | e99b6f4b9bf84a9da27e20c9cbfe887a                                                       |
   | roles        | Member anotherrole                                                                     |
   | secret       | _My16dlySn6jr7pGvBxjcMrmPA0MCpYlkKWs3gpY3-Ybk05yt2Hh83uMdTLPWlFeh8lOXajIAVHrQaBQ06iz5Q |
   | unrestricted | False                                                                                  |
   +--------------+----------------------------------------------------------------------------------------+

By default, application credentials are restricted from creating or deleting
other application credentials and from creating or deleting trusts. If your
application needs to be able to perform these actions and you accept the risks
involved, you can disable this protection:

.. warning::

   Restrictions on these Identity operations are deliberately imposed as a
   safeguard to prevent a compromised application credential from regenerating
   itself. Disabling this restriction poses an inherent added risk.

.. code-block:: console

   $ openstack application credential create monitoring --unrestricted
   +--------------+----------------------------------------------------------------------------------------+
   | Field        | Value                                                                                  |
   +--------------+----------------------------------------------------------------------------------------+
   | description  | None                                                                                   |
   | expires_at   | None                                                                                   |
   | id           | 0a0372dbedfb4e82ab66449c3316ef1e                                                       |
   | name         | monitoring                                                                             |
   | project_id   | e99b6f4b9bf84a9da27e20c9cbfe887a                                                       |
   | roles        | Member anotherrole                                                                     |
   | secret       | ArOy6DYcLeLTRlTmfvF1TH1QmRzYbmD91cbVPOHL3ckyRaLXlaq5pTGJqvCvqg6leEvTI1SQeX3QK-3iwmdPxg |
   | unrestricted | True                                                                                   |
   +--------------+----------------------------------------------------------------------------------------+

Using Application Credentials
=============================

Applications can authenticate using the application_credential auth method. For
a service using keystonemiddleware to authenticate with keystone, the
auth section would look like this:

.. code-block:: ini

   [keystone_authtoken]
   auth_url = https://keystone.server/identity/v3
   auth_type = v3applicationcredential
   application_credential_id = 6cb5fa6a13184e6fab65ba2108adf50c
   application_credential_secret= glance_secret

You can also identify your application credential with its name and the name or
ID of its owner. For example:

.. code-block:: ini

   [keystone_authtoken]
   auth_url = https://keystone.server/identity/v3
   auth_type = v3applicationcredential
   username = glance
   user_domain_name = Default
   application_credential_name = glance_cred
   application_credential_secret = glance_secret

Rotating Application Credentials
================================

A user can create multiple application credentials with the same role
assignments on the same project. This allows the application credential to be
gracefully rotated with minimal or no downtime for your application. In
contrast, changing a service user's password results in immediate downtime for
any application using that password until the application can be updated with
the new password.

.. note::

   Rotating application credentials is essential if a team member who has
   knowledge of the application credential identifier and secret leaves the team
   for any reason. Rotating application credentials is also recommended as part
   of regular application maintenance.

Rotating an application credential is a simple process:

#. Create a new application credential. Application credential names must be
   unique within the user's set of application credentials, so this new
   application credential must not have the same name as the old one.

#. Update your application's configuration to use the new ID (or name and user
   identifier) and the new secret. For a distributed application, this can be
   done one node at a time.

#. When your application is fully set up with the new application credential,
   delete the old one.
