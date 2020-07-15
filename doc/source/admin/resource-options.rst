================
Resource Options
================

A resource option is an attribute that can be optionally set on an entity in
keystone. These options are used to control specific features or behaviors
within keystone. This allows flexibility on a per-resource basis as opposed to
settings a configuration file value that controls a behavior for all resources
in a deployment.

This flexibility can be useful for deployments is setting different
authentication requirements for users. For example, operators can use resource
options to set the number of failed authentication attempts on a per-user basis
as opposed to setting a global value that is applied to all users.

The purpose of this document is to formally document the supported resource
options used in keystone, their intended behavior, and how to use them.

User Options
============

The following options are available on user resources. If left undefined, they
are assumed to be false or disabled.

These can be set either in the initial user creation (``POST /v3/users``)
or by updating an existing user to include new options
(``PATCH /v3/users/{user_id}``):

.. code-block:: json

   {
       "user": {
           "options": {
               "ignore_lockout_failure_attempts": true
           }
       }
   }

.. note::

    User options of the ``Boolean`` type can be set to ``True``, ``False``, or
    ``None``; if the option is set to ``None``, it is removed from the user's
    data structure.

.. _ignore_user_inactivity:

ignore_user_inactivity
----------------------

Type: ``Boolean``

Opt into ignoring global inactivity lock settings defined in
``keystone.conf [security_compliance]`` on a per-user basis. Setting this
option to ``True`` will make users not set as disabled even after the
globally configured inactivity period is reached.

.. code-block:: json

   {
       "user": {
           "options": {
               "ignore_user_inactivity": true
           }
       }
   }

.. note::
    Setting this option for users which are already disabled will not
    make them automatically enabled. Such users must be enabled manually
    after setting this option to True for them.

See the `security compliance documentation
<security-compliance.html>`_ for more details.

.. _ignore_change_password_upon_first_use:

ignore_change_password_upon_first_use
-------------------------------------

Type: ``Boolean``

Control if a user should be forced to change their password immediately after
they log into keystone for the first time. This can be useful for deployments
that auto-generate passwords but want to ensure a user picks a new password
when they start using the deployment.

.. code-block:: json

   {
       "user": {
           "options": {
               "ignore_change_password_upon_first_use": true
           }
       }
   }

See the :ref:`security compliance documentation
<security_compliance>` for more details.

.. _ignore_password_expiry:

ignore_password_expiry
----------------------

Type: ``Boolean``

Opt into ignoring global password expiration settings defined in
``keystone.conf [security_compliance]`` on a per-user basis. Setting this
option to ``True`` will allow users to continue using passwords that may be
expired according to global configuration values.

.. code-block:: json

   {
       "user": {
           "options": {
               "ignore_password_expiry": true
           }
       }
   }

See the :ref:`security compliance documentation
<security_compliance>` for more details.

.. _ignore_lockout_failure_attempts:

ignore_lockout_failure_attempts
-------------------------------

Type: ``Boolean``

If ``True``, opt into ignoring the number of times a user has authenticated and
locking out the user as a result.

.. code-block:: json

   {
       "user": {
           "options": {
               "ignore_lockout_failure_attempts": true
           }
       }
   }

See the :ref:`security compliance documentation
<security_compliance>` for more details.

.. _lock_password:

lock_password
-------------

Type: ``Boolean``

If set to ``True``, this option disables the ability for users to change their
password through self-service APIs.

.. code-block:: json

   {
       "user": {
           "options": {
               "lock_password": true
           }
       }
   }


See the :ref:`security compliance documentation
<security_compliance>` for more details.

.. _multi_factor_auth_enabled:

multi_factor_auth_enabled
-------------------------

Type: ``Boolean``

Specify if a user has multi-factor authentication enabled on their account.
This will result in different behavior at authentication time and the user may
be presented with different authentication requirements based on multi-factor
configuration.

.. code-block:: json

   {
       "user": {
           "options": {
               "multi_factor_auth_enabled": true
           }
       }
   }

See :ref:`multi_factor_authentication` for further details.

.. _multi_factor_auth_rules:

multi_factor_auth_rules
-----------------------

Type: ``List of Lists of Strings``

Define a list of strings that represent the methods required for a user to
authenticate.

.. code-block:: json

   {
       "user": {
           "options": {
               "multi_factor_auth_rules": [
                   ["password", "totp"],
                   ["password", "u2f"]
               ]
           }
       }
   }


See :ref:`multi_factor_authentication` for further details.

Role Options
============

The following options are available on role resources. If left undefined, they
are assumed to be false or disabled.

immutable
---------

Type: ``Boolean``

Specify whether a role is immutable. An immutable role may not be deleted or
modified except to remove the ``immutable`` option.

.. code-block:: json

   {
       "role": {
           "options": {
               "immutable": true
           }
       }
   }

Project Options
===============

The following options are available on project resources. If left undefined, they
are assumed to be false or disabled.

immutable
---------

Type: ``Boolean``

Specify whether a project is immutable. An immutable project may not be deleted
or modified except to remove the ``immutable`` option.

.. code-block:: json

   {
       "project": {
           "options": {
               "immutable": true
           }
       }
   }

Domain Options
==============

The following options are available on domain resources. If left undefined, they
are assumed to be false or disabled.

immutable
---------

Type: ``Boolean``

Specify whether a domain is immutable. An immutable domain may not be deleted
or modified except to remove the ``immutable`` option.

.. code-block:: json

   {
       "domain": {
           "options": {
               "immutable": true
           }
       }
   }
