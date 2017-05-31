.. _identity_security_compliance:

===============================
Security compliance and PCI-DSS
===============================

As of the Newton release, the Identity service contains additional security
compliance features, specifically to satisfy Payment Card Industry -
Data Security Standard (PCI-DSS) v3.1 requirements. See
`Security Hardening PCI-DSS`_ for more information on PCI-DSS.

Security compliance features are disabled by default and most of the features
only apply to the SQL backend for the identity driver. Other identity backends,
such as LDAP, should implement their own security controls.

Enable these features by changing the configuration settings under the
``[security_compliance]`` section in ``keystone.conf``.

Setting the account lockout threshold
-------------------------------------

The account lockout feature limits the number of incorrect password attempts.
If a user fails to authenticate after the maximum number of attempts, the
service disables the user. Re-enable the user by explicitly setting the
enable user attribute with the update user API call, either
`v2.0`_ or `v3`_.

You set the maximum number of failed authentication attempts by setting
the ``lockout_failure_attempts``:

.. code-block:: ini

    [security_compliance]
    lockout_failure_attempts = 6

You set the number of minutes a user would be locked out by setting
the ``lockout_duration`` in seconds:

.. code-block:: ini

    [security_compliance]
    lockout_duration = 1800

If you do not set the ``lockout_duration``, users may be locked out
indefinitely until the user is explicitly enabled via the API.

Disabling inactive users
------------------------

PCI-DSS 8.1.4 requires that inactive user accounts be removed or disabled
within 90 days. You can achieve this by setting the
``disable_user_account_days_inactive``:

.. code-block:: ini

    [security_compliance]
    disable_user_account_days_inactive = 90

This above example means that users that have not authenticated (inactive) for
the past 90 days are automatically disabled. Users can be re-enabled by
explicitly setting the enable user attribute via the API.

Configuring password expiration
-------------------------------

Passwords can be configured to expire within a certain number of days by
setting the ``password_expires_days``:

.. code-block:: ini

    [security_compliance]
    password_expires_days = 90

Once set, any new password changes have an expiration date based on the
date/time of the password change plus the number of days defined here. Existing
passwords will not be impacted. If you want existing passwords to have an
expiration date, you would need to run a SQL script against the password table
in the database to update the expires_at column.

In addition, you can set it so that passwords never expire for some users by
adding their user ID to ``password_expires_ignore_user_ids`` list:

.. code-block:: ini

    [security_compliance]
    password_expires_ignore_user_ids = [3a54353c9dcc44f690975ea768512f6a]

In this example, the password for user ID ``3a54353c9dcc44f690975ea768512f6a``
would never expire.

Indicating password strength requirements
-----------------------------------------

You set password strength requirements, such as requiring numbers in passwords
or setting a minimum password length, by adding a regular expression to the
``password_regex``:

.. code-block:: ini

    [security_compliance]
    password_regex = ^(?=.*\d)(?=.*[a-zA-Z]).{7,}$

The above example is a regular expression that requires a password to have
one letter, one digit, and a minimum length of seven characters.

If you do set the ``password_regex``, you should provide text that
describes your password strength requirements. You can do this by setting the
``password_regex_description``:

.. code-block:: ini

    [security_compliance]
    password_regex_description = Passwords must contain at least 1 letter, 1
                                 digit, and be a minimum length of 7
                                 characters.

The service returns that description to users to explain why their requested
password did not meet requirements.

.. note::

    You must ensure the ``password_regex_description`` accurately and
    completely describes the ``password_regex``. If the two options are out of
    sync, the help text could inaccurately describe the password requirements
    being applied to the password. This would lead to poor user experience.

Requiring a unique password history
-----------------------------------

The password history requirements controls the number of passwords for a user
that must be unique before an old password can be reused. You can enforce this
by setting the ``unique_last_password_count``:

.. code-block:: ini

    [security_compliance]
    unique_last_password_count= 5

The above example does not allow a user to create a new password that is the
same as any of their last four previous passwords.

Similarly, you can set the number of days that a password must be used before
the user can change it by setting the ``minimum_password_age``:

.. code-block:: ini

    [security_compliance]
    minimum_password_age = 1

In the above example, once a user changes their password, they would not be
able to change it again for one day. This prevents users from changing their
passwords immediately in order to wipe out their password history and reuse an
old password.

.. note::

    When you set ``password_expires_days``, the value for the
    ``minimum_password_age`` should be less than the ``password_expires_days``.
    Otherwise, users would not be able to change their passwords before they
    expire.

.. _Security Hardening PCI-DSS: https://specs.openstack.org/openstack/keystone-specs/specs/keystone/newton/pci-dss.html


.. _v2.0: https://developer.openstack.org/api-ref/identity/v2-admin/index.html?expanded=update-user-admin-endpoint-detail#update-user-admin-endpoint

.. _v3: https://developer.openstack.org/api-ref/identity/v3/index.html#update-user
