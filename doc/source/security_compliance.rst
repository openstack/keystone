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

=============================
Security Compliance & PCI-DSS
=============================

As of the Newton release, keystone added security compliance features,
specifically to satisfy Payment Card Industry - Data Security Standard
(PCI-DSS) v3.1 requirements.  See `Security Hardening: PCI-DSS
<https://specs.openstack.org/openstack/keystone-specs/specs/keystone/newton/
pci-dss.html>`_ for more information on PCI-DSS.

Security compliance features are disabled by default and most of the features
only apply to the SQL backend for the identity driver. Other identity backends,
such as LDAP, should implement their own security controls.

These features can be enabled by changing the configuration settings under the
``[security_compliance]`` section in ``keystone.conf``.

Account Lockout Threshold
-------------------------

The account lockout feature limits the number of times a user can attempt to
login with an incorrect password. If a user fails to authenticate after the
maximum number of attempts, the user will be disabled. Users can be re-enabled
by explicitly setting the enable user attribute via the API.

You can set the maximum number of failed authentication attempts by setting
the ``lockout_failure_attempts``:

.. code-block:: ini

    [security_compliance]
    lockout_failure_attempts = 6

You can then set the number of minutes a user would be locked out by setting
the ``lockout_duration`` in seconds:

.. code-block:: ini

    [security_compliance]
    lockout_duration = 1800

If the ``lockout_duration`` is not set, then users may be locked out
indefinitely until the user is explicitly enabled via the API.

Finally, you can set it so that some users, such as service users, are never
locked out by setting the user options attribute
``ignore_lockout_failure_attempts`` to ``True`` via a user update API
(``PATCH /v3/users``) call.

Disabling Inactive Users
------------------------

PCI-DSS 8.1.4 requires that inactive user accounts be removed or disabled
within 90 days.  You can achieve this by setting the
``disable_user_account_days_inactive``:

.. code-block:: ini

    [security_compliance]
    disable_user_account_days_inactive = 90

This above example means that users that have not authenticated (inactive) for
the past 90 days will be automatically disabled. Users can be re-enabled by
explicitly setting the enable user attribute via the API.

Force users to immediately change their password upon first use
---------------------------------------------------------------

PCI-DSS 8.2.6 requires users to change their password for first time use and
upon an administrative password reset. Within the identity `user API`_,
`create user` and `update user` are considered administrative password
changes. Whereas, `change password for user` is a self-service password
change. Once this feature is enabled, new users, and users that have had their
password reset, will be required to change their password at the next
authentication (first use), before being able to access any services.

Prior to enabling this feature, you will want to exempt any users, especially
service account users, that you do not wish to be required to change their
password. You can mark a user as exempt by setting the user options attribute
``ignore_change_password_upon_first_use`` to ``True`` via a user update API
(``PATCH /v3/users``) call.

.. WARNING::

    Failure to mark service users as exempt from this requirement will result
    in your service account passwords becoming expired after being reset.

When ready, you can configure it so that users are forced to change their
password upon first use by setting ``change_password_after_first_use``:

.. code-block:: ini

    [security_compliance]
    change_password_after_first_use = True

.. _`user API`: http://developer.openstack.org/api-ref/identity/v3/index.html#users

Password Expiration
-------------------

Passwords can be configured to expire within a certain number of days by
setting the ``password_expires_days``:

.. code-block:: ini

    [security_compliance]
    password_expires_days = 90

Once set, any new password changes will have an expiration date based on the
date/time of the password change plus the number of days defined here. Existing
passwords will not be impacted. If you want existing passwords to have an
expiration date, you would need to run a SQL script against the password table
in the database to update the expires_at column.

In addition, you can set it so that passwords never expire for some users by
setting the user options attribute ``ignore_password_expiry`` to ``True`` via
a user update API (``PATCH /v3/users``) call.

Password Strength Requirements
------------------------------

You set password strength requirements, such as requiring numbers in passwords
or setting a minimum password length, by adding a regular expression to the
``password_regex``:

.. code-block:: ini

    [security_compliance]
    password_regex = ^(?=.*\d)(?=.*[a-zA-Z]).{7,}$

The above is an example of a regular expression that requires 1 letter, 1
digit, and a minimum length of 7 characters.

If you do set the ``password_regex``, you will also want to provide text that
describes your password strength requirements. You can do this by setting the
``password_regex_description``:

.. code-block:: ini

    [security_compliance]
    password_regex_description = Passwords must contain at least 1 letter, 1
                                 digit, and be a minimum length of 7
                                 characters.

The description will be returned to users to explain why their requested
password was insufficient.

.. NOTE::

    It is imperative to ensure the ``password_regex_description`` fully and
    completely describes the ``password_regex``. If the two options are out of
    sync, the help text may inaccurately describe the password requirements
    being applied to the password. This can lead to poor user experience.

Unique Password History
-----------------------

The password history requirements controls the number of passwords for a user
that must be unique before an old password can be reused. You can enforce this
by setting the ``unique_last_password_count``:

.. code-block:: ini

    [security_compliance]
    unique_last_password_count= 5

The above example will not allow a user to create a new password that is the
same as any of their last 4 previous passwords.

Similarly, you can set the number of days that a password must be used before
the user can change it by setting the ``minimum_password_age``:

.. code-block:: ini

    [security_compliance]
    minimum_password_age = 1

In the above example, once a user changes their password, they would not be
able to change it again for 1 day. This prevents users from changing their
passwords immediately in order to wipe out their password history and reuse an
old password.

.. NOTE::

    If ``password_expires_days`` is set, then the value for the
    ``minimum_password_age`` should be less than the ``password_expires_days``.
    Otherwise, users would not be able to change their passwords before they
    expire.
