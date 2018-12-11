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

ignore_change_password_upon_first_use
-------------------------------------

Type: ``Boolean``

Control if a user should be forced to change their password immediately after
they log into keystone for the first time. This can be useful for deployments
that auto-generate passwords but want to ensure a user picks a new password
when they start using the deployment.

See the `security compliance documentation
<security-compliance.html>`_ for more details.

ignore_password_expiry
----------------------

Type: ``Boolean``

Opt into ignoring global password expiration settings defined in
``keystone.conf [security_compliance]`` on a per-user basis. Setting this
option to ``True`` will allow users to continue using passwords that may be
expired according to global configuration values.

See the `security compliance documentation
<security-compliance.html>`_ for more details.

ignore_lockout_failure_attempts
-------------------------------

Type: ``Boolean``

If ``True``, opt into ignoring the number of times a user has authenticated and
locking out the user as a result.

See the `security compliance documentation
<security-compliance.html>`_ for more details.

lock_password
-------------

Type: ``Boolean``

If set to ``True``, this option disables the ability for users to change their
password through self-service APIs.

See the `security compliance documentation
<security-compliance.html>`_ for more details.

multi_factor_auth_enabled
-------------------------

Type: ``Boolean``

Specify if a user has multi-factor authentication enabled on their account.
This will result in different behavior at authentication time and the user may
be presented with different authentication requirements based on multi-factor
configuration.

multi_factor_auth_rules
-----------------------

Type: ``List of Lists of Strings``

Define a list of strings that represent the methods required for a user to
authenticate.
