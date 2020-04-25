# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from oslo_config import cfg

from keystone.conf import utils


disable_user_account_days_inactive = cfg.IntOpt(
    'disable_user_account_days_inactive',
    min=1,
    help=utils.fmt("""
The maximum number of days a user can go without authenticating before being
considered "inactive" and automatically disabled (locked). This feature is
disabled by default; set any value to enable it. This feature depends on the
`sql` backend for the `[identity] driver`. When a user exceeds this threshold
and is considered "inactive", the user's `enabled` attribute in the HTTP API
may not match the value of the user's `enabled` column in the user table.
"""))

lockout_failure_attempts = cfg.IntOpt(
    'lockout_failure_attempts',
    min=1,
    help=utils.fmt("""
The maximum number of times that a user can fail to authenticate before the
user account is locked for the number of seconds specified by
`[security_compliance] lockout_duration`. This feature is disabled by
default. If this feature is enabled and `[security_compliance]
lockout_duration` is not set, then users may be locked out indefinitely
until the user is explicitly enabled via the API. This feature depends on
the `sql` backend for the `[identity] driver`.
"""))

lockout_duration = cfg.IntOpt(
    'lockout_duration',
    default=1800,
    min=1,
    help=utils.fmt("""
The number of seconds a user account will be locked when the maximum number of
failed authentication attempts (as specified by `[security_compliance]
lockout_failure_attempts`) is exceeded. Setting this option will have no effect
unless you also set `[security_compliance] lockout_failure_attempts` to a
non-zero value. This feature depends on the `sql` backend for the `[identity]
driver`.
"""))

password_expires_days = cfg.IntOpt(
    'password_expires_days',
    min=1,
    help=utils.fmt("""
The number of days for which a password will be considered valid
before requiring it to be changed. This feature is disabled by default. If
enabled, new password changes will have an expiration date, however existing
passwords would not be impacted. This feature depends on the `sql` backend for
the `[identity] driver`.
"""))

unique_last_password_count = cfg.IntOpt(
    'unique_last_password_count',
    default=0,
    min=0,
    help=utils.fmt("""
This controls the number of previous user password iterations to keep in
history, in order to enforce that newly created passwords are unique. The total
number which includes the new password should not be greater or equal to this
value. Setting the value to zero (the default) disables this feature. Thus, to
enable this feature, values must be greater than 0. This feature depends on
the `sql` backend for the `[identity] driver`.
"""))

minimum_password_age = cfg.IntOpt(
    'minimum_password_age',
    default=0,
    min=0,
    help=utils.fmt("""
The number of days that a password must be used before the user can change it.
This prevents users from changing their passwords immediately in order to wipe
out their password history and reuse an old password. This feature does not
prevent administrators from manually resetting passwords. It is disabled by
default and allows for immediate password changes. This feature depends on the
`sql` backend for the `[identity] driver`. Note: If `[security_compliance]
password_expires_days` is set, then the value for this option should be less
than the `password_expires_days`.
"""))

password_regex = cfg.StrOpt(
    'password_regex',
    help=utils.fmt("""
The regular expression used to validate password strength requirements. By
default, the regular expression will match any password. The following is an
example of a pattern which requires at least 1 letter, 1 digit, and have a
minimum length of 7 characters: ^(?=.*\\\d)(?=.*[a-zA-Z]).{7,}$ This feature
depends on the `sql` backend for the `[identity] driver`.
"""))  # noqa: W605

password_regex_description = cfg.StrOpt(
    'password_regex_description',
    help=utils.fmt("""
Describe your password regular expression here in language for humans. If a
password fails to match the regular expression, the contents of this
configuration variable will be returned to users to explain why their
requested password was insufficient.
"""))

change_password_upon_first_use = cfg.BoolOpt(
    'change_password_upon_first_use',
    default=False,
    help=utils.fmt("""
Enabling this option requires users to change their password when the user is
created, or upon administrative reset. Before accessing any services, affected
users will have to change their password. To ignore this requirement for
specific users, such as service users, set the `options` attribute
`ignore_change_password_upon_first_use` to `True` for the desired user via the
update user API. This feature is disabled by default. This feature is only
applicable with the `sql` backend for the `[identity] driver`.
"""))


GROUP_NAME = __name__.split('.')[-1]
ALL_OPTS = [
    disable_user_account_days_inactive,
    lockout_failure_attempts,
    lockout_duration,
    password_expires_days,
    unique_last_password_count,
    minimum_password_age,
    password_regex,
    password_regex_description,
    change_password_upon_first_use
]


def register_opts(conf):
    conf.register_opts(ALL_OPTS, group=GROUP_NAME)


def list_opts():
    return {GROUP_NAME: ALL_OPTS}
