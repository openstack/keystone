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
    default=None,
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
    default=0,
    min=0,
    help=utils.fmt("""
The maximum number of times that a user can fail to authenticate before the
user account is locked for the number of seconds specified by
`[security_compliance] lockout_duration`. Setting this value to zero (the
default) disables this feature. This feature depends on the `sql` backend for
the `[identity] driver`.
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
    default=0,
    min=0,
    help=utils.fmt("""
The number of days which a password will be considered valid before requiring
the user to change it. Setting the value to zero (the default) disables this
feature. This feature depends on the `sql` backend for the `[identity] driver`.
"""))

unique_last_password_count = cfg.IntOpt(
    'unique_last_password_count',
    default=0,
    min=0,
    help=utils.fmt("""
This controls the number of previous user password iterations to keep in
history, in order to enforce that newly created passwords are unique. Setting
the value to zero (the default) disables this feature. This feature depends on
the `sql` backend for the `[identity] driver`.
"""))

password_change_limit_per_day = cfg.IntOpt(
    'password_change_limit_per_day',
    default=0,
    min=0,
    help=utils.fmt("""
The maximum number of times a user can change their password in a single day.
Setting the value to zero (the default) disables this feature. This feature
depends on the `sql` backend for the `[identity] driver`.
"""))

password_regex = cfg.StrOpt(
    'password_regex',
    default='^$',
    help=utils.fmt("""
The regular expression used to validate password strength requirements. By
default, the regular expression will match any password. The following is an
example of a pattern which requires at least 1 letter, 1 digit, and have a
minimum length of 7 characters: ^(?=.*\d)(?=.*[a-zA-Z]).{7,}$ This feature
depends on the `sql` backend for the `[identity] driver`.
"""))


GROUP_NAME = __name__.split('.')[-1]
ALL_OPTS = [
    disable_user_account_days_inactive,
    lockout_failure_attempts,
    lockout_duration,
    password_expires_days,
    unique_last_password_count,
    password_change_limit_per_day,
    password_regex,
]


def register_opts(conf):
    conf.register_opts(ALL_OPTS, group=GROUP_NAME)


def list_opts():
    return {GROUP_NAME: ALL_OPTS}
