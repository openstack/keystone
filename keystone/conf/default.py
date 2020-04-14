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


admin_token = cfg.StrOpt(
    'admin_token',
    secret=True,
    help=utils.fmt("""
Using this feature is *NOT* recommended. Instead, use the `keystone-manage
bootstrap` command. The value of this option is treated as a "shared secret"
that can be used to bootstrap Keystone through the API. This "token" does not
represent a user (it has no identity), and carries no explicit authorization
(it effectively bypasses most authorization checks). If set to `None`, the
value is ignored and the `admin_token` middleware is effectively disabled.
"""))

public_endpoint = cfg.URIOpt(
    'public_endpoint',
    help=utils.fmt("""
The base public endpoint URL for Keystone that is advertised to clients (NOTE:
this does NOT affect how Keystone listens for connections). Defaults to the
base host URL of the request. For example, if keystone receives a request to
`http://server:5000/v3/users`, then this will option will be automatically
treated as `http://server:5000`. You should only need to set option if either
the value of the base URL contains a path that keystone does not automatically
infer (`/prefix/v3`), or if the endpoint should be found on a different host.
"""))

max_project_tree_depth = cfg.IntOpt(
    'max_project_tree_depth',
    default=5,
    help=utils.fmt("""
Maximum depth of the project hierarchy, excluding the project acting as a
domain at the top of the hierarchy. WARNING: Setting it to a large value may
adversely impact performance.
"""))

max_param_size = cfg.IntOpt(
    'max_param_size',
    default=64,
    help=utils.fmt("""
Limit the sizes of user & project ID/names.
"""))

# NOTE(breton): 255 is the size of the database columns used for ID fields.
# This size is picked so that the tokens can be indexed in-place as opposed to
# being entries in a string table. Thus, this is a performance decision.
max_token_size = cfg.IntOpt(
    'max_token_size',
    default=255,
    help=utils.fmt("""
Similar to `[DEFAULT] max_param_size`, but provides an exception for token
values. With Fernet tokens, this can be set as low as 255.
"""))

list_limit = cfg.IntOpt(
    'list_limit',
    help=utils.fmt("""
The maximum number of entities that will be returned in a collection. This
global limit may be then overridden for a specific driver, by specifying a
list_limit in the appropriate section (for example, `[assignment]`). No limit
is set by default. In larger deployments, it is recommended that you set this
to a reasonable number to prevent operations like listing all users and
projects from placing an unnecessary load on the system.
"""))

strict_password_check = cfg.BoolOpt(
    'strict_password_check',
    default=False,
    help=utils.fmt("""
If set to true, strict password length checking is performed for password
manipulation. If a password exceeds the maximum length, the operation will fail
with an HTTP 403 Forbidden error. If set to false, passwords are automatically
truncated to the maximum length.
"""))

insecure_debug = cfg.BoolOpt(
    'insecure_debug',
    default=False,
    help=utils.fmt("""
If set to true, then the server will return information in HTTP responses that
may allow an unauthenticated or authenticated user to get more information than
normal, such as additional details about why authentication failed. This may be
useful for debugging but is insecure.
"""))

default_publisher_id = cfg.StrOpt(
    'default_publisher_id',
    help=utils.fmt("""
Default `publisher_id` for outgoing notifications. If left undefined, Keystone
will default to using the server's host name.
"""))

notification_format = cfg.StrOpt(
    'notification_format',
    default='cadf',
    choices=['basic', 'cadf'],
    help=utils.fmt("""
Define the notification format for identity service events. A `basic`
notification only has information about the resource being operated on. A
`cadf` notification has the same information, as well as information about the
initiator of the event. The `cadf` option is entirely backwards compatible with
the `basic` option, but is fully CADF-compliant, and is recommended for
auditing use cases.
"""))

notification_opt_out = cfg.MultiStrOpt(
    'notification_opt_out',
    default=["identity.authenticate.success",
             "identity.authenticate.pending",
             "identity.authenticate.failed"],
    help=utils.fmt("""
You can reduce the number of notifications keystone emits by explicitly
opting out. Keystone will not emit notifications that match the patterns
expressed in this list. Values are expected to be in the form of
`identity.<resource_type>.<operation>`. By default, all notifications
related to authentication are automatically suppressed. This field can be
set multiple times in order to opt-out of multiple notification topics. For
example, the following suppresses notifications describing user creation or
successful authentication events:
notification_opt_out=identity.user.create
notification_opt_out=identity.authenticate.success
"""))


GROUP_NAME = 'DEFAULT'
ALL_OPTS = [
    admin_token,
    public_endpoint,
    max_project_tree_depth,
    max_param_size,
    max_token_size,
    list_limit,
    strict_password_check,
    insecure_debug,
    default_publisher_id,
    notification_format,
    notification_opt_out,
]


def register_opts(conf):
    conf.register_opts(ALL_OPTS)


def list_opts():
    return {GROUP_NAME: ALL_OPTS}
