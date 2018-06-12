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
from oslo_log import versionutils

from keystone.conf import utils


_DEPRECATE_PROXY_SSL = utils.fmt("""
This option has been deprecated in the N release and will be removed in the P
release. Use oslo.middleware.http_proxy_to_wsgi configuration instead.
""")


_DEPRECATE_MEMBER_ID_AND_NAME = utils.fmt("""
This option was used to create a default member role for keystone v2 role
assignments, but with the removal of the v2 API it is no longer necessary to
create this default role. This option is deprecated and will be removed in the
S release. If you are depending on having a predictable role name and ID for
this member role you will need to update your tooling.
""")


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

admin_endpoint = cfg.URIOpt(
    'admin_endpoint',
    deprecated_since=versionutils.deprecated.ROCKY,
    deprecated_for_removal=True,
    deprecated_reason=utils.fmt("""
With the removal of the 2.0 API keystone does not distinguish between admin
and public endpoints.
"""),
    help=utils.fmt("""
The base admin endpoint URL for Keystone that is advertised to clients (NOTE:
this does NOT affect how Keystone listens for connections). Defaults to the
base host URL of the request. For example, if keystone receives a request to
`http://server:35357/v3/users`, then this will option will be automatically
treated as `http://server:35357`. You should only need to set option if either
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
values. With Fernet tokens, this can be set as low as 255. With UUID tokens,
this should be set to 32).
"""))

member_role_id = cfg.StrOpt(
    'member_role_id',
    default='9fe2ff9ee4384b1894a90878d3e92bab',
    deprecated_for_removal=True,
    deprecated_reason=_DEPRECATE_MEMBER_ID_AND_NAME,
    deprecated_since=versionutils.deprecated.QUEENS,
    help=utils.fmt("""
Similar to the `[DEFAULT] member_role_name` option, this represents the default
role ID used to associate users with their default projects in the v2 API. This
will be used as the explicit role where one is not specified by the v2 API. You
do not need to set this value unless you want keystone to use an existing role
with a different ID, other than the arbitrarily defined `_member_` role (in
which case, you should set `[DEFAULT] member_role_name` as well).
"""))

member_role_name = cfg.StrOpt(
    'member_role_name',
    default='_member_',
    deprecated_for_removal=True,
    deprecated_reason=_DEPRECATE_MEMBER_ID_AND_NAME,
    deprecated_since=versionutils.deprecated.QUEENS,
    help=utils.fmt("""
This is the role name used in combination with the `[DEFAULT] member_role_id`
option; see that option for more detail. You do not need to set this option
unless you want keystone to use an existing role (in which case, you should set
`[DEFAULT] member_role_id` as well).
"""))

# NOTE(lbragstad/morganfainberg): This value of 10k was measured as having an
# approximate 30% clock-time savings over the old default of 40k.  The passlib
# default is not static and grows over time to constantly approximate ~300ms of
# CPU time to hash; this was considered too high.  This value still exceeds the
# glibc default of 5k.
crypt_strength = cfg.IntOpt(
    'crypt_strength',
    default=10000,
    min=1000,
    max=100000,
    deprecated_since=versionutils.deprecated.PIKE,
    deprecated_reason=utils.fmt("""
sha512_crypt is insufficient for password hashes, use of bcrypt, pbkfd2_sha512
and scrypt are now supported. Options are located in the [identity] config
block. This option is still used for rolling upgrade compatibility password
hashing.
"""),
    help=utils.fmt("""
The value passed as the keyword "rounds" to passlib's encrypt method. This
option represents a trade off between security and performance. Higher values
lead to slower performance, but higher security. Changing this option will only
affect newly created passwords as existing password hashes already have a fixed
number of rounds applied, so it is safe to tune this option in a running
cluster. For more information, see
https://pythonhosted.org/passlib/password_hash_api.html#choosing-the-right-rounds-value
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

secure_proxy_ssl_header = cfg.StrOpt(
    'secure_proxy_ssl_header',
    default='HTTP_X_FORWARDED_PROTO',
    deprecated_for_removal=True,
    deprecated_reason=_DEPRECATE_PROXY_SSL,
    deprecated_since=versionutils.deprecated.NEWTON,
    help=utils.fmt("""
The HTTP header used to determine the scheme for the original request, even if
it was removed by an SSL terminating proxy.
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
    admin_endpoint,
    max_project_tree_depth,
    max_param_size,
    max_token_size,
    member_role_id,
    member_role_name,
    crypt_strength,
    list_limit,
    strict_password_check,
    secure_proxy_ssl_header,
    insecure_debug,
    default_publisher_id,
    notification_format,
    notification_opt_out,
]


def register_opts(conf):
    conf.register_opts(ALL_OPTS)


def list_opts():
    return {GROUP_NAME: ALL_OPTS}
