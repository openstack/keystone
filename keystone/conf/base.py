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


_DEPRECATE_DII_MSG = utils.fmt("""
The option to set domain_id_immutable to false has been deprecated in the M
release and will be removed in the O release.
""")


admin_token = cfg.StrOpt(
    'admin_token',
    secret=True,
    default=None,
    help=utils.fmt("""
A "shared secret" that can be used to bootstrap Keystone. This "token" does not
represent a user, and carries no explicit authorization. If set to `None`, the
value is ignored and the `admin_token` log in mechanism is effectively
disabled. To completely disable `admin_token` in production (highly
recommended), remove AdminTokenAuthMiddleware from your paste application
pipelines (for example, in keystone-paste.ini).
"""))

public_endpoint = cfg.StrOpt(
    'public_endpoint',
    help=utils.fmt("""
The base public endpoint URL for Keystone that is advertised to clients (NOTE:
this does NOT affect how Keystone listens for connections). Defaults to the
base host URL of the request. E.g. a request to http://server:5000/v3/users
will default to http://server:5000. You should only need to set this value if
the base URL contains a path (e.g. /prefix/v3) or the endpoint should be found
on a different server.
"""))

admin_endpoint = cfg.StrOpt(
    'admin_endpoint',
    help=utils.fmt("""
The base admin endpoint URL for Keystone that is advertised to clients (NOTE:
this does NOT affect how Keystone listens for connections). Defaults to the
base host URL of the request. E.g. a request to http://server:35357/v3/users
will default to http://server:35357. You should only need to set this value if
the base URL contains a path (e.g. /prefix/v3) or the endpoint should be found
on a different server.
"""))

max_project_tree_depth = cfg.IntOpt(
    'max_project_tree_depth',
    default=5,
    help=utils.fmt("""
Maximum depth of the project hierarchy, excluding the project acting as a
domain at the top of the hierarchy. WARNING: setting it to a large value may
adversely impact  performance.
"""))

max_param_size = cfg.IntOpt(
    'max_param_size',
    default=64,
    help=utils.fmt("""
Limit the sizes of user & project ID/names.
"""))

# we allow tokens to be a bit larger to accommodate PKI
max_token_size = cfg.IntOpt(
    'max_token_size',
    default=8192,
    help=utils.fmt("""
Similar to max_param_size, but provides an exception for token values.
"""))

member_role_id = cfg.StrOpt(
    'member_role_id',
    default='9fe2ff9ee4384b1894a90878d3e92bab',
    help=utils.fmt("""
Similar to the member_role_name option, this represents the default role ID
used to associate users with their default projects in the v2 API. This will be
used as the explicit role where one is not specified by the v2 API.
"""))

member_role_name = cfg.StrOpt(
    'member_role_name',
    default='_member_',
    help=utils.fmt("""
This is the role name used in combination with the member_role_id option; see
that option for more detail.
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
    help=utils.fmt("""
The value passed as the keyword "rounds" to passlib\'s encrypt method.
"""))

list_limit = cfg.IntOpt(
    'list_limit',
    help=utils.fmt("""
The maximum number of entities that will be returned in a collection, with no
limit set by default. This global limit may be then overridden for a specific
driver, by specifying a list_limit in the appropriate section (e.g.
[assignment]).
"""))

domain_id_immutable = cfg.BoolOpt(
    'domain_id_immutable',
    default=True,
    deprecated_for_removal=True,
    deprecated_reason=_DEPRECATE_DII_MSG,
    help=utils.fmt("""
Set this to false if you want to enable the ability for user, group and project
entities to be moved between domains by updating their domain_id. Allowing such
movement is not recommended if the scope of a domain admin is being restricted
by use of an appropriate policy file (see policy.v3cloudsample as an example).
This ability is deprecated and will be removed in a future release.
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
    deprecated_reason=utils.fmt("""
Use http_proxy_to_wsgi middleware configuration instead.
"""),
    help=utils.fmt("""
The HTTP header used to determine the scheme for the original request, even if
it was removed by an SSL terminating proxy.
"""))

insecure_debug = cfg.BoolOpt(
    'insecure_debug',
    default=False,
    help=utils.fmt("""
If set to true the server will return information in the response that may
allow an unauthenticated or authenticated user to get more information than
normal, such as why authentication failed. This may be useful for debugging but
is insecure.
"""))

default_publisher_id = cfg.StrOpt(
    'default_publisher_id',
    help=utils.fmt("""
Default publisher_id for outgoing notifications
"""))

notification_format = cfg.StrOpt(
    'notification_format',
    default='basic',
    choices=['basic', 'cadf'],
    help=utils.fmt("""
Define the notification format for Identity Service events. A "basic"
notification has information about the resource being operated on. A "cadf"
notification has the same information, as well as information about the
initiator of the event.
"""))

notification_opt_out = cfg.MultiStrOpt(
    'notification_opt_out',
    default=[],
    help=utils.fmt("""
Define the notification options to opt-out from. The value expected is:
identity.<resource_type>.<operation>. This field can be set multiple times in
order to add more notifications to opt-out from. For example:
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
    domain_id_immutable,
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
