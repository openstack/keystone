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


url = cfg.StrOpt(
    'url',
    default='ldap://localhost',
    help=utils.fmt("""
URL(s) for connecting to the LDAP server. Multiple LDAP URLs may be specified
as a comma separated string. The first URL to successfully bind is used for the
connection.
"""))

user = cfg.StrOpt(
    'user',
    help=utils.fmt("""
The user name of the administrator bind DN to use when querying the LDAP
server, if your LDAP server requires it.
"""))

password = cfg.StrOpt(
    'password',
    secret=True,
    help=utils.fmt("""
The password of the administrator bind DN to use when querying the LDAP server,
if your LDAP server requires it.
"""))

suffix = cfg.StrOpt(
    'suffix',
    default='cn=example,cn=com',
    help=utils.fmt("""
The default LDAP server suffix to use, if a DN is not defined via either
`[ldap] user_tree_dn` or `[ldap] group_tree_dn`.
"""))

query_scope = cfg.StrOpt(
    'query_scope',
    default='one',
    choices=['one', 'sub'],
    help=utils.fmt("""
The search scope which defines how deep to search within the search base. A
value of `one` (representing `oneLevel` or `singleLevel`) indicates a search of
objects immediately below to the base object, but does not include the base
object itself. A value of `sub` (representing `subtree` or `wholeSubtree`)
indicates a search of both the base object itself and the entire subtree below
it.
"""))

page_size = cfg.IntOpt(
    'page_size',
    default=0,
    min=0,
    help=utils.fmt("""
Defines the maximum number of results per page that keystone should request
from the LDAP server when listing objects. A value of zero (`0`) disables
paging.
"""))

alias_dereferencing = cfg.StrOpt(
    'alias_dereferencing',
    default='default',
    choices=['never', 'searching', 'always', 'finding', 'default'],
    help=utils.fmt("""
The LDAP dereferencing option to use for queries involving aliases. A value of
`default` falls back to using default dereferencing behavior configured by your
`ldap.conf`. A value of `never` prevents aliases from being dereferenced at
all. A value of `searching` dereferences aliases only after name resolution. A
value of `finding` dereferences aliases only during name resolution. A value of
`always` dereferences aliases in all cases.
"""))

debug_level = cfg.IntOpt(
    'debug_level',
    min=-1,
    help=utils.fmt("""
Sets the LDAP debugging level for LDAP calls. A value of 0 means that debugging
is not enabled. This value is a bitmask, consult your LDAP documentation for
possible values.
"""))

chase_referrals = cfg.BoolOpt(
    'chase_referrals',
    help=utils.fmt("""
Sets keystone's referral chasing behavior across directory partitions. If left
unset, the system's default behavior will be used.
"""))

user_tree_dn = cfg.StrOpt(
    'user_tree_dn',
    help=utils.fmt("""
The search base to use for users. Defaults to `ou=Users` with the `[ldap]
suffix` appended to it.
"""))

user_filter = cfg.StrOpt(
    'user_filter',
    help=utils.fmt("""
The LDAP search filter to use for users.
"""))

user_objectclass = cfg.StrOpt(
    'user_objectclass',
    default='inetOrgPerson',
    help=utils.fmt("""
The LDAP object class to use for users.
"""))

user_id_attribute = cfg.StrOpt(
    'user_id_attribute',
    default='cn',
    help=utils.fmt("""
The LDAP attribute mapped to user IDs in keystone. This must NOT be a
multivalued attribute. User IDs are expected to be globally unique across
keystone domains and URL-safe.
"""))

user_name_attribute = cfg.StrOpt(
    'user_name_attribute',
    default='sn',
    help=utils.fmt("""
The LDAP attribute mapped to user names in keystone. User names are expected to
be unique only within a keystone domain and are not expected to be URL-safe.
"""))

user_description_attribute = cfg.StrOpt(
    'user_description_attribute',
    default='description',
    help=utils.fmt("""
The LDAP attribute mapped to user descriptions in keystone.
"""))

user_mail_attribute = cfg.StrOpt(
    'user_mail_attribute',
    default='mail',
    help=utils.fmt("""
The LDAP attribute mapped to user emails in keystone.
"""))

user_pass_attribute = cfg.StrOpt(
    'user_pass_attribute',
    default='userPassword',
    help=utils.fmt("""
The LDAP attribute mapped to user passwords in keystone.
"""))

user_enabled_attribute = cfg.StrOpt(
    'user_enabled_attribute',
    default='enabled',
    help=utils.fmt("""
The LDAP attribute mapped to the user enabled attribute in keystone. If setting
this option to `userAccountControl`, then you may be interested in setting
`[ldap] user_enabled_mask` and `[ldap] user_enabled_default` as well.
"""))

user_enabled_invert = cfg.BoolOpt(
    'user_enabled_invert',
    default=False,
    help=utils.fmt("""
Logically negate the boolean value of the enabled attribute obtained from the
LDAP server. Some LDAP servers use a boolean lock attribute where "true" means
an account is disabled. Setting `[ldap] user_enabled_invert = true` will allow
these lock attributes to be used. This option will have no effect if either the
`[ldap] user_enabled_mask` or `[ldap] user_enabled_emulation` options are in
use.
"""))

user_enabled_mask = cfg.IntOpt(
    'user_enabled_mask',
    default=0,
    min=0,
    help=utils.fmt("""
Bitmask integer to select which bit indicates the enabled value if the LDAP
server represents "enabled" as a bit on an integer rather than as a discrete
boolean. A value of `0` indicates that the mask is not used. If this is not set
to `0` the typical value is `2`. This is typically used when `[ldap]
user_enabled_attribute = userAccountControl`. Setting this option causes
keystone to ignore the value of `[ldap] user_enabled_invert`.
"""))

user_enabled_default = cfg.StrOpt(
    'user_enabled_default',
    default='True',
    help=utils.fmt("""
The default value to enable users. This should match an appropriate integer
value if the LDAP server uses non-boolean (bitmask) values to indicate if a
user is enabled or disabled. If this is not set to `True`, then the typical
value is `512`. This is typically used when `[ldap] user_enabled_attribute =
userAccountControl`.
"""))

user_attribute_ignore = cfg.ListOpt(
    'user_attribute_ignore',
    default=['default_project_id'],
    help=utils.fmt("""
List of user attributes to ignore on create and update, or whether a specific
user attribute should be filtered for list or show user.
"""))

user_default_project_id_attribute = cfg.StrOpt(
    'user_default_project_id_attribute',
    help=utils.fmt("""
The LDAP attribute mapped to a user's default_project_id in keystone. This is
most commonly used when keystone has write access to LDAP.
"""))

user_enabled_emulation = cfg.BoolOpt(
    'user_enabled_emulation',
    default=False,
    help=utils.fmt("""
If enabled, keystone uses an alternative method to determine if a user is
enabled or not by checking if they are a member of the group defined by the
`[ldap] user_enabled_emulation_dn` option. Enabling this option causes keystone
to ignore the value of `[ldap] user_enabled_invert`.
"""))

user_enabled_emulation_dn = cfg.StrOpt(
    'user_enabled_emulation_dn',
    help=utils.fmt("""
DN of the group entry to hold enabled users when using enabled emulation.
Setting this option has no effect unless `[ldap] user_enabled_emulation` is
also enabled.
"""))

user_enabled_emulation_use_group_config = cfg.BoolOpt(
    'user_enabled_emulation_use_group_config',
    default=False,
    help=utils.fmt("""
Use the `[ldap] group_member_attribute` and `[ldap] group_objectclass` settings
to determine membership in the emulated enabled group. Enabling this option has
no effect unless `[ldap] user_enabled_emulation` is also enabled.
"""))

user_additional_attribute_mapping = cfg.ListOpt(
    'user_additional_attribute_mapping',
    default=[],
    help=utils.fmt("""
A list of LDAP attribute to keystone user attribute pairs used for mapping
additional attributes to users in keystone. The expected format is
`<ldap_attr>:<user_attr>`, where `ldap_attr` is the attribute in the LDAP
object and `user_attr` is the attribute which should appear in the identity
API.
"""))

group_tree_dn = cfg.StrOpt(
    'group_tree_dn',
    help=utils.fmt("""
The search base to use for groups. Defaults to `ou=UserGroups` with the `[ldap]
suffix` appended to it.
"""))

group_filter = cfg.StrOpt(
    'group_filter',
    help=utils.fmt("""
The LDAP search filter to use for groups.
"""))

group_objectclass = cfg.StrOpt(
    'group_objectclass',
    default='groupOfNames',
    help=utils.fmt("""
The LDAP object class to use for groups. If setting this option to
`posixGroup`, you may also be interested in enabling the `[ldap]
group_members_are_ids` option.
"""))

group_id_attribute = cfg.StrOpt(
    'group_id_attribute',
    default='cn',
    help=utils.fmt("""
The LDAP attribute mapped to group IDs in keystone. This must NOT be a
multivalued attribute. Group IDs are expected to be globally unique across
keystone domains and URL-safe.
"""))

group_name_attribute = cfg.StrOpt(
    'group_name_attribute',
    default='ou',
    help=utils.fmt("""
The LDAP attribute mapped to group names in keystone. Group names are expected
to be unique only within a keystone domain and are not expected to be URL-safe.
"""))

group_member_attribute = cfg.StrOpt(
    'group_member_attribute',
    default='member',
    help=utils.fmt("""
The LDAP attribute used to indicate that a user is a member of the group.
"""))

group_members_are_ids = cfg.BoolOpt(
    'group_members_are_ids',
    default=False,
    help=utils.fmt("""
Enable this option if the members of the group object class are keystone user
IDs rather than LDAP DNs. This is the case when using `posixGroup` as the group
object class in Open Directory.
"""))

group_desc_attribute = cfg.StrOpt(
    'group_desc_attribute',
    default='description',
    help=utils.fmt("""
The LDAP attribute mapped to group descriptions in keystone.
"""))

group_attribute_ignore = cfg.ListOpt(
    'group_attribute_ignore',
    default=[],
    help=utils.fmt("""
List of group attributes to ignore on create and update. or whether a specific
group attribute should be filtered for list or show group.
"""))

group_additional_attribute_mapping = cfg.ListOpt(
    'group_additional_attribute_mapping',
    default=[],
    help=utils.fmt("""
A list of LDAP attribute to keystone group attribute pairs used for mapping
additional attributes to groups in keystone. The expected format is
`<ldap_attr>:<group_attr>`, where `ldap_attr` is the attribute in the LDAP
object and `group_attr` is the attribute which should appear in the identity
API.
"""))

group_ad_nesting = cfg.BoolOpt(
    'group_ad_nesting',
    default=False,
    help=utils.fmt("""
If enabled, group queries will use Active Directory specific filters for
nested groups.
"""))

tls_cacertfile = cfg.StrOpt(
    'tls_cacertfile',
    help=utils.fmt("""
An absolute path to a CA certificate file to use when communicating with LDAP
servers. This option will take precedence over `[ldap] tls_cacertdir`, so there
is no reason to set both.
"""))

tls_cacertdir = cfg.StrOpt(
    'tls_cacertdir',
    help=utils.fmt("""
An absolute path to a CA certificate directory to use when communicating with
LDAP servers. There is no reason to set this option if you've also set `[ldap]
tls_cacertfile`.
"""))

use_tls = cfg.BoolOpt(
    'use_tls',
    default=False,
    help=utils.fmt("""
Enable TLS when communicating with LDAP servers. You should also set the
`[ldap] tls_cacertfile` and `[ldap] tls_cacertdir` options when using this
option. Do not set this option if you are using LDAP over SSL (LDAPS) instead
of TLS.
"""))

tls_req_cert = cfg.StrOpt(
    'tls_req_cert',
    default='demand',
    choices=['demand', 'never', 'allow'],
    help=utils.fmt("""
Specifies which checks to perform against client certificates on incoming TLS
sessions. If set to `demand`, then a certificate will always be requested and
required from the LDAP server. If set to `allow`, then a certificate will
always be requested but not required from the LDAP server. If set to `never`,
then a certificate will never be requested.
"""))

connection_timeout = cfg.IntOpt(
    'connection_timeout',
    default=-1,
    min=-1,
    help=utils.fmt("""
The connection timeout to use with the LDAP server. A value of `-1` means that
connections will never timeout.
"""))

use_pool = cfg.BoolOpt(
    'use_pool',
    default=True,
    help=utils.fmt("""
Enable LDAP connection pooling for queries to the LDAP server. There is
typically no reason to disable this.
"""))

pool_size = cfg.IntOpt(
    'pool_size',
    default=10,
    min=1,
    help=utils.fmt("""
The size of the LDAP connection pool. This option has no effect unless `[ldap]
use_pool` is also enabled.
"""))

pool_retry_max = cfg.IntOpt(
    'pool_retry_max',
    default=3,
    min=1,
    help=utils.fmt("""
The maximum number of times to attempt connecting to the LDAP server before
aborting. A value of one makes only one connection attempt.
This option has no effect unless `[ldap] use_pool` is also enabled.
"""))

pool_retry_delay = cfg.FloatOpt(
    'pool_retry_delay',
    default=0.1,
    help=utils.fmt("""
The number of seconds to wait before attempting to reconnect to the LDAP
server. This option has no effect unless `[ldap] use_pool` is also enabled.
"""))

pool_connection_timeout = cfg.IntOpt(
    'pool_connection_timeout',
    default=-1,
    min=-1,
    help=utils.fmt("""
The connection timeout to use when pooling LDAP connections. A value of `-1`
means that connections will never timeout. This option has no effect unless
`[ldap] use_pool` is also enabled.
"""))

pool_connection_lifetime = cfg.IntOpt(
    'pool_connection_lifetime',
    default=600,
    min=1,
    help=utils.fmt("""
The maximum connection lifetime to the LDAP server in seconds. When this
lifetime is exceeded, the connection will be unbound and removed from the
connection pool. This option has no effect unless `[ldap] use_pool` is also
enabled.
"""))

use_auth_pool = cfg.BoolOpt(
    'use_auth_pool',
    default=True,
    help=utils.fmt("""
Enable LDAP connection pooling for end user authentication. There is typically
no reason to disable this.
"""))

auth_pool_size = cfg.IntOpt(
    'auth_pool_size',
    default=100,
    min=1,
    help=utils.fmt("""
The size of the connection pool to use for end user authentication. This option
has no effect unless `[ldap] use_auth_pool` is also enabled.
"""))

auth_pool_connection_lifetime = cfg.IntOpt(
    'auth_pool_connection_lifetime',
    default=60,
    min=1,
    help=utils.fmt("""
The maximum end user authentication connection lifetime to the LDAP server in
seconds. When this lifetime is exceeded, the connection will be unbound and
removed from the connection pool. This option has no effect unless `[ldap]
use_auth_pool` is also enabled.
"""))


GROUP_NAME = __name__.split('.')[-1]
ALL_OPTS = [
    url,
    user,
    password,
    suffix,
    query_scope,
    page_size,
    alias_dereferencing,
    debug_level,
    chase_referrals,
    user_tree_dn,
    user_filter,
    user_objectclass,
    user_id_attribute,
    user_name_attribute,
    user_description_attribute,
    user_mail_attribute,
    user_pass_attribute,
    user_enabled_attribute,
    user_enabled_invert,
    user_enabled_mask,
    user_enabled_default,
    user_attribute_ignore,
    user_default_project_id_attribute,
    user_enabled_emulation,
    user_enabled_emulation_dn,
    user_enabled_emulation_use_group_config,
    user_additional_attribute_mapping,
    group_tree_dn,
    group_filter,
    group_objectclass,
    group_id_attribute,
    group_name_attribute,
    group_member_attribute,
    group_members_are_ids,
    group_desc_attribute,
    group_attribute_ignore,
    group_additional_attribute_mapping,
    group_ad_nesting,
    tls_cacertfile,
    tls_cacertdir,
    use_tls,
    tls_req_cert,
    connection_timeout,
    use_pool,
    pool_size,
    pool_retry_max,
    pool_retry_delay,
    pool_connection_timeout,
    pool_connection_lifetime,
    use_auth_pool,
    auth_pool_size,
    auth_pool_connection_lifetime,
]


def register_opts(conf):
    conf.register_opts(ALL_OPTS, group=GROUP_NAME)


def list_opts():
    return {GROUP_NAME: ALL_OPTS}
