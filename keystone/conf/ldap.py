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


_DEPRECATED_LDAP_WRITE = utils.fmt("""
Write support for Identity LDAP backends has been deprecated in the M release
and will be removed in the O release.
""")


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
User BindDN to query the LDAP server.
"""))

password = cfg.StrOpt(
    'password',
    secret=True,
    help=utils.fmt("""
Password for the BindDN to query the LDAP server.
"""))

suffix = cfg.StrOpt(
    'suffix',
    default='cn=example,cn=com',
    help=utils.fmt("""
LDAP server suffix
"""))

use_dumb_member = cfg.BoolOpt(
    'use_dumb_member',
    default=False,
    help=utils.fmt("""
If true, will add a dummy member to groups. This is required if the objectclass
for groups requires the "member" attribute.
    """))

dumb_member = cfg.StrOpt(
    'dumb_member',
    default='cn=dumb,dc=nonexistent',
    help=utils.fmt("""
DN of the "dummy member" to use when "use_dumb_member" is enabled.
"""))

allow_subtree_delete = cfg.BoolOpt(
    'allow_subtree_delete',
    default=False,
    help=utils.fmt("""
Delete subtrees using the subtree delete control. Only enable this option if
your LDAP server supports subtree deletion.
"""))

query_scope = cfg.StrOpt(
    'query_scope',
    default='one',
    choices=['one', 'sub'],
    help=utils.fmt("""
The LDAP scope for queries, "one" represents oneLevel/singleLevel and "sub"
represents subtree/wholeSubtree options.
"""))

page_size = cfg.IntOpt(
    'page_size',
    default=0,
    help=utils.fmt("""
Maximum results per page; a value of zero ("0") disables paging.
"""))

alias_dereferencing = cfg.StrOpt(
    'alias_dereferencing',
    default='default',
    choices=['never', 'searching', 'always', 'finding', 'default'],
    help=utils.fmt("""
The LDAP dereferencing option for queries. The "default" option falls back to
using default dereferencing configured by your ldap.conf.
"""))

debug_level = cfg.IntOpt(
    'debug_level',
    help=utils.fmt("""
Sets the LDAP debugging level for LDAP calls. A value of 0 means that debugging
is not enabled. This value is a bitmask, consult your LDAP documentation for
possible values.
"""))

chase_referrals = cfg.BoolOpt(
    'chase_referrals',
    help=utils.fmt("""
Override the system's default referral chasing behavior for queries.
"""))

user_tree_dn = cfg.StrOpt(
    'user_tree_dn',
    help=utils.fmt("""
Search base for users. Defaults to the suffix value.
"""))

user_filter = cfg.StrOpt(
    'user_filter',
    help=utils.fmt("""
LDAP search filter for users.
"""))

user_objectclass = cfg.StrOpt(
    'user_objectclass',
    default='inetOrgPerson',
    help=utils.fmt("""
LDAP objectclass for users.
"""))

user_id_attribute = cfg.StrOpt(
    'user_id_attribute',
    default='cn',
    help=utils.fmt("""
LDAP attribute mapped to user id. WARNING: must not be a multivalued
attribute.
"""))

user_name_attribute = cfg.StrOpt(
    'user_name_attribute',
    default='sn',
    help=utils.fmt("""
LDAP attribute mapped to user name.
"""))

user_description_attribute = cfg.StrOpt(
    'user_description_attribute',
    default='description',
    help=utils.fmt("""
LDAP attribute mapped to user description.
"""))

user_mail_attribute = cfg.StrOpt(
    'user_mail_attribute',
    default='mail',
    help=utils.fmt("""
LDAP attribute mapped to user email.
"""))

user_pass_attribute = cfg.StrOpt(
    'user_pass_attribute',
    default='userPassword',
    help=utils.fmt("""
LDAP attribute mapped to password.
"""))

user_enabled_attribute = cfg.StrOpt(
    'user_enabled_attribute',
    default='enabled',
    help=utils.fmt("""
LDAP attribute mapped to user enabled flag.
"""))

user_enabled_invert = cfg.BoolOpt(
    'user_enabled_invert',
    default=False,
    help=utils.fmt("""
Invert the meaning of the boolean enabled values. Some LDAP servers use a
boolean lock attribute where "true" means an account is disabled. Setting
"user_enabled_invert = true" will allow these lock attributes to be used. This
setting will have no effect if "user_enabled_mask" or "user_enabled_emulation"
settings are in use.
"""))

user_enabled_mask = cfg.IntOpt(
    'user_enabled_mask',
    default=0,
    help=utils.fmt("""
Bitmask integer to indicate the bit that the enabled value is stored in if the
LDAP server represents "enabled" as a bit on an integer rather than a boolean.
A value of "0" indicates the mask is not used. If this is not set to "0" the
typical value is "2". This is typically used when "user_enabled_attribute =
userAccountControl".
"""))

user_enabled_default = cfg.StrOpt(
    'user_enabled_default',
    default='True',
    help=utils.fmt("""
Default value to enable users. This should match an appropriate int value if
the LDAP server uses non-boolean (bitmask) values to indicate if a user is
enabled or disabled. If this is not set to "True" the typical value is "512".
This is typically used when "user_enabled_attribute = userAccountControl".
"""))

user_attribute_ignore = cfg.ListOpt(
    'user_attribute_ignore',
    default=['default_project_id'],
    help=utils.fmt("""
List of attributes stripped off the user on update.
"""))

user_default_project_id_attribute = cfg.StrOpt(
    'user_default_project_id_attribute',
    help=utils.fmt("""
LDAP attribute mapped to default_project_id for users.
"""))

user_allow_create = cfg.BoolOpt(
    'user_allow_create',
    default=True,
    deprecated_for_removal=True,
    deprecated_reason=_DEPRECATED_LDAP_WRITE,
    help=utils.fmt("""
Allow user creation in LDAP backend.
"""))

user_allow_update = cfg.BoolOpt(
    'user_allow_update',
    default=True,
    deprecated_for_removal=True,
    deprecated_reason=_DEPRECATED_LDAP_WRITE,
    help=utils.fmt("""
Allow user updates in LDAP backend.
"""))

user_allow_delete = cfg.BoolOpt(
    'user_allow_delete',
    default=True,
    deprecated_for_removal=True,
    deprecated_reason=_DEPRECATED_LDAP_WRITE,
    help=utils.fmt("""
Allow user deletion in LDAP backend.
"""))

user_enabled_emulation = cfg.BoolOpt(
    'user_enabled_emulation',
    default=False,
    help=utils.fmt("""
If true, Keystone uses an alternative method to determine if a user is enabled
or not by checking if they are a member of the "user_enabled_emulation_dn"
group.
"""))

user_enabled_emulation_dn = cfg.StrOpt(
    'user_enabled_emulation_dn',
    help=utils.fmt("""
DN of the group entry to hold enabled users when using enabled emulation.
"""))

user_enabled_emulation_use_group_config = cfg.BoolOpt(
    'user_enabled_emulation_use_group_config',
    default=False,
    help=utils.fmt("""
Use the "group_member_attribute" and "group_objectclass" settings to determine
membership in the emulated enabled group.
"""))

user_additional_attribute_mapping = cfg.ListOpt(
    'user_additional_attribute_mapping',
    default=[],
    help=utils.fmt("""
List of additional LDAP attributes used for mapping additional attribute
mappings for users. Attribute mapping format is <ldap_attr>:<user_attr>, where
ldap_attr is the attribute in the LDAP entry and user_attr is the Identity API
attribute.
"""))

group_tree_dn = cfg.StrOpt(
    'group_tree_dn',
    help=utils.fmt("""
Search base for groups. Defaults to the suffix value.
"""))

group_filter = cfg.StrOpt(
    'group_filter',
    help=utils.fmt("""
LDAP search filter for groups.
"""))

group_objectclass = cfg.StrOpt(
    'group_objectclass',
    default='groupOfNames',
    help=utils.fmt("""
LDAP objectclass for groups.
"""))

group_id_attribute = cfg.StrOpt(
    'group_id_attribute',
    default='cn',
    help=utils.fmt("""
LDAP attribute mapped to group id.
"""))

group_name_attribute = cfg.StrOpt(
    'group_name_attribute',
    default='ou',
    help=utils.fmt("""
LDAP attribute mapped to group name.
"""))

group_member_attribute = cfg.StrOpt(
    'group_member_attribute',
    default='member',
    help=utils.fmt("""
LDAP attribute mapped to show group membership.
"""))

group_desc_attribute = cfg.StrOpt(
    'group_desc_attribute',
    default='description',
    help=utils.fmt("""
LDAP attribute mapped to group description.
"""))

group_attribute_ignore = cfg.ListOpt(
    'group_attribute_ignore',
    default=[],
    help=utils.fmt("""
List of attributes stripped off the group on update.
"""))

group_allow_create = cfg.BoolOpt(
    'group_allow_create',
    default=True,
    deprecated_for_removal=True,
    deprecated_reason=_DEPRECATED_LDAP_WRITE,
    help=utils.fmt("""
Allow group creation in LDAP backend.
"""))

group_allow_update = cfg.BoolOpt(
    'group_allow_update',
    default=True,
    deprecated_for_removal=True,
    deprecated_reason=_DEPRECATED_LDAP_WRITE,
    help=utils.fmt("""
Allow group update in LDAP backend.
"""))

group_allow_delete = cfg.BoolOpt(
    'group_allow_delete',
    default=True,
    deprecated_for_removal=True,
    deprecated_reason=_DEPRECATED_LDAP_WRITE,
    help=utils.fmt("""
Allow group deletion in LDAP backend.
"""))

group_additional_attribute_mapping = cfg.ListOpt(
    'group_additional_attribute_mapping',
    default=[],
    help=utils.fmt("""
Additional attribute mappings for groups. Attribute mapping format is
<ldap_attr>:<user_attr>, where ldap_attr is the attribute in the LDAP entry and
user_attr is the Identity API attribute.
"""))


tls_cacertfile = cfg.StrOpt(
    'tls_cacertfile',
    help=utils.fmt("""
CA certificate file path for communicating with LDAP servers.
"""))

tls_cacertdir = cfg.StrOpt(
    'tls_cacertdir',
    help=utils.fmt("""
CA certificate directory path for communicating with LDAP servers.
"""))

use_tls = cfg.BoolOpt(
    'use_tls',
    default=False,
    help=utils.fmt("""
Enable TLS for communicating with LDAP servers.
"""))

tls_req_cert = cfg.StrOpt(
    'tls_req_cert',
    default='demand',
    choices=['demand', 'never', 'allow'],
    help=utils.fmt("""
Specifies what checks to perform on client certificates in an incoming TLS
session.
"""))

use_pool = cfg.BoolOpt(
    'use_pool',
    default=True,
    help=utils.fmt("""
Enable LDAP connection pooling.
"""))

pool_size = cfg.IntOpt(
    'pool_size',
    default=10,
    help=utils.fmt("""
Connection pool size.
"""))

pool_retry_max = cfg.IntOpt(
    'pool_retry_max',
    default=3,
    help=utils.fmt("""
Maximum count of reconnect trials.
"""))

pool_retry_delay = cfg.FloatOpt(
    'pool_retry_delay',
    default=0.1,
    help=utils.fmt("""
Time span in seconds to wait between two reconnect trials.
"""))

pool_connection_timeout = cfg.IntOpt(
    'pool_connection_timeout',
    default=-1,
    help=utils.fmt("""
Connector timeout in seconds. Value -1 indicates indefinite wait for
response.
"""))

pool_connection_lifetime = cfg.IntOpt(
    'pool_connection_lifetime',
    default=600,
    help=utils.fmt("""
Connection lifetime in seconds.
"""))

use_auth_pool = cfg.BoolOpt(
    'use_auth_pool',
    default=True,
    help=utils.fmt("""
Enable LDAP connection pooling for end user authentication. If use_pool is
disabled, then this setting is meaningless and is not used at all.
"""))

auth_pool_size = cfg.IntOpt(
    'auth_pool_size',
    default=100,
    help=utils.fmt("""
End user auth connection pool size.
"""))

auth_pool_connection_lifetime = cfg.IntOpt(
    'auth_pool_connection_lifetime',
    default=60,
    help=utils.fmt("""
End user auth connection lifetime in seconds.
"""))

group_members_are_ids = cfg.BoolOpt(
    'group_members_are_ids',
    default=False,
    help=utils.fmt("""
If the members of the group objectclass are user IDs rather than DNs, set this
to true. This is the case when using posixGroup as the group objectclass and
OpenDirectory.
"""))


GROUP_NAME = __name__.split('.')[-1]
ALL_OPTS = [
    url,
    user,
    password,
    suffix,
    use_dumb_member,
    dumb_member,
    allow_subtree_delete,
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
    user_allow_create,
    user_allow_update,
    user_allow_delete,
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
    group_desc_attribute,
    group_attribute_ignore,
    group_allow_create,
    group_allow_update,
    group_allow_delete,
    group_additional_attribute_mapping,
    tls_cacertfile,
    tls_cacertdir,
    use_tls,
    tls_req_cert,
    use_pool,
    pool_size,
    pool_retry_max,
    pool_retry_delay,
    pool_connection_timeout,
    pool_connection_lifetime,
    use_auth_pool,
    auth_pool_size,
    auth_pool_connection_lifetime,
    group_members_are_ids,
]


def register_opts(conf):
    conf.register_opts(ALL_OPTS, group=GROUP_NAME)


def list_opts():
    return {GROUP_NAME: ALL_OPTS}
