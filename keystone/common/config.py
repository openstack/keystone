# Copyright 2012 OpenStack Foundation
#
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

import logging
import os

from oslo_cache import core as cache
from oslo_config import cfg
from oslo_log import log
import oslo_messaging
from oslo_middleware import cors
from osprofiler import opts as profiler
import passlib.utils

from keystone import exception


_DEFAULT_AUTH_METHODS = ['external', 'password', 'token', 'oauth1']
_CERTFILE = '/etc/keystone/ssl/certs/signing_cert.pem'
_KEYFILE = '/etc/keystone/ssl/private/signing_key.pem'
_SSO_CALLBACK = '/etc/keystone/sso_callback_template.html'

_DEPRECATE_PKI_MSG = ('PKI token support has been deprecated in the M '
                      'release and will be removed in the O release. Fernet '
                      'or UUID tokens are recommended.')

_DEPRECATE_INHERIT_MSG = ('The option to enable the OS-INHERIT extension has '
                          'been deprecated in the M release and will be '
                          'removed in the O release. The OS-INHERIT extension '
                          'will be enabled by default.')

_DEPRECATE_EP_MSG = ('The option to enable the OS-ENDPOINT-POLICY extension '
                     'has been deprecated in the M release and will be '
                     'removed in the O release. The OS-ENDPOINT-POLICY '
                     'extension will be enabled by default.')

_DEPRECATE_DII_MSG = ('The option to set domain_id_immutable to false '
                      'has been deprecated in the M release and will '
                      'be removed in the O release.')

_DEPRECATE_EVENTLET_MSG = ('Support for running keystone under eventlet has '
                           'been removed in the N release. These options '
                           'remain for backwards compatibility because they '
                           'are used for URL substitutions.')

FILE_OPTIONS = {
    None: [
        cfg.StrOpt('admin_token', secret=True, default=None,
                   help='A "shared secret" that can be used to bootstrap '
                        'Keystone. This "token" does not represent a user, '
                        'and carries no explicit authorization. If set '
                        'to `None`, the value is ignored and the '
                        '`admin_token` log in mechanism is effectively '
                        'disabled. To completely disable `admin_token` '
                        'in production (highly recommended), remove '
                        'AdminTokenAuthMiddleware from your paste '
                        'application pipelines (for example, in '
                        'keystone-paste.ini).'),
        cfg.StrOpt('public_endpoint',
                   help='The base public endpoint URL for Keystone that is '
                        'advertised to clients (NOTE: this does NOT affect '
                        'how Keystone listens for connections). '
                        'Defaults to the base host URL of the request. E.g. a '
                        'request to http://server:5000/v3/users will '
                        'default to http://server:5000. You should only need '
                        'to set this value if the base URL contains a path '
                        '(e.g. /prefix/v3) or the endpoint should be found '
                        'on a different server.'),
        cfg.StrOpt('admin_endpoint',
                   help='The base admin endpoint URL for Keystone that is '
                        'advertised to clients (NOTE: this does NOT affect '
                        'how Keystone listens for connections). '
                        'Defaults to the base host URL of the request. E.g. a '
                        'request to http://server:35357/v3/users will '
                        'default to http://server:35357. You should only need '
                        'to set this value if the base URL contains a path '
                        '(e.g. /prefix/v3) or the endpoint should be found '
                        'on a different server.'),
        cfg.IntOpt('max_project_tree_depth', default=5,
                   help='Maximum depth of the project hierarchy, excluding '
                        'the project acting as a domain at the top of the '
                        'hierarchy. WARNING: setting it to a large value may '
                        'adversely impact  performance.'),
        cfg.IntOpt('max_param_size', default=64,
                   help='Limit the sizes of user & project ID/names.'),
        # we allow tokens to be a bit larger to accommodate PKI
        cfg.IntOpt('max_token_size', default=8192,
                   help='Similar to max_param_size, but provides an '
                        'exception for token values.'),
        cfg.StrOpt('member_role_id',
                   default='9fe2ff9ee4384b1894a90878d3e92bab',
                   help='Similar to the member_role_name option, this '
                        'represents the default role ID used to associate '
                        'users with their default projects in the v2 API. '
                        'This will be used as the explicit role where one is '
                        'not specified by the v2 API.'),
        cfg.StrOpt('member_role_name', default='_member_',
                   help='This is the role name used in combination with the '
                        'member_role_id option; see that option for more '
                        'detail.'),
        # NOTE(lbragstad/morganfainberg): This value of 10k was
        # measured as having an approximate 30% clock-time savings
        # over the old default of 40k.  The passlib default is not
        # static and grows over time to constantly approximate ~300ms
        # of CPU time to hash; this was considered too high.  This
        # value still exceeds the glibc default of 5k.
        cfg.IntOpt('crypt_strength', default=10000, min=1000, max=100000,
                   help='The value passed as the keyword "rounds" to '
                        'passlib\'s encrypt method.'),
        cfg.IntOpt('list_limit',
                   help='The maximum number of entities that will be '
                        'returned in a collection, with no limit set by '
                        'default. This global limit may be then overridden '
                        'for a specific driver, by specifying a list_limit '
                        'in the appropriate section (e.g. [assignment]).'),
        cfg.BoolOpt('domain_id_immutable', default=True,
                    help='Set this to false if you want to enable the '
                         'ability for user, group and project entities '
                         'to be moved between domains by updating their '
                         'domain_id. Allowing such movement is not '
                         'recommended if the scope of a domain admin is being '
                         'restricted by use of an appropriate policy file '
                         '(see policy.v3cloudsample as an example). This '
                         'ability is deprecated and will be removed in a '
                         'future release.',
                    deprecated_for_removal=True,
                    deprecated_reason=_DEPRECATE_DII_MSG),
        cfg.BoolOpt('strict_password_check', default=False,
                    help='If set to true, strict password length checking is '
                         'performed for password manipulation. If a password '
                         'exceeds the maximum length, the operation will fail '
                         'with an HTTP 403 Forbidden error. If set to false, '
                         'passwords are automatically truncated to the '
                         'maximum length.'),
        cfg.StrOpt('secure_proxy_ssl_header', default='HTTP_X_FORWARDED_PROTO',
                   help='The HTTP header used to determine the scheme for the '
                        'original request, even if it was removed by an SSL '
                        'terminating proxy.'),
        cfg.BoolOpt('insecure_debug', default=False,
                    help='If set to true the server will return information '
                         'in the response that may allow an unauthenticated '
                         'or authenticated user to get more information than '
                         'normal, such as why authentication failed. This may '
                         'be useful for debugging but is insecure.'),
    ],
    'identity': [
        cfg.StrOpt('default_domain_id', default='default',
                   help='This references the domain to use for all '
                        'Identity API v2 requests (which are not aware of '
                        'domains). A domain with this ID will be created '
                        'for you by keystone-manage db_sync in migration '
                        '008. The domain referenced by this ID cannot be '
                        'deleted on the v3 API, to prevent accidentally '
                        'breaking the v2 API. There is nothing special about '
                        'this domain, other than the fact that it must '
                        'exist to order to maintain support for your v2 '
                        'clients.'),
        cfg.BoolOpt('domain_specific_drivers_enabled',
                    default=False,
                    help='A subset (or all) of domains can have their own '
                         'identity driver, each with their own partial '
                         'configuration options, stored in either the '
                         'resource backend or in a file in a domain '
                         'configuration directory (depending on the setting '
                         'of domain_configurations_from_database). Only '
                         'values specific to the domain need to be specified '
                         'in this manner. This feature is disabled by '
                         'default; set to true to enable.'),
        cfg.BoolOpt('domain_configurations_from_database',
                    default=False,
                    help='Extract the domain specific configuration options '
                         'from the resource backend where they have been '
                         'stored with the domain data. This feature is '
                         'disabled by default (in which case the domain '
                         'specific options will be loaded from files in the '
                         'domain configuration directory); set to true to '
                         'enable.'),
        cfg.StrOpt('domain_config_dir',
                   default='/etc/keystone/domains',
                   help='Path for Keystone to locate the domain specific '
                        'identity configuration files if '
                        'domain_specific_drivers_enabled is set to true.'),
        cfg.StrOpt('driver',
                   default='sql',
                   help='Entrypoint for the identity backend driver in the '
                        'keystone.identity namespace. Supplied drivers are '
                        'ldap and sql.'),
        cfg.BoolOpt('caching', default=True,
                    help='Toggle for identity caching. This has no '
                         'effect unless global caching is enabled.'),
        cfg.IntOpt('cache_time', default=600,
                   help='Time to cache identity data (in seconds). This has '
                        'no effect unless global and identity caching are '
                        'enabled.'),
        cfg.IntOpt('max_password_length', default=4096,
                   max=passlib.utils.MAX_PASSWORD_SIZE,
                   help='Maximum supported length for user passwords; '
                        'decrease to improve performance.'),
        cfg.IntOpt('list_limit',
                   help='Maximum number of entities that will be returned in '
                        'an identity collection.'),
    ],
    'identity_mapping': [
        cfg.StrOpt('driver',
                   default='sql',
                   help='Entrypoint for the identity mapping backend driver '
                        'in the keystone.identity.id_mapping namespace.'),
        cfg.StrOpt('generator',
                   default='sha256',
                   help='Entrypoint for the public ID generator for user and '
                        'group entities in the keystone.identity.id_generator '
                        'namespace. The Keystone identity mapper only '
                        'supports generators that produce no more than 64 '
                        'characters.'),
        cfg.BoolOpt('backward_compatible_ids',
                    default=True,
                    help='The format of user and group IDs changed '
                         'in Juno for backends that do not generate UUIDs '
                         '(e.g. LDAP), with keystone providing a hash mapping '
                         'to the underlying attribute in LDAP. By default '
                         'this mapping is disabled, which ensures that '
                         'existing IDs will not change. Even when the '
                         'mapping is enabled by using domain specific '
                         'drivers, any users and groups from the default '
                         'domain being handled by LDAP will still not be '
                         'mapped to ensure their IDs remain backward '
                         'compatible. Setting this value to False will '
                         'enable the mapping for even the default LDAP '
                         'driver. It is only safe to do this if you do not '
                         'already have assignments for users and '
                         'groups from the default LDAP domain, and it is '
                         'acceptable for Keystone to provide the different '
                         'IDs to clients than it did previously. Typically '
                         'this means that the only time you can set this '
                         'value to False is when configuring a fresh '
                         'installation.'),
    ],
    'shadow_users': [
        cfg.StrOpt('driver',
                   default='sql',
                   help='Entrypoint for the shadow users backend driver '
                        'in the keystone.identity.shadow_users namespace.'),
    ],
    'trust': [
        cfg.BoolOpt('enabled', default=True,
                    help='Delegation and impersonation features can be '
                         'optionally disabled.'),
        cfg.BoolOpt('allow_redelegation', default=False,
                    help='Enable redelegation feature.'),
        cfg.IntOpt('max_redelegation_count', default=3,
                   help='Maximum depth of trust redelegation.'),
        cfg.StrOpt('driver',
                   default='sql',
                   help='Entrypoint for the trust backend driver in the '
                        'keystone.trust namespace.')],
    'os_inherit': [
        cfg.BoolOpt('enabled', default=True,
                    deprecated_for_removal=True,
                    deprecated_reason=_DEPRECATE_INHERIT_MSG,
                    help='role-assignment inheritance to projects from '
                         'owning domain or from projects higher in the '
                         'hierarchy can be optionally disabled. In the '
                         'future, this option will be removed and the '
                         'hierarchy will be always enabled.'),
    ],
    'fernet_tokens': [
        cfg.StrOpt('key_repository',
                   default='/etc/keystone/fernet-keys/',
                   help='Directory containing Fernet token keys.'),
        cfg.IntOpt('max_active_keys',
                   default=3,
                   help='This controls how many keys are held in rotation by '
                        'keystone-manage fernet_rotate before they are '
                        'discarded. The default value of 3 means that '
                        'keystone will maintain one staged key, one primary '
                        'key, and one secondary key. Increasing this value '
                        'means that additional secondary keys will be kept in '
                        'the rotation.'),
    ],
    'token': [
        cfg.ListOpt('bind', default=[],
                    help='External auth mechanisms that should add bind '
                         'information to token, e.g., kerberos,x509.'),
        cfg.StrOpt('enforce_token_bind', default='permissive',
                   help='Enforcement policy on tokens presented to Keystone '
                        'with bind information. One of disabled, permissive, '
                        'strict, required or a specifically required bind '
                        'mode, e.g., kerberos or x509 to require binding to '
                        'that authentication.'),
        cfg.IntOpt('expiration', default=3600,
                   help='Amount of time a token should remain valid '
                        '(in seconds).'),
        cfg.StrOpt('provider',
                   default='uuid',
                   help='Controls the token construction, validation, and '
                        'revocation operations. Entrypoint in the '
                        'keystone.token.provider namespace. Core providers '
                        'are [fernet|pkiz|pki|uuid].'),
        cfg.StrOpt('driver',
                   default='sql',
                   help='Entrypoint for the token persistence backend driver '
                        'in the keystone.token.persistence namespace. '
                        'Supplied drivers are kvs, memcache, memcache_pool, '
                        'and sql.'),
        cfg.BoolOpt('caching', default=True,
                    help='Toggle for token system caching. This has no '
                         'effect unless global caching is enabled.'),
        cfg.IntOpt('cache_time',
                   help='Time to cache tokens (in seconds). This has no '
                        'effect unless global and token caching are '
                        'enabled.'),
        cfg.BoolOpt('revoke_by_id', default=True,
                    help='Revoke token by token identifier. Setting '
                    'revoke_by_id to true enables various forms of '
                    'enumerating tokens, e.g. `list tokens for user`. '
                    'These enumerations are processed to determine the '
                    'list of tokens to revoke. Only disable if you are '
                    'switching to using the Revoke extension with a '
                    'backend other than KVS, which stores events in memory.'),
        cfg.BoolOpt('allow_rescope_scoped_token', default=True,
                    help='Allow rescoping of scoped token. Setting '
                    'allow_rescoped_scoped_token to false prevents a user '
                    'from exchanging a scoped token for any other token.'),
        cfg.StrOpt('hash_algorithm', default='md5',
                   deprecated_for_removal=True,
                   deprecated_reason=_DEPRECATE_PKI_MSG,
                   help='The hash algorithm to use for PKI tokens. This can '
                        'be set to any algorithm that hashlib supports. '
                        'WARNING: Before changing this value, the auth_token '
                        'middleware must be configured with the '
                        'hash_algorithms, otherwise token revocation will '
                        'not be processed correctly.'),
        cfg.BoolOpt('infer_roles', default=True,
                    help='Add roles to token that are not explicitly added, '
                         'but that are linked implicitly to other roles.'),
    ],
    'revoke': [
        cfg.StrOpt('driver',
                   default='sql',
                   help='Entrypoint for an implementation of the backend for '
                        'persisting revocation events in the keystone.revoke '
                        'namespace. Supplied drivers are kvs and sql.'),
        cfg.IntOpt('expiration_buffer', default=1800,
                   help='This value (calculated in seconds) is added to token '
                        'expiration before a revocation event may be removed '
                        'from the backend.'),
        cfg.BoolOpt('caching', default=True,
                    help='Toggle for revocation event caching. This has no '
                         'effect unless global caching is enabled.'),
        cfg.IntOpt('cache_time', default=3600,
                   help='Time to cache the revocation list and the revocation '
                        'events (in seconds). This has no effect unless '
                        'global and token caching are enabled.',
                   deprecated_opts=[cfg.DeprecatedOpt(
                       'revocation_cache_time', group='token')]),
    ],
    'signing': [
        cfg.StrOpt('certfile',
                   default=_CERTFILE,
                   deprecated_for_removal=True,
                   deprecated_reason=_DEPRECATE_PKI_MSG,
                   help='Path of the certfile for token signing. For '
                        'non-production environments, you may be interested '
                        'in using `keystone-manage pki_setup` to generate '
                        'self-signed certificates.'),
        cfg.StrOpt('keyfile',
                   default=_KEYFILE,
                   deprecated_for_removal=True,
                   deprecated_reason=_DEPRECATE_PKI_MSG,
                   help='Path of the keyfile for token signing.'),
        cfg.StrOpt('ca_certs',
                   deprecated_for_removal=True,
                   deprecated_reason=_DEPRECATE_PKI_MSG,
                   default='/etc/keystone/ssl/certs/ca.pem',
                   help='Path of the CA for token signing.'),
        cfg.StrOpt('ca_key',
                   default='/etc/keystone/ssl/private/cakey.pem',
                   deprecated_for_removal=True,
                   deprecated_reason=_DEPRECATE_PKI_MSG,
                   help='Path of the CA key for token signing.'),
        cfg.IntOpt('key_size', default=2048, min=1024,
                   deprecated_for_removal=True,
                   deprecated_reason=_DEPRECATE_PKI_MSG,
                   help='Key size (in bits) for token signing cert '
                        '(auto generated certificate).'),
        cfg.IntOpt('valid_days', default=3650,
                   deprecated_for_removal=True,
                   deprecated_reason=_DEPRECATE_PKI_MSG,
                   help='Days the token signing cert is valid for '
                        '(auto generated certificate).'),
        cfg.StrOpt('cert_subject',
                   deprecated_for_removal=True,
                   deprecated_reason=_DEPRECATE_PKI_MSG,
                   default=('/C=US/ST=Unset/L=Unset/O=Unset/'
                            'CN=www.example.com'),
                   help='Certificate subject (auto generated certificate) for '
                        'token signing.'),
    ],
    'assignment': [
        cfg.StrOpt('driver',
                   help='Entrypoint for the assignment backend driver in the '
                        'keystone.assignment namespace. Only an SQL driver is '
                        'supplied. If an assignment driver is not '
                        'specified, the identity driver will choose the '
                        'assignment driver (driver selection based on '
                        '`[identity]/driver` option is deprecated and will be '
                        'removed in the "O" release).'),
        cfg.ListOpt('prohibited_implied_role', default=['admin'],
                    help='A list of role names which are prohibited from '
                         'being an implied role.'),
    ],
    'resource': [
        cfg.StrOpt('driver',
                   help='Entrypoint for the resource backend driver in the '
                        'keystone.resource namespace. Only an SQL driver is '
                        'supplied. If a resource driver is not specified, '
                        'the assignment driver will choose the resource '
                        'driver.'),
        cfg.BoolOpt('caching', default=True,
                    deprecated_opts=[cfg.DeprecatedOpt('caching',
                                                       group='assignment')],
                    help='Toggle for resource caching. This has no effect '
                         'unless global caching is enabled.'),
        cfg.IntOpt('cache_time',
                   deprecated_opts=[cfg.DeprecatedOpt('cache_time',
                                                      group='assignment')],
                   help='TTL (in seconds) to cache resource data. This has '
                        'no effect unless global caching is enabled.'),
        cfg.IntOpt('list_limit',
                   deprecated_opts=[cfg.DeprecatedOpt('list_limit',
                                                      group='assignment')],
                   help='Maximum number of entities that will be returned '
                        'in a resource collection.'),
        cfg.StrOpt('admin_project_domain_name',
                   help='Name of the domain that owns the '
                        '`admin_project_name`. Defaults to None.'),
        cfg.StrOpt('admin_project_name',
                   help='Special project for performing administrative '
                   'operations on remote services. Tokens scoped to '
                   'this project will contain the key/value '
                   '`is_admin_project=true`. Defaults to None.'),
        cfg.StrOpt('project_name_url_safe',
                   choices=['off', 'new', 'strict'], default='off',
                   help='Whether the names of projects are restricted from '
                        'containing url reserved characters. If set to new, '
                        'attempts to create or update a project with a url '
                        'unsafe name will return an error. In addition, if '
                        'set to strict, attempts to scope a token using '
                        'an unsafe project name will return an error.'),
        cfg.StrOpt('domain_name_url_safe',
                   choices=['off', 'new', 'strict'], default='off',
                   help='Whether the names of domains are restricted from '
                        'containing url reserved characters. If set to new, '
                        'attempts to create or update a domain with a url '
                        'unsafe name will return an error. In addition, if '
                        'set to strict, attempts to scope a token using a '
                        'domain name which is unsafe will return an error.'),
    ],
    'domain_config': [
        cfg.StrOpt('driver',
                   default='sql',
                   help='Entrypoint for the domain config backend driver in '
                        'the keystone.resource.domain_config namespace.'),
        cfg.BoolOpt('caching', default=True,
                    help='Toggle for domain config caching. This has no '
                         'effect unless global caching is enabled.'),
        cfg.IntOpt('cache_time', default=300,
                   help='TTL (in seconds) to cache domain config data. This '
                        'has no effect unless domain config caching is '
                        'enabled.'),
    ],
    'role': [
        # The role driver has no default for backward compatibility reasons.
        # If role driver is not specified, the assignment driver chooses
        # the backend
        cfg.StrOpt('driver',
                   help='Entrypoint for the role backend driver in the '
                        'keystone.role namespace. Only an SQL driver is '
                        'supplied'),
        cfg.BoolOpt('caching', default=True,
                    help='Toggle for role caching. This has no effect '
                         'unless global caching is enabled.'),
        cfg.IntOpt('cache_time',
                   help='TTL (in seconds) to cache role data. This has '
                        'no effect unless global caching is enabled.'),
        cfg.IntOpt('list_limit',
                   help='Maximum number of entities that will be returned '
                        'in a role collection.'),
    ],
    'credential': [
        cfg.StrOpt('driver',
                   default='sql',
                   help='Entrypoint for the credential backend driver in the '
                        'keystone.credential namespace.'),
    ],
    'oauth1': [
        cfg.StrOpt('driver',
                   default='sql',
                   help='Entrypoint for the OAuth backend driver in the '
                        'keystone.oauth1 namespace.'),
        cfg.IntOpt('request_token_duration', default=28800,
                   help='Duration (in seconds) for the OAuth Request Token.'),
        cfg.IntOpt('access_token_duration', default=86400,
                   help='Duration (in seconds) for the OAuth Access Token.'),
    ],
    'federation': [
        cfg.StrOpt('driver',
                   default='sql',
                   help='Entrypoint for the federation backend driver in the '
                        'keystone.federation namespace.'),
        cfg.StrOpt('assertion_prefix', default='',
                   help='Value to be used when filtering assertion parameters '
                        'from the environment.'),
        cfg.StrOpt('remote_id_attribute',
                   help='Value to be used to obtain the entity ID of the '
                        'Identity Provider from the environment (e.g. if '
                        'using the mod_shib plugin this value is '
                        '`Shib-Identity-Provider`).'),
        cfg.StrOpt('federated_domain_name', default='Federated',
                   help='A domain name that is reserved to allow federated '
                        'ephemeral users to have a domain concept. Note that '
                        'an admin will not be able to create a domain with '
                        'this name or update an existing domain to this '
                        'name. You are not advised to change this value '
                        'unless you really have to.'),
        cfg.MultiStrOpt('trusted_dashboard', default=[],
                        help='A list of trusted dashboard hosts. Before '
                             'accepting a Single Sign-On request to return a '
                             'token, the origin host must be a member of the '
                             'trusted_dashboard list. This configuration '
                             'option may be repeated for multiple values. '
                             'For example: '
                             'trusted_dashboard=http://acme.com/auth/websso '
                             'trusted_dashboard=http://beta.com/auth/websso'),
        cfg.StrOpt('sso_callback_template', default=_SSO_CALLBACK,
                   help='Location of Single Sign-On callback handler, will '
                        'return a token to a trusted dashboard host.'),
    ],
    'policy': [
        cfg.StrOpt('driver',
                   default='sql',
                   help='Entrypoint for the policy backend driver in the '
                        'keystone.policy namespace. Supplied drivers are '
                        'rules and sql.'),
        cfg.IntOpt('list_limit',
                   help='Maximum number of entities that will be returned '
                        'in a policy collection.'),
    ],
    'endpoint_filter': [
        cfg.StrOpt('driver',
                   default='sql',
                   help='Entrypoint for the endpoint filter backend driver in '
                        'the keystone.endpoint_filter namespace.'),
        cfg.BoolOpt('return_all_endpoints_if_no_filter', default=True,
                    help='Toggle to return all active endpoints if no filter '
                         'exists.'),
    ],
    'endpoint_policy': [
        cfg.BoolOpt('enabled',
                    default=True,
                    deprecated_for_removal=True,
                    deprecated_reason=_DEPRECATE_EP_MSG,
                    help='Enable endpoint_policy functionality.'),
        cfg.StrOpt('driver',
                   default='sql',
                   help='Entrypoint for the endpoint policy backend driver in '
                        'the keystone.endpoint_policy namespace.'),
    ],
    'ldap': [
        cfg.StrOpt('url', default='ldap://localhost',
                   help='URL(s) for connecting to the LDAP server. Multiple '
                        'LDAP URLs may be specified as a comma separated '
                        'string. The first URL to successfully bind is used '
                        'for the connection.'),
        cfg.StrOpt('user',
                   help='User BindDN to query the LDAP server.'),
        cfg.StrOpt('password', secret=True,
                   help='Password for the BindDN to query the LDAP server.'),
        cfg.StrOpt('suffix', default='cn=example,cn=com',
                   help='LDAP server suffix'),
        cfg.BoolOpt('use_dumb_member', default=False,
                    help='If true, will add a dummy member to groups. This is '
                         'required if the objectclass for groups requires the '
                         '"member" attribute.'),
        cfg.StrOpt('dumb_member', default='cn=dumb,dc=nonexistent',
                   help='DN of the "dummy member" to use when '
                        '"use_dumb_member" is enabled.'),
        cfg.BoolOpt('allow_subtree_delete', default=False,
                    help='Delete subtrees using the subtree delete control. '
                         'Only enable this option if your LDAP server '
                         'supports subtree deletion.'),
        cfg.StrOpt('query_scope', default='one',
                   choices=['one', 'sub'],
                   help='The LDAP scope for queries, "one" represents '
                        'oneLevel/singleLevel and "sub" represents '
                        'subtree/wholeSubtree options.'),
        cfg.IntOpt('page_size', default=0,
                   help='Maximum results per page; a value of zero ("0") '
                        'disables paging.'),
        cfg.StrOpt('alias_dereferencing', default='default',
                   choices=['never', 'searching', 'always', 'finding',
                            'default'],
                   help='The LDAP dereferencing option for queries. The '
                        '"default" option falls back to using default '
                        'dereferencing configured by your ldap.conf.'),
        cfg.IntOpt('debug_level',
                   help='Sets the LDAP debugging level for LDAP calls. '
                        'A value of 0 means that debugging is not enabled. '
                        'This value is a bitmask, consult your LDAP '
                        'documentation for possible values.'),
        cfg.BoolOpt('chase_referrals',
                    help='Override the system\'s default referral chasing '
                         'behavior for queries.'),
        cfg.StrOpt('user_tree_dn',
                   help='Search base for users. '
                        'Defaults to the suffix value.'),
        cfg.StrOpt('user_filter',
                   help='LDAP search filter for users.'),
        cfg.StrOpt('user_objectclass', default='inetOrgPerson',
                   help='LDAP objectclass for users.'),
        cfg.StrOpt('user_id_attribute', default='cn',
                   help='LDAP attribute mapped to user id. '
                        'WARNING: must not be a multivalued attribute.'),
        cfg.StrOpt('user_name_attribute', default='sn',
                   help='LDAP attribute mapped to user name.'),
        cfg.StrOpt('user_description_attribute', default='description',
                   help='LDAP attribute mapped to user description.'),
        cfg.StrOpt('user_mail_attribute', default='mail',
                   help='LDAP attribute mapped to user email.'),
        cfg.StrOpt('user_pass_attribute', default='userPassword',
                   help='LDAP attribute mapped to password.'),
        cfg.StrOpt('user_enabled_attribute', default='enabled',
                   help='LDAP attribute mapped to user enabled flag.'),
        cfg.BoolOpt('user_enabled_invert', default=False,
                    help='Invert the meaning of the boolean enabled values. '
                         'Some LDAP servers use a boolean lock attribute '
                         'where "true" means an account is disabled. Setting '
                         '"user_enabled_invert = true" will allow these lock '
                         'attributes to be used. This setting will have no '
                         'effect if "user_enabled_mask" or '
                         '"user_enabled_emulation" settings are in use.'),
        cfg.IntOpt('user_enabled_mask', default=0,
                   help='Bitmask integer to indicate the bit that the enabled '
                        'value is stored in if the LDAP server represents '
                        '"enabled" as a bit on an integer rather than a '
                        'boolean. A value of "0" indicates the mask is not '
                        'used. If this is not set to "0" the typical value '
                        'is "2". This is typically used when '
                        '"user_enabled_attribute = userAccountControl".'),
        cfg.StrOpt('user_enabled_default', default='True',
                   help='Default value to enable users. This should match an '
                        'appropriate int value if the LDAP server uses '
                        'non-boolean (bitmask) values to indicate if a user '
                        'is enabled or disabled. If this is not set to "True" '
                        'the typical value is "512". This is typically used '
                        'when "user_enabled_attribute = userAccountControl".'),
        cfg.ListOpt('user_attribute_ignore',
                    default=['default_project_id'],
                    help='List of attributes stripped off the user on '
                         'update.'),
        cfg.StrOpt('user_default_project_id_attribute',
                   help='LDAP attribute mapped to default_project_id for '
                        'users.'),
        cfg.BoolOpt('user_allow_create', default=True,
                    deprecated_for_removal=True,
                    deprecated_reason="Write support for Identity LDAP "
                                      "backends has been deprecated in the M "
                                      "release and will be removed in the O "
                                      "release.",
                    help='Allow user creation in LDAP backend.'),
        cfg.BoolOpt('user_allow_update', default=True,
                    deprecated_for_removal=True,
                    deprecated_reason="Write support for Identity LDAP "
                                      "backends has been deprecated in the M "
                                      "release and will be removed in the O "
                                      "release.",
                    help='Allow user updates in LDAP backend.'),
        cfg.BoolOpt('user_allow_delete', default=True,
                    deprecated_for_removal=True,
                    deprecated_reason="Write support for Identity LDAP "
                                      "backends has been deprecated in the M "
                                      "release and will be removed in the O "
                                      "release.",
                    help='Allow user deletion in LDAP backend.'),
        cfg.BoolOpt('user_enabled_emulation', default=False,
                    help='If true, Keystone uses an alternative method to '
                         'determine if a user is enabled or not by checking '
                         'if they are a member of the '
                         '"user_enabled_emulation_dn" group.'),
        cfg.StrOpt('user_enabled_emulation_dn',
                   help='DN of the group entry to hold enabled users when '
                        'using enabled emulation.'),
        cfg.BoolOpt('user_enabled_emulation_use_group_config', default=False,
                    help='Use the "group_member_attribute" and '
                         '"group_objectclass" settings to determine '
                         'membership in the emulated enabled group.'),
        cfg.ListOpt('user_additional_attribute_mapping',
                    default=[],
                    help='List of additional LDAP attributes used for mapping '
                         'additional attribute mappings for users. Attribute '
                         'mapping format is <ldap_attr>:<user_attr>, where '
                         'ldap_attr is the attribute in the LDAP entry and '
                         'user_attr is the Identity API attribute.'),
        cfg.StrOpt('group_tree_dn',
                   help='Search base for groups. '
                        'Defaults to the suffix value.'),
        cfg.StrOpt('group_filter',
                   help='LDAP search filter for groups.'),
        cfg.StrOpt('group_objectclass', default='groupOfNames',
                   help='LDAP objectclass for groups.'),
        cfg.StrOpt('group_id_attribute', default='cn',
                   help='LDAP attribute mapped to group id.'),
        cfg.StrOpt('group_name_attribute', default='ou',
                   help='LDAP attribute mapped to group name.'),
        cfg.StrOpt('group_member_attribute', default='member',
                   help='LDAP attribute mapped to show group membership.'),
        cfg.StrOpt('group_desc_attribute', default='description',
                   help='LDAP attribute mapped to group description.'),
        cfg.ListOpt('group_attribute_ignore', default=[],
                    help='List of attributes stripped off the group on '
                         'update.'),
        cfg.BoolOpt('group_allow_create', default=True,
                    deprecated_for_removal=True,
                    deprecated_reason="Write support for Identity LDAP "
                                      "backends has been deprecated in the M "
                                      "release and will be removed in the O "
                                      "release.",
                    help='Allow group creation in LDAP backend.'),
        cfg.BoolOpt('group_allow_update', default=True,
                    deprecated_for_removal=True,
                    deprecated_reason="Write support for Identity LDAP "
                                      "backends has been deprecated in the M "
                                      "release and will be removed in the O "
                                      "release.",
                    help='Allow group update in LDAP backend.'),
        cfg.BoolOpt('group_allow_delete', default=True,
                    deprecated_for_removal=True,
                    deprecated_reason="Write support for Identity LDAP "
                                      "backends has been deprecated in the M "
                                      "release and will be removed in the O "
                                      "release.",
                    help='Allow group deletion in LDAP backend.'),
        cfg.ListOpt('group_additional_attribute_mapping',
                    default=[],
                    help='Additional attribute mappings for groups. Attribute '
                         'mapping format is <ldap_attr>:<user_attr>, where '
                         'ldap_attr is the attribute in the LDAP entry and '
                         'user_attr is the Identity API attribute.'),

        cfg.StrOpt('tls_cacertfile',
                   help='CA certificate file path for communicating with '
                        'LDAP servers.'),
        cfg.StrOpt('tls_cacertdir',
                   help='CA certificate directory path for communicating with '
                        'LDAP servers.'),
        cfg.BoolOpt('use_tls', default=False,
                    help='Enable TLS for communicating with LDAP servers.'),
        cfg.StrOpt('tls_req_cert', default='demand',
                   choices=['demand', 'never', 'allow'],
                   help='Specifies what checks to perform on client '
                        'certificates in an incoming TLS session.'),
        cfg.BoolOpt('use_pool', default=True,
                    help='Enable LDAP connection pooling.'),
        cfg.IntOpt('pool_size', default=10,
                   help='Connection pool size.'),
        cfg.IntOpt('pool_retry_max', default=3,
                   help='Maximum count of reconnect trials.'),
        cfg.FloatOpt('pool_retry_delay', default=0.1,
                     help='Time span in seconds to wait between two '
                          'reconnect trials.'),
        cfg.IntOpt('pool_connection_timeout', default=-1,
                   help='Connector timeout in seconds. Value -1 indicates '
                        'indefinite wait for response.'),
        cfg.IntOpt('pool_connection_lifetime', default=600,
                   help='Connection lifetime in seconds.'),
        cfg.BoolOpt('use_auth_pool', default=True,
                    help='Enable LDAP connection pooling for end user '
                         'authentication. If use_pool is disabled, then this '
                         'setting is meaningless and is not used at all.'),
        cfg.IntOpt('auth_pool_size', default=100,
                   help='End user auth connection pool size.'),
        cfg.IntOpt('auth_pool_connection_lifetime', default=60,
                   help='End user auth connection lifetime in seconds.'),
        cfg.BoolOpt('group_members_are_ids', default=False,
                    help='If the members of the group objectclass are user '
                         'IDs rather than DNs, set this to true. This is the '
                         'case when using posixGroup as the group '
                         'objectclass and OpenDirectory.'),
    ],
    'auth': [
        cfg.ListOpt('methods', default=_DEFAULT_AUTH_METHODS,
                    help='Allowed authentication methods.'),
        cfg.StrOpt('password',  # nosec : This is the name of the plugin, not
                   # a password that needs to be protected.
                   help='Entrypoint for the password auth plugin module in '
                        'the keystone.auth.password namespace.'),
        cfg.StrOpt('token',
                   help='Entrypoint for the token auth plugin module in the '
                        'keystone.auth.token namespace.'),
        # deals with REMOTE_USER authentication
        cfg.StrOpt('external',
                   help='Entrypoint for the external (REMOTE_USER) auth '
                        'plugin module in the keystone.auth.external '
                        'namespace. Supplied drivers are DefaultDomain and '
                        'Domain. The default driver is DefaultDomain.'),
        cfg.StrOpt('oauth1',
                   help='Entrypoint for the oAuth1.0 auth plugin module in '
                        'the keystone.auth.oauth1 namespace.'),
    ],
    'tokenless_auth': [
        cfg.MultiStrOpt('trusted_issuer', default=[],
                        help='The list of trusted issuers to further filter '
                             'the certificates that are allowed to '
                             'participate in the X.509 tokenless '
                             'authorization. If the option is absent then '
                             'no certificates will be allowed. '
                             'The naming format for the attributes of a '
                             'Distinguished Name(DN) must be separated by a '
                             'comma and contain no spaces. This configuration '
                             'option may be repeated for multiple values. '
                             'For example: '
                             'trusted_issuer=CN=john,OU=keystone,O=openstack '
                             'trusted_issuer=CN=mary,OU=eng,O=abc'),
        cfg.StrOpt('protocol', default='x509',
                   help='The protocol name for the X.509 tokenless '
                        'authorization along with the option issuer_attribute '
                        'below can look up its corresponding mapping.'),
        cfg.StrOpt('issuer_attribute', default='SSL_CLIENT_I_DN',
                   help='The issuer attribute that is served as an IdP ID '
                        'for the X.509 tokenless authorization along with '
                        'the protocol to look up its corresponding mapping. '
                        'It is the environment variable in the WSGI '
                        'environment that references to the issuer of the '
                        'client certificate.'),
    ],
    'paste_deploy': [
        cfg.StrOpt('config_file', default='keystone-paste.ini',
                   help='Name of the paste configuration file that defines '
                        'the available pipelines.'),
    ],
    'memcache': [
        cfg.ListOpt('servers', default=['localhost:11211'],
                    help='Memcache servers in the format of "host:port".'),
        cfg.IntOpt('dead_retry',
                   default=5 * 60,
                   help='Number of seconds memcached server is considered dead'
                        ' before it is tried again. This is used by the key '
                        'value store system (e.g. token '
                        'pooled memcached persistence backend).'),
        cfg.IntOpt('socket_timeout',
                   default=3,
                   help='Timeout in seconds for every call to a server. This '
                        'is used by the key value store system (e.g. token '
                        'pooled memcached persistence backend).'),
        cfg.IntOpt('pool_maxsize',
                   default=10,
                   help='Max total number of open connections to every'
                        ' memcached server. This is used by the key value '
                        'store system (e.g. token pooled memcached '
                        'persistence backend).'),
        cfg.IntOpt('pool_unused_timeout',
                   default=60,
                   help='Number of seconds a connection to memcached is held'
                        ' unused in the pool before it is closed. This is used'
                        ' by the key value store system (e.g. token pooled '
                        'memcached persistence backend).'),
        cfg.IntOpt('pool_connection_get_timeout',
                   default=10,
                   help='Number of seconds that an operation will wait to get '
                        'a memcache client connection. This is used by the '
                        'key value store system (e.g. token pooled memcached '
                        'persistence backend).'),
    ],
    'catalog': [
        cfg.StrOpt('template_file',
                   default='default_catalog.templates',
                   help='Catalog template file name for use with the '
                        'template catalog backend.'),
        cfg.StrOpt('driver',
                   default='sql',
                   help='Entrypoint for the catalog backend driver in the '
                        'keystone.catalog namespace. Supplied drivers are '
                        'kvs, sql, templated, and endpoint_filter.sql'),
        cfg.BoolOpt('caching', default=True,
                    help='Toggle for catalog caching. This has no '
                         'effect unless global caching is enabled.'),
        cfg.IntOpt('cache_time',
                   help='Time to cache catalog data (in seconds). This has no '
                        'effect unless global and catalog caching are '
                        'enabled.'),
        cfg.IntOpt('list_limit',
                   help='Maximum number of entities that will be returned '
                        'in a catalog collection.'),
    ],
    'kvs': [
        cfg.ListOpt('backends', default=[],
                    help='Extra dogpile.cache backend modules to register '
                         'with the dogpile.cache library.'),
        cfg.StrOpt('config_prefix', default='keystone.kvs',
                   help='Prefix for building the configuration dictionary '
                        'for the KVS region. This should not need to be '
                        'changed unless there is another dogpile.cache '
                        'region with the same configuration name.'),
        cfg.BoolOpt('enable_key_mangler', default=True,
                    help='Toggle to disable using a key-mangling function '
                         'to ensure fixed length keys. This is toggle-able '
                         'for debugging purposes, it is highly recommended '
                         'to always leave this set to true.'),
        cfg.IntOpt('default_lock_timeout', default=5,
                   help='Default lock timeout (in seconds) for distributed '
                        'locking.'),
    ],
    'saml': [
        cfg.IntOpt('assertion_expiration_time', default=3600,
                   help='Default TTL, in seconds, for any generated SAML '
                        'assertion created by Keystone.'),
        cfg.StrOpt('xmlsec1_binary',
                   default='xmlsec1',
                   help='Binary to be called for XML signing. Install the '
                        'appropriate package, specify absolute path or adjust '
                        'your PATH environment variable if the binary cannot '
                        'be found.'),
        cfg.StrOpt('certfile',
                   default=_CERTFILE,
                   help='Path of the certfile for SAML signing. For '
                        'non-production environments, you may be interested '
                        'in using `keystone-manage pki_setup` to generate '
                        'self-signed certificates. Note, the path cannot '
                        'contain a comma.'),
        cfg.StrOpt('keyfile',
                   default=_KEYFILE,
                   help='Path of the keyfile for SAML signing. Note, the path '
                        'cannot contain a comma.'),
        cfg.StrOpt('idp_entity_id',
                   help='Entity ID value for unique Identity Provider '
                        'identification. Usually FQDN is set with a suffix. '
                        'A value is required to generate IDP Metadata. '
                        'For example: https://keystone.example.com/v3/'
                        'OS-FEDERATION/saml2/idp'),
        cfg.StrOpt('idp_sso_endpoint',
                   help='Identity Provider Single-Sign-On service value, '
                        'required in the Identity Provider\'s metadata. '
                        'A value is required to generate IDP Metadata. '
                        'For example: https://keystone.example.com/v3/'
                        'OS-FEDERATION/saml2/sso'),
        cfg.StrOpt('idp_lang', default='en',
                   help='Language used by the organization.'),
        cfg.StrOpt('idp_organization_name',
                   help='Organization name the installation belongs to.'),
        cfg.StrOpt('idp_organization_display_name',
                   help='Organization name to be displayed.'),
        cfg.StrOpt('idp_organization_url',
                   help='URL of the organization.'),
        cfg.StrOpt('idp_contact_company',
                   help='Company of contact person.'),
        cfg.StrOpt('idp_contact_name',
                   help='Given name of contact person'),
        cfg.StrOpt('idp_contact_surname',
                   help='Surname of contact person.'),
        cfg.StrOpt('idp_contact_email',
                   help='Email address of contact person.'),
        cfg.StrOpt('idp_contact_telephone',
                   help='Telephone number of contact person.'),
        cfg.StrOpt('idp_contact_type', default='other',
                   choices=['technical', 'support', 'administrative',
                            'billing', 'other'],
                   help='The contact type describing the main point of '
                        'contact for the identity provider.'),
        cfg.StrOpt('idp_metadata_path',
                   default='/etc/keystone/saml2_idp_metadata.xml',
                   help='Path to the Identity Provider Metadata file. '
                        'This file should be generated with the '
                        'keystone-manage saml_idp_metadata command.'),
        cfg.StrOpt('relay_state_prefix',
                   default='ss:mem:',
                   help='The prefix to use for the RelayState SAML '
                        'attribute, used when generating ECP wrapped '
                        'assertions.'),
    ],
    'eventlet_server': [
        cfg.StrOpt('public_bind_host',
                   default='0.0.0.0',  # nosec : Bind to all interfaces by
                   # default for backwards compatibility.
                   deprecated_opts=[cfg.DeprecatedOpt('bind_host',
                                                      group='DEFAULT'),
                                    cfg.DeprecatedOpt('public_bind_host',
                                                      group='DEFAULT'), ],
                   deprecated_for_removal=True,
                   deprecated_reason=_DEPRECATE_EVENTLET_MSG,
                   help='The IP address of the network interface for the '
                        'public service to listen on.'),
        cfg.PortOpt('public_port', default=5000,
                    deprecated_name='public_port',
                    deprecated_group='DEFAULT',
                    deprecated_for_removal=True,
                    deprecated_reason=_DEPRECATE_EVENTLET_MSG,
                    help='The port number which the public service listens '
                         'on.'),
        cfg.StrOpt('admin_bind_host',
                   default='0.0.0.0',  # nosec : Bind to all interfaces by
                   # default for backwards compatibility.
                   deprecated_opts=[cfg.DeprecatedOpt('bind_host',
                                                      group='DEFAULT'),
                                    cfg.DeprecatedOpt('admin_bind_host',
                                                      group='DEFAULT')],
                   deprecated_for_removal=True,
                   deprecated_reason=_DEPRECATE_EVENTLET_MSG,
                   help='The IP address of the network interface for the '
                        'admin service to listen on.'),
        cfg.PortOpt('admin_port', default=35357,
                    deprecated_name='admin_port',
                    deprecated_group='DEFAULT',
                    deprecated_for_removal=True,
                    deprecated_reason=_DEPRECATE_EVENTLET_MSG,
                    help='The port number which the admin service listens '
                         'on.'),
    ],
}


CONF = cfg.CONF
oslo_messaging.set_transport_defaults(control_exchange='keystone')


def _register_auth_plugin_opt(conf, option):
    conf.register_opt(option, group='auth')


def setup_authentication(conf=None):
    # register any non-default auth methods here (used by extensions, etc)
    if conf is None:
        conf = CONF
    for method_name in conf.auth.methods:
        if method_name not in _DEFAULT_AUTH_METHODS:
            option = cfg.StrOpt(method_name)
            _register_auth_plugin_opt(conf, option)


def set_default_for_default_log_levels():
    """Set the default for the default_log_levels option for keystone.

    Keystone uses some packages that other OpenStack services don't use that do
    logging. This will set the default_log_levels default level for those
    packages.

    This function needs to be called before CONF().

    """
    extra_log_level_defaults = [
        'dogpile=INFO',
        'routes=INFO',
    ]

    log.register_options(CONF)
    log.set_defaults(default_log_levels=log.get_default_log_levels() +
                     extra_log_level_defaults)


def setup_logging():
    """Set up logging for the keystone package."""
    log.setup(CONF, 'keystone')
    logging.captureWarnings(True)


def find_paste_config():
    """Find Keystone's paste.deploy configuration file.

    Keystone's paste.deploy configuration file is specified in the
    ``[paste_deploy]`` section of the main Keystone configuration file,
    ``keystone.conf``.

    For example::

        [paste_deploy]
        config_file = keystone-paste.ini

    :returns: The selected configuration filename
    :raises: exception.ConfigFileNotFound

    """
    if CONF.paste_deploy.config_file:
        paste_config = CONF.paste_deploy.config_file
        paste_config_value = paste_config
        if not os.path.isabs(paste_config):
            paste_config = CONF.find_file(paste_config)
    elif CONF.config_file:
        paste_config = CONF.config_file[0]
        paste_config_value = paste_config
    else:
        # this provides backwards compatibility for keystone.conf files that
        # still have the entire paste configuration included, rather than just
        # a [paste_deploy] configuration section referring to an external file
        paste_config = CONF.find_file('keystone.conf')
        paste_config_value = 'keystone.conf'
    if not paste_config or not os.path.exists(paste_config):
        raise exception.ConfigFileNotFound(config_file=paste_config_value)
    return paste_config


def configure(conf=None):
    if conf is None:
        conf = CONF

    conf.register_cli_opt(
        cfg.BoolOpt('standard-threads', default=False,
                    help='Do not monkey-patch threading system modules.'))
    conf.register_cli_opt(
        cfg.StrOpt('pydev-debug-host',
                   help='Host to connect to for remote debugger.'))
    conf.register_cli_opt(
        cfg.PortOpt('pydev-debug-port',
                    help='Port to connect to for remote debugger.'))

    for section in FILE_OPTIONS:
        for option in FILE_OPTIONS[section]:
            if section:
                conf.register_opt(option, group=section)
            else:
                conf.register_opt(option)

    # register any non-default auth methods here (used by extensions, etc)
    setup_authentication(conf)
    # add oslo.cache related config options
    cache.configure(conf)


def list_opts():
    """Return a list of oslo_config options available in Keystone.

    The returned list includes all oslo_config options which are registered as
    the "FILE_OPTIONS" in keystone.common.config. This list will not include
    the options from the oslo-incubator library or any options registered
    dynamically at run time.

    Each object in the list is a two element tuple. The first element of
    each tuple is the name of the group under which the list of options in the
    second element will be registered. A group name of None corresponds to the
    [DEFAULT] group in config files.

    This function is also discoverable via the 'oslo_config.opts' entry point
    under the 'keystone.config.opts' namespace.

    The purpose of this is to allow tools like the Oslo sample config file
    generator to discover the options exposed to users by this library.

    :returns: a list of (group_name, opts) tuples
    """
    return list(FILE_OPTIONS.items())


def set_external_opts_defaults():
    """Update default configuration options for oslo.middleware."""
    # CORS Defaults
    # TODO(krotscheck): Update with https://review.openstack.org/#/c/285368/
    cfg.set_defaults(cors.CORS_OPTS,
                     allow_headers=['X-Auth-Token',
                                    'X-Openstack-Request-Id',
                                    'X-Subject-Token',
                                    'X-Project-Id',
                                    'X-Project-Name',
                                    'X-Project-Domain-Id',
                                    'X-Project-Domain-Name',
                                    'X-Domain-Id',
                                    'X-Domain-Name'],
                     expose_headers=['X-Auth-Token',
                                     'X-Openstack-Request-Id',
                                     'X-Subject-Token'],
                     allow_methods=['GET',
                                    'PUT',
                                    'POST',
                                    'DELETE',
                                    'PATCH']
                     )

    # configure OSprofiler options
    profiler.set_defaults(CONF, enabled=False, trace_sqlalchemy=False)

    # Oslo.cache is always enabled by default for request-local caching
    # TODO(morganfainberg): Fix this to not use internal interface when
    # oslo.cache has proper interface to set defaults added. This is is
    # just a bad way to do this.
    opts = cache._opts.list_opts()
    for opt_list in opts:
        if opt_list[0] == 'cache':
            for o in opt_list[1]:
                if o.name == 'enabled':
                    o.default = True


def set_config_defaults():
    """Override all configuration default values for keystone."""
    set_default_for_default_log_levels()
    set_external_opts_defaults()
