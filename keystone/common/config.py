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

from oslo.config import cfg


_DEFAULT_AUTH_METHODS = ['external', 'password', 'token']


FILE_OPTIONS = {
    None: [
        cfg.StrOpt('admin_token', secret=True, default='ADMIN',
                   help='A "shared secret" that can be used to bootstrap '
                        'Keystone. This "token" does not represent a user, '
                        'and carries no explicit authorization. To disable '
                        'in production (highly recommended), remove '
                        'AdminTokenAuthMiddleware from your paste '
                        'application pipelines (for example, in '
                        'keystone-paste.ini).'),
        cfg.StrOpt('public_bind_host',
                   default='0.0.0.0',
                   deprecated_opts=[cfg.DeprecatedOpt('bind_host',
                                                      group='DEFAULT')],
                   help='The IP Address of the network interface to for the '
                        'public service to listen on.'),
        cfg.StrOpt('admin_bind_host',
                   default='0.0.0.0',
                   deprecated_opts=[cfg.DeprecatedOpt('bind_host',
                                                      group='DEFAULT')],
                   help='The IP Address of the network interface to for the '
                        'admin service to listen on.'),
        cfg.IntOpt('compute_port', default=8774,
                   help='The port which the OpenStack Compute service '
                        'listens on.'),
        cfg.IntOpt('admin_port', default=35357,
                   help='The port number which the admin service listens '
                        'on.'),
        cfg.IntOpt('public_port', default=5000,
                   help='The port number which the public service listens '
                        'on.'),
        cfg.StrOpt('public_endpoint',
                   help='The base public endpoint URL for keystone that are '
                        'advertised to clients (NOTE: this does NOT affect '
                        'how keystone listens for connections). '
                        'Defaults to the base host URL of the request. Eg a '
                        'request to http://server:5000/v2.0/users will '
                        'default to http://server:5000. You should only need '
                        'to set this value if the base URL contains a path '
                        '(eg /prefix/v2.0) or the endpoint should be found on '
                        'a different server.'),
        cfg.StrOpt('admin_endpoint',
                   help='The base admin endpoint URL for keystone that are '
                        'advertised to clients (NOTE: this does NOT affect '
                        'how keystone listens for connections). '
                        'Defaults to the base host URL of the request. Eg a '
                        'request to http://server:35357/v2.0/users will '
                        'default to http://server:35357. You should only need '
                        'to set this value if the base URL contains a path '
                        '(eg /prefix/v2.0) or the endpoint should be found on '
                        'a different server.'),
        cfg.StrOpt('onready',
                   help='onready allows you to send a notification when the '
                        'process is ready to serve For example, to have it '
                        'notify using systemd, one could set shell command: '
                        '"onready = systemd-notify --ready" or a module '
                        'with notify() method: '
                        '"onready = keystone.common.systemd".'),
        # default max request size is 112k
        cfg.IntOpt('max_request_body_size', default=114688,
                   help='enforced by optional sizelimit middleware '
                        '(keystone.middleware:RequestBodySizeLimiter).'),
        cfg.IntOpt('max_param_size', default=64,
                   help='limit the sizes of user & tenant ID/names.'),
        # we allow tokens to be a bit larger to accommodate PKI
        cfg.IntOpt('max_token_size', default=8192,
                   help='similar to max_param_size, but provides an '
                        'exception for token values.'),
        cfg.StrOpt('member_role_id',
                   default='9fe2ff9ee4384b1894a90878d3e92bab',
                   help='During a SQL upgrade member_role_id will be used '
                        'to create a new role that will replace records in '
                        'the user_tenant_membership table with explicit '
                        'role grants. After migration, the member_role_id '
                        'will be used in the API add_user_to_project.'),
        cfg.StrOpt('member_role_name', default='_member_',
                   help='During a SQL upgrade member_role_id will be used '
                        'to create a new role that will replace records in '
                        'the user_tenant_membership table with explicit '
                        'role grants. After migration, member_role_name will '
                        'be ignored.'),
        cfg.IntOpt('crypt_strength', default=40000,
                   help='The value passed as the keyword "rounds" to passlib '
                        'encrypt method.'),
        cfg.BoolOpt('tcp_keepalive', default=False,
                    help='Set this to True if you want to enable '
                         'TCP_KEEPALIVE on server sockets i.e. sockets used '
                         'by the keystone wsgi server for client '
                         'connections.'),
        cfg.IntOpt('tcp_keepidle',
                   default=600,
                   help='Sets the value of TCP_KEEPIDLE in seconds for each '
                        'server socket. Only applies if tcp_keepalive is '
                        'True. Not supported on OS X.'),
        cfg.IntOpt('list_limit', default=None,
                   help='The maximum number of entities that will be '
                        'returned in a collection can be set with '
                        'list_limit, with no limit set by default. This '
                        'global limit may be then overridden for a specific '
                        'driver, by specifying a list_limit in the '
                        'appropriate section (e.g. [assignment]).'),
        cfg.BoolOpt('domain_id_immutable', default=True,
                    help='Set this to false if you want to enable the '
                         'ability for user, group and project entities '
                         'to be moved between domains by updating their '
                         'domain_id. Allowing such movement is not '
                         'recommended if the scope of a domain admin is being '
                         'restricted by use of an appropriate policy file '
                         '(see policy.v3cloudsample as an example).')],
    'identity': [
        cfg.StrOpt('default_domain_id', default='default',
                   help='This references the domain to use for all '
                        'Identity API v2 requests (which are not aware of '
                        'domains). A domain with this ID will be created '
                        'for you by keystone-manage db_sync in migration '
                        '008.  The domain referenced by this ID cannot be '
                        'deleted on the v3 API, to prevent accidentally '
                        'breaking the v2 API. There is nothing special about '
                        'this domain, other than the fact that it must '
                        'exist to order to maintain support for your v2 '
                        'clients.'),
        cfg.BoolOpt('domain_specific_drivers_enabled',
                    default=False,
                    help='A subset (or all) of domains can have their own '
                         'identity driver, each with their own partial '
                         'configuration file in a domain configuration '
                         'directory. Only values specific to the domain '
                         'need to be placed in the domain specific '
                         'configuration file. This feature is disabled by '
                         'default; set to True to enable.'),
        cfg.StrOpt('domain_config_dir',
                   default='/etc/keystone/domains',
                   help='Path for Keystone to locate the domain specific'
                        'identity configuration files if '
                        'domain_specific_drivers_enabled is set to true.'),
        cfg.StrOpt('driver',
                   default=('keystone.identity.backends'
                            '.sql.Identity'),
                   help='Keystone Identity backend driver.'),
        cfg.IntOpt('max_password_length', default=4096,
                   help='Maximum supported length for user passwords; '
                        'decrease to improve performance.'),
        cfg.IntOpt('list_limit', default=None,
                   help='Maximum number of entities that will be returned in '
                        'an identity collection.')],
    'trust': [
        cfg.BoolOpt('enabled', default=True,
                    help='delegation and impersonation features can be '
                         'optionally disabled.'),
        cfg.StrOpt('driver',
                   default='keystone.trust.backends.sql.Trust',
                   help='Keystone Trust backend driver.')],
    'os_inherit': [
        cfg.BoolOpt('enabled', default=False,
                    help='role-assignment inheritance to projects from '
                         'owning domain can be optionally enabled.')],
    'token': [
        cfg.ListOpt('bind', default=[],
                    help='External auth mechanisms that should add bind '
                         'information to token e.g. kerberos, x509.'),
        cfg.StrOpt('enforce_token_bind', default='permissive',
                   help='Enforcement policy on tokens presented to keystone '
                        'with bind information. One of disabled, permissive, '
                        'strict, required or a specifically required bind '
                        'mode e.g. kerberos or x509 to require binding to '
                        'that authentication.'),
        cfg.IntOpt('expiration', default=3600,
                   help='Amount of time a token should remain valid '
                        '(in seconds).'),
        cfg.StrOpt('provider', default=None,
                   help='Controls the token construction, validation, and '
                        'revocation operations. Core providers are '
                        '"keystone.token.providers.[pki|uuid].Provider".'),
        cfg.StrOpt('driver',
                   default='keystone.token.backends.sql.Token',
                   help='Keystone Token persistence backend driver.'),
        cfg.BoolOpt('caching', default=True,
                    help='Toggle for token system cacheing. This has no '
                         'effect unless global caching is enabled.'),
        cfg.IntOpt('revocation_cache_time', default=3600,
                   help='Time to cache the revocation list and the revocation '
                        'events if revoke extension is enabled (in seconds). '
                        'This has no effect unless global and token '
                        'caching are enabled.'),
        cfg.IntOpt('cache_time', default=None,
                   help='Time to cache tokens (in seconds). This has no '
                        'effect unless global and token caching are '
                        'enabled.'),
        cfg.BoolOpt('revoke_by_id', default=True,
                    help='Revoke token by token identifier.  Setting '
                    'revoke_by_id to True enables various forms of '
                    'enumerating tokens, e.g. `list tokens for user`.  '
                    'These enumerations are processed to determine the '
                    'list of tokens to revoke.   Only disable if you are '
                    'switching to using the Revoke extension with a '
                    'backend other than KVS, which stores events in memory.')
    ],
    'revoke': [
        cfg.StrOpt('driver',
                   default='keystone.contrib.revoke.backends.kvs.Revoke',
                   help='An implementation of the backend for persisting '
                        'revocation events.'),
        cfg.IntOpt('expiration_buffer', default=1800,
                   help='This value (calculated in seconds) is added to token '
                        'expiration before a revocation event may be removed '
                        'from the backend.'),
        cfg.BoolOpt('caching', default=True,
                    help='Toggle for revocation event cacheing. This has no '
                         'effect unless global caching is enabled.'),
    ],
    'cache': [
        cfg.StrOpt('config_prefix', default='cache.keystone',
                   help='Prefix for building the configuration dictionary '
                        'for the cache region. This should not need to be '
                        'changed unless there is another dogpile.cache '
                        'region with the same configuration name.'),
        cfg.IntOpt('expiration_time', default=600,
                   help='Default TTL, in seconds, for any cached item in '
                        'the dogpile.cache region. This applies to any '
                        'cached method that doesn\'t have an explicit '
                        'cache expiration time defined for it.'),
        # NOTE(morganfainberg): the dogpile.cache.memory acceptable in devstack
        # and other such single-process/thread deployments. Running
        # dogpile.cache.memory in any other configuration has the same pitfalls
        # as the KVS token backend. It is recommended that either Redis or
        # Memcached are used as the dogpile backend for real workloads. To
        # prevent issues with the memory cache ending up in "production"
        # unintentionally, we register a no-op as the keystone default caching
        # backend.
        cfg.StrOpt('backend', default='keystone.common.cache.noop',
                   help='Dogpile.cache backend module. It is recommended '
                        'that Memcache (dogpile.cache.memcached) or Redis '
                        '(dogpile.cache.redis) be used in production '
                        'deployments.  Small workloads (single process) '
                        'like devstack can use the dogpile.cache.memory '
                        'backend.'),
        cfg.BoolOpt('use_key_mangler', default=True,
                    help='Use a key-mangling function (sha1) to ensure '
                         'fixed length cache-keys. This is toggle-able for '
                         'debugging purposes, it is highly recommended to '
                         'always leave this set to True.'),
        cfg.MultiStrOpt('backend_argument', default=[],
                        help='Arguments supplied to the backend module. '
                             'Specify this option once per argument to be '
                             'passed to the dogpile.cache backend. Example '
                             'format: "<argname>:<value>".'),
        cfg.ListOpt('proxies', default=[],
                    help='Proxy Classes to import that will affect the way '
                         'the dogpile.cache backend functions. See the '
                         'dogpile.cache documentation on '
                         'changing-backend-behavior. Comma delimited '
                         'list e.g. '
                         'my.dogpile.proxy.Class, my.dogpile.proxyClass2.'),
        cfg.BoolOpt('enabled', default=False,
                    help='Global toggle for all caching using the '
                         'should_cache_fn mechanism.'),
        cfg.BoolOpt('debug_cache_backend', default=False,
                    help='Extra debugging from the cache backend (cache '
                         'keys, get/set/delete/etc calls) This is only '
                         'really useful if you need to see the specific '
                         'cache-backend get/set/delete calls with the '
                         'keys/values.  Typically this should be left set '
                         'to False.')],
    'ssl': [
        cfg.BoolOpt('enable', default=False,
                    help='Toggle for SSL support on the keystone '
                         'eventlet servers.'),
        cfg.StrOpt('certfile',
                   default="/etc/keystone/ssl/certs/keystone.pem",
                   help='Path of the certfile for SSL.'),
        cfg.StrOpt('keyfile',
                   default='/etc/keystone/ssl/private/keystonekey.pem',
                   help='Path of the keyfile for SSL.'),
        cfg.StrOpt('ca_certs',
                   default='/etc/keystone/ssl/certs/ca.pem',
                   help='Path of the ca cert file for SSL.'),
        cfg.StrOpt('ca_key',
                   default='/etc/keystone/ssl/private/cakey.pem',
                   help='Path of the CA key file for SSL.'),
        cfg.BoolOpt('cert_required', default=False,
                    help='Require client certificate.'),
        cfg.IntOpt('key_size', default=1024,
                   help='SSL Key Length (in bits) (auto generated '
                        'certificate).'),
        cfg.IntOpt('valid_days', default=3650,
                   help='Days the certificate is valid for once signed '
                        '(auto generated certificate).'),
        cfg.StrOpt('cert_subject',
                   default='/C=US/ST=Unset/L=Unset/O=Unset/CN=localhost',
                   help='SSL Certificate Subject (auto generated '
                        'certificate).')],
    'signing': [
        cfg.StrOpt('token_format', default=None,
                   help='Deprecated in favor of provider in the '
                        '[token] section.'),
        cfg.StrOpt('certfile',
                   default='/etc/keystone/ssl/certs/signing_cert.pem',
                   help='Path of the certfile for token signing.'),
        cfg.StrOpt('keyfile',
                   default='/etc/keystone/ssl/private/signing_key.pem',
                   help='Path of the keyfile for token signing.'),
        cfg.StrOpt('ca_certs',
                   default='/etc/keystone/ssl/certs/ca.pem',
                   help='Path of the CA for token signing.'),
        cfg.StrOpt('ca_key',
                   default='/etc/keystone/ssl/private/cakey.pem',
                   help='Path of the CA Key for token signing.'),
        cfg.IntOpt('key_size', default=2048,
                   help='Key Size (in bits) for token signing cert '
                        '(auto generated certificate).'),
        cfg.IntOpt('valid_days', default=3650,
                   help='Day the token signing cert is valid for '
                        '(auto generated certificate).'),
        cfg.StrOpt('cert_subject',
                   default=('/C=US/ST=Unset/L=Unset/O=Unset/'
                            'CN=www.example.com'),
                   help='Certificate Subject (auto generated certificate) for '
                        'token signing.')],
    'assignment': [
        # assignment has no default for backward compatibility reasons.
        # If assignment driver is not specified, the identity driver chooses
        # the backend
        cfg.StrOpt('driver', default=None,
                   help='Keystone Assignment backend driver.'),
        cfg.BoolOpt('caching', default=True,
                    help='Toggle for assignment caching. This has no effect '
                         'unless global caching is enabled.'),
        cfg.IntOpt('cache_time', default=None,
                   help='TTL (in seconds) to cache assignment data. This has '
                        'no effect unless global caching is enabled.'),
        cfg.IntOpt('list_limit', default=None,
                   help='Maximum number of entities that will be returned '
                        'in an assignment collection.')],
    'credential': [
        cfg.StrOpt('driver',
                   default=('keystone.credential.backends'
                            '.sql.Credential'),
                   help='Keystone Credential backend driver.')],
    'oauth1': [
        cfg.StrOpt('driver',
                   default='keystone.contrib.oauth1.backends.sql.OAuth1',
                   help='Keystone Credential backend driver.'),
        cfg.IntOpt('request_token_duration', default=28800,
                   help='Duration (in seconds) for the OAuth Request Token.'),
        cfg.IntOpt('access_token_duration', default=86400,
                   help='Duration (in seconds) for the OAuth Access Token.')],

    'federation': [
        cfg.StrOpt('driver',
                   default='keystone.contrib.federation.'
                           'backends.sql.Federation',
                   help='Keystone Federation backend driver.'),
        cfg.StrOpt('assertion_prefix', default='',
                   help='Value to be used when filtering assertion parameters '
                        'from the environment.')],

    'policy': [
        cfg.StrOpt('driver',
                   default='keystone.policy.backends.sql.Policy',
                   help='Keystone Policy backend driver.'),
        cfg.IntOpt('list_limit', default=None,
                   help='Maximum number of entities that will be returned '
                        'in a policy collection.')],
    'ec2': [
        cfg.StrOpt('driver',
                   default='keystone.contrib.ec2.backends.kvs.Ec2',
                   help='Keystone EC2Credential backend driver.')],
    'endpoint_filter': [
        cfg.StrOpt('driver',
                   default='keystone.contrib.endpoint_filter.backends'
                           '.sql.EndpointFilter',
                   help='Keystone Endpoint Filter backend driver'),
        cfg.BoolOpt('return_all_endpoints_if_no_filter', default=True,
                    help='Toggle to return all active endpoints if no filter '
                         'exists.')],
    'stats': [
        cfg.StrOpt('driver',
                   default=('keystone.contrib.stats.backends'
                            '.kvs.Stats'),
                   help='Keystone stats backend driver.')],
    'ldap': [
        cfg.StrOpt('url', default='ldap://localhost',
                   help='URL for connecting to the LDAP server.'),
        cfg.StrOpt('user', default=None,
                   help='User BindDN to query the LDAP server.'),
        cfg.StrOpt('password', secret=True, default=None,
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
                    help='allow deleting subtrees.'),
        cfg.StrOpt('query_scope', default='one',
                   help='The LDAP scope for queries, this can be either '
                        '"one" (onelevel/singleLevel) or "sub" '
                        '(subtree/wholeSubtree).'),
        cfg.IntOpt('page_size', default=0,
                   help='Maximum results per page; a value of zero ("0") '
                        'disables paging.'),
        cfg.StrOpt('alias_dereferencing', default='default',
                   help='The LDAP dereferencing option for queries. This '
                        'can be either "never", "searching", "always", '
                        '"finding" or "default". The "default" option falls '
                        'back to using default dereferencing configured by '
                        'your ldap.conf.'),
        cfg.BoolOpt('chase_referrals', default=None,
                    help='Override the system\'s default referral chasing '
                         'behavior for queries.'),
        cfg.StrOpt('user_tree_dn', default=None,
                   help='Search base for users.'),
        cfg.StrOpt('user_filter', default=None,
                   help='LDAP search filter for users.'),
        cfg.StrOpt('user_objectclass', default='inetOrgPerson',
                   help='LDAP objectClass for users.'),
        cfg.StrOpt('user_id_attribute', default='cn',
                   help='LDAP attribute mapped to user id.'),
        cfg.StrOpt('user_name_attribute', default='sn',
                   help='LDAP attribute mapped to user name.'),
        cfg.StrOpt('user_mail_attribute', default='email',
                   help='LDAP attribute mapped to user email.'),
        cfg.StrOpt('user_pass_attribute', default='userPassword',
                   help='LDAP attribute mapped to password.'),
        cfg.StrOpt('user_enabled_attribute', default='enabled',
                   help='LDAP attribute mapped to user enabled flag.'),
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
                        'is enabled or disabled. If this is not set to "True"'
                        'the typical value is "512". This is typically used '
                        'when "user_enabled_attribute = userAccountControl".'),
        cfg.ListOpt('user_attribute_ignore',
                    default=['default_project_id', 'tenants'],
                    help='List of attributes stripped off the user on '
                         'update.'),
        cfg.StrOpt('user_default_project_id_attribute', default=None,
                   help='LDAP attribute mapped to default_project_id for '
                        'users.'),
        cfg.BoolOpt('user_allow_create', default=True,
                    help='Allow user creation in LDAP backend.'),
        cfg.BoolOpt('user_allow_update', default=True,
                    help='Allow user updates in LDAP backend.'),
        cfg.BoolOpt('user_allow_delete', default=True,
                    help='Allow user deletion in LDAP backend.'),
        cfg.BoolOpt('user_enabled_emulation', default=False,
                    help='If True, Keystone uses an alternative method to '
                         'determine if a user is enabled or not by checking '
                         'if they are a member of the '
                         '"user_enabled_emulation_dn" group.'),
        cfg.StrOpt('user_enabled_emulation_dn', default=None,
                   help='DN of the group entry to hold enabled users when '
                        'using enabled emulation.'),
        cfg.ListOpt('user_additional_attribute_mapping',
                    default=[],
                    help='List of additional LDAP attributes used for mapping '
                         'Additional attribute mappings for users. Attribute '
                         'mapping format is <ldap_attr>:<user_attr>, where '
                         'ldap_attr is the attribute in the LDAP entry and '
                         'user_attr is the Identity API attribute.'),

        cfg.StrOpt('tenant_tree_dn', default=None,
                   help='Search base for projects'),
        cfg.StrOpt('tenant_filter', default=None,
                   help='LDAP search filter for projects.'),
        cfg.StrOpt('tenant_objectclass', default='groupOfNames',
                   help='LDAP objectClass for projects.'),
        cfg.StrOpt('tenant_id_attribute', default='cn',
                   help='LDAP attribute mapped to project id.'),
        cfg.StrOpt('tenant_member_attribute', default='member',
                   help='LDAP attribute mapped to project membership for '
                        'user.'),
        cfg.StrOpt('tenant_name_attribute', default='ou',
                   help='LDAP attribute mapped to project name.'),
        cfg.StrOpt('tenant_desc_attribute', default='description',
                   help='LDAP attribute mapped to project description.'),
        cfg.StrOpt('tenant_enabled_attribute', default='enabled',
                   help='LDAP attribute mapped to project enabled.'),
        cfg.StrOpt('tenant_domain_id_attribute',
                   default='businessCategory',
                   help='LDAP attribute mapped to project domain_id.'),
        cfg.ListOpt('tenant_attribute_ignore', default=[],
                    help='List of attributes stripped off the project on '
                         'update.'),
        cfg.BoolOpt('tenant_allow_create', default=True,
                    help='Allow tenant creation in LDAP backend.'),
        cfg.BoolOpt('tenant_allow_update', default=True,
                    help='Allow tenant update in LDAP backend.'),
        cfg.BoolOpt('tenant_allow_delete', default=True,
                    help='Allow tenant deletion in LDAP backend.'),
        cfg.BoolOpt('tenant_enabled_emulation', default=False,
                    help='If True, Keystone uses an alternative method to '
                         'determine if a project is enabled or not by '
                         'checking if they are a member of the '
                         '"tenant_enabled_emulation_dn" group.'),
        cfg.StrOpt('tenant_enabled_emulation_dn', default=None,
                   help='DN of the group entry to hold enabled projects when '
                        'using enabled emulation.'),
        cfg.ListOpt('tenant_additional_attribute_mapping',
                    default=[],
                    help='Additional attribute mappings for projects. '
                         'Attribute mapping format is '
                         '<ldap_attr>:<user_attr>, where ldap_attr is the '
                         'attribute in the LDAP entry and user_attr is the '
                         'Identity API attribute.'),

        cfg.StrOpt('role_tree_dn', default=None,
                   help='Search base for roles.'),
        cfg.StrOpt('role_filter', default=None,
                   help='LDAP search filter for roles.'),
        cfg.StrOpt('role_objectclass', default='organizationalRole',
                   help='LDAP objectClass for roles.'),
        cfg.StrOpt('role_id_attribute', default='cn',
                   help='LDAP attribute mapped to role id.'),
        cfg.StrOpt('role_name_attribute', default='ou',
                   help='LDAP attribute mapped to role name.'),
        cfg.StrOpt('role_member_attribute', default='roleOccupant',
                   help='LDAP attribute mapped to role membership.'),
        cfg.ListOpt('role_attribute_ignore', default=[],
                    help='List of attributes stripped off the role on '
                         'update.'),
        cfg.BoolOpt('role_allow_create', default=True,
                    help='Allow role creation in LDAP backend.'),
        cfg.BoolOpt('role_allow_update', default=True,
                    help='Allow role update in LDAP backend.'),
        cfg.BoolOpt('role_allow_delete', default=True,
                    help='Allow role deletion in LDAP backend.'),
        cfg.ListOpt('role_additional_attribute_mapping',
                    default=[],
                    help='Additional attribute mappings for roles. Attribute '
                         'mapping format is <ldap_attr>:<user_attr>, where '
                         'ldap_attr is the attribute in the LDAP entry and '
                         'user_attr is the Identity API attribute.'),

        cfg.StrOpt('group_tree_dn', default=None,
                   help='Search base for groups.'),
        cfg.StrOpt('group_filter', default=None,
                   help='LDAP search filter for groups.'),
        cfg.StrOpt('group_objectclass', default='groupOfNames',
                   help='LDAP objectClass for groups.'),
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
                    help='Allow group creation in LDAP backend.'),
        cfg.BoolOpt('group_allow_update', default=True,
                    help='Allow group update in LDAP backend.'),
        cfg.BoolOpt('group_allow_delete', default=True,
                    help='Allow group deletion in LDAP backend.'),
        cfg.ListOpt('group_additional_attribute_mapping',
                    default=[],
                    help='Additional attribute mappings for groups. Attribute '
                         'mapping format is <ldap_attr>:<user_attr>, where '
                         'ldap_attr is the attribute in the LDAP entry and '
                         'user_attr is the Identity API attribute.'),

        cfg.StrOpt('tls_cacertfile', default=None,
                   help='CA certificate file path for communicating with '
                        'LDAP servers.'),
        cfg.StrOpt('tls_cacertdir', default=None,
                   help='CA certificate directory path for communicating with '
                        'LDAP servers.'),
        cfg.BoolOpt('use_tls', default=False,
                    help='Enable TLS for communicating with LDAP servers.'),
        cfg.StrOpt('tls_req_cert', default='demand',
                   help='valid options for tls_req_cert are demand, never, '
                        'and allow.')],
    'auth': [
        cfg.ListOpt('methods', default=_DEFAULT_AUTH_METHODS,
                    help='Default auth methods.'),
        cfg.StrOpt('password',
                   default='keystone.auth.plugins.password.Password',
                   help='The password auth plugin module.'),
        cfg.StrOpt('token',
                   default='keystone.auth.plugins.token.Token',
                   help='The token auth plugin module.'),
        #deals with REMOTE_USER authentication
        cfg.StrOpt('external',
                   default='keystone.auth.plugins.external.DefaultDomain',
                   help='The external (REMOTE_USER) auth plugin module.')],
    'paste_deploy': [
        cfg.StrOpt('config_file', default='keystone-paste.ini',
                   help='Name of the paste configuration file that defines '
                        'the available pipelines.')],
    'memcache': [
        cfg.ListOpt('servers', default=['localhost:11211'],
                    help='Memcache servers in the format of "host:port"'),
        cfg.IntOpt('max_compare_and_set_retry', default=16,
                   help='Number of compare-and-set attempts to make when '
                        'using compare-and-set in the token memcache back '
                        'end.')],
    'catalog': [
        cfg.StrOpt('template_file',
                   default='default_catalog.templates',
                   help='Catalog template file name for use with the '
                        'template catalog backend.'),
        cfg.StrOpt('driver',
                   default='keystone.catalog.backends.sql.Catalog',
                   help='Keystone catalog backend driver.'),
        cfg.IntOpt('list_limit', default=None,
                   help='Maximum number of entities that will be returned '
                        'in a catalog collection.'),
        cfg.ListOpt('endpoint_substitution_whitelist',
                    default=['tenant_id', 'user_id', 'public_bind_host',
                             'admin_bind_host', 'compute_host', 'compute_port',
                             'admin_port', 'public_port', 'public_endpoint',
                             'admin_endpoint'],
                    help='List of possible substitutions for use in '
                         'formatting endpoints. Use caution when modifying '
                         'this list. It will give users with permission to '
                         'create endpoints the ability to see those values '
                         'in your configuration file.')],
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
                         'to always leave this set to True.'),
        cfg.IntOpt('default_lock_timeout', default=5,
                   help='Default lock timeout for distributed locking.')]}


CONF = cfg.CONF


def setup_authentication(conf=None):
    # register any non-default auth methods here (used by extensions, etc)
    if conf is None:
        conf = CONF
    for method_name in conf.auth.methods:
        if method_name not in _DEFAULT_AUTH_METHODS:
            conf.register_opt(cfg.StrOpt(method_name), group='auth')


def configure(conf=None):
    if conf is None:
        conf = CONF

    conf.register_cli_opt(
        cfg.BoolOpt('standard-threads', default=False,
                    help='Do not monkey-patch threading system modules.'))
    conf.register_cli_opt(
        cfg.StrOpt('pydev-debug-host', default=None,
                   help='Host to connect to for remote debugger.'))
    conf.register_cli_opt(
        cfg.IntOpt('pydev-debug-port', default=None,
                   help='Port to connect to for remote debugger.'))

    for section in FILE_OPTIONS:
        for option in FILE_OPTIONS[section]:
            if section:
                conf.register_opt(option, group=section)
            else:
                conf.register_opt(option)

    # register any non-default auth methods here (used by extensions, etc)
    setup_authentication(conf)


def list_opts():
    """Return a list of oslo.config options available in Keystone.

    The returned list includes all oslo.config options which are registered as
    the "FILE_OPTIONS" in keystone.common.config. This list will not include
    the options from the oslo-incubator library or any options registered
    dynamically at run time.

    Each object in the list is a two element tuple. The first element of
    each tuple is the name of the group under which the list of options in the
    second element will be registered. A group name of None corresponds to the
    [DEFAULT] group in config files.

    This function is also discoverable via the 'oslo.config.opts' entry point
    under the 'keystone.config.opts' namespace.

    The purpose of this is to allow tools like the Oslo sample config file
    generator to discover the options exposed to users by this library.

    :returns: a list of (group_name, opts) tuples
    """
    return FILE_OPTIONS.items()
