# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

from keystone.openstack.common import log as logging


_DEFAULT_LOG_FORMAT = "%(asctime)s %(levelname)8s [%(name)s] %(message)s"
_DEFAULT_LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
_DEFAULT_AUTH_METHODS = ['external', 'password', 'token']


FILE_OPTIONS = {
    '': [
        cfg.StrOpt('admin_token', secret=True, default='ADMIN'),
        cfg.StrOpt('bind_host', default='0.0.0.0'),
        cfg.IntOpt('compute_port', default=8774),
        cfg.IntOpt('admin_port', default=35357),
        cfg.IntOpt('public_port', default=5000),
        cfg.StrOpt('public_endpoint',
                   default='http://localhost:%(public_port)s/'),
        cfg.StrOpt('admin_endpoint',
                   default='http://localhost:%(admin_port)s/'),
        cfg.StrOpt('onready'),
        cfg.StrOpt('auth_admin_prefix', default=''),
        # default max request size is 112k
        cfg.IntOpt('max_request_body_size', default=114688),
        cfg.IntOpt('max_param_size', default=64),
        # we allow tokens to be a bit larger to accommodate PKI
        cfg.IntOpt('max_token_size', default=8192),
        cfg.StrOpt('member_role_id',
                   default='9fe2ff9ee4384b1894a90878d3e92bab'),
        cfg.StrOpt('member_role_name', default='_member_'),
        cfg.IntOpt('crypt_strength', default=40000)],
    'identity': [
        cfg.StrOpt('default_domain_id', default='default'),
        cfg.BoolOpt('domain_specific_drivers_enabled',
                    default=False),
        cfg.StrOpt('domain_config_dir',
                   default='/etc/keystone/domains'),
        cfg.StrOpt('driver',
                   default=('keystone.identity.backends'
                            '.sql.Identity')),
        cfg.IntOpt('max_password_length', default=4096)],
    'trust': [
        cfg.BoolOpt('enabled', default=True),
        cfg.StrOpt('driver',
                   default='keystone.trust.backends.sql.Trust')],
    'os_inherit': [
        cfg.BoolOpt('enabled', default=False)],
    'token': [
        cfg.ListOpt('bind', default=[]),
        cfg.StrOpt('enforce_token_bind', default='permissive'),
        cfg.IntOpt('expiration', default=86400),
        cfg.StrOpt('provider', default=None),
        cfg.StrOpt('driver',
                   default='keystone.token.backends.sql.Token'),
        cfg.BoolOpt('caching', default=True),
        cfg.IntOpt('revocation_cache_time', default=3600),
        cfg.IntOpt('cache_time', default=None)],
    'cache': [
        cfg.StrOpt('config_prefix', default='cache.keystone'),
        cfg.IntOpt('expiration_time', default=600),
        # NOTE(morganfainberg): the dogpile.cache.memory acceptable in devstack
        # and other such single-process/thread deployments. Running
        # dogpile.cache.memory in any other configuration has the same pitfalls
        # as the KVS token backend. It is recommended that either Redis or
        # Memcached are used as the dogpile backend for real workloads. To
        # prevent issues with the memory cache ending up in "production"
        # unintentionally, we register a no-op as the keystone default caching
        # backend.
        cfg.StrOpt('backend', default='keystone.common.cache.noop'),
        cfg.BoolOpt('use_key_mangler', default=True),
        cfg.MultiStrOpt('backend_argument', default=[]),
        cfg.ListOpt('proxies', default=[]),
        # Global toggle for all caching using the should_cache_fn mechanism.
        cfg.BoolOpt('enabled', default=False),
        # caching backend specific debugging.
        cfg.BoolOpt('debug_cache_backend', default=False)],
    'ssl': [
        cfg.BoolOpt('enable', default=False),
        cfg.StrOpt('certfile',
                   default="/etc/keystone/ssl/certs/keystone.pem"),
        cfg.StrOpt('keyfile',
                   default="/etc/keystone/ssl/private/keystonekey.pem"),
        cfg.StrOpt('ca_certs',
                   default="/etc/keystone/ssl/certs/ca.pem"),
        cfg.StrOpt('ca_key',
                   default="/etc/keystone/ssl/certs/cakey.pem"),
        cfg.BoolOpt('cert_required', default=False),
        cfg.IntOpt('key_size', default=1024),
        cfg.IntOpt('valid_days', default=3650),
        cfg.StrOpt('cert_subject',
                   default='/C=US/ST=Unset/L=Unset/O=Unset/CN=localhost')],
    'signing': [
        cfg.StrOpt('token_format', default=None),
        cfg.StrOpt('certfile',
                   default="/etc/keystone/ssl/certs/signing_cert.pem"),
        cfg.StrOpt('keyfile',
                   default="/etc/keystone/ssl/private/signing_key.pem"),
        cfg.StrOpt('ca_certs',
                   default="/etc/keystone/ssl/certs/ca.pem"),
        cfg.StrOpt('ca_key',
                   default="/etc/keystone/ssl/certs/cakey.pem"),
        cfg.IntOpt('key_size', default=2048),
        cfg.IntOpt('valid_days', default=3650),
        cfg.StrOpt('cert_subject',
                   default=('/C=US/ST=Unset/L=Unset/O=Unset/'
                            'CN=www.example.com'))],
    'sql': [
        cfg.StrOpt('connection', secret=True,
                   default='sqlite:///keystone.db'),
        cfg.IntOpt('idle_timeout', default=200)],
    'assignment': [
        # assignment has no default for backward compatibility reasons.
        # If assignment driver is not specified, the identity driver chooses
        # the backend
        cfg.StrOpt('driver', default=None),
        cfg.BoolOpt('caching', default=True),
        cfg.IntOpt('cache_time', default=None)],
    'credential': [
        cfg.StrOpt('driver',
                   default=('keystone.credential.backends'
                            '.sql.Credential'))],
    'oauth1': [
        cfg.StrOpt('driver',
                   default='keystone.contrib.oauth1.backends.sql.OAuth1'),
        cfg.IntOpt('request_token_duration', default=28800),
        cfg.IntOpt('access_token_duration', default=86400)],
    'policy': [
        cfg.StrOpt('driver',
                   default='keystone.policy.backends.sql.Policy')],
    'ec2': [
        cfg.StrOpt('driver',
                   default='keystone.contrib.ec2.backends.kvs.Ec2')],
    'endpoint_filter': [
        cfg.StrOpt('driver',
                   default='keystone.contrib.endpoint_filter.backends'
                           '.sql.EndpointFilter'),
        cfg.BoolOpt('return_all_endpoints_if_no_filter', default=True)],
    'stats': [
        cfg.StrOpt('driver',
                   default=('keystone.contrib.stats.backends'
                            '.kvs.Stats'))],
    'ldap': [
        cfg.StrOpt('url', default='ldap://localhost'),
        cfg.StrOpt('user', default=None),
        cfg.StrOpt('password', secret=True, default=None),
        cfg.StrOpt('suffix', default='cn=example,cn=com'),
        cfg.BoolOpt('use_dumb_member', default=False),
        cfg.StrOpt('dumb_member', default='cn=dumb,dc=nonexistent'),
        cfg.BoolOpt('allow_subtree_delete', default=False),
        cfg.StrOpt('query_scope', default='one'),
        cfg.IntOpt('page_size', default=0),
        cfg.StrOpt('alias_dereferencing', default='default'),

        cfg.StrOpt('user_tree_dn', default=None),
        cfg.StrOpt('user_filter', default=None),
        cfg.StrOpt('user_objectclass', default='inetOrgPerson'),
        cfg.StrOpt('user_id_attribute', default='cn'),
        cfg.StrOpt('user_name_attribute', default='sn'),
        cfg.StrOpt('user_mail_attribute', default='email'),
        cfg.StrOpt('user_pass_attribute', default='userPassword'),
        cfg.StrOpt('user_enabled_attribute', default='enabled'),
        cfg.IntOpt('user_enabled_mask', default=0),
        cfg.StrOpt('user_enabled_default', default='True'),
        cfg.ListOpt('user_attribute_ignore',
                    default='default_project_id,tenants'),
        cfg.StrOpt('user_default_project_id_attribute', default=None),
        cfg.BoolOpt('user_allow_create', default=True),
        cfg.BoolOpt('user_allow_update', default=True),
        cfg.BoolOpt('user_allow_delete', default=True),
        cfg.BoolOpt('user_enabled_emulation', default=False),
        cfg.StrOpt('user_enabled_emulation_dn', default=None),
        cfg.ListOpt('user_additional_attribute_mapping',
                    default=None),

        cfg.StrOpt('tenant_tree_dn', default=None),
        cfg.StrOpt('tenant_filter', default=None),
        cfg.StrOpt('tenant_objectclass', default='groupOfNames'),
        cfg.StrOpt('tenant_id_attribute', default='cn'),
        cfg.StrOpt('tenant_member_attribute', default='member'),
        cfg.StrOpt('tenant_name_attribute', default='ou'),
        cfg.StrOpt('tenant_desc_attribute', default='description'),
        cfg.StrOpt('tenant_enabled_attribute', default='enabled'),
        cfg.StrOpt('tenant_domain_id_attribute',
                   default='businessCategory'),
        cfg.ListOpt('tenant_attribute_ignore', default=''),
        cfg.BoolOpt('tenant_allow_create', default=True),
        cfg.BoolOpt('tenant_allow_update', default=True),
        cfg.BoolOpt('tenant_allow_delete', default=True),
        cfg.BoolOpt('tenant_enabled_emulation', default=False),
        cfg.StrOpt('tenant_enabled_emulation_dn', default=None),
        cfg.ListOpt('tenant_additional_attribute_mapping',
                    default=None),

        cfg.StrOpt('role_tree_dn', default=None),
        cfg.StrOpt('role_filter', default=None),
        cfg.StrOpt('role_objectclass', default='organizationalRole'),
        cfg.StrOpt('role_id_attribute', default='cn'),
        cfg.StrOpt('role_name_attribute', default='ou'),
        cfg.StrOpt('role_member_attribute', default='roleOccupant'),
        cfg.ListOpt('role_attribute_ignore', default=''),
        cfg.BoolOpt('role_allow_create', default=True),
        cfg.BoolOpt('role_allow_update', default=True),
        cfg.BoolOpt('role_allow_delete', default=True),
        cfg.ListOpt('role_additional_attribute_mapping',
                    default=None),

        cfg.StrOpt('group_tree_dn', default=None),
        cfg.StrOpt('group_filter', default=None),
        cfg.StrOpt('group_objectclass', default='groupOfNames'),
        cfg.StrOpt('group_id_attribute', default='cn'),
        cfg.StrOpt('group_name_attribute', default='ou'),
        cfg.StrOpt('group_member_attribute', default='member'),
        cfg.StrOpt('group_desc_attribute', default='description'),
        cfg.ListOpt('group_attribute_ignore', default=''),
        cfg.BoolOpt('group_allow_create', default=True),
        cfg.BoolOpt('group_allow_update', default=True),
        cfg.BoolOpt('group_allow_delete', default=True),
        cfg.ListOpt('group_additional_attribute_mapping',
                    default=None),

        cfg.StrOpt('tls_cacertfile', default=None),
        cfg.StrOpt('tls_cacertdir', default=None),
        cfg.BoolOpt('use_tls', default=False),
        cfg.StrOpt('tls_req_cert', default='demand')],
    'pam': [
        cfg.StrOpt('userid', default=None),
        cfg.StrOpt('password', default=None)],
    'auth': [
        cfg.ListOpt('methods', default=_DEFAULT_AUTH_METHODS),
        cfg.StrOpt('password',
                   default='keystone.auth.plugins.password.Password'),
        cfg.StrOpt('token',
                   default='keystone.auth.plugins.token.Token'),
        #deals with REMOTE_USER authentication
        cfg.StrOpt('external',
                   default='keystone.auth.plugins.external.ExternalDefault')],
    'paste_deploy': [
        cfg.StrOpt('config_file', default=None)],
    'memcache': [
        cfg.StrOpt('servers', default='localhost:11211'),
        cfg.IntOpt('max_compare_and_set_retry', default=16)],
    'catalog': [
        cfg.StrOpt('template_file',
                   default='default_catalog.templates'),
        cfg.StrOpt('driver',
                   default='keystone.catalog.backends.sql.Catalog')]}


CONF = cfg.CONF


def setup_logging(conf, product_name='keystone'):
    """Sets up the logging options for a log with supplied name

    :param conf: a cfg.ConfOpts object
    """
    # NOTE(ldbragst): This method will be removed along with other
    # refactoring in favor of using the
    # keystone/openstack/common/log.py implementation. This just ensures
    # that in the time between introduction and refactoring, we still have
    # a working logging implementation.
    logging.setup(product_name)


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
