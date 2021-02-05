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

from oslo_cache import core as cache
from oslo_config import cfg
from oslo_log import log
from oslo_log import versionutils
import oslo_messaging
from oslo_middleware import cors
from oslo_policy import opts as policy_opts
from osprofiler import opts as profiler

from keystone.conf import application_credential
from keystone.conf import assignment
from keystone.conf import auth
from keystone.conf import catalog
from keystone.conf import credential
from keystone.conf import default
from keystone.conf import domain_config
from keystone.conf import endpoint_filter
from keystone.conf import endpoint_policy
from keystone.conf import eventlet_server
from keystone.conf import federation
from keystone.conf import fernet_receipts
from keystone.conf import fernet_tokens
from keystone.conf import identity
from keystone.conf import identity_mapping
from keystone.conf import jwt_tokens
from keystone.conf import ldap
from keystone.conf import memcache
from keystone.conf import oauth1
from keystone.conf import policy
from keystone.conf import receipt
from keystone.conf import resource
from keystone.conf import revoke
from keystone.conf import role
from keystone.conf import saml
from keystone.conf import security_compliance
from keystone.conf import shadow_users
from keystone.conf import token
from keystone.conf import tokenless_auth
from keystone.conf import totp
from keystone.conf import trust
from keystone.conf import unified_limit
from keystone.conf import wsgi

CONF = cfg.CONF


conf_modules = [
    application_credential,
    assignment,
    auth,
    catalog,
    credential,
    default,
    domain_config,
    endpoint_filter,
    endpoint_policy,
    eventlet_server,
    federation,
    fernet_receipts,
    fernet_tokens,
    identity,
    identity_mapping,
    jwt_tokens,
    ldap,
    memcache,
    oauth1,
    policy,
    receipt,
    resource,
    revoke,
    role,
    saml,
    security_compliance,
    shadow_users,
    token,
    tokenless_auth,
    totp,
    trust,
    unified_limit,
    wsgi
]


oslo_messaging.set_transport_defaults(control_exchange='keystone')
_DEPRECATED_REASON = ('This option is only used by eventlet mode which has '
                      'been removed from Keystone in Newton release.')


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


def configure(conf=None):
    if conf is None:
        conf = CONF

    conf.register_cli_opt(
        cfg.BoolOpt('standard-threads', default=False,
                    help='Do not monkey-patch threading system modules.',
                    deprecated_for_removal=True,
                    deprecated_reason=_DEPRECATED_REASON,
                    deprecated_since=versionutils.deprecated.STEIN))
    conf.register_cli_opt(
        cfg.StrOpt('pydev-debug-host',
                   help='Host to connect to for remote debugger.',
                   deprecated_for_removal=True,
                   deprecated_reason=_DEPRECATED_REASON,
                   deprecated_since=versionutils.deprecated.STEIN))
    conf.register_cli_opt(
        cfg.PortOpt('pydev-debug-port',
                    help='Port to connect to for remote debugger.',
                    deprecated_for_removal=True,
                    deprecated_reason=_DEPRECATED_REASON,
                    deprecated_since=versionutils.deprecated.STEIN))

    for module in conf_modules:
        module.register_opts(conf)

    # register any non-default auth methods here (used by extensions, etc)
    auth.setup_authentication()

    # add oslo.cache related config options
    cache.configure(conf)


def set_external_opts_defaults():
    """Update default configuration options for oslo.middleware."""
    cors.set_defaults(
        allow_headers=['X-Auth-Token',
                       'X-Openstack-Request-Id',
                       'X-Subject-Token',
                       'X-Project-Id',
                       'X-Project-Name',
                       'X-Project-Domain-Id',
                       'X-Project-Domain-Name',
                       'X-Domain-Id',
                       'X-Domain-Name',
                       'Openstack-Auth-Receipt'],
        expose_headers=['X-Auth-Token',
                        'X-Openstack-Request-Id',
                        'X-Subject-Token',
                        'Openstack-Auth-Receipt'],
        allow_methods=['GET',
                       'PUT',
                       'POST',
                       'DELETE',
                       'PATCH']
    )

    # configure OSprofiler options
    profiler.set_defaults(CONF, enabled=False, trace_sqlalchemy=False)

    # TODO(gmann): Remove setting the default value of config policy_file
    # once oslo_policy change the default value to 'policy.yaml'.
    # https://github.com/openstack/oslo.policy/blob/a626ad12fe5a3abd49d70e3e5b95589d279ab578/oslo_policy/opts.py#L49
    DEFAULT_POLICY_FILE = 'policy.yaml'
    policy_opts.set_defaults(cfg.CONF, DEFAULT_POLICY_FILE)

    # Oslo.cache is always enabled by default for request-local caching
    # TODO(morganfainberg): Fix this to not use internal interface when
    # oslo.cache has proper interface to set defaults added. This is
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
