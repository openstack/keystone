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

from keystone.conf import constants
from keystone.conf import utils


methods = cfg.ListOpt(
    'methods',
    default=constants._DEFAULT_AUTH_METHODS,
    help=utils.fmt("""
Allowed authentication methods. Note: You should disable the `external` auth
method if you are currently using federation. External auth and federation
both use the REMOTE_USER variable. Since both the mapped and external plugin
are being invoked to validate attributes in the request environment, it can
cause conflicts.
"""))

password = cfg.StrOpt(  # nosec : This is the name of the plugin, not
    'password',         # a password that needs to be protected.
    help=utils.fmt("""
Entry point for the password auth plugin module in the `keystone.auth.password`
namespace. You do not need to set this unless you are overriding keystone's own
password authentication plugin.
"""))

token = cfg.StrOpt(
    'token',
    help=utils.fmt("""
Entry point for the token auth plugin module in the `keystone.auth.token`
namespace. You do not need to set this unless you are overriding keystone's own
token authentication plugin.
"""))

# deals with REMOTE_USER authentication
external = cfg.StrOpt(
    'external',
    help=utils.fmt("""
Entry point for the external (`REMOTE_USER`) auth plugin module in the
`keystone.auth.external` namespace. Supplied drivers are `DefaultDomain` and
`Domain`. The default driver is `DefaultDomain`, which assumes that all users
identified by the username specified to keystone in the `REMOTE_USER` variable
exist within the context of the default domain. The `Domain` option expects an
additional environment variable be presented to keystone, `REMOTE_DOMAIN`,
containing the domain name of the `REMOTE_USER` (if `REMOTE_DOMAIN` is not set,
then the default domain will be used instead). You do not need to set this
unless you are taking advantage of "external authentication", where the
application server (such as Apache) is handling authentication instead of
keystone.
"""))

oauth1 = cfg.StrOpt(
    'oauth1',
    help=utils.fmt("""
Entry point for the OAuth 1.0a auth plugin module in the `keystone.auth.oauth1`
namespace. You do not need to set this unless you are overriding keystone's own
`oauth1` authentication plugin.
"""))

mapped = cfg.StrOpt(
    'mapped',
    help=utils.fmt("""
Entry point for the mapped auth plugin module in the `keystone.auth.mapped`
namespace. You do not need to set this unless you are overriding keystone's own
`mapped` authentication plugin.
"""))

application_credential = cfg.StrOpt(
    'application_credential',
    help=utils.fmt("""
Entry point for the application_credential auth plugin module in the
`keystone.auth.application_credential` namespace. You do not need to set this
unless you are overriding keystone's own `application_credential`
authentication plugin.
"""))


GROUP_NAME = __name__.split('.')[-1]
ALL_OPTS = [
    methods,
    password,
    token,
    external,
    oauth1,
    mapped,
    application_credential,
]


def _register_auth_plugin_opt(conf, option):
    conf.register_opt(option, group=GROUP_NAME)


def setup_authentication(conf=None):
    """Register non-default auth methods (used by extensions, etc)."""
    # register any non-default auth methods here (used by extensions, etc)
    if conf is None:
        conf = cfg.CONF
    for method_name in conf.auth.methods:
        if method_name not in constants._DEFAULT_AUTH_METHODS:
            option = cfg.StrOpt(method_name)
            _register_auth_plugin_opt(conf, option)


def register_opts(conf):
    conf.register_opts(ALL_OPTS, group=GROUP_NAME)

    setup_authentication(conf)


def list_opts():
    return {GROUP_NAME: ALL_OPTS}
