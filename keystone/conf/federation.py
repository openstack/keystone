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


driver = cfg.StrOpt(
    'driver',
    default='sql',
    help=utils.fmt("""
Entry point for the federation backend driver in the `keystone.federation`
namespace. Keystone only provides a `sql` driver, so there is no reason to set
this option unless you are providing a custom entry point.
"""))

assertion_prefix = cfg.StrOpt(
    'assertion_prefix',
    default='',
    help=utils.fmt("""
Prefix to use when filtering environment variable names for federated
assertions. Matched variables are passed into the federated mapping engine.
"""))

remote_id_attribute = cfg.StrOpt(
    'remote_id_attribute',
    help=utils.fmt("""
Value to be used to obtain the entity ID of the Identity Provider from the
environment. For `mod_shib`, this would be `Shib-Identity-Provider`. For
`mod_auth_openidc`, this could be `HTTP_OIDC_ISS`. For `mod_auth_mellon`, this
could be `MELLON_IDP`.
"""))

federated_domain_name = cfg.StrOpt(
    'federated_domain_name',
    default='Federated',
    help=utils.fmt("""
An arbitrary domain name that is reserved to allow federated ephemeral users to
have a domain concept. Note that an admin will not be able to create a domain
with this name or update an existing domain to this name. You are not advised
to change this value unless you really have to.
"""))

trusted_dashboard = cfg.MultiStrOpt(
    'trusted_dashboard',
    default=[],
    help=utils.fmt("""
A list of trusted dashboard hosts. Before accepting a Single Sign-On request to
return a token, the origin host must be a member of this list. This
configuration option may be repeated for multiple values. You must set this in
order to use web-based SSO flows. For example:
trusted_dashboard=https://acme.example.com/auth/websso
trusted_dashboard=https://beta.example.com/auth/websso
"""))

sso_callback_template = cfg.StrOpt(
    'sso_callback_template',
    default='/etc/keystone/sso_callback_template.html',
    help=utils.fmt("""
Absolute path to an HTML file used as a Single Sign-On callback handler. This
page is expected to redirect the user from keystone back to a trusted dashboard
host, by form encoding a token in a POST request. Keystone's default value
should be sufficient for most deployments.
"""))


caching = cfg.BoolOpt(
    'caching',
    default=True,
    help=utils.fmt("""
Toggle for federation caching. This has no effect unless global caching is
enabled. There is typically no reason to disable this.
"""))


GROUP_NAME = __name__.split('.')[-1]
ALL_OPTS = [
    driver,
    assertion_prefix,
    remote_id_attribute,
    federated_domain_name,
    trusted_dashboard,
    sso_callback_template,
    caching,
]


def register_opts(conf):
    conf.register_opts(ALL_OPTS, group=GROUP_NAME)


def list_opts():
    return {GROUP_NAME: ALL_OPTS}
