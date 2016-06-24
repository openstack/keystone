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
Entrypoint for the federation backend driver in the keystone.federation
namespace.
"""))

assertion_prefix = cfg.StrOpt(
    'assertion_prefix',
    default='',
    help=utils.fmt("""
Value to be used when filtering assertion parameters from the environment.
"""))

remote_id_attribute = cfg.StrOpt(
    'remote_id_attribute',
    help=utils.fmt("""
Value to be used to obtain the entity ID of the Identity Provider from the
environment (e.g. if using the mod_shib plugin this value is
`Shib-Identity-Provider`).
"""))

federated_domain_name = cfg.StrOpt(
    'federated_domain_name',
    default='Federated',
    help=utils.fmt("""
A domain name that is reserved to allow federated ephemeral users to have a
domain concept. Note that an admin will not be able to create a domain with
this name or update an existing domain to this name. You are not advised to
change this value unless you really have to.
"""))

trusted_dashboard = cfg.MultiStrOpt(
    'trusted_dashboard',
    default=[],
    help=utils.fmt("""
A list of trusted dashboard hosts. Before accepting a Single Sign-On request to
return a token, the origin host must be a member of the trusted_dashboard list.
This configuration option may be repeated for multiple values. For example:
trusted_dashboard=http://acme.com/auth/websso
trusted_dashboard=http://beta.com/auth/websso
"""))

sso_callback_template = cfg.StrOpt(
    'sso_callback_template',
    default='/etc/keystone/sso_callback_template.html',
    help=utils.fmt("""
Location of Single Sign-On callback handler, will return a token to a trusted
dashboard host.
"""))


caching = cfg.BoolOpt(
    'caching',
    default=True,
    help=utils.fmt("""
Toggle for federation caching. This has no effect unless global caching is
enabled.
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
