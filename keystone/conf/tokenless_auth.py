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


trusted_issuer = cfg.MultiStrOpt(
    'trusted_issuer',
    default=[],
    help=utils.fmt("""
The list of distinguished names which identify trusted issuers of client
certificates allowed to use X.509 tokenless authorization. If the option is
absent then no certificates will be allowed. The format for the values of a
distinguished name (DN) must be separated by a comma and contain no spaces.
Furthermore, because an individual DN may contain commas, this configuration
option may be repeated multiple times to represent multiple values. For
example, keystone.conf would include two consecutive lines in order to trust
two different DNs, such as `trusted_issuer = CN=john,OU=keystone,O=openstack`
and `trusted_issuer = CN=mary,OU=eng,O=abc`.
"""))

protocol = cfg.StrOpt(
    'protocol',
    default='x509',
    help=utils.fmt("""
The federated protocol ID used to represent X.509 tokenless authorization. This
is used in combination with the value of `[tokenless_auth] issuer_attribute` to
find a corresponding federated mapping. In a typical deployment, there is no
reason to change this value.
"""))

issuer_attribute = cfg.StrOpt(
    'issuer_attribute',
    default='SSL_CLIENT_I_DN',
    help=utils.fmt("""
The name of the WSGI environment variable used to pass the issuer of the client
certificate to keystone. This attribute is used as an identity provider ID
for the X.509 tokenless authorization along with the protocol to look up its
corresponding mapping. In a typical deployment, there is no reason to change
this value.
"""))


GROUP_NAME = __name__.split('.')[-1]
ALL_OPTS = [
    trusted_issuer,
    protocol,
    issuer_attribute,
]


def register_opts(conf):
    conf.register_opts(ALL_OPTS, group=GROUP_NAME)


def list_opts():
    return {GROUP_NAME: ALL_OPTS}
