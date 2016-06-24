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
The list of trusted issuers to further filter the certificates that are allowed
to participate in the X.509 tokenless authorization. If the option is absent
then no certificates will be allowed. The naming format for the attributes of a
Distinguished Name(DN) must be separated by a comma and contain no spaces. This
configuration option may be repeated for multiple values. For example:
trusted_issuer=CN=john,OU=keystone,O=openstack
trusted_issuer=CN=mary,OU=eng,O=abc
"""))

protocol = cfg.StrOpt(
    'protocol',
    default='x509',
    help=utils.fmt("""
The protocol name for the X.509 tokenless authorization along with the option
issuer_attribute below can look up its corresponding mapping.
"""))

issuer_attribute = cfg.StrOpt(
    'issuer_attribute',
    default='SSL_CLIENT_I_DN',
    help=utils.fmt("""
The issuer attribute that is served as an IdP ID for the X.509 tokenless
authorization along with the protocol to look up its corresponding mapping. It
is the environment variable in the WSGI environment that references to the
issuer of the client certificate.
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
