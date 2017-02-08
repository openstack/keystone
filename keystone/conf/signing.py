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
from oslo_log import versionutils

from keystone.conf import constants
from keystone.conf import utils


_DEPRECATED_MSG = utils.fmt("""
`keystone-manage pki_setup` was deprecated in Mitaka and removed in Pike.
These options remain for backwards compatibility.
""")

certfile = cfg.StrOpt(
    'certfile',
    default=constants._CERTFILE,
    deprecated_for_removal=True,
    deprecated_reason=_DEPRECATED_MSG,
    deprecated_since=versionutils.deprecated.PIKE,
    help=utils.fmt("""
Absolute path to the public certificate file to use for signing responses to
revocation lists requests. Set this together with `[signing] keyfile`. For
non-production environments, you may be interested in using `keystone-manage
pki_setup` to generate self-signed certificates.
"""))

keyfile = cfg.StrOpt(
    'keyfile',
    default=constants._KEYFILE,
    deprecated_for_removal=True,
    deprecated_reason=_DEPRECATED_MSG,
    deprecated_since=versionutils.deprecated.PIKE,
    help=utils.fmt("""
Absolute path to the private key file to use for signing responses to
revocation lists requests. Set this together with `[signing] certfile`.
"""))

ca_certs = cfg.StrOpt(
    'ca_certs',
    deprecated_for_removal=True,
    deprecated_reason=_DEPRECATED_MSG,
    deprecated_since=versionutils.deprecated.PIKE,
    default='/etc/keystone/ssl/certs/ca.pem',
    help=utils.fmt("""
Absolute path to the public certificate authority (CA) file to use when
creating self-signed certificates with `keystone-manage pki_setup`. Set this
together with `[signing] ca_key`. There is no reason to set this option unless
you are requesting revocation lists in a non-production environment. Use a
`[signing] certfile` issued from a trusted certificate authority instead.
"""))

ca_key = cfg.StrOpt(
    'ca_key',
    default='/etc/keystone/ssl/private/cakey.pem',
    deprecated_for_removal=True,
    deprecated_reason=_DEPRECATED_MSG,
    deprecated_since=versionutils.deprecated.PIKE,
    help=utils.fmt("""
Absolute path to the private certificate authority (CA) key file to use when
creating self-signed certificates with `keystone-manage pki_setup`. Set this
together with `[signing] ca_certs`. There is no reason to set this option
unless you are requesting revocation lists in a non-production environment.
Use a `[signing] certfile` issued from a trusted certificate authority instead.
"""))

key_size = cfg.IntOpt(
    'key_size',
    default=2048,
    min=1024,
    deprecated_for_removal=True,
    deprecated_reason=_DEPRECATED_MSG,
    deprecated_since=versionutils.deprecated.PIKE,
    help=utils.fmt("""
Key size (in bits) to use when generating a self-signed token signing
certificate. There is no reason to set this option unless you are requesting
revocation lists in a non-production environment. Use a `[signing] certfile`
issued from a trusted certificate authority instead.
"""))

valid_days = cfg.IntOpt(
    'valid_days',
    default=3650,
    deprecated_for_removal=True,
    deprecated_reason=_DEPRECATED_MSG,
    deprecated_since=versionutils.deprecated.PIKE,
    help=utils.fmt("""
The validity period (in days) to use when generating a self-signed token
signing certificate. There is no reason to set this option unless you are
requesting revocation lists in a non-production environment. Use a
`[signing] certfile` issued from a trusted certificate authority instead.
"""))

cert_subject = cfg.StrOpt(
    'cert_subject',
    default=('/C=US/ST=Unset/L=Unset/O=Unset/CN=www.example.com'),
    deprecated_for_removal=True,
    deprecated_reason=_DEPRECATED_MSG,
    deprecated_since=versionutils.deprecated.PIKE,
    help=utils.fmt("""
The certificate subject to use when generating a self-signed token signing
certificate. There is no reason to set this option unless you are requesting
revocation lists in a non-production environment. Use a
`[signing] certfile` issued from a trusted certificate authority instead.
"""))


GROUP_NAME = __name__.split('.')[-1]
ALL_OPTS = [
    certfile,
    keyfile,
    ca_certs,
    ca_key,
    key_size,
    valid_days,
    cert_subject,
]


def register_opts(conf):
    conf.register_opts(ALL_OPTS, group=GROUP_NAME)


def list_opts():
    return {GROUP_NAME: ALL_OPTS}
