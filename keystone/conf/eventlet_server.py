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

from keystone.conf import utils


_DEPRECATE_EVENTLET_MSG = utils.fmt("""
Support for running keystone under eventlet has been removed in the Newton
release. These options remain for backwards compatibility because they are used
for URL substitutions.
""")


public_bind_host = cfg.HostAddressOpt(
    'public_bind_host',
    default='0.0.0.0',  # nosec : Bind to all interfaces by default for
                        # backwards compatibility.
    deprecated_opts=[
        cfg.DeprecatedOpt('bind_host', group='DEFAULT'),
        cfg.DeprecatedOpt('public_bind_host', group='DEFAULT'),
    ],
    deprecated_for_removal=True,
    deprecated_reason=_DEPRECATE_EVENTLET_MSG,
    deprecated_since=versionutils.deprecated.KILO,
    help=utils.fmt("""
The IP address of the network interface for the public service to listen on.
"""))

public_port = cfg.PortOpt(
    'public_port',
    default=5000,
    deprecated_name='public_port',
    deprecated_group='DEFAULT',
    deprecated_for_removal=True,
    deprecated_reason=_DEPRECATE_EVENTLET_MSG,
    deprecated_since=versionutils.deprecated.KILO,
    help=utils.fmt("""
The port number for the public service to listen on.
"""))

admin_bind_host = cfg.HostAddressOpt(
    'admin_bind_host',
    default='0.0.0.0',  # nosec : Bind to all interfaces by default for
                        # backwards compatibility.
    deprecated_opts=[
        cfg.DeprecatedOpt('bind_host', group='DEFAULT'),
        cfg.DeprecatedOpt('admin_bind_host', group='DEFAULT'),
    ],
    deprecated_for_removal=True,
    deprecated_reason=_DEPRECATE_EVENTLET_MSG,
    deprecated_since=versionutils.deprecated.KILO,
    help=utils.fmt("""
The IP address of the network interface for the admin service to listen on.
"""))

admin_port = cfg.PortOpt(
    'admin_port',
    default=35357,
    deprecated_name='admin_port',
    deprecated_group='DEFAULT',
    deprecated_for_removal=True,
    deprecated_reason=_DEPRECATE_EVENTLET_MSG,
    deprecated_since=versionutils.deprecated.KILO,
    help=utils.fmt("""
The port number for the admin service to listen on.
"""))


GROUP_NAME = __name__.split('.')[-1]
ALL_OPTS = [
    public_bind_host,
    public_port,
    admin_bind_host,
    admin_port,
]


def register_opts(conf):
    conf.register_opts(ALL_OPTS, group=GROUP_NAME)


def list_opts():
    return {GROUP_NAME: ALL_OPTS}
