# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

from keystone.openstack.common import log

CONF = cfg.CONF

API_SERVICE_OPTS = [
    cfg.StrOpt('bind_ip',
               default='0.0.0.0',
               help='IP for the server to bind to'),
    cfg.IntOpt('port',
               default=9109,
               help='The port for the server'),
]

CONF.register_opts(API_SERVICE_OPTS)


def parse_args(args, default_config_files=None):
    CONF(args=args[1:],
         project='kds',
         default_config_files=default_config_files)


def prepare_service(argv=[]):
    cfg.set_defaults(log.log_opts,
                     default_log_levels=['sqlalchemy=WARN',
                                         'eventlet.wsgi.server=WARN'
                                         ])
    parse_args(argv)
    log.setup('kds')
