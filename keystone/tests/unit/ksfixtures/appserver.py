# Copyright 2013 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import absolute_import

import fixtures
from oslo_config import cfg
from paste import deploy

from keystone.common import environment


CONF = cfg.CONF

MAIN = 'main'
ADMIN = 'admin'


class AppServer(fixtures.Fixture):
    """A fixture for managing an application server instance.
    """

    def __init__(self, config, name, cert=None, key=None, ca=None,
                 cert_required=False, host='127.0.0.1', port=0):
        super(AppServer, self).__init__()
        self.config = config
        self.name = name
        self.cert = cert
        self.key = key
        self.ca = ca
        self.cert_required = cert_required
        self.host = host
        self.port = port

    def setUp(self):
        super(AppServer, self).setUp()

        app = deploy.loadapp(self.config, name=self.name)
        self.server = environment.Server(app, self.host, self.port)
        self._setup_SSL_if_requested()
        self.server.start(key='socket')

        # some tests need to know the port we ran on.
        self.port = self.server.socket_info['socket'][1]
        self._update_config_opt()

        self.addCleanup(self.server.stop)

    def _setup_SSL_if_requested(self):
        # TODO(dstanek): fix environment.Server to take a SSLOpts instance
        # so that the params are either always set or not
        if (self.cert is not None and
                self.ca is not None and
                self.key is not None):
            self.server.set_ssl(certfile=self.cert,
                                keyfile=self.key,
                                ca_certs=self.ca,
                                cert_required=self.cert_required)

    def _update_config_opt(self):
        """Updates the config with the actual port used."""
        opt_name = self._get_config_option_for_section_name()
        CONF.set_override(opt_name, self.port, group='eventlet_server')

    def _get_config_option_for_section_name(self):
        """Maps Paster config section names to port option names."""
        return {'admin': 'admin_port', 'main': 'public_port'}[self.name]
