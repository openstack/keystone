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
import pecan

from keystone.contrib.kds.api import config as pecan_config
from keystone.contrib.kds.api import hooks

CONF = cfg.CONF


def get_pecan_config():
    # Set up the pecan configuration
    filename = pecan_config.__file__.replace('.pyc', '.py')
    return pecan.configuration.conf_from_file(filename)


def setup_app(config=None, extra_hooks=None):
    app_hooks = [hooks.ConfigHook()]

    if extra_hooks:
        app_hooks.extend(extra_hooks)

    if not config:
        config = get_pecan_config()

    pecan.configuration.set_config(dict(config), overwrite=True)

    app = pecan.make_app('keystone.contrib.kds.api.root.RootController',
                         debug=CONF.debug,
                         hooks=app_hooks)

    return app
