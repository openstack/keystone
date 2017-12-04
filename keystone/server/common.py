
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.


from oslo_log import log

from keystone.common import sql
import keystone.conf
from keystone.server import backends


CONF = keystone.conf.CONF
LOG = log.getLogger(__name__)


def configure(version=None, config_files=None,
              pre_setup_logging_fn=lambda: None):
    keystone.conf.configure()
    sql.initialize()
    keystone.conf.set_config_defaults()

    CONF(project='keystone', version=version,
         default_config_files=config_files)

    pre_setup_logging_fn()
    keystone.conf.setup_logging()

    if CONF.insecure_debug:
        LOG.warning(
            'insecure_debug is enabled so responses may include sensitive '
            'information.')


def setup_backends(load_extra_backends_fn=lambda: {},
                   startup_application_fn=lambda: None):
    drivers = backends.load_backends()
    drivers.update(load_extra_backends_fn())
    res = startup_application_fn()
    return drivers, res
