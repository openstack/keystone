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
import osprofiler.initializer

import keystone.conf


CONF = keystone.conf.CONF
LOG = log.getLogger(__name__)


def setup(name, host='0.0.0.0'):  # nosec
    """Setup OSprofiler notifier and enable profiling.

    :param name: name of the service that will be profiled
    :param host: hostname or host IP address that the service will be
                 running on. By default host will be set to 0.0.0.0, but more
                 specified host name / address usage is highly recommended.
    """
    if CONF.profiler.enabled:
        osprofiler.initializer.init_from_conf(
            conf=CONF,
            context={},
            project="keystone",
            service=name,
            host=host
        )
        LOG.info("OSProfiler is enabled.\n"
                 "Traces provided from the profiler "
                 "can only be subscribed to using the same HMAC keys that "
                 "are configured in Keystone's configuration file "
                 "under the [profiler] section. \n To disable OSprofiler "
                 "set in /etc/keystone/keystone.conf:\n"
                 "[profiler]\n"
                 "enabled=false")
