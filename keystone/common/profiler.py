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
import oslo_messaging
import osprofiler.notifier
import osprofiler.web

import keystone.conf
from keystone.i18n import _LI


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
        _notifier = osprofiler.notifier.create(
            "Messaging", oslo_messaging, {},
            oslo_messaging.get_transport(CONF), "keystone", name, host)
        osprofiler.notifier.set(_notifier)
        osprofiler.web.enable(CONF.profiler.hmac_keys)
        LOG.info(_LI("OSProfiler is enabled.\n"
                     "Traces provided from the profiler "
                     "can only be subscribed to using the same HMAC keys that "
                     "are configured in Keystone's configuration file "
                     "under the [profiler] section. \n To disable OSprofiler "
                     "set in /etc/keystone/keystone.conf:\n"
                     "[profiler]\n"
                     "enabled=false"))
