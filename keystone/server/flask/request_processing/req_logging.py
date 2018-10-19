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

# LOG some debug output about the request. This was originally in the
# dispatch middleware

import flask
from oslo_log import log


LOG = log.getLogger(__name__)


def log_request_info():
    # Add in any extra debug logging about the request that is desired
    # note that this is executed prior to routing the request to a resource
    # so the data is somewhat raw.
    LOG.debug('REQUEST_METHOD: `%s`', flask.request.method)
    LOG.debug('SCRIPT_NAME: `%s`', flask.request.script_root)
    LOG.debug('PATH_INFO: `%s`', flask.request.path)
