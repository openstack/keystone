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

from keystone.common import wsgi
from keystone.contrib.revoke import controllers


class RevokeExtension(wsgi.ExtensionRouter):

    PATH_PREFIX = '/OS-REVOKE'

    def add_routes(self, mapper):
        revoke_controller = controllers.RevokeController()
        mapper.connect(self.PATH_PREFIX + '/events',
                       controller=revoke_controller,
                       action='list_revoke_events',
                       conditions=dict(method=['GET']))
