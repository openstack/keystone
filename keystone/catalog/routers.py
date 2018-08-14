# Copyright 2012 OpenStack Foundation
#
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

from keystone.catalog import controllers
from keystone.common import router
from keystone.common import wsgi


class Routers(wsgi.RoutersBase):
    """API for the keystone catalog."""

    _path_prefixes = ('endpoints', 'services')

    def append_v3_routers(self, mapper, routers):
        routers.append(router.Router(controllers.ServiceV3(),
                                     'services', 'service',
                                     resource_descriptions=self.v3_resources))
        routers.append(router.Router(controllers.EndpointV3(),
                                     'endpoints', 'endpoint',
                                     resource_descriptions=self.v3_resources))
