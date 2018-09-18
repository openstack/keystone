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

# NOTE(morgan): Import relevant stuff so importing individual under-pinnings
# isn't needed, keystone.server.flask exposes all the interesting bits
# needed to develop restful APIs for keystone.

from keystone.server.flask.common import APIBase  # noqa
from keystone.server.flask.common import base_url  # noqa
from keystone.server.flask.common import construct_json_home_data  # noqa
from keystone.server.flask.common import construct_resource_map  # noqa
from keystone.server.flask.common import full_url  # noqa
from keystone.server.flask.common import JsonHomeData  # noqa
from keystone.server.flask.common import ResourceBase  # noqa
from keystone.server.flask.common import ResourceMap  # noqa
from keystone.server.flask.common import unenforced_api  # noqa


# NOTE(morgan): This allows for from keystone.flask import * and have all the
# cool stuff needed to develop new APIs within a module/subsystem
__all__ = ('APIBase', 'JsonHomeData', 'ResourceBase', 'ResourceMap',
           'base_url', 'construct_json_home_data',
           'construct_resource_map', 'full_url', 'unenforced_api')
