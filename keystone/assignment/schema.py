# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from keystone.assignment.role_backends import resource_options as ro
from keystone.common.validation import parameter_types

# Schema for Identity v3 API

_role_properties = {
    'name': parameter_types.name,
    'description': parameter_types.description,
    'options': ro.ROLE_OPTIONS_REGISTRY.json_schema
}

role_create = {
    'type': 'object',
    'properties': _role_properties,
    'required': ['name'],
    'additionalProperties': True
}

role_update = {
    'type': 'object',
    'properties': _role_properties,
    'minProperties': 1,
    'additionalProperties': True
}
