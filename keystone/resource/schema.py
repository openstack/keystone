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

from keystone.common import validation
from keystone.common.validation import parameter_types


_project_properties = {
    'description': validation.nullable(parameter_types.description),
    # NOTE(lbragstad): domain_id isn't nullable according to some backends.
    # The identity-api should be updated to be consistent with the
    # implementation.
    'domain_id': parameter_types.id_string,
    'enabled': parameter_types.boolean,
    'is_domain': parameter_types.boolean,
    'parent_id': validation.nullable(parameter_types.id_string),
    'name': {
        'type': 'string',
        'minLength': 1,
        'maxLength': 64
    }
}

project_create = {
    'type': 'object',
    'properties': _project_properties,
    # NOTE(lbragstad): A project name is the only parameter required for
    # project creation according to the Identity V3 API. We should think
    # about using the maxProperties validator here, and in update.
    'required': ['name'],
    'additionalProperties': True
}

project_update = {
    'type': 'object',
    'properties': _project_properties,
    # NOTE(lbragstad) Make sure at least one property is being updated
    'minProperties': 1,
    'additionalProperties': True
}

_domain_properties = {
    'description': validation.nullable(parameter_types.description),
    'enabled': parameter_types.boolean,
    'name': {
        'type': 'string',
        'minLength': 1,
        'maxLength': 64
    }
}

domain_create = {
    'type': 'object',
    'properties': _domain_properties,
    # TODO(lbragstad): According to the V3 API spec, name isn't required but
    # the current implementation in assignment.controller:DomainV3 requires a
    # name for the domain.
    'required': ['name'],
    'additionalProperties': True
}

domain_update = {
    'type': 'object',
    'properties': _domain_properties,
    'minProperties': 1,
    'additionalProperties': True
}
