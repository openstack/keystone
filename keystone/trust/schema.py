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


_trust_properties = {
    # NOTE(lbragstad): These are set as external_id_string because they have
    # the ability to be read as LDAP user identifiers, which could be something
    # other than uuid.
    'trustor_user_id': parameter_types.external_id_string,
    'trustee_user_id': parameter_types.external_id_string,
    'impersonation': parameter_types.boolean,
    'project_id': validation.nullable(parameter_types.id_string),
    'remaining_uses': {
        'type': ['integer', 'null'],
        'minimum': 1
    },
    'expires_at': {
        'type': ['null', 'string']
    },
    'allow_redelegation': {
        'type': ['boolean', 'null']
    },
    'redelegation_count': {
        'type': ['integer', 'null'],
        'minimum': 0
    },
    # TODO(lbragstad): Need to find a better way to do this. We should be
    # checking that a role is a list of IDs and/or names.
    'roles': validation.add_array_type(parameter_types.id_string)
}

trust_create = {
    'type': 'object',
    'properties': _trust_properties,
    'required': ['trustor_user_id', 'trustee_user_id', 'impersonation'],
    'additionalProperties': True
}
