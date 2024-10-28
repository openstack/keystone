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
from typing import Any

from keystone.api.validation import parameter_types
from keystone.api.validation import response_types
from keystone.common import validation
from keystone.common.validation import parameter_types as old_parameter_types
from keystone.resource.backends import resource_options as ro

_name_properties = {
    'type': 'string',
    'minLength': 1,
    'maxLength': 64,
    'pattern': r'[\S]+',
}

_project_tag_name_properties = {
    'type': 'string',
    'minLength': 1,
    'maxLength': 255,
    # NOTE(gagehugo) This pattern is for tags which follows the
    # guidelines as set by the API-WG, which matches anything that
    # does not contain a '/' or ','.
    # https://specs.openstack.org/openstack/api-wg/guidelines/tags.html
    'pattern': '^[^,/]*$',
}

_project_tags_list_properties = {
    'type': 'array',
    'items': _project_tag_name_properties,
    'required': [],
    'maxItems': 80,
    'uniqueItems': True,
}

_project_properties = {
    'description': validation.nullable(old_parameter_types.description),
    # NOTE(htruta): domain_id is nullable for projects acting as a domain.
    'domain_id': validation.nullable(old_parameter_types.id_string),
    'enabled': parameter_types.boolean,
    'is_domain': parameter_types.boolean,
    'parent_id': validation.nullable(old_parameter_types.id_string),
    'name': _name_properties,
    'tags': _project_tags_list_properties,
    'options': ro.PROJECT_OPTIONS_REGISTRY.json_schema,
}

# This is for updating a single project tag via the URL
project_tag_create = _project_tag_name_properties

# This is for updaing a project with a list of tags
project_tags_update = _project_tags_list_properties

project_create = {
    'type': 'object',
    'properties': _project_properties,
    # NOTE(lbragstad): A project name is the only parameter required for
    # project creation according to the Identity V3 API. We should think
    # about using the maxProperties validator here, and in update.
    'required': ['name'],
    'additionalProperties': True,
}

project_update = {
    'type': 'object',
    'properties': _project_properties,
    # NOTE(lbragstad): Make sure at least one property is being updated
    'minProperties': 1,
    'additionalProperties': True,
}

_domain_properties = {
    'description': validation.nullable(old_parameter_types.description),
    'enabled': parameter_types.boolean,
    'name': _name_properties,
    'tags': project_tags_update,
}

domain_create = {
    'type': 'object',
    'properties': _domain_properties,
    # TODO(lbragstad): According to the V3 API spec, name isn't required but
    # the current implementation in assignment.controller:DomainV3 requires a
    # name for the domain.
    'required': ['name'],
    'additionalProperties': True,
}

domain_update = {
    'type': 'object',
    'properties': _domain_properties,
    'minProperties': 1,
    'additionalProperties': True,
}

project_index_request_query = {
    'type': 'object',
    'properties': {
        "domain_id": parameter_types.domain_id,
        "enabled": parameter_types.boolean,
        "name": _name_properties,
        "parent_id": parameter_types.parent_id,
        "is_domain": parameter_types.boolean,
        "tags": parameter_types.tags,
        "tags-any": parameter_types.tags,
        "not-tags": parameter_types.tags,
        "not-tags-any": parameter_types.tags,
        "marker": {
            "type": "string",
            "description": "ID of the last fetched entry",
        },
        "limit": {"type": ["integer", "string"]},
    },
}

project_schema: dict[str, Any] = {
    "type": "object",
    "properties": {
        "id": {"type": "string", "readOnly": True},
        "links": response_types.resource_links,
        **_project_properties,
    },
    "additionalProperties": True,
}

project_get_response_body: dict[str, Any] = {
    "type": "object",
    "properties": {"project": project_schema},
    "additionalProperties": False,
}

project_index_response_body: dict[str, Any] = {
    "type": "object",
    "properties": {
        "projects": {"type": "array", "items": project_schema},
        "links": response_types.links,
        "truncated": response_types.truncated,
    },
    "additionalProperties": False,
}

project_create_request_body: dict[str, Any] = {
    "type": "object",
    "properties": {
        "project": {
            "type": "object",
            "properties": _project_properties,
            "required": ["name"],
        }
    },
    "additionalProperties": False,
}

project_create_response_body: dict[str, Any] = project_get_response_body

# Explicitly list attributes allowed to be updated.
# Since updating `domain_id` is since very long time marked deprecated do not
# even include it in the schema
project_update_request_body: dict[str, Any] = {
    "type": "object",
    "properties": {
        "project": {
            "type": "object",
            "properties": {
                'description': validation.nullable(
                    old_parameter_types.description
                ),
                'enabled': parameter_types.boolean,
                'name': _name_properties,
                'tags': _project_tags_list_properties,
            },
        }
    },
    "additionalProperties": False,
}

project_update_response_body: dict[str, Any] = project_get_response_body

tags_response_body: dict[str, Any] = response_types.tags

tags_update_request_body: dict[str, Any] = {
    "type": "object",
    "properties": {
        "tags": {"type": "array", "items": _project_tag_name_properties}
    },
    "additionalProperties": False,
}
