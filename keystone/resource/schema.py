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
from keystone.assignment.schema import role_schema
from keystone.common import validation
from keystone.common.validation import parameter_types as old_parameter_types
from keystone.resource.backends import resource_options as ro

_name_properties = {
    'type': 'string',
    'description': 'The resource name.',
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
                'options': ro.PROJECT_OPTIONS_REGISTRY.json_schema,
                'tags': _project_tags_list_properties,
            },
        }
    },
    "additionalProperties": False,
}

project_update_response_body: dict[str, Any] = project_get_response_body

_domain_properties = {
    "description": validation.nullable(parameter_types.description),
    "enabled": {
        "description": "If set to true, domain is enabled. If set to false, domain is disabled.",
        **parameter_types.boolean,
    },
    "name": _name_properties,
    "options": ro.PROJECT_OPTIONS_REGISTRY.json_schema,
    "tags": project_tags_update,
}

domain_schema: dict[str, Any] = {
    "type": "object",
    "properties": {
        "id": {"type": "string", "readOnly": True},
        "links": response_types.resource_links,
        **_domain_properties,
    },
    "additionalProperties": False,
}

domain_get_response_body: dict[str, Any] = {
    "type": "object",
    "properties": {"domain": domain_schema},
    "required": ["domain"],
    "additionalProperties": False,
}

domain_index_request_query: dict[str, Any] = {
    "type": "object",
    "properties": {
        "enabled": {
            "description": "If set to true, then only domains that are enabled will be returned, if set to false only that are disabled will be returned. Any value other than 0, including no value, will be interpreted as true.",
            **parameter_types.boolean,
        },
        "name": _name_properties,
        "marker": {
            "type": "string",
            "description": "ID of the last fetched entry",
        },
        "limit": {"type": ["integer", "string"]},
    },
    "additionalProperties": "False",
}

domain_index_response_body: dict[str, Any] = {
    "type": "object",
    "properties": {
        "domains": {"type": "array", "items": domain_schema},
        "links": response_types.links,
        "truncated": response_types.truncated,
    },
    "additionalProperties": False,
}

domain_update_request_body: dict[str, Any] = {
    "type": "object",
    "properties": {
        "domain": {
            "type": "object",
            "properties": _domain_properties,
            "minProperties": 1,
        }
    },
    "required": ["domain"],
    "additionalProperties": False,
}

domain_update_response_body: dict[str, Any] = {
    "type": "object",
    "properties": {"domain": domain_schema},
    "required": ["domain"],
    "additionalProperties": False,
}

domain_create_request_body: dict[str, Any] = {
    "type": "object",
    "properties": {
        "domain": {
            "type": "object",
            "properties": {
                "explicit_domain_id": {
                    "description": "The ID of the domain. A domain created this way will not use an auto-generated ID, but will use the ID passed in instead. Identifiers passed in this way must conform to the existing ID generation scheme: UUID4 without dashes.",
                    **parameter_types.domain_id,
                },
                **_domain_properties,
            },
            "required": ["name"],
        }
    },
    "required": ["domain"],
    "additionalProperties": False,
}

domain_create_response_body: dict[str, Any] = {
    "type": "object",
    "properties": {"domain": domain_schema},
    "required": ["domain"],
    "additionalProperties": False,
}

tags_response_body: dict[str, Any] = response_types.tags

tags_update_request_body: dict[str, Any] = {
    "type": "object",
    "properties": {
        "tags": {"type": "array", "items": _project_tag_name_properties}
    },
    "additionalProperties": False,
}

# Response body of the `GET /[projects|domains]/{id}/[users|groups]/{id}/roles`
# API operations returning a list of roles
# Also used for the `GET /system/[users|groups]/{id}/roles` API operations
grants_get_response_body: dict[str, Any] = {
    "type": "object",
    "properties": {
        "links": response_types.links,
        "roles": {
            "type": "array",
            "items": {**role_schema, "additionalProperties": False},
        },
        "truncated": response_types.truncated,
    },
    "additionalProperties": False,
}
