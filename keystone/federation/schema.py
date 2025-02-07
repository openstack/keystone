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
from keystone.common.validation import parameter_types as ks_parameter_types

basic_property_id = {
    'type': 'object',
    'properties': {'id': {'type': 'string'}},
    'required': ['id'],
    'additionalProperties': False,
}

saml_create = {
    'type': 'object',
    'properties': {
        'identity': {
            'type': 'object',
            'properties': {
                'token': basic_property_id,
                'methods': {'type': 'array'},
            },
            'required': ['token'],
            'additionalProperties': False,
        },
        'scope': {
            'type': 'object',
            'properties': {'service_provider': basic_property_id},
            'required': ['service_provider'],
            'additionalProperties': False,
        },
    },
    'required': ['identity', 'scope'],
    'additionalProperties': False,
}

_service_provider_properties = {
    # NOTE(rodrigods): The database accepts URLs with 256 as max length,
    # but parameter_types.url uses 225 as max length.
    "auth_url": {
        **parameter_types.url,
        "description": "The URL to authenticate against",
    },
    "sp_url": {
        **parameter_types.url,
        "description": "The service provider's URL",
    },
    "description": {
        "type": ["string", "null"],
        "description": "The description of the service provider",
    },
    "enabled": {
        **parameter_types.boolean,
        "description": "Whether the service provider is enabled or not",
    },
    "relay_state_prefix": {
        "type": ["string", "null"],
        "description": "The prefix of the RelayState SAML attribute",
    },
}

service_provider_schema: dict[str, Any] = {
    "type": "object",
    "description": "A service provider object",
    "properties": {
        "id": {
            "type": "string",
            "readOnly": True,
            "description": "The service provider ID",
        },
        "links": response_types.resource_links,
        **_service_provider_properties,
    },
    "additionalProperties": True,
}

service_provider_index_request_query: dict[str, Any] = {
    "type": "object",
    "properties": {
        "id": {"type": "string", "description": "The service provider ID"},
        "enabled": {
            **parameter_types.boolean,
            "description": "Whether the service provider is enabled or not",
        },
    },
    "additionalProperties": False,
}

service_provider_index_response_body: dict[str, Any] = {
    "type": "object",
    "properties": {
        "service_providers": {
            "type": "array",
            "items": service_provider_schema,
            "description": "A list of service provider objects",
        },
        "links": response_types.links,
        "truncated": response_types.truncated,
    },
    "additionalProperties": False,
}

service_provider_response_body: dict[str, Any] = {
    "type": "object",
    "description": "A service provider object",
    "properties": {"service_provider": service_provider_schema},
    "additionalProperties": False,
}

service_provider_create_request_body: dict[str, Any] = {
    "type": "object",
    "description": "A service provider object",
    "properties": {
        "service_provider": {
            "type": "object",
            "properties": _service_provider_properties,
            "required": ["auth_url", "sp_url"],
            "additionalProperties": False,
        }
    },
    "required": ["service_provider"],
    "additionalProperties": False,
}

service_provider_update_request_body: dict[str, Any] = {
    "type": "object",
    "description": "A service provider object",
    "properties": {
        # NOTE(rodrigods): 'id' is not required since it is passed in the URL
        "service_provider": {
            "type": "object",
            "properties": _service_provider_properties,
            "additionalProperties": False,
            "minProperties": 1,
        }
    },
    "required": ["service_provider"],
    "additionalProperties": False,
}

identity_provider_response_links: dict[str, Any] = {
    "type": "object",
    "properties": {
        "self": {"type": "string", "format": "uri"},
        "protocols": {"type": "string", "format": "uri"},
    },
    "additionalProperties": False,
}

_identity_provider_properties = {
    "enabled": {
        **parameter_types.boolean,
        "description": "Whether the identity provider is enabled or not",
    },
    "description": {
        "type": ["string", "null"],
        "description": "The identity provider description",
    },
    "authorization_ttl": {
        "type": ["integer", "null"],
        "minimum": 0,
        "description": (
            "The length of validity in minutes for group memberships "
            "carried over through mapping and persisted in the database. "
            "If left unset, the default value configured in keystone will "
            "be used, if enabled."
        ),
    },
    "remote_ids": {
        "type": ["array", "null"],
        "description": "List of the unique identity provider's remote IDs",
        "items": {"type": "string"},
        "uniqueItems": True,
    },
}

identity_provider_schema: dict[str, Any] = {
    "type": "object",
    "description": "An identity provider object",
    "properties": {
        "id": {
            "type": "string",
            "readOnly": True,
            "description": "The identity provider ID",
        },
        "links": identity_provider_response_links,
        **_identity_provider_properties,
    },
    "additionalProperties": True,
}

identity_provider_index_request_query: dict[str, Any] = {
    "type": "object",
    "properties": {
        "id": {"type": "string", "description": "The identity provider ID"},
        "enabled": {
            **parameter_types.boolean,
            "description": "Whether the identity provider is enabled or not",
        },
    },
    "additionalProperties": True,
}

identity_provider_index_response_body: dict[str, Any] = {
    "type": "object",
    "properties": {
        "identity_providers": {
            "type": "array",
            "items": identity_provider_schema,
            "description": "A list of identity provider objects",
        },
        "links": response_types.links,
    },
    "additionalProperties": True,
}

identity_provider_request_query: dict[str, Any] = {
    "type": "object",
    "properties": {},
    "additionalProperties": True,
}

identity_provider_response_body: dict[str, Any] = {
    "type": "object",
    "description": "An identity provider object",
    "properties": {"identity_provider": identity_provider_schema},
    "additionalProperties": False,
}

identity_provider_create_request_body: dict[str, Any] = {
    "type": "object",
    "description": "An identity provider object",
    "properties": {
        "identity_provider": {
            "type": "object",
            "properties": {
                **_identity_provider_properties,
                "domain_id": {
                    "type": ["string", "null"],
                    "minLength": 1,
                    "maxLength": 64,
                    "pattern": r"^[a-zA-Z0-9-]+$",
                    "description": (
                        "The ID of a domain that is associated with the "
                        "identity provider. Federated users that "
                        "authenticate with the identity provider will be "
                        "created under the domain specified."
                    ),
                },
            },
            "additionalProperties": False,
        }
    },
    "additionalProperties": False,
}

identity_provider_update_request_body: dict[str, Any] = {
    "type": "object",
    "description": "An identity provider object",
    "properties": {
        "identity_provider": {
            "type": "object",
            "properties": _identity_provider_properties,
            "additionalProperties": False,
            "minProperties": 1,
        }
    },
    "required": ["identity_provider"],
}

_remote_id_attribute_properties = {'type': 'string', 'maxLength': 64}

_protocol_properties = {
    'mapping_id': ks_parameter_types.mapping_id_string,
    'remote_id_attribute': _remote_id_attribute_properties,
}

protocol_create = {
    'type': 'object',
    'properties': _protocol_properties,
    'required': ['mapping_id'],
    'additionalProperties': False,
}

protocol_update = {
    'type': 'object',
    'properties': _protocol_properties,
    'minProperties': 1,
    'additionalProperties': False,
}
