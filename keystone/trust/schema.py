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
from keystone.assignment.role_backends import resource_options as ro
from keystone.common import validation

_role_response_properties = {
    "type": "array",
    "items": {
        "type": "object",
        "properties": {
            "description": validation.nullable(parameter_types.description),
            "domain_id": validation.nullable(parameter_types.domain_id),
            "id": parameter_types.id_string,
            "name": parameter_types.name,
            "options": ro.ROLE_OPTIONS_REGISTRY.json_schema,
            "links": response_types.links,
        },
        "additionalProperties": False,
    },
}

_trust_properties = {
    # NOTE(lbragstad): These are set as external_id_string because they have
    # the ability to be read as LDAP user identifiers, which could be something
    # other than uuid.
    "trustor_user_id": {
        "type": "string",
        "description": (
            "Represents the user who created the trust, and who's "
            "authorization is being delegated."
        ),
    },
    "trustee_user_id": {
        "type": "string",
        "description": "Represents the user who is capable of consuming "
        "the trust.",
    },
    "impersonation": {
        "type": "boolean",
        "description": (
            "If set to true, then the user attribute of tokens generated "
            "based on the trust will represent that of the trustor rather "
            "than the trustee, thus allowing the trustee to impersonate "
            "the trustor. If impersonation if set to false, then the token's "
            "user attribute will represent that of the trustee."
        ),
    },
    "project_id": {
        "type": ["string", "null"],
        "format": "uuid",
        "description": (
            "Identifies the project upon which the trustor is "
            "delegating authorization."
        ),
    },
    "remaining_uses": {
        "type": ["integer", "null"],
        "minimum": 1,
        "description": (
            "Specifies how many times the trust can be used to obtain "
            "a token. This value is decreased each time a token is issued "
            "through the trust. Once it reaches 0, no further tokens will "
            "be issued through the trust. The default value is null, "
            "meaning there is no limit on the number of tokens issued "
            "through the trust. If redelegation is enabled it must "
            "not be set."
        ),
    },
    "expires_at": {
        "type": ["null", "string"],
        "description": (
            "Specifies the expiration time of the trust. A trust may "
            "be revoked ahead of expiration. If the value represents "
            "a time in the past, the trust is deactivated. In the "
            "redelegation case it must not exceed the value of the "
            "corresponding expires_at field of the redelegated trust "
            "or it may be ommitted, then the expires_at value is copied "
            "from the redelegated trust."
        ),
    },
    "allow_redelegation": {
        "type": ["boolean", "null"],
        "description": (
            "If set to true then a trust between a trustor and any "
            "third-party user may be issued by the trustee just like a "
            "regular trust. If set to false, stops further redelegation. "
            "False by default."
        ),
    },
    "redelegation_count": {
        "type": ["integer", "null"],
        "minimum": 0,
        "description": (
            "Specifies the maximum remaining depth of the redelegated "
            "trust chain. Each subsequent trust has this field decremented "
            "by 1 automatically. The initial trustor issuing new trust "
            "that can be redelegated, must set allow_redelegation to true "
            "and may set redelegation_count to an integer value less than "
            "or equal to max_redelegation_count configuration parameter "
            "in order to limit the possible length of derivated trust chains. "
            "The trust issued by the trustor using a project-scoped token "
            "(not redelegating), in which allow_redelegation is set to true "
            "(the new trust is redelegatable), will be populated with the "
            "value specified in the max_redelegation_count configuration "
            "parameter if redelegation_count is not set or set to null. If "
            "allow_redelegation is set to false then redelegation_count "
            "will be set to 0 in the trust. If the trust is being issued by "
            "the trustee of a redelegatable trust-scoped token (redelegation "
            "case) then redelegation_count should not be set, as it will "
            "automatically be set to the value in the redelegatable "
            "trust-scoped token decremented by 1. Note, if the resulting "
            "value is 0, this means that the new trust will not be "
            "redelegatable, regardless of the value of allow_redelegation."
        ),
    },
    "redelegated_trust_id": {
        "type": ["string", "null"],
        "description": (
            "Returned with redelegated trust provides information "
            "about the predecessor in the trust chain.",
        ),
    },
}

trust_schema: dict[str, Any] = {
    "type": "object",
    "description": "A trust object.",
    "properties": {
        "deleted_at": {"type": ["string", "null"]},
        "id": {
            "type": "string",
            "readOnly": True,
            "description": "The ID of the trust.",
        },
        "links": response_types.links,
        "roles": _role_response_properties,
        "roles_links": response_types.links,
        **_trust_properties,
    },
    "additionalProperties": False,
}

trust_index_request_query: dict[str, Any] = {
    "type": "object",
    "properties": {
        "trustor_user_id": {
            "type": "string",
            "description": (
                "Represents the user who created the trust, and who's "
                "authorization is being delegated."
            ),
        },
        "trustee_user_id": {
            "type": "string",
            "description": "Represents the user who is capable of consuming "
            "the trust.",
        },
    },
    "additionalProperties": False,
}

trust_index_response_body: dict[str, Any] = {
    "type": "object",
    "properties": {
        "trusts": {
            "type": "array",
            "items": trust_schema,
            "description": "A list of trust objects.",
        },
        "links": response_types.links,
        "truncated": response_types.truncated,
    },
    "additionalProperties": False,
}

trust_request_query: dict[str, Any] = {
    "type": "object",
    "properties": {},
    "additionalProperties": False,
}

trust_response_body: dict[str, Any] = {
    "type": "object",
    "description": "A trust object",
    "properties": {"trust": trust_schema},
    "additionalProperties": False,
}

trust_create_request_body: dict[str, Any] = {
    "type": "object",
    "description": "A trust object",
    "properties": {
        "trust": {
            "type": "object",
            "properties": {
                **_trust_properties,
                "roles": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "id": parameter_types.id_string,
                            "name": parameter_types.name,
                        },
                        "minProperties": 1,
                        "maxProperties": 1,
                        "additionalProperties": False,
                    },
                },
            },
            "required": [
                "trustor_user_id",
                "trustee_user_id",
                "impersonation",
            ],
            "additionalProperties": True,
        }
    },
    "additionalProperties": False,
    "required": ["trust"],
}
