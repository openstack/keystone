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

# Schema for Identity v3 API

_role_properties: dict[str, Any] = {
    "name": parameter_types.name,
    "description": validation.nullable(parameter_types.description),
    "domain_id": validation.nullable(parameter_types.domain_id),
    "options": ro.ROLE_OPTIONS_REGISTRY.json_schema,
}
# NOTE(0weng): Multiple response body examples in the docs are
# incorrectly missing the `options` field.

# Common schema of `Role` resource
role_schema: dict[str, Any] = {
    "type": "object",
    "description": "A role object.",
    "properties": {
        "id": {
            "type": "string",
            "format": "uuid",
            "description": "The role ID.",
            "readOnly": True,
        },
        "links": response_types.resource_links,
        **_role_properties,
    },
    "additionalProperties": True,
}

# Response body of API operations returning a single role
# `GET /roles/{role_id}`, `POST /roles`, and `PATCH /roles/{role_id}`
role_show_response_body: dict[str, Any] = {
    "type": "object",
    "properties": {"role": role_schema},
    "additionalProperties": False,
}

# Query parameters of the `GET /roles` API operation
# returning a list of roles
roles_index_request_query: dict[str, Any] = {
    "type": "object",
    "properties": {
        "name": parameter_types.name,
        "domain_id": parameter_types.domain_id,
    },
    "additionalProperties": False,
}

# Response body of the `GET /roles` API operation
# returning a list of roles
roles_index_response_body: dict[str, Any] = {
    "type": "object",
    "properties": {
        "links": response_types.links,
        "roles": {
            "type": "array",
            "items": role_schema,
            "description": "A list of role objects.",
        },
        "truncated": response_types.truncated,
    },
    "additionalProperties": False,
}

# Request body of the `POST /roles` API operation
role_create_request_body = {
    "type": "object",
    "properties": {
        "role": {
            "type": "object",
            "properties": _role_properties,
            "description": "A role object.",
            "required": ["name"],
            "additionalProperties": True,
        }
    },
    "required": ["role"],
    "additionalProperties": False,
}

# FIXME(0weng): There's no error if additional properties are added
# at the top level, e.g. POST/PATCH with this body:
# {"role": {"some_key":"some_value"}, "no_error": "no_error_here"}
# Is this intended, or should it be disallowed by the schema (as it is here)?
# 400 errors do occur if the "role" property is missing
# (the error message is that '{}' is not enough properties,
# so I imagine extra properties are removed)
# or no properties are provided.

# Request body of the `PATCH /roles/{role_id}` operation
role_update_request_body = {
    "type": "object",
    "properties": {
        "role": {
            "type": "object",
            "properties": _role_properties,
            "description": "A role object.",
            "minProperties": 1,
            "additionalProperties": True,
        }
    },
    "required": ["role"],
    "additionalProperties": False,
}

# Individual properties of a returned prior/implied role
_implied_role_properties: dict[str, Any] = {
    "id": {
        "type": "string",
        "format": "uuid",
        "description": "The role ID.",
        "readOnly": True,
    },
    "links": response_types.resource_links,
    "name": parameter_types.name,
}

# Common schema of prior role
prior_role_schema: dict[str, Any] = {
    "type": "object",
    "description": "A prior role object.",
    "properties": _implied_role_properties,
    "additionalProperties": False,
}

# Common schema of implied role
implied_role_schema: dict[str, Any] = {
    "type": "object",
    "description": "An implied role object.",
    "properties": _implied_role_properties,
    "additionalProperties": False,
}

# Response body of API operations returning a single implied role
# `GET /v3/roles/{prior_role_id}/implies/{implies_role_id}`
# and `PUT /v3/roles/{prior_role_id}/implies/{implies_role_id}`
implied_role_show_response_body: dict[str, Any] = {
    "type": "object",
    "properties": {
        "role_inference": {
            "type": "object",
            "description": (
                "Role inference object that contains "
                "prior_role object and implies object."
            ),
            "properties": {
                "prior_role": prior_role_schema,
                "implies": implied_role_schema,
            },
            "additionalProperties": False,
        },
        "links": response_types.links,
    },
    "additionalProperties": False,
}

# Response body of the `GET /v3/roles/{prior_role_id}/implies` API operation
# returning a single role inference
role_inference_show_response_body: dict[str, Any] = {
    "type": "object",
    "properties": {
        "role_inference": {
            "type": "object",
            "description": "A role inference object.",
            "properties": {
                "prior_role": prior_role_schema,
                "implies": {
                    "type": "array",
                    "items": implied_role_schema,
                    "description": "A list of implied role objects.",
                },
            },
            "additionalProperties": False,
        },
        "links": response_types.links,
    },
    "additionalProperties": False,
}

# Response body of the `GET /v3/role_inferences` API operation
# returning a list of role inferences
role_inferences_index_response_body: dict[str, Any] = {
    "type": "object",
    "properties": {
        "role_inferences": {
            "type": "array",
            "description": "A list of role inference objects.",
            "items": {
                "type": "object",
                "properties": {
                    # NOTE(0weng): The example in the docs incorrectly
                    # includes the `description` field in the output.
                    "prior_role": prior_role_schema,
                    "implies": {
                        "type": "array",
                        "items": implied_role_schema,
                        "description": "A list of implied role objects.",
                    },
                },
                "additionalProperties": False,
            },
            "additionalProperties": False,
        },
        "links": response_types.links,
    },
    "additionalProperties": False,
}

# Common schema of `Role Assignment` resource
role_assignment_schema: dict[str, Any] = {
    "type": "object",
    "description": "A role assignment object.",
    "properties": {
        "links": {
            "type": "object",
            "properties": {
                "assignment": {"type": "string", "format": "uri"},
                "membership": {"type": "string", "format": "uri"},
                "prior_role": {"type": "string", "format": "uri"},
            },
            "required": ["assignment"],
            "additionalProperties": False,
        },
        "role": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "object",
                    "properties": {
                        "id": parameter_types.id_string,
                        "name": parameter_types.name,
                    },
                    "required": ["id"],
                    "additionalProperties": False,
                },
                "id": parameter_types.id_string,
                "name": parameter_types.name,
            },
            "required": ["id"],
            "additionalProperties": False,
        },
        "scope": {
            "properties": {
                "project": {
                    "type": "object",
                    "properties": {
                        "domain": {
                            "type": "object",
                            "properties": {
                                "id": parameter_types.id_string,
                                "name": parameter_types.name,
                            },
                            "required": ["id"],
                            "additionalProperties": False,
                        },
                        "id": parameter_types.id_string,
                        "name": parameter_types.name,
                    },
                    "required": ["id"],
                    "additionalProperties": False,
                },
                "OS-INHERIT:inherited_to": {"const": "projects"},
                "domain": {
                    "type": "object",
                    "properties": {
                        "id": parameter_types.id_string,
                        "name": parameter_types.name,
                    },
                    "required": ["id"],
                },
                "system": {
                    "type": "object",
                    "properties": {"all": {"const": True}},
                    "required": ["all"],
                },
            },
            "oneOf": [
                {"required": ["project"]},
                {"required": ["domain"]},
                {"required": ["system"]},
            ],
            "additionalProperties": False,
        },
        "user": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "object",
                    "properties": {
                        "id": parameter_types.id_string,
                        "name": parameter_types.name,
                    },
                    "required": ["id"],
                    "additionalProperties": False,
                },
                "id": parameter_types.id_string,
                "name": parameter_types.name,
            },
            "required": ["id"],
            "additionalProperties": False,
        },
        "group": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "object",
                    "properties": {
                        "id": parameter_types.id_string,
                        "name": parameter_types.name,
                    },
                    "required": ["id"],
                    "additionalProperties": False,
                },
                "id": parameter_types.id_string,
                "name": parameter_types.name,
            },
            "required": ["id"],
            "additionalProperties": False,
        },
    },
    "required": ["role", "links", "scope"],
    "oneOf": [{"required": ["user"]}, {"required": ["group"]}],
    "additionalProperties": False,
}

# Query parameters of the `GET /role_assignments` API operation
# returning a list of role assignments
role_assignments_index_request_query: dict[str, Any] = {
    "type": "object",
    "properties": {
        # NOTE(0weng): `effective`, `include_names`, and `include_subtree`
        # are all key-only query parameters and will interpret the parameter
        # as true for any value except 0 and for no value at all.
        "effective": {},
        "include_names": {},
        "include_subtree": {},
        "group.id": parameter_types.id_string,
        "role.id": parameter_types.id_string,
        # NOTE(0weng): Similar to the previous note, `scope.system`
        # accepts anything, but it will only be interpreted as true if
        # its value is "all"; otherwise it's ignored.
        "scope.system": {},
        "scope.domain.id": parameter_types.domain_id,
        "scope.project.id": parameter_types.project_id,
        "user.id": parameter_types.id_string,
        # NOTE(0weng): `scope.OS-INHERIT:inherited_to` accepts anything,
        # but it will only show inherited role assignments if its value is
        # `projects`; otherwise, only non-inherited role assignments are shown.
        "scope.OS-INHERIT:inherited_to": {},
    },
    "dependentRequired": {"include_subtree": ["scope.project.id"]},
    # NOTE(0weng): {"not": {"required": "some_property"}} indicates that
    # the property is not allowed to be present, not that it's optional.
    "oneOf": [
        {"required": ["scope.project.id"]},
        {"required": ["scope.domain.id"]},
        {"required": ["scope.system"]},
        {
            "allOf": [
                {"not": {"required": ["scope.project.id"]}},
                {"not": {"required": ["scope.domain.id"]}},
                {"not": {"required": ["scope.system"]}},
            ]
        },
    ],
    "oneOf": [
        {"required": ["user.id"]},
        {"required": ["group.id"]},
        {
            "allOf": [
                {"not": {"required": ["user.id"]}},
                {"not": {"required": ["group.id"]}},
            ]
        },
    ],
    "not": {
        "required": [
            "effective",
            "scope.domain.id",
            "scope.OS-INHERIT:inherited_to",
        ]
    },
    "not": {"required": ["effective", "group"]},
    "additionalProperties": False,
}

# Response body of the `GET /role_assignments` API operation
# returning a list of role assignments
role_assignments_index_response_body: dict[str, Any] = {
    "type": "object",
    "properties": {
        "links": response_types.links,
        "role_assignments": {
            "type": "array",
            "items": role_assignment_schema,
            "description": "A list of role assignment objects.",
        },
        "truncated": response_types.truncated,
    },
    "additionalProperties": False,
}
