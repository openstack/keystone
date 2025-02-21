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

_region_properties = {
    'description': validation.nullable(parameter_types.description),
    # NOTE(lbragstad): Regions use ID differently. The user can specify the ID
    # or it will be generated automatically.
    'id': {'type': 'string'},
    'parent_region_id': {'type': ['string', 'null']},
}

region_create = {
    'type': 'object',
    'properties': _region_properties,
    'additionalProperties': True,
    # NOTE(lbragstad): No parameters are required for creating regions.
}

region_update = {
    'type': 'object',
    'properties': _region_properties,
    'minProperties': 1,
    'additionalProperties': True,
}

# Schema for Service v3
# Individual properties of 'Service'
_service_properties = {
    "enabled": {
        "type": "boolean",
        "description": (
            "Defines whether the service and its endpoints appear in the "
            "service catalog - false. The service and its endpoints do "
            "not appear in the service catalog - true."
        ),
    },
    "type": {
        "type": "string",
        "description": (
            "The service type, which describes the API implemented by the "
            "service. Value is compute, ec2, identity, image, network, "
            "or volume."
        ),
        "minLength": 1,
        "maxLength": 255,
    },
}

_service_name_properties = {
    "name": {
        "type": "string",
        "description": "The service name.",
        "minLength": 1,
        "maxLength": 255,
    }
}

# Common schema of `Service` resource
service_schema: dict[str, Any] = {
    "type": "object",
    "description": "A service object",
    "properties": {
        "id": {
            "type": "string",
            "readOnly": True,
            "description": (
                "The UUID of the service to which the endpoint belongs."
            ),
        },
        "name": {
            "type": "string",
            "description": "The service name.",
            "minLength": 0,
            "maxLength": 255,
        },
        "links": response_types.resource_links,
        **_service_properties,
    },
    "additionalProperties": True,
}

# Query parameters of the `/services` API
service_index_request_query: dict[str, Any] = {
    "type": "object",
    "properties": {},
    "additionalProperties": True,
}

# Response of the `/services` API
service_index_response_body: dict[str, Any] = {
    "type": "object",
    "properties": {
        "services": {
            "type": "array",
            "items": service_schema,
            "description": "A list of service object.",
        },
        "links": response_types.links,
        "truncated": response_types.truncated,
    },
    "additionalProperties": False,
}

# Response of the `/services` API returning a single service
service_response_body: dict[str, Any] = {
    "type": "object",
    "description": "A service object.",
    "properties": {"service": service_schema},
    "additionalProperties": False,
}

# Request body of the `POST /services` operation
service_create_request_body: dict[str, Any] = {
    "type": "object",
    "description": "A service object.",
    "properties": {
        "service": {
            "type": "object",
            "properties": {**_service_properties, **_service_name_properties},
            "additionalProperties": True,
            "required": ["type"],
        }
    },
}

# Request body of the `PATCH /services/{service_id}` operation
service_update_request_body: dict[str, Any] = {
    "type": "object",
    "description": "A service object.",
    "properties": {
        "service": {
            "type": "object",
            "properties": {**_service_properties, **_service_name_properties},
            "additionalProperties": True,
            "minProperties": 1,
        }
    },
    "required": ["service"],
}

# Individual properties of 'Endpoint'
_endpoint_properties = {
    "enabled": {
        "type": "boolean",
        "description": (
            "Indicates whether the endpoint appears in the service "
            "catalog -false. The endpoint does not appear in the service "
            "catalog. -true. The endpoint appears in the service catalog."
        ),
    },
    "interface": {
        "type": "string",
        "enum": ["admin", "internal", "public"],
        "description": (
            "The interface type, which describes the visibility of the "
            "endpoint. Value is: -public. Visible by end users on a "
            "publicly available network interface. -internal. Visible "
            "by end users on an unmetered internal network interface. -admin. "
            "Visible by administrative users on a secure network interface."
        ),
    },
    "region_id": {
        "type": ["string", "null"],
        "description": (
            "(Since v3.2) The ID of the region that contains the "
            "service endpoint."
        ),
        "x-openstack": {"min-ver": 3.2},
    },
    "region": {
        "type": ["string", "null"],
        "description": (
            "(Deprecated in v3.2) The geographic location of "
            "the service endpoint."
        ),
        "x-openstack": {"max-ver": 3.2},
    },
    "service_id": {
        "type": "string",
        "description": "The UUID of the service to which the endpoint belongs",
    },
    "url": {
        "type": "string",
        "description": "The endpoint URL.",
        "minLength": 0,
        "maxLength": 225,
        "pattern": "^[a-zA-Z0-9+.-]+:.+",
    },
    "name": {"type": "string", "description": "The name of the endpoint."},
    "description": {
        "type": ["string", "null"],
        "description": "A description of the endpoint.",
    },
}

# Common schema of `Endpoint` resource
endpoint_schema: dict[str, Any] = {
    "type": "object",
    "description": "An endpoint object",
    "properties": {
        "id": {
            "type": "string",
            "readOnly": True,
            "description": "The endpoint ID",
        },
        "links": response_types.resource_links,
        **_endpoint_properties,
    },
    "additionalProperties": False,
}

# Query parameters of the `/endpoints` API
endpoint_index_request_query: dict[str, Any] = {
    "type": "object",
    "properties": {
        "interface": {
            "type": "string",
            "enum": ["admin", "internal", "public"],
            "description": (
                "The interface type, which describes the visibility of the "
                "endpoint. Value is: -public. Visible by end users on a "
                "publicly available network interface. -internal. Visible "
                "by end users on an unmetered internal network interface."
                "-admin. Visible by administrative users on a secure "
                "network interface."
            ),
        },
        "region_id": {
            "type": ["string", "null"],
            "description": (
                "(Since v3.2) The ID of the region that contains the "
                "service endpoint."
            ),
            "x-openstack": {"min-ver": 3.2},
        },
        "service_id": {
            "type": "string",
            "description": "The UUID of the service to which the "
            "endpoint belongs",
        },
    },
    "additionalProperties": False,
}

# Response of the `/endpoints` API
endpoint_index_response_body: dict[str, Any] = {
    "type": "object",
    "properties": {
        "endpoints": {
            "type": "array",
            "items": endpoint_schema,
            "description": "A list of endpoint objects.",
        },
        "links": response_types.links,
        "truncated": response_types.truncated,
    },
    "additionalProperties": False,
}

endpoint_request_query: dict[str, Any] = {
    "type": "object",
    "properties": {},
    "additionalProperties": False,
}

# Response of the `/endpoints` API returning a single endpoint
endpoint_response_body: dict[str, Any] = {
    "type": "object",
    "description": "An endpoint object",
    "properties": {"endpoint": endpoint_schema},
    "additionalProperties": False,
}

# Request body of the `POST /endpoints` operation
endpoint_create_request_body: dict[str, Any] = {
    "type": "object",
    "description": "An endpoint object",
    "properties": {
        "endpoint": {
            "type": "object",
            "properties": {
                "id": {"type": "string", "description": "The endpoint ID."},
                **_endpoint_properties,
            },
            "required": ["interface", "service_id", "url"],
            "additionalProperties": True,
        }
    },
    "additionalProperties": False,
}

# Request body of the `PATCH /endpoints/{endpoint_id}`
endpoint_update_request_body: dict[str, Any] = {
    "type": "object",
    "description": "An endpoint object",
    "properties": {
        "endpoint": {
            "type": "object",
            "properties": _endpoint_properties,
            "additionalProperties": True,
            "minProperties": 1,
        }
    },
    "required": ["endpoint"],
    "additionalProperties": False,
}

# Individual properties of 'Endpoint Group'
_endpoint_group_properties = {
    "description": {
        "type": ["string", "null"],
        "description": "The endpoint group description.",
    },
    "filters": {
        "type": "object",
        "description": (
            "Describes the filtering performed by the endpoint group. "
            "The filter used must be an endpoint property, such as "
            "interface, service_id, region, and enabled. Note that "
            "if using interface as a filter, the only available values "
            "are public, internal, and admin."
        ),
        "properties": {
            "interface": {
                "type": "string",
                "enum": ["admin", "internal", "public"],
                "description": (
                    "The interface type, which describes the visibility of "
                    "the endpoint. Value is: -public. Visible by end users "
                    "on a publicly available network interface. -internal. "
                    "Visible by end users on an unmetered internal network "
                    "interface. -admin. Visible by administrative users on "
                    "a secure network interface."
                ),
            },
            "service_id": {
                "type": "string",
                "description": "The UUID of the service to which the "
                "endpoint belongs",
            },
            "region_id": {
                "type": ["string", "null"],
                "description": (
                    "(Since v3.2) The ID of the region that contains the "
                    "service endpoint."
                ),
                "x-openstack": {"min-ver": 3.2},
            },
            "enabled": {
                "type": "boolean",
                "description": (
                    "Indicates whether the endpoint appears in the service "
                    "catalog -false. The endpoint does not appear in the "
                    "service catalog. -true. The endpoint appears in the "
                    "service catalog."
                ),
            },
        },
    },
    "name": {
        **parameter_types.name,
        "description": "The name of the endpoint group.",
    },
}

# Common schema of `Endpoint Group` resource
endpoint_group_schema: dict[str, Any] = {
    "type": "object",
    "description": "An endpoint group object.",
    "properties": {
        "id": {
            "type": "string",
            "readOnly": True,
            "description": "The endpoint group ID",
        },
        "links": response_types.resource_links,
        **_endpoint_group_properties,
    },
    "additionalProperties": False,
}

# Query parameters of the `/endpoint_groups` API
endpoint_group_index_request_query: dict[str, Any] = {
    "type": "object",
    "properties": {
        "name": {
            **parameter_types.name,
            "description": "The name of the endpoint group.",
        }
    },
    "additionalProperties": False,
}

# Response of the `/endpoint_groups` API
endpoint_group_index_response_body: dict[str, Any] = {
    "type": "object",
    "properties": {
        "endpoint_groups": {
            "type": "array",
            "items": endpoint_group_schema,
            "description": "A list of endpoint group objects",
        },
        "links": response_types.links,
        "truncated": response_types.truncated,
    },
    "additionalProperties": False,
}

# Response of the `/endpoint_groups/{endpoint_group_id}` API
# returning a single endpoint group
endpoint_group_response_body: dict[str, Any] = {
    "type": "object",
    "description": "An endpoint group object",
    "properties": {"endpoint_group": endpoint_group_schema},
    "additionalProperties": False,
}

# Request body of the `POST /endpoint_groups` operation
endpoint_group_create_request_body: dict[str, Any] = {
    "type": "object",
    "description": "An endpoint group object",
    "properties": {
        "endpoint_group": {
            "type": "object",
            "properties": _endpoint_group_properties,
            "required": ["name", "filters"],
            "additionalProperties": False,
        }
    },
    "additionalProperties": False,
}

# Request body of the `PATCH /endpoint_groups/{endpoint_group_id}` operation
endpoint_group_update_request_body: dict[str, Any] = {
    "type": "object",
    "description": "An endpoint group object",
    "properties": {
        "endpoint_group": {
            "type": "object",
            "properties": _endpoint_group_properties,
            "minProperties": 1,
            "additionalProperties": False,
        }
    },
    "required": ["endpoint_group"],
    "additionalProperties": False,
}
