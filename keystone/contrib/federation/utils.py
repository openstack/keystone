# vim: tabstop=4 shiftwidth=4 softtabstop=4

#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""Utilities for Federation Extension."""

import jsonschema

from keystone import exception


MAPPING_SCHEMA = {
    "type": "object",
    "properties": {
        "rules": {
            "minItems": 1,
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "local": {
                        "type": "array"
                    },
                    "remote": {
                        "minItems": 1,
                        "type": "array",
                        "items": {
                            "type": "object",
                            "oneOf": [
                                {"$ref": "#/definitions/empty"},
                                {"$ref": "#/definitions/any_one_of"},
                                {"$ref": "#/definitions/not_any_of"}
                            ],
                        }
                    }
                }
            }
        }
    },
    "definitions": {
        "empty": {
            "type": "object",
            "properties": {
                "required": ['type'],
                "type": {
                    "type": "string"
                },
            },
            "additionalProperties": False,
        },
        "any_one_of": {
            "type": "object",
            "additionalProperties": False,
            "required": ['type', 'any_one_of'],
            "properties": {
                "type": {
                    "type": "string"
                },
                "any_one_of": {
                    "type": "array"
                },
                "regex": {
                    "type": "boolean"
                }
            }
        },
        "not_any_of": {
            "type": "object",
            "additionalProperties": False,
            "required": ['type', 'not_any_of'],
            "properties": {
                "type": {
                    "type": "string"
                },
                "not_any_of": {
                    "type": "array"
                },
                "regex": {
                    "type": "boolean"
                }
            }
        }
    }
}


def validate_mapping_structure(ref):
        v = jsonschema.Draft4Validator(MAPPING_SCHEMA)

        messages = ''
        for error in sorted(v.iter_errors(ref), key=str):
            messages = messages + error.message + "\n"

        if messages:
            raise exception.ValidationError(messages)
