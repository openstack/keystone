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

# Implement the "Immutable" resource option
from keystone.common.resource_options import core as ro_core
from keystone.common.validation import parameter_types
from keystone import exception

IMMUTABLE_OPT = (
    ro_core.ResourceOption(
        option_id='IMMU',
        option_name='immutable',
        validator=ro_core.boolean_validator,
        json_schema_validation=parameter_types.boolean
    ))


def check_resource_immutable(resource_ref):
    """Check to see if a resource is immutable.

    :param resource_ref: a dict reference of a resource to inspect
    """
    return resource_ref.get('options', {}).get(
        IMMUTABLE_OPT.option_name, False)


def check_immutable_update(original_resource_ref, new_resource_ref, type,
                           resource_id):
    """Check if an update is allowed to an immutable resource.

    Valid cases where an update is allowed:

        * Resource is not immutable
        * Resource is immutable, and update to set immutable to False or None

    :param original_resource_ref: a dict resource reference representing
                                  the current resource
    :param new_resource_ref: a dict reference of the updates to perform
    :param type: the resource type, e.g. 'project'
    :param resource_id: the id of the resource (e.g. project['id']),
                        usually a UUID
    :raises: ResourceUpdateForbidden
    """
    immutable = check_resource_immutable(original_resource_ref)
    if immutable:
        new_options = new_resource_ref.get('options', {})
        if ((len(new_resource_ref.keys()) > 1) or
                (IMMUTABLE_OPT.option_name not in new_options) or
                (new_options[IMMUTABLE_OPT.option_name] not in (False, None))):
            raise exception.ResourceUpdateForbidden(
                type=type, resource_id=resource_id)


def check_immutable_delete(resource_ref, resource_type, resource_id):
    """Check if a delete is allowed on a resource.

    :param resource_ref: dict reference of the resource
    :param resource_type: resource type (str) e.g. 'project'
    :param resource_id: id of the resource (str) e.g. project['id']
    :raises: ResourceDeleteForbidden
    """
    if check_resource_immutable(resource_ref):
        raise exception.ResourceDeleteForbidden(
            type=resource_type, resource_id=resource_id)
