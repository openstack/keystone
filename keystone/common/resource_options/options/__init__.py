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

# All resource options are defined in this module. The individual resource
# implementations explicitly register the options that are desired directly
# in their individual registry. Each entry is imported from it's own
# module directly to allow for custom implementation details as needed.

from keystone.common.resource_options.options import immutable

__all__ = (
    'IMMUTABLE_OPT',
    'check_resource_immutable',
    'check_immutable_update',
    'check_immutable_delete',
)

# Immutable Option and helper functions
IMMUTABLE_OPT = immutable.IMMUTABLE_OPT
check_resource_immutable = immutable.check_resource_immutable
check_immutable_update = immutable.check_immutable_update
check_immutable_delete = immutable.check_immutable_delete
