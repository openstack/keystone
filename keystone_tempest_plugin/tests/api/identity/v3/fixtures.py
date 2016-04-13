# Copyright 2016 Red Hat, Inc.
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

from tempest.lib.common.utils import data_utils


def idp_ref(enabled=None, remote_ids=None):
    ref = {
        'description': data_utils.rand_uuid_hex(),
    }
    if enabled is not None:
        ref['enabled'] = enabled

    if remote_ids:
        ref['remote_ids'] = remote_ids

    return ref


def mapping_ref():
    rules = [{
        'local': [
            {
                'user': {'name': '{0}'}
            },
            {
                'group_ids': '{1}'
            }
        ],
        'remote': [
            {
                'type': 'openstack_username'
            },
            {
                'type': 'group_ids',
                'whitelist': ['abc', '123']
            }

        ]
    }]
    return {'rules': rules}


def sp_ref(enabled=None, relay_state_prefix=None):
    ref = {
        'auth_url': data_utils.rand_url(),
        'description': data_utils.rand_uuid_hex(),
        'sp_url': data_utils.rand_url(),
    }
    if enabled:
        ref['enabled'] = enabled

    if relay_state_prefix:
        ref['relay_state_prefix'] = relay_state_prefix

    return ref
