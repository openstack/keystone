# Copyright 2012 OpenStack Foundation
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

from oslo_log import versionutils
import six

from keystone.common import controller
from keystone.common import provider_api
from keystone.common import validation
from keystone.policy import schema


PROVIDERS = provider_api.ProviderAPIs


def policy_deprecated(f):
    @six.wraps(f)
    def wrapper(*args, **kwargs):
        deprecated = versionutils.deprecated(
            what=f.__name__ + ' of the v3 Policy APIs',
            as_of=versionutils.deprecated.QUEENS)
        return deprecated(f)
    return wrapper()


class PolicyV3(controller.V3Controller):
    collection_name = 'policies'
    member_name = 'policy'

    @policy_deprecated
    @controller.protected()
    def create_policy(self, request, policy):
        validation.lazy_validate(schema.policy_create, policy)
        ref = self._assign_unique_id(self._normalize_dict(policy))
        ref = PROVIDERS.policy_api.create_policy(
            ref['id'], ref, initiator=request.audit_initiator
        )
        return PolicyV3.wrap_member(request.context_dict, ref)

    @policy_deprecated
    @controller.filterprotected('type')
    def list_policies(self, request, filters):
        hints = PolicyV3.build_driver_hints(request, filters)
        refs = PROVIDERS.policy_api.list_policies(hints=hints)
        return PolicyV3.wrap_collection(request.context_dict,
                                        refs, hints=hints)

    @policy_deprecated
    @controller.protected()
    def get_policy(self, request, policy_id):
        ref = PROVIDERS.policy_api.get_policy(policy_id)
        return PolicyV3.wrap_member(request.context_dict, ref)

    @policy_deprecated
    @controller.protected()
    def update_policy(self, request, policy_id, policy):
        validation.lazy_validate(schema.policy_update, policy)
        ref = PROVIDERS.policy_api.update_policy(
            policy_id, policy, initiator=request.audit_initiator
        )
        return PolicyV3.wrap_member(request.context_dict, ref)

    @policy_deprecated
    @controller.protected()
    def delete_policy(self, request, policy_id):
        return PROVIDERS.policy_api.delete_policy(
            policy_id, initiator=request.audit_initiator
        )
