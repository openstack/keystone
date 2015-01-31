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

from keystone.common import controller
from keystone.common import dependency
from keystone.common import validation
from keystone import notifications
from keystone.policy import schema


@dependency.requires('policy_api')
class PolicyV3(controller.V3Controller):
    collection_name = 'policies'
    member_name = 'policy'

    @controller.protected()
    @validation.validated(schema.policy_create, 'policy')
    def create_policy(self, context, policy):
        ref = self._assign_unique_id(self._normalize_dict(policy))
        initiator = notifications._get_request_audit_info(context)
        ref = self.policy_api.create_policy(ref['id'], ref, initiator)
        return PolicyV3.wrap_member(context, ref)

    @controller.filterprotected('type')
    def list_policies(self, context, filters):
        hints = PolicyV3.build_driver_hints(context, filters)
        refs = self.policy_api.list_policies(hints=hints)
        return PolicyV3.wrap_collection(context, refs, hints=hints)

    @controller.protected()
    def get_policy(self, context, policy_id):
        ref = self.policy_api.get_policy(policy_id)
        return PolicyV3.wrap_member(context, ref)

    @controller.protected()
    @validation.validated(schema.policy_update, 'policy')
    def update_policy(self, context, policy_id, policy):
        initiator = notifications._get_request_audit_info(context)
        ref = self.policy_api.update_policy(policy_id, policy, initiator)
        return PolicyV3.wrap_member(context, ref)

    @controller.protected()
    def delete_policy(self, context, policy_id):
        initiator = notifications._get_request_audit_info(context)
        return self.policy_api.delete_policy(policy_id, initiator)
