# Copyright 2018 Huawei
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
from keystone.common import validation
from keystone import exception
from keystone.i18n import _
from keystone.limit import schema


class RegisteredLimitV3(controller.V3Controller):
    collection_name = 'registered_limits'
    member_name = 'registered_limit'

    def __init__(self):
        super(RegisteredLimitV3, self).__init__()
        self.get_member_from_driver = (
            self.unified_limit_api.get_registered_limit
        )

    @controller.protected()
    def create_registered_limits(self, request, registered_limits):
        validation.lazy_validate(schema.registered_limit_create,
                                 registered_limits)
        registered_limits = [self._assign_unique_id(self._normalize_dict(
            registered_limit)) for registered_limit in registered_limits]
        refs = self.unified_limit_api.create_registered_limits(
            registered_limits)
        refs = RegisteredLimitV3.wrap_collection(request.context_dict, refs)
        refs.pop("links")
        return refs

    @controller.protected()
    def update_registered_limits(self, request, registered_limits):
        validation.lazy_validate(schema.registered_limit_update,
                                 registered_limits)
        refs = self.unified_limit_api.update_registered_limits(
            [self._normalize_dict(registered_limit) for registered_limit in
             registered_limits])
        refs = RegisteredLimitV3.wrap_collection(request.context_dict, refs)
        refs.pop("links")
        return refs

    @controller.filterprotected('service_id', 'region_id', 'resource_name')
    def list_registered_limits(self, request, filters):
        hints = RegisteredLimitV3.build_driver_hints(request, filters)
        refs = self.unified_limit_api.list_registered_limits(hints)
        return RegisteredLimitV3.wrap_collection(request.context_dict, refs,
                                                 hints=hints)

    @controller.protected()
    def get_registered_limit(self, request, registered_limit_id):
        ref = self.unified_limit_api.get_registered_limit(
            registered_limit_id)
        return RegisteredLimitV3.wrap_member(request.context_dict, ref)

    @controller.protected()
    def delete_registered_limit(self, request, registered_limit_id):
        return self.unified_limit_api.delete_registered_limit(
            registered_limit_id)


class LimitV3(controller.V3Controller):
    collection_name = 'limits'
    member_name = 'limit'

    def __init__(self):
        super(LimitV3, self).__init__()
        self.get_member_from_driver = self.unified_limit_api.get_limit

    @controller.protected()
    def create_limits(self, request, limits):
        validation.lazy_validate(schema.limit_create, limits)
        limits = [self._assign_unique_id(self._normalize_dict(limit))
                  for limit in limits]
        refs = self.unified_limit_api.create_limits(limits)
        refs = LimitV3.wrap_collection(request.context_dict, refs)
        refs.pop("links")
        return refs

    @controller.protected()
    def update_limits(self, request, limits):
        validation.lazy_validate(schema.limit_update, limits)
        refs = self.unified_limit_api.update_limits(
            [self._normalize_dict(limit) for limit in limits])
        refs = LimitV3.wrap_collection(request.context_dict, refs)
        refs.pop("links")
        return refs

    @controller.filterprotected('service_id', 'region_id', 'resource_name')
    def list_limits(self, request, filters):
        hints = LimitV3.build_driver_hints(request, filters)
        # TODO(wxy): Add system-scope check. If the request is system-scoped,
        # it can get all limits.
        context = request.context
        if not context.is_admin and not ('admin' in context.roles):
            project_id = context.project_id
            if project_id:
                hints.add_filter('project_id', project_id)
        refs = self.unified_limit_api.list_limits(hints)
        return LimitV3.wrap_collection(request.context_dict, refs, hints=hints)

    @controller.protected()
    def get_limit(self, request, limit_id):
        ref = self.unified_limit_api.get_limit(limit_id)
        # TODO(wxy): Add system-scope check. If the request is system-scoped,
        # it can get any limits.
        context = request.context
        if not context.is_admin and not ('admin' in context.roles):
            project_id = context.project_id
            if project_id and project_id != ref['project_id']:
                action = _("The authenticated project should match the "
                           "project_id")
                raise exception.Forbidden(action=action)

        return LimitV3.wrap_member(request.context_dict, ref)

    @controller.protected()
    def delete_limit(self, request, limit_id):
        return self.unified_limit_api.delete_limit(limit_id)
