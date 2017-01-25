# Copyright 2013 Metacloud, Inc.
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

"""Workflow Logic the Resource service."""

import uuid

from six.moves import http_client

from keystone.common import controller
from keystone.common import dependency
from keystone.common import validation
from keystone.common import wsgi
import keystone.conf
from keystone import exception
from keystone.i18n import _
from keystone.resource import schema


CONF = keystone.conf.CONF


@dependency.requires('resource_api')
class Tenant(controller.V2Controller):

    @controller.v2_deprecated
    def get_all_projects(self, request, **kw):
        """Get a list of all tenants for an admin user."""
        self.assert_admin(request)

        name = request.params.get('name')
        if name:
            return self._get_project_by_name(name)

        try:
            tenant_refs = self.resource_api.list_projects_in_domain(
                CONF.identity.default_domain_id)
        except exception.DomainNotFound:
            # If the default domain doesn't exist then there are no V2
            # projects.
            tenant_refs = []
        tenant_refs = [self.v3_to_v2_project(tenant_ref)
                       for tenant_ref in tenant_refs
                       if not tenant_ref.get('is_domain')]
        params = {
            'limit': request.params.get('limit'),
            'marker': request.params.get('marker'),
        }
        return self.format_project_list(tenant_refs, **params)

    def _assert_not_is_domain_project(self, project_id, project_ref=None):
        # Projects acting as a domain should not be visible via v2
        if not project_ref:
            project_ref = self.resource_api.get_project(project_id)
        if project_ref.get('is_domain'):
            raise exception.ProjectNotFound(project_id)

    @controller.v2_deprecated
    def get_project(self, request, tenant_id):
        # TODO(termie): this stuff should probably be moved to middleware
        self.assert_admin(request)
        ref = self.resource_api.get_project(tenant_id)
        self._assert_not_is_domain_project(tenant_id, ref)
        return {'tenant': self.v3_to_v2_project(ref)}

    def _get_project_by_name(self, tenant_name):
        # Projects acting as a domain should not be visible via v2
        ref = self.resource_api.get_project_by_name(
            tenant_name, CONF.identity.default_domain_id)
        self._assert_not_is_domain_project(ref['id'], ref)
        return {'tenant': self.v3_to_v2_project(ref)}

    # CRUD Extension
    @controller.v2_deprecated
    def create_project(self, request, tenant):
        tenant_ref = self._normalize_dict(tenant)

        validation.lazy_validate(schema.tenant_create, tenant)
        self.assert_admin(request)

        self.resource_api.ensure_default_domain_exists()

        tenant_ref['id'] = tenant_ref.get('id', uuid.uuid4().hex)
        tenant = self.resource_api.create_project(
            tenant_ref['id'],
            self._normalize_domain_id(request, tenant_ref),
            initiator=request.audit_initiator)
        return {'tenant': self.v3_to_v2_project(tenant)}

    @controller.v2_deprecated
    def update_project(self, request, tenant_id, tenant):
        validation.lazy_validate(schema.tenant_update, tenant)
        self.assert_admin(request)
        self._assert_not_is_domain_project(tenant_id)

        tenant_ref = self.resource_api.update_project(
            tenant_id, tenant, initiator=request.audit_initiator)
        return {'tenant': self.v3_to_v2_project(tenant_ref)}

    @controller.v2_deprecated
    def delete_project(self, request, tenant_id):
        self.assert_admin(request)
        self._assert_not_is_domain_project(tenant_id)
        self.resource_api.delete_project(
            tenant_id,
            initiator=request.audit_initiator
        )


@dependency.requires('resource_api')
class DomainV3(controller.V3Controller):
    collection_name = 'domains'
    member_name = 'domain'

    def __init__(self):
        super(DomainV3, self).__init__()
        self.get_member_from_driver = self.resource_api.get_domain

    @controller.protected()
    def create_domain(self, request, domain):
        validation.lazy_validate(schema.domain_create, domain)
        ref = self._assign_unique_id(self._normalize_dict(domain))
        ref = self.resource_api.create_domain(
            ref['id'], ref, initiator=request.audit_initiator
        )
        return DomainV3.wrap_member(request.context_dict, ref)

    @controller.filterprotected('enabled', 'name')
    def list_domains(self, request, filters):
        hints = DomainV3.build_driver_hints(request, filters)
        refs = self.resource_api.list_domains(hints=hints)
        return DomainV3.wrap_collection(request.context_dict,
                                        refs, hints=hints)

    @controller.protected()
    def get_domain(self, request, domain_id):
        ref = self.resource_api.get_domain(domain_id)
        return DomainV3.wrap_member(request.context_dict, ref)

    @controller.protected()
    def update_domain(self, request, domain_id, domain):
        validation.lazy_validate(schema.domain_update, domain)
        self._require_matching_id(domain_id, domain)
        ref = self.resource_api.update_domain(
            domain_id, domain, initiator=request.audit_initiator
        )
        return DomainV3.wrap_member(request.context_dict, ref)

    @controller.protected()
    def delete_domain(self, request, domain_id):
        return self.resource_api.delete_domain(
            domain_id, initiator=request.audit_initiator
        )


@dependency.requires('domain_config_api')
@dependency.requires('resource_api')
class DomainConfigV3(controller.V3Controller):
    member_name = 'config'

    @controller.protected()
    def create_domain_config(self, request, domain_id, config):
        self.resource_api.get_domain(domain_id)
        original_config = (
            self.domain_config_api.get_config_with_sensitive_info(domain_id))
        ref = self.domain_config_api.create_config(domain_id, config)
        if original_config:
            # Return status code 200, since config already existed
            return wsgi.render_response(body={self.member_name: ref})
        else:
            return wsgi.render_response(
                body={self.member_name: ref},
                status=(http_client.CREATED,
                        http_client.responses[http_client.CREATED]))

    def get_domain_config_wrapper(self, request, domain_id, group=None,
                                  option=None):
        if group and group == 'security_compliance':
            return self.get_security_compliance_domain_config(
                request, domain_id, group=group, option=option
            )
        else:
            return self.get_domain_config(
                request, domain_id, group=group, option=option
            )

    @controller.protected()
    def get_security_compliance_domain_config(self, request, domain_id,
                                              group=None, option=None):
        ref = self.domain_config_api.get_security_compliance_config(
            domain_id, group, option=option
        )
        return {self.member_name: ref}

    @controller.protected()
    def get_domain_config(self, request, domain_id, group=None, option=None):
        self.resource_api.get_domain(domain_id)
        ref = self.domain_config_api.get_config(domain_id, group, option)
        return {self.member_name: ref}

    @controller.protected()
    def update_domain_config(
            self, request, domain_id, config, group, option):
        self.resource_api.get_domain(domain_id)
        ref = self.domain_config_api.update_config(
            domain_id, config, group, option)
        return wsgi.render_response(body={self.member_name: ref})

    def update_domain_config_group(self, context, domain_id, group, config):
        self.resource_api.get_domain(domain_id)
        return self.update_domain_config(
            context, domain_id, config, group, option=None)

    def update_domain_config_only(self, context, domain_id, config):
        self.resource_api.get_domain(domain_id)
        return self.update_domain_config(
            context, domain_id, config, group=None, option=None)

    @controller.protected()
    def delete_domain_config(
            self, request, domain_id, group=None, option=None):
        self.resource_api.get_domain(domain_id)
        self.domain_config_api.delete_config(domain_id, group, option)

    @controller.protected()
    def get_domain_config_default(self, request, group=None, option=None):
        ref = self.domain_config_api.get_config_default(group, option)
        return {self.member_name: ref}


@dependency.requires('resource_api')
class ProjectV3(controller.V3Controller):
    collection_name = 'projects'
    member_name = 'project'

    def __init__(self):
        super(ProjectV3, self).__init__()
        self.get_member_from_driver = self.resource_api.get_project

    @controller.protected()
    def create_project(self, request, project):
        validation.lazy_validate(schema.project_create, project)
        ref = self._assign_unique_id(self._normalize_dict(project))

        if not ref.get('is_domain'):
            ref = self._normalize_domain_id(request, ref)
        # Our API requires that you specify the location in the hierarchy
        # unambiguously. This could be by parent_id or, if it is a top level
        # project, just by providing a domain_id.
        if not ref.get('parent_id'):
            ref['parent_id'] = ref.get('domain_id')

        try:
            ref = self.resource_api.create_project(
                ref['id'],
                ref,
                initiator=request.audit_initiator)
        except (exception.DomainNotFound, exception.ProjectNotFound) as e:
            raise exception.ValidationError(e)
        return ProjectV3.wrap_member(request.context_dict, ref)

    @controller.filterprotected('domain_id', 'enabled', 'name',
                                'parent_id', 'is_domain')
    def list_projects(self, request, filters):
        hints = ProjectV3.build_driver_hints(request, filters)
        # If 'is_domain' has not been included as a query, we default it to
        # False (which in query terms means '0')
        if 'is_domain' not in request.params:
            hints.add_filter('is_domain', '0')
        refs = self.resource_api.list_projects(hints=hints)
        return ProjectV3.wrap_collection(request.context_dict,
                                         refs, hints=hints)

    def _expand_project_ref(self, request, ref):
        params = request.params
        context = request.context_dict

        parents_as_list = 'parents_as_list' in params and (
            self.query_filter_is_true(params['parents_as_list']))
        parents_as_ids = 'parents_as_ids' in params and (
            self.query_filter_is_true(params['parents_as_ids']))

        subtree_as_list = 'subtree_as_list' in params and (
            self.query_filter_is_true(params['subtree_as_list']))
        subtree_as_ids = 'subtree_as_ids' in params and (
            self.query_filter_is_true(params['subtree_as_ids']))

        # parents_as_list and parents_as_ids are mutually exclusive
        if parents_as_list and parents_as_ids:
            msg = _('Cannot use parents_as_list and parents_as_ids query '
                    'params at the same time.')
            raise exception.ValidationError(msg)

        # subtree_as_list and subtree_as_ids are mutually exclusive
        if subtree_as_list and subtree_as_ids:
            msg = _('Cannot use subtree_as_list and subtree_as_ids query '
                    'params at the same time.')
            raise exception.ValidationError(msg)

        if parents_as_list:
            parents = self.resource_api.list_project_parents(
                ref['id'], request.context.user_id)
            ref['parents'] = [ProjectV3.wrap_member(context, p)
                              for p in parents]
        elif parents_as_ids:
            ref['parents'] = self.resource_api.get_project_parents_as_ids(ref)

        if subtree_as_list:
            subtree = self.resource_api.list_projects_in_subtree(
                ref['id'], request.context.user_id)
            ref['subtree'] = [ProjectV3.wrap_member(context, p)
                              for p in subtree]
        elif subtree_as_ids:
            ref['subtree'] = self.resource_api.get_projects_in_subtree_as_ids(
                ref['id'])

    @controller.protected()
    def get_project(self, request, project_id):
        ref = self.resource_api.get_project(project_id)
        self._expand_project_ref(request, ref)
        return ProjectV3.wrap_member(request.context_dict, ref)

    @controller.protected()
    def update_project(self, request, project_id, project):
        validation.lazy_validate(schema.project_update, project)
        self._require_matching_id(project_id, project)
        ref = self.resource_api.update_project(
            project_id,
            project,
            initiator=request.audit_initiator)
        return ProjectV3.wrap_member(request.context_dict, ref)

    @controller.protected()
    def delete_project(self, request, project_id):
        return self.resource_api.delete_project(
            project_id,
            initiator=request.audit_initiator)
