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

from oslo_config import cfg
from oslo_log import log

from keystone.common import controller
from keystone.common import dependency
from keystone.common import validation
from keystone.common import wsgi
from keystone import exception
from keystone.i18n import _
from keystone import notifications
from keystone.resource import schema


CONF = cfg.CONF
LOG = log.getLogger(__name__)


@dependency.requires('resource_api')
class Tenant(controller.V2Controller):

    @controller.v2_deprecated
    def get_all_projects(self, context, **kw):
        """Gets a list of all tenants for an admin user."""
        if 'name' in context['query_string']:
            return self.get_project_by_name(
                context, context['query_string'].get('name'))

        self.assert_admin(context)
        tenant_refs = self.resource_api.list_projects_in_domain(
            CONF.identity.default_domain_id)
        tenant_refs = [self.v3_to_v2_project(tenant_ref)
                       for tenant_ref in tenant_refs
                       if not tenant_ref.get('is_domain')]
        params = {
            'limit': context['query_string'].get('limit'),
            'marker': context['query_string'].get('marker'),
        }
        return self.format_project_list(tenant_refs, **params)

    def _assert_not_is_domain_project(self, project_id, project_ref=None):
        # Projects acting as a domain should not be visible via v2
        if not project_ref:
            project_ref = self.resource_api.get_project(project_id)
        if project_ref.get('is_domain'):
            raise exception.ProjectNotFound(project_id)

    @controller.v2_deprecated
    def get_project(self, context, tenant_id):
        # TODO(termie): this stuff should probably be moved to middleware
        self.assert_admin(context)
        ref = self.resource_api.get_project(tenant_id)
        self._assert_not_is_domain_project(tenant_id, ref)
        return {'tenant': self.v3_to_v2_project(ref)}

    @controller.v2_deprecated
    def get_project_by_name(self, context, tenant_name):
        self.assert_admin(context)
        # Projects acting as a domain should not be visible via v2
        ref = self.resource_api.get_project_by_name(
            tenant_name, CONF.identity.default_domain_id)
        return {'tenant': self.v3_to_v2_project(ref)}

    # CRUD Extension
    @controller.v2_deprecated
    def create_project(self, context, tenant):
        tenant_ref = self._normalize_dict(tenant)

        if 'name' not in tenant_ref or not tenant_ref['name']:
            msg = _('Name field is required and cannot be empty')
            raise exception.ValidationError(message=msg)

        self.assert_admin(context)
        tenant_ref['id'] = tenant_ref.get('id', uuid.uuid4().hex)
        tenant = self.resource_api.create_project(
            tenant_ref['id'],
            self._normalize_domain_id(context, tenant_ref))
        return {'tenant': self.v3_to_v2_project(tenant)}

    @controller.v2_deprecated
    def update_project(self, context, tenant_id, tenant):
        self.assert_admin(context)
        self._assert_not_is_domain_project(tenant_id)
        # Remove domain_id and is_domain if specified - a v2 api caller
        # should not be specifying that
        clean_tenant = tenant.copy()
        clean_tenant.pop('domain_id', None)
        clean_tenant.pop('is_domain', None)
        tenant_ref = self.resource_api.update_project(
            tenant_id, clean_tenant)
        return {'tenant': self.v3_to_v2_project(tenant_ref)}

    @controller.v2_deprecated
    def delete_project(self, context, tenant_id):
        self.assert_admin(context)
        self._assert_not_is_domain_project(tenant_id)
        self.resource_api.delete_project(tenant_id)


@dependency.requires('resource_api')
class DomainV3(controller.V3Controller):
    collection_name = 'domains'
    member_name = 'domain'

    def __init__(self):
        super(DomainV3, self).__init__()
        self.get_member_from_driver = self.resource_api.get_domain

    @controller.protected()
    @validation.validated(schema.domain_create, 'domain')
    def create_domain(self, context, domain):
        ref = self._assign_unique_id(self._normalize_dict(domain))
        initiator = notifications._get_request_audit_info(context)
        ref = self.resource_api.create_domain(ref['id'], ref, initiator)
        return DomainV3.wrap_member(context, ref)

    @controller.filterprotected('enabled', 'name')
    def list_domains(self, context, filters):
        hints = DomainV3.build_driver_hints(context, filters)
        refs = self.resource_api.list_domains(hints=hints)
        return DomainV3.wrap_collection(context, refs, hints=hints)

    @controller.protected()
    def get_domain(self, context, domain_id):
        ref = self.resource_api.get_domain(domain_id)
        return DomainV3.wrap_member(context, ref)

    @controller.protected()
    @validation.validated(schema.domain_update, 'domain')
    def update_domain(self, context, domain_id, domain):
        self._require_matching_id(domain_id, domain)
        initiator = notifications._get_request_audit_info(context)
        ref = self.resource_api.update_domain(domain_id, domain, initiator)
        return DomainV3.wrap_member(context, ref)

    @controller.protected()
    def delete_domain(self, context, domain_id):
        initiator = notifications._get_request_audit_info(context)
        return self.resource_api.delete_domain(domain_id, initiator)


@dependency.requires('domain_config_api')
class DomainConfigV3(controller.V3Controller):
    member_name = 'config'

    @controller.protected()
    def create_domain_config(self, context, domain_id, config):
        original_config = (
            self.domain_config_api.get_config_with_sensitive_info(domain_id))
        ref = self.domain_config_api.create_config(domain_id, config)
        if original_config:
            # Return status code 200, since config already existed
            return wsgi.render_response(body={self.member_name: ref})
        else:
            return wsgi.render_response(body={self.member_name: ref},
                                        status=('201', 'Created'))

    @controller.protected()
    def get_domain_config(self, context, domain_id, group=None, option=None):
        ref = self.domain_config_api.get_config(domain_id, group, option)
        return {self.member_name: ref}

    @controller.protected()
    def update_domain_config(
            self, context, domain_id, config, group, option):
        ref = self.domain_config_api.update_config(
            domain_id, config, group, option)
        return wsgi.render_response(body={self.member_name: ref})

    def update_domain_config_group(self, context, domain_id, group, config):
        return self.update_domain_config(
            context, domain_id, config, group, option=None)

    def update_domain_config_only(self, context, domain_id, config):
        return self.update_domain_config(
            context, domain_id, config, group=None, option=None)

    @controller.protected()
    def delete_domain_config(
            self, context, domain_id, group=None, option=None):
        self.domain_config_api.delete_config(domain_id, group, option)


@dependency.requires('resource_api')
class ProjectV3(controller.V3Controller):
    collection_name = 'projects'
    member_name = 'project'

    def __init__(self):
        super(ProjectV3, self).__init__()
        self.get_member_from_driver = self.resource_api.get_project

    @controller.protected()
    @validation.validated(schema.project_create, 'project')
    def create_project(self, context, project):
        ref = self._assign_unique_id(self._normalize_dict(project))
        ref = self._normalize_domain_id(context, ref)

        if ref.get('is_domain'):
            msg = _('The creation of projects acting as domains is not '
                    'allowed yet.')
            raise exception.NotImplemented(msg)

        initiator = notifications._get_request_audit_info(context)
        try:
            ref = self.resource_api.create_project(ref['id'], ref,
                                                   initiator=initiator)
        except exception.DomainNotFound as e:
            raise exception.ValidationError(e)
        return ProjectV3.wrap_member(context, ref)

    @controller.filterprotected('domain_id', 'enabled', 'name',
                                'parent_id')
    def list_projects(self, context, filters):
        hints = ProjectV3.build_driver_hints(context, filters)
        refs = self.resource_api.list_projects(hints=hints)
        return ProjectV3.wrap_collection(context, refs, hints=hints)

    def _expand_project_ref(self, context, ref):
        params = context['query_string']

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

        user_id = self.get_auth_context(context).get('user_id')

        if parents_as_list:
            parents = self.resource_api.list_project_parents(
                ref['id'], user_id)
            ref['parents'] = [ProjectV3.wrap_member(context, p)
                              for p in parents]
        elif parents_as_ids:
            ref['parents'] = self.resource_api.get_project_parents_as_ids(ref)

        if subtree_as_list:
            subtree = self.resource_api.list_projects_in_subtree(
                ref['id'], user_id)
            ref['subtree'] = [ProjectV3.wrap_member(context, p)
                              for p in subtree]
        elif subtree_as_ids:
            ref['subtree'] = self.resource_api.get_projects_in_subtree_as_ids(
                ref['id'])

    @controller.protected()
    def get_project(self, context, project_id):
        ref = self.resource_api.get_project(project_id)
        self._expand_project_ref(context, ref)
        return ProjectV3.wrap_member(context, ref)

    @controller.protected()
    @validation.validated(schema.project_update, 'project')
    def update_project(self, context, project_id, project):
        self._require_matching_id(project_id, project)
        self._require_matching_domain_id(
            project_id, project, self.resource_api.get_project)
        initiator = notifications._get_request_audit_info(context)
        ref = self.resource_api.update_project(project_id, project,
                                               initiator=initiator)
        return ProjectV3.wrap_member(context, ref)

    @controller.protected()
    def delete_project(self, context, project_id):
        initiator = notifications._get_request_audit_info(context)
        return self.resource_api.delete_project(project_id,
                                                initiator=initiator)
