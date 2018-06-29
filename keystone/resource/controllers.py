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

from six.moves import http_client

from keystone.common import controller
from keystone.common import provider_api
from keystone.common import validation
from keystone.common import wsgi
import keystone.conf
from keystone import exception
from keystone.i18n import _
from keystone.resource import schema


CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs


class DomainV3(controller.V3Controller):
    collection_name = 'domains'
    member_name = 'domain'

    def __init__(self):
        super(DomainV3, self).__init__()
        self.get_member_from_driver = PROVIDERS.resource_api.get_domain

    @controller.protected()
    def create_domain(self, request, domain):
        validation.lazy_validate(schema.domain_create, domain)
        ref = self._assign_unique_id(self._normalize_dict(domain))
        ref = PROVIDERS.resource_api.create_domain(
            ref['id'], ref, initiator=request.audit_initiator
        )
        return DomainV3.wrap_member(request.context_dict, ref)

    @controller.filterprotected('enabled', 'name')
    def list_domains(self, request, filters):
        hints = DomainV3.build_driver_hints(request, filters)
        refs = PROVIDERS.resource_api.list_domains(hints=hints)
        return DomainV3.wrap_collection(request.context_dict,
                                        refs, hints=hints)

    @controller.protected()
    def get_domain(self, request, domain_id):
        ref = PROVIDERS.resource_api.get_domain(domain_id)
        return DomainV3.wrap_member(request.context_dict, ref)

    @controller.protected()
    def update_domain(self, request, domain_id, domain):
        validation.lazy_validate(schema.domain_update, domain)
        self._require_matching_id(domain_id, domain)
        ref = PROVIDERS.resource_api.update_domain(
            domain_id, domain, initiator=request.audit_initiator
        )
        return DomainV3.wrap_member(request.context_dict, ref)

    @controller.protected()
    def delete_domain(self, request, domain_id):
        return PROVIDERS.resource_api.delete_domain(
            domain_id, initiator=request.audit_initiator
        )


class DomainConfigV3(controller.V3Controller):
    member_name = 'config'

    @controller.protected()
    def create_domain_config(self, request, domain_id, config):
        PROVIDERS.resource_api.get_domain(domain_id)
        original_config = (
            PROVIDERS.domain_config_api.get_config_with_sensitive_info(
                domain_id
            )
        )
        ref = PROVIDERS.domain_config_api.create_config(domain_id, config)
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
        ref = PROVIDERS.domain_config_api.get_security_compliance_config(
            domain_id, group, option=option
        )
        return {self.member_name: ref}

    @controller.protected()
    def get_domain_config(self, request, domain_id, group=None, option=None):
        PROVIDERS.resource_api.get_domain(domain_id)
        ref = PROVIDERS.domain_config_api.get_config(domain_id, group, option)
        return {self.member_name: ref}

    @controller.protected()
    def update_domain_config(
            self, request, domain_id, config, group, option):
        PROVIDERS.resource_api.get_domain(domain_id)
        ref = PROVIDERS.domain_config_api.update_config(
            domain_id, config, group, option)
        return wsgi.render_response(body={self.member_name: ref})

    def update_domain_config_group(self, context, domain_id, group, config):
        PROVIDERS.resource_api.get_domain(domain_id)
        return self.update_domain_config(
            context, domain_id, config, group, option=None)

    def update_domain_config_only(self, context, domain_id, config):
        PROVIDERS.resource_api.get_domain(domain_id)
        return self.update_domain_config(
            context, domain_id, config, group=None, option=None)

    @controller.protected()
    def delete_domain_config(
            self, request, domain_id, group=None, option=None):
        PROVIDERS.resource_api.get_domain(domain_id)
        PROVIDERS.domain_config_api.delete_config(domain_id, group, option)

    @controller.protected()
    def get_domain_config_default(self, request, group=None, option=None):
        ref = PROVIDERS.domain_config_api.get_config_default(group, option)
        return {self.member_name: ref}


class ProjectV3(controller.V3Controller):
    collection_name = 'projects'
    member_name = 'project'

    def __init__(self):
        super(ProjectV3, self).__init__()
        self.get_member_from_driver = PROVIDERS.resource_api.get_project

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
            ref = PROVIDERS.resource_api.create_project(
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
        # If any tags filters are passed in when listing projects, add them
        # to the hint filters
        tag_params = ['tags', 'tags-any', 'not-tags', 'not-tags-any']
        for t in tag_params:
            if t in request.params:
                hints.add_filter(t, request.params[t])
        refs = PROVIDERS.resource_api.list_projects(hints=hints)
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
        include_limits = 'include_limits' in params and (
            self.query_filter_is_true(params['include_limits']))

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
            parents = PROVIDERS.resource_api.list_project_parents(
                ref['id'], request.context.user_id, include_limits)
            ref['parents'] = [ProjectV3.wrap_member(context, p)
                              for p in parents]
        elif parents_as_ids:
            ref['parents'] = PROVIDERS.resource_api.get_project_parents_as_ids(
                ref
            )

        if subtree_as_list:
            subtree = PROVIDERS.resource_api.list_projects_in_subtree(
                ref['id'], request.context.user_id, include_limits)
            ref['subtree'] = [ProjectV3.wrap_member(context, p)
                              for p in subtree]
        elif subtree_as_ids:
            ref['subtree'] = (
                PROVIDERS.resource_api.get_projects_in_subtree_as_ids(
                    ref['id']
                )
            )

    @controller.protected()
    def get_project(self, request, project_id):
        ref = PROVIDERS.resource_api.get_project(project_id)
        self._expand_project_ref(request, ref)
        return ProjectV3.wrap_member(request.context_dict, ref)

    @controller.protected()
    def update_project(self, request, project_id, project):
        validation.lazy_validate(schema.project_update, project)
        self._require_matching_id(project_id, project)
        ref = PROVIDERS.resource_api.update_project(
            project_id,
            project,
            initiator=request.audit_initiator)
        return ProjectV3.wrap_member(request.context_dict, ref)

    @controller.protected()
    def delete_project(self, request, project_id):
        return PROVIDERS.resource_api.delete_project(
            project_id,
            initiator=request.audit_initiator)


class ProjectTagV3(controller.V3Controller):
    collection_name = 'projects'
    member_name = 'tags'

    def __init__(self):
        super(ProjectTagV3, self).__init__()
        self.get_member_from_driver = PROVIDERS.resource_api.get_project_tag

    @classmethod
    def wrap_member(cls, context, ref):
        # NOTE(gagehugo): Overriding this due to how the common controller
        # expects the ref to have an id, which for tags it does not.
        new_ref = {'links': {'self': cls.full_url(context)}}
        new_ref[cls.member_name] = (ref or [])
        return new_ref

    @classmethod
    def wrap_header(cls, context, query):
        # NOTE(gagehugo: The API spec for tags has a specific guideline for
        # what to return when adding a single tag. This wrapper handles
        # returning the specified url in the header while the body is empty.
        context['environment']['QUERY_STRING'] = '/' + query
        url = cls.full_url(context)
        headers = [('Location', url.replace('?', ''))]
        status = (http_client.CREATED,
                  http_client.responses[http_client.CREATED])
        return wsgi.render_response(status=status, headers=headers)

    @controller.protected()
    def create_project_tag(self, request, project_id, value):
        validation.lazy_validate(schema.project_tag_create, value)
        # Check if we will exceed the max number of tags on this project
        tags = PROVIDERS.resource_api.list_project_tags(project_id)
        tags.append(value)
        validation.lazy_validate(schema.project_tags_update, tags)
        PROVIDERS.resource_api.create_project_tag(
            project_id, value, initiator=request.audit_initiator)
        query = '/'.join((project_id, 'tags', value))
        return ProjectTagV3.wrap_header(request.context_dict, query)

    @controller.protected()
    def get_project_tag(self, request, project_id, value):
        PROVIDERS.resource_api.get_project_tag(project_id, value)

    @controller.protected()
    def delete_project_tag(self, request, project_id, value):
        PROVIDERS.resource_api.delete_project_tag(project_id, value)

    @controller.protected()
    def list_project_tags(self, request, project_id):
        ref = PROVIDERS.resource_api.list_project_tags(project_id)
        return ProjectTagV3.wrap_member(request.context_dict, ref)

    @controller.protected()
    def update_project_tags(self, request, project_id, tags):
        validation.lazy_validate(schema.project_tags_update, tags)
        ref = PROVIDERS.resource_api.update_project_tags(
            project_id, tags, initiator=request.audit_initiator)
        return ProjectTagV3.wrap_member(request.context_dict, ref)

    @controller.protected()
    def delete_project_tags(self, request, project_id):
        PROVIDERS.resource_api.update_project_tags(project_id, [])
