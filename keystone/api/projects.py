#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

# This file handles all flask-restful resources for /v3/projects

import functools

import flask
import http.client

from keystone.common import json_home
from keystone.common import provider_api
from keystone.common import rbac_enforcer
from keystone.common import validation
import keystone.conf
from keystone import exception
from keystone.i18n import _
from keystone.resource import schema
from keystone.server import flask as ks_flask

CONF = keystone.conf.CONF
ENFORCER = rbac_enforcer.RBACEnforcer
PROVIDERS = provider_api.ProviderAPIs


def _build_project_target_enforcement():
    target = {}
    try:
        target['project'] = PROVIDERS.resource_api.get_project(
            flask.request.view_args.get('project_id')
        )
    except exception.NotFound:  # nosec
        # Defer existence in the event the project doesn't exist, we'll
        # check this later anyway.
        pass

    return target


class ProjectResource(ks_flask.ResourceBase):
    collection_key = 'projects'
    member_key = 'project'
    get_member_from_driver = PROVIDERS.deferred_provider_lookup(
        api='resource_api', method='get_project')

    def _expand_project_ref(self, ref):
        parents_as_list = self.query_filter_is_true('parents_as_list')
        parents_as_ids = self.query_filter_is_true('parents_as_ids')

        subtree_as_list = self.query_filter_is_true('subtree_as_list')

        subtree_as_ids = self.query_filter_is_true('subtree_as_ids')
        include_limits = self.query_filter_is_true('include_limits')

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
                ref['id'], self.oslo_context.user_id, include_limits)
            ref['parents'] = [self.wrap_member(p)
                              for p in parents]
        elif parents_as_ids:
            ref['parents'] = PROVIDERS.resource_api.get_project_parents_as_ids(
                ref
            )

        if subtree_as_list:
            subtree = PROVIDERS.resource_api.list_projects_in_subtree(
                ref['id'], self.oslo_context.user_id, include_limits)
            ref['subtree'] = [self.wrap_member(p)
                              for p in subtree]
        elif subtree_as_ids:
            ref['subtree'] = (
                PROVIDERS.resource_api.get_projects_in_subtree_as_ids(
                    ref['id']
                )
            )

    def _get_project(self, project_id):
        """Get project.

        GET/HEAD /v3/projects/{project_id}
        """
        ENFORCER.enforce_call(
            action='identity:get_project',
            build_target=_build_project_target_enforcement
        )
        project = PROVIDERS.resource_api.get_project(project_id)
        self._expand_project_ref(project)
        return self.wrap_member(project)

    def _list_projects(self):
        """List projects.

        GET/HEAD /v3/projects
        """
        filters = ('domain_id', 'enabled', 'name', 'parent_id', 'is_domain')
        target = None
        if self.oslo_context.domain_id:
            target = {'domain_id': self.oslo_context.domain_id}
        ENFORCER.enforce_call(action='identity:list_projects',
                              filters=filters,
                              target_attr=target)
        hints = self.build_driver_hints(filters)

        # If 'is_domain' has not been included as a query, we default it to
        # False (which in query terms means '0')
        if 'is_domain' not in flask.request.args:
            hints.add_filter('is_domain', '0')

        tag_params = ['tags', 'tags-any', 'not-tags', 'not-tags-any']
        for t in tag_params:
            if t in flask.request.args:
                hints.add_filter(t, flask.request.args[t])
        refs = PROVIDERS.resource_api.list_projects(hints=hints)
        if self.oslo_context.domain_id:
            domain_id = self.oslo_context.domain_id
            filtered_refs = [
                ref for ref in refs if ref['domain_id'] == domain_id
            ]
        else:
            filtered_refs = refs
        return self.wrap_collection(filtered_refs, hints=hints)

    def get(self, project_id=None):
        """Get project or list projects.

        GET/HEAD /v3/projects
        GET/HEAD /v3/projects/{project_id}
        """
        if project_id is not None:
            return self._get_project(project_id)
        else:
            return self._list_projects()

    def post(self):
        """Create project.

        POST /v3/projects
        """
        project = self.request_body_json.get('project', {})
        target = {'project': project}
        ENFORCER.enforce_call(
            action='identity:create_project', target_attr=target
        )
        validation.lazy_validate(schema.project_create, project)
        project = self._assign_unique_id(project)
        if not project.get('is_domain'):
            project = self._normalize_domain_id(project)
            # Our API requires that you specify the location in the hierarchy
            # unambiguously. This could be by parent_id or, if it is a top
            # level project, just by providing a domain_id.
        if not project.get('parent_id'):
            project['parent_id'] = project.get('domain_id')
        project = self._normalize_dict(project)
        try:
            ref = PROVIDERS.resource_api.create_project(
                project['id'],
                project,
                initiator=self.audit_initiator)
        except (exception.DomainNotFound, exception.ProjectNotFound) as e:
            raise exception.ValidationError(e)
        return self.wrap_member(ref), http.client.CREATED

    def patch(self, project_id):
        """Update project.

        PATCH /v3/projects/{project_id}
        """
        ENFORCER.enforce_call(
            action='identity:update_project',
            build_target=_build_project_target_enforcement
        )
        project = self.request_body_json.get('project', {})
        validation.lazy_validate(schema.project_update, project)
        self._require_matching_id(project)
        ref = PROVIDERS.resource_api.update_project(
            project_id,
            project,
            initiator=self.audit_initiator)
        return self.wrap_member(ref)

    def delete(self, project_id):
        """Delete project.

        DELETE /v3/projects/{project_id}
        """
        ENFORCER.enforce_call(
            action='identity:delete_project',
            build_target=_build_project_target_enforcement
        )
        PROVIDERS.resource_api.delete_project(
            project_id,
            initiator=self.audit_initiator)
        return None, http.client.NO_CONTENT


class _ProjectTagResourceBase(ks_flask.ResourceBase):
    collection_key = 'projects'
    member_key = 'tags'
    get_member_from_driver = PROVIDERS.deferred_provider_lookup(
        api='resource_api', method='get_project_tag')

    @classmethod
    def wrap_member(cls, ref, collection_name=None, member_name=None):
        member_name = member_name or cls.member_key
        # NOTE(gagehugo): Overriding this due to how the common controller
        # expects the ref to have an id, which for tags it does not.
        new_ref = {'links': {'self': ks_flask.full_url()}}
        new_ref[member_name] = (ref or [])
        return new_ref


class ProjectTagsResource(_ProjectTagResourceBase):
    def get(self, project_id):
        """List tags associated with a given project.

        GET /v3/projects/{project_id}/tags
        """
        ENFORCER.enforce_call(
            action='identity:list_project_tags',
            build_target=_build_project_target_enforcement
        )
        ref = PROVIDERS.resource_api.list_project_tags(project_id)
        return self.wrap_member(ref)

    def put(self, project_id):
        """Update all tags associated with a given project.

        PUT /v3/projects/{project_id}/tags
        """
        ENFORCER.enforce_call(
            action='identity:update_project_tags',
            build_target=_build_project_target_enforcement
        )
        tags = self.request_body_json.get('tags', {})
        validation.lazy_validate(schema.project_tags_update, tags)
        ref = PROVIDERS.resource_api.update_project_tags(
            project_id, tags, initiator=self.audit_initiator)
        return self.wrap_member(ref)

    def delete(self, project_id):
        """Delete all tags associated with a given project.

        DELETE /v3/projects/{project_id}/tags
        """
        ENFORCER.enforce_call(
            action='identity:delete_project_tags',
            build_target=_build_project_target_enforcement
        )
        PROVIDERS.resource_api.update_project_tags(project_id, [])
        return None, http.client.NO_CONTENT


class ProjectTagResource(_ProjectTagResourceBase):
    def get(self, project_id, value):
        """Get information for a single tag associated with a given project.

        GET /v3/projects/{project_id}/tags/{value}
        """
        ENFORCER.enforce_call(
            action='identity:get_project_tag',
            build_target=_build_project_target_enforcement,
        )
        PROVIDERS.resource_api.get_project_tag(project_id, value)
        return None, http.client.NO_CONTENT

    def put(self, project_id, value):
        """Add a single tag to a project.

        PUT /v3/projects/{project_id}/tags/{value}
        """
        ENFORCER.enforce_call(
            action='identity:create_project_tag',
            build_target=_build_project_target_enforcement
        )
        validation.lazy_validate(schema.project_tag_create, value)
        # Check if we will exceed the max number of tags on this project
        tags = PROVIDERS.resource_api.list_project_tags(project_id)
        tags.append(value)
        validation.lazy_validate(schema.project_tags_update, tags)
        PROVIDERS.resource_api.create_project_tag(
            project_id,
            value,
            initiator=self.audit_initiator
        )
        url = '/'.join((ks_flask.base_url(), project_id, 'tags', value))
        response = flask.make_response('', http.client.CREATED)
        response.headers['Location'] = url
        return response

    def delete(self, project_id, value):
        """Delete a single tag from a project.

        /v3/projects/{project_id}/tags/{value}
        """
        ENFORCER.enforce_call(
            action='identity:delete_project_tag',
            build_target=_build_project_target_enforcement
        )
        PROVIDERS.resource_api.delete_project_tag(project_id, value)
        return None, http.client.NO_CONTENT


class _ProjectGrantResourceBase(ks_flask.ResourceBase):
    collection_key = 'roles'
    member_key = 'role'
    get_member_from_driver = PROVIDERS.deferred_provider_lookup(
        api='role_api', method='get_role')

    @staticmethod
    def _check_if_inherited():
        return flask.request.path.endswith('/inherited_to_projects')

    @staticmethod
    def _build_enforcement_target_attr(role_id=None, user_id=None,
                                       group_id=None, domain_id=None,
                                       project_id=None,
                                       allow_non_existing=False):
        ref = {}
        if role_id:
            ref['role'] = PROVIDERS.role_api.get_role(role_id)

        try:
            if user_id:
                ref['user'] = PROVIDERS.identity_api.get_user(user_id)
            else:
                ref['group'] = PROVIDERS.identity_api.get_group(group_id)
        except (exception.UserNotFound, exception.GroupNotFound):
            if not allow_non_existing:
                raise

        # NOTE(lbragstad): This if/else check will need to be expanded in the
        # future to handle system hierarchies if that is implemented.
        if domain_id:
            ref['domain'] = PROVIDERS.resource_api.get_domain(domain_id)
        elif project_id:
            ref['project'] = PROVIDERS.resource_api.get_project(project_id)

        return ref


class ProjectUserGrantResource(_ProjectGrantResourceBase):
    def get(self, project_id, user_id, role_id):
        """Check grant for project, user, role.

        GET/HEAD /v3/projects/{project_id/users/{user_id}/roles/{role_id}
        """
        ENFORCER.enforce_call(
            action='identity:check_grant',
            build_target=functools.partial(
                self._build_enforcement_target_attr, role_id=role_id,
                project_id=project_id, user_id=user_id)
        )
        inherited = self._check_if_inherited()
        PROVIDERS.assignment_api.get_grant(
            role_id=role_id, user_id=user_id, project_id=project_id,
            inherited_to_projects=inherited)
        return None, http.client.NO_CONTENT

    def put(self, project_id, user_id, role_id):
        """Grant role for user on project.

        PUT /v3/projects/{project_id}/users/{user_id}/roles/{role_id}
        """
        ENFORCER.enforce_call(
            action='identity:create_grant',
            build_target=functools.partial(
                self._build_enforcement_target_attr,
                role_id=role_id, project_id=project_id, user_id=user_id)
        )
        inherited = self._check_if_inherited()
        PROVIDERS.assignment_api.create_grant(
            role_id=role_id, user_id=user_id, project_id=project_id,
            inherited_to_projects=inherited, initiator=self.audit_initiator)
        return None, http.client.NO_CONTENT

    def delete(self, project_id, user_id, role_id):
        """Delete grant of role for user on project.

        DELETE /v3/projects/{project_id}/users/{user_id}/roles/{role_id}
        """
        ENFORCER.enforce_call(
            action='identity:revoke_grant',
            build_target=functools.partial(
                self._build_enforcement_target_attr,
                role_id=role_id, user_id=user_id, project_id=project_id,
                allow_non_existing=True)
        )
        inherited = self._check_if_inherited()
        PROVIDERS.assignment_api.delete_grant(
            role_id=role_id, user_id=user_id, project_id=project_id,
            inherited_to_projects=inherited, initiator=self.audit_initiator)
        return None, http.client.NO_CONTENT


class ProjectUserListGrantResource(_ProjectGrantResourceBase):
    def get(self, project_id, user_id):
        """List grants for user on project.

        GET/HEAD /v3/projects/{project_id}/users/{user_id}
        """
        ENFORCER.enforce_call(
            action='identity:list_grants',
            build_target=functools.partial(
                self._build_enforcement_target_attr,
                project_id=project_id, user_id=user_id)
        )
        inherited = self._check_if_inherited()
        refs = PROVIDERS.assignment_api.list_grants(
            user_id=user_id, project_id=project_id,
            inherited_to_projects=inherited)
        return self.wrap_collection(refs)


class ProjectGroupGrantResource(_ProjectGrantResourceBase):
    def get(self, project_id, group_id, role_id):
        """Check grant for project, group, role.

        GET/HEAD /v3/projects/{project_id/groups/{group_id}/roles/{role_id}
        """
        ENFORCER.enforce_call(
            action='identity:check_grant',
            build_target=functools.partial(
                self._build_enforcement_target_attr, role_id=role_id,
                project_id=project_id, group_id=group_id)
        )
        inherited = self._check_if_inherited()
        PROVIDERS.assignment_api.get_grant(
            role_id=role_id, group_id=group_id, project_id=project_id,
            inherited_to_projects=inherited)
        return None, http.client.NO_CONTENT

    def put(self, project_id, group_id, role_id):
        """Grant role for group on project.

        PUT /v3/projects/{project_id}/groups/{group_id}/roles/{role_id}
        """
        ENFORCER.enforce_call(
            action='identity:create_grant',
            build_target=functools.partial(
                self._build_enforcement_target_attr,
                role_id=role_id, project_id=project_id, group_id=group_id)
        )
        inherited = self._check_if_inherited()
        PROVIDERS.assignment_api.create_grant(
            role_id=role_id, group_id=group_id, project_id=project_id,
            inherited_to_projects=inherited, initiator=self.audit_initiator)
        return None, http.client.NO_CONTENT

    def delete(self, project_id, group_id, role_id):
        """Delete grant of role for group on project.

        DELETE /v3/projects/{project_id}/groups/{group_id}/roles/{role_id}
        """
        ENFORCER.enforce_call(
            action='identity:revoke_grant',
            build_target=functools.partial(
                self._build_enforcement_target_attr,
                role_id=role_id, group_id=group_id, project_id=project_id,
                allow_non_existing=True)
        )
        inherited = self._check_if_inherited()
        PROVIDERS.assignment_api.delete_grant(
            role_id=role_id, group_id=group_id, project_id=project_id,
            inherited_to_projects=inherited, initiator=self.audit_initiator)
        return None, http.client.NO_CONTENT


class ProjectGroupListGrantResource(_ProjectGrantResourceBase):
    def get(self, project_id, group_id):
        """List grants for group on project.

        GET/HEAD /v3/projects/{project_id}/groups/{group_id}
        """
        ENFORCER.enforce_call(
            action='identity:list_grants',
            build_target=functools.partial(
                self._build_enforcement_target_attr,
                project_id=project_id, group_id=group_id)
        )
        inherited = self._check_if_inherited()
        refs = PROVIDERS.assignment_api.list_grants(
            group_id=group_id, project_id=project_id,
            inherited_to_projects=inherited)
        return self.wrap_collection(refs)


class ProjectAPI(ks_flask.APIBase):
    _name = 'projects'
    _import_name = __name__
    resources = [ProjectResource]
    resource_mapping = [
        ks_flask.construct_resource_map(
            resource=ProjectTagsResource,
            url='/projects/<string:project_id>/tags',
            resource_kwargs={},
            rel='project_tags',
            path_vars={
                'project_id': json_home.Parameters.PROJECT_ID}
        ),
        ks_flask.construct_resource_map(
            resource=ProjectTagResource,
            url='/projects/<string:project_id>/tags/<string:value>',
            resource_kwargs={},
            rel='project_tags',
            path_vars={
                'project_id': json_home.Parameters.PROJECT_ID,
                'value': json_home.Parameters.TAG_VALUE}
        ),
        ks_flask.construct_resource_map(
            resource=ProjectUserGrantResource,
            url=('/projects/<string:project_id>/users/<string:user_id>/'
                 'roles/<string:role_id>'),
            resource_kwargs={},
            rel='project_user_role',
            path_vars={
                'project_id': json_home.Parameters.PROJECT_ID,
                'user_id': json_home.Parameters.USER_ID,
                'role_id': json_home.Parameters.ROLE_ID
            },
        ),
        ks_flask.construct_resource_map(
            resource=ProjectUserListGrantResource,
            url='/projects/<string:project_id>/users/<string:user_id>/roles',
            resource_kwargs={},
            rel='project_user_roles',
            path_vars={
                'project_id': json_home.Parameters.PROJECT_ID,
                'user_id': json_home.Parameters.USER_ID
            }
        ),
        ks_flask.construct_resource_map(
            resource=ProjectGroupGrantResource,
            url=('/projects/<string:project_id>/groups/<string:group_id>/'
                 'roles/<string:role_id>'),
            resource_kwargs={},
            rel='project_group_role',
            path_vars={
                'project_id': json_home.Parameters.PROJECT_ID,
                'group_id': json_home.Parameters.GROUP_ID,
                'role_id': json_home.Parameters.ROLE_ID
            },
        ),
        ks_flask.construct_resource_map(
            resource=ProjectGroupListGrantResource,
            url='/projects/<string:project_id>/groups/<string:group_id>/roles',
            resource_kwargs={},
            rel='project_group_roles',
            path_vars={
                'project_id': json_home.Parameters.PROJECT_ID,
                'group_id': json_home.Parameters.GROUP_ID
            },
        ),
    ]


APIs = (ProjectAPI,)
