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

# This file handles all flask-restful resources for /v3/OS-INHERIT

import flask_restful
import functools
import http.client
from oslo_log import log

from keystone.api._shared import json_home_relations
from keystone.common import json_home
from keystone.common import provider_api
from keystone.common import rbac_enforcer
from keystone import exception
from keystone.server import flask as ks_flask


ENFORCER = rbac_enforcer.RBACEnforcer
PROVIDERS = provider_api.ProviderAPIs
LOG = log.getLogger(__name__)

_build_resource_relation = json_home_relations.os_inherit_resource_rel_func


def _build_enforcement_target_attr(role_id=None, user_id=None, group_id=None,
                                   project_id=None, domain_id=None,
                                   allow_non_existing=False):
    """Check protection for role grant APIs.

    The policy rule might want to inspect attributes of any of the entities
    involved in the grant.  So we get these and pass them to the
    check_protection() handler in the controller.

    """
    # !!!!!!!!!! WARNING: Security Concern !!!!!!!!!!
    #
    # NOTE(morgan): This function must handle all expected exceptions,
    # including NOT FOUNDs otherwise the exception will be raised up to the
    # end user before enforcement, resulting in the exception being returned
    # instead of an appropriate 403. In each case, it is logged that a value
    # was not found and the target is explicitly set to empty. This allows for
    # the enforcement rule to decide what to do (most of the time raise an
    # appropriate 403).
    #
    # ###############################################

    target = {}
    if role_id:
        try:
            target['role'] = PROVIDERS.role_api.get_role(role_id)
        except exception.RoleNotFound:
            LOG.info('Role (%(role_id)s) not found, Enforcement target of '
                     '`role` remaind empty', {'role_id': role_id})
            target['role'] = {}
    if user_id:
        try:
            target['user'] = PROVIDERS.identity_api.get_user(user_id)
        except exception.UserNotFound:
            if not allow_non_existing:
                LOG.info('User (%(user_id)s) was not found. Enforcement target'
                         ' of `user` remains empty.', {'user_id': user_id})
                target['user'] = {}
    else:
        try:
            target['group'] = PROVIDERS.identity_api.get_group(group_id)
        except exception.GroupNotFound:
            if not allow_non_existing:
                LOG.info('Group (%(group_id)s) was not found. Enforcement '
                         'target of `group` remains empty.',
                         {'group_id': group_id})
                target['group'] = {}

    # NOTE(lbragstad): This if/else check will need to be expanded in the
    # future to handle system hierarchies if that is implemented.
    if domain_id:
        try:
            target['domain'] = PROVIDERS.resource_api.get_domain(domain_id)
        except exception.DomainNotFound:
            LOG.info('Domain (%(domain_id)s) was not found. Enforcement '
                     'target of `domain` remains empty.',
                     {'domain_id': domain_id})
            target['domain'] = {}
    elif project_id:
        try:
            target['project'] = PROVIDERS.resource_api.get_project(project_id)
        except exception.ProjectNotFound:
            LOG.info('Project (%(project_id)s) was not found. Enforcement '
                     'target of `project` remains empty.',
                     {'project_id': project_id})
            target['project'] = {}

    return target


class OSInheritDomainGroupRolesResource(flask_restful.Resource):
    def get(self, domain_id, group_id, role_id):
        """Check for an inherited grant for a group on a domain.

        GET/HEAD /OS-INHERIT/domains/{domain_id}/groups/{group_id}
                 /roles/{role_id}/inherited_to_projects
        """
        ENFORCER.enforce_call(
            action='identity:check_grant',
            build_target=functools.partial(_build_enforcement_target_attr,
                                           domain_id=domain_id,
                                           group_id=group_id,
                                           role_id=role_id))
        PROVIDERS.assignment_api.get_grant(
            domain_id=domain_id, group_id=group_id, role_id=role_id,
            inherited_to_projects=True)
        return None, http.client.NO_CONTENT

    def put(self, domain_id, group_id, role_id):
        """Create an inherited grant for a group on a domain.

        PUT /OS-INHERIT/domains/{domain_id}/groups/{group_id}
            /roles/{role_id}/inherited_to_projects
        """
        ENFORCER.enforce_call(
            action='identity:create_grant',
            build_target=functools.partial(_build_enforcement_target_attr,
                                           domain_id=domain_id,
                                           group_id=group_id,
                                           role_id=role_id))
        PROVIDERS.assignment_api.create_grant(
            domain_id=domain_id, group_id=group_id, role_id=role_id,
            inherited_to_projects=True)
        return None, http.client.NO_CONTENT

    def delete(self, domain_id, group_id, role_id):
        """Revoke an inherited grant for a group on a domain.

        DELETE /OS-INHERIT/domains/{domain_id}/groups/{group_id}
               /roles/{role_id}/inherited_to_projects
        """
        ENFORCER.enforce_call(
            action='identity:revoke_grant',
            build_target=functools.partial(_build_enforcement_target_attr,
                                           domain_id=domain_id,
                                           group_id=group_id,
                                           role_id=role_id))
        PROVIDERS.assignment_api.delete_grant(
            domain_id=domain_id, group_id=group_id, role_id=role_id,
            inherited_to_projects=True)
        return None, http.client.NO_CONTENT


class OSInheritDomainGroupRolesListResource(flask_restful.Resource):
    def get(self, domain_id, group_id):
        """List roles (inherited) for a group on a domain.

        GET/HEAD /OS-INHERIT/domains/{domain_id}/groups/{group_id}
                 /roles/inherited_to_projects
        """
        ENFORCER.enforce_call(
            action='identity:list_grants',
            build_target=functools.partial(_build_enforcement_target_attr,
                                           domain_id=domain_id,
                                           group_id=group_id))
        refs = PROVIDERS.assignment_api.list_grants(
            domain_id=domain_id, group_id=group_id, inherited_to_projects=True)
        return ks_flask.ResourceBase.wrap_collection(
            refs, collection_name='roles')


class OSInheritDomainUserRolesResource(flask_restful.Resource):
    def get(self, domain_id, user_id, role_id):
        """Check for an inherited grant for a user on a domain.

        GET/HEAD /OS-INHERIT/domains/{domain_id}/users/{user_id}/roles
                 /{role_id}/inherited_to_projects
        """
        ENFORCER.enforce_call(
            action='identity:check_grant',
            build_target=functools.partial(_build_enforcement_target_attr,
                                           domain_id=domain_id,
                                           user_id=user_id,
                                           role_id=role_id))
        PROVIDERS.assignment_api.get_grant(
            domain_id=domain_id, user_id=user_id, role_id=role_id,
            inherited_to_projects=True)
        return None, http.client.NO_CONTENT

    def put(self, domain_id, user_id, role_id):
        """Create an inherited grant for a user on a domain.

        PUT /OS-INHERIT/domains/{domain_id}/users/{user_id}/roles/{role_id}
            /inherited_to_projects
        """
        ENFORCER.enforce_call(
            action='identity:create_grant',
            build_target=functools.partial(_build_enforcement_target_attr,
                                           domain_id=domain_id,
                                           user_id=user_id,
                                           role_id=role_id))
        PROVIDERS.assignment_api.create_grant(
            domain_id=domain_id, user_id=user_id, role_id=role_id,
            inherited_to_projects=True)
        return None, http.client.NO_CONTENT

    def delete(self, domain_id, user_id, role_id):
        """Revoke a grant from a user on a domain.

        DELETE /OS-INHERIT/domains/{domain_id}/users/{user_id}/roles
               /{role_id}/inherited_to_projects
        """
        ENFORCER.enforce_call(
            action='identity:revoke_grant',
            build_target=functools.partial(_build_enforcement_target_attr,
                                           domain_id=domain_id,
                                           user_id=user_id,
                                           role_id=role_id))
        PROVIDERS.assignment_api.delete_grant(
            domain_id=domain_id, user_id=user_id, role_id=role_id,
            inherited_to_projects=True)
        return None, http.client.NO_CONTENT


class OSInheritDomainUserRolesListResource(flask_restful.Resource):
    def get(self, domain_id, user_id):
        """List roles (inherited) for a user on a domain.

        GET/HEAD /OS-INHERIT/domains/{domain_id}/users/{user_id}
                 /roles/inherited_to_projects
        """
        ENFORCER.enforce_call(
            action='identity:list_grants',
            build_target=functools.partial(_build_enforcement_target_attr,
                                           domain_id=domain_id,
                                           user_id=user_id))
        refs = PROVIDERS.assignment_api.list_grants(
            domain_id=domain_id, user_id=user_id, inherited_to_projects=True)
        return ks_flask.ResourceBase.wrap_collection(
            refs, collection_name='roles')


class OSInheritProjectUserResource(flask_restful.Resource):
    def get(self, project_id, user_id, role_id):
        """Check for an inherited grant for a user on a project.

        GET/HEAD /OS-INHERIT/projects/{project_id}/users/{user_id}
                 /roles/{role_id}/inherited_to_projects
        """
        ENFORCER.enforce_call(
            action='identity:check_grant',
            build_target=functools.partial(_build_enforcement_target_attr,
                                           project_id=project_id,
                                           user_id=user_id,
                                           role_id=role_id))
        PROVIDERS.assignment_api.get_grant(
            project_id=project_id, user_id=user_id, role_id=role_id,
            inherited_to_projects=True)
        return None, http.client.NO_CONTENT

    def put(self, project_id, user_id, role_id):
        """Create an inherited grant for a user on a project.

        PUT /OS-INHERIT/projects/{project_id}/users/{user_id}
            /roles/{role_id}/inherited_to_projects
        """
        ENFORCER.enforce_call(
            action='identity:create_grant',
            build_target=functools.partial(_build_enforcement_target_attr,
                                           project_id=project_id,
                                           user_id=user_id,
                                           role_id=role_id))
        PROVIDERS.assignment_api.create_grant(
            project_id=project_id, user_id=user_id, role_id=role_id,
            inherited_to_projects=True)
        return None, http.client.NO_CONTENT

    def delete(self, project_id, user_id, role_id):
        """Revoke an inherited grant for a user on a project.

        DELETE /OS-INHERIT/projects/{project_id}/users/{user_id}
               /roles/{role_id}/inherited_to_projects
        """
        ENFORCER.enforce_call(
            action='identity:revoke_grant',
            build_target=functools.partial(_build_enforcement_target_attr,
                                           project_id=project_id,
                                           user_id=user_id,
                                           role_id=role_id))
        PROVIDERS.assignment_api.delete_grant(
            project_id=project_id, user_id=user_id, role_id=role_id,
            inherited_to_projects=True)
        return None, http.client.NO_CONTENT


class OSInheritProjectGroupResource(flask_restful.Resource):
    def get(self, project_id, group_id, role_id):
        """Check for an inherited grant for a group on a project.

        GET/HEAD /OS-INHERIT/projects/{project_id}/groups/{group_id}
                 /roles/{role_id}/inherited_to_projects
        """
        ENFORCER.enforce_call(
            action='identity:check_grant',
            build_target=functools.partial(_build_enforcement_target_attr,
                                           project_id=project_id,
                                           group_id=group_id,
                                           role_id=role_id))
        PROVIDERS.assignment_api.get_grant(
            project_id=project_id, group_id=group_id, role_id=role_id,
            inherited_to_projects=True)
        return None, http.client.NO_CONTENT

    def put(self, project_id, group_id, role_id):
        """Create an inherited grant for a group on a project.

        PUT /OS-INHERIT/projects/{project_id}/groups/{group_id}
            /roles/{role_id}/inherited_to_projects
        """
        ENFORCER.enforce_call(
            action='identity:create_grant',
            build_target=functools.partial(_build_enforcement_target_attr,
                                           project_id=project_id,
                                           group_id=group_id,
                                           role_id=role_id))
        PROVIDERS.assignment_api.create_grant(
            project_id=project_id, group_id=group_id, role_id=role_id,
            inherited_to_projects=True)
        return None, http.client.NO_CONTENT

    def delete(self, project_id, group_id, role_id):
        """Revoke an inherited grant for a group on a project.

        DELETE /OS-INHERIT/projects/{project_id}/groups/{group_id}
               /roles/{role_id}/inherited_to_projects
        """
        ENFORCER.enforce_call(
            action='identity:revoke_grant',
            build_target=functools.partial(_build_enforcement_target_attr,
                                           project_id=project_id,
                                           group_id=group_id,
                                           role_id=role_id))
        PROVIDERS.assignment_api.delete_grant(
            project_id=project_id, group_id=group_id, role_id=role_id,
            inherited_to_projects=True)
        return None, http.client.NO_CONTENT


class OSInheritAPI(ks_flask.APIBase):
    _name = "OS-INHERIT"
    _import_name = __name__
    _api_url_prefix = '/OS-INHERIT'
    resources = []
    resource_mapping = [
        ks_flask.construct_resource_map(
            resource=OSInheritDomainGroupRolesResource,
            url=('/domains/<string:domain_id>/groups/<string:group_id>/roles'
                 '/<string:role_id>/inherited_to_projects'),
            resource_kwargs={},
            rel='domain_group_role_inherited_to_projects',
            resource_relation_func=_build_resource_relation,
            path_vars={
                'domain_id': json_home.Parameters.DOMAIN_ID,
                'group_id': json_home.Parameters.GROUP_ID,
                'role_id': json_home.Parameters.ROLE_ID}),
        ks_flask.construct_resource_map(
            resource=OSInheritDomainGroupRolesListResource,
            url=('/domains/<string:domain_id>/groups/<string:group_id>/roles'
                 '/inherited_to_projects'),
            resource_kwargs={},
            rel='domain_group_roles_inherited_to_projects',
            resource_relation_func=_build_resource_relation,
            path_vars={
                'domain_id': json_home.Parameters.DOMAIN_ID,
                'group_id': json_home.Parameters.GROUP_ID}),
        ks_flask.construct_resource_map(
            resource=OSInheritDomainUserRolesResource,
            url=('/domains/<string:domain_id>/users/<string:user_id>/roles'
                 '/<string:role_id>/inherited_to_projects'),
            resource_kwargs={},
            rel='domain_user_role_inherited_to_projects',
            resource_relation_func=_build_resource_relation,
            path_vars={
                'domain_id': json_home.Parameters.DOMAIN_ID,
                'user_id': json_home.Parameters.USER_ID,
                'role_id': json_home.Parameters.ROLE_ID}),
        ks_flask.construct_resource_map(
            resource=OSInheritDomainUserRolesListResource,
            url=('/domains/<string:domain_id>/users/<string:user_id>/roles'
                 '/inherited_to_projects'),
            resource_kwargs={},
            rel='domain_user_roles_inherited_to_projects',
            resource_relation_func=_build_resource_relation,
            path_vars={
                'domain_id': json_home.Parameters.DOMAIN_ID,
                'user_id': json_home.Parameters.USER_ID}),
        ks_flask.construct_resource_map(
            resource=OSInheritProjectUserResource,
            url=('projects/<string:project_id>/users/<string:user_id>/roles'
                 '/<string:role_id>/inherited_to_projects'),
            resource_kwargs={},
            rel='project_user_role_inherited_to_projects',
            resource_relation_func=_build_resource_relation,
            path_vars={
                'project_id': json_home.Parameters.PROJECT_ID,
                'user_id': json_home.Parameters.USER_ID,
                'role_id': json_home.Parameters.ROLE_ID}),
        ks_flask.construct_resource_map(
            resource=OSInheritProjectGroupResource,
            url=('projects/<string:project_id>/groups/<string:group_id>/roles'
                 '/<string:role_id>/inherited_to_projects'),
            resource_kwargs={},
            rel='project_group_role_inherited_to_projects',
            resource_relation_func=_build_resource_relation,
            path_vars={
                'project_id': json_home.Parameters.PROJECT_ID,
                'group_id': json_home.Parameters.GROUP_ID,
                'role_id': json_home.Parameters.ROLE_ID})
    ]


APIs = (OSInheritAPI,)
