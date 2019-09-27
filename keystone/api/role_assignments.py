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

# This file handles all flask-restful resources for /v3/role_assignments

import flask

from keystone.common import provider_api
from keystone.common import rbac_enforcer
from keystone import exception
from keystone.i18n import _
from keystone.server import flask as ks_flask


ENFORCER = rbac_enforcer.RBACEnforcer
PROVIDERS = provider_api.ProviderAPIs


class RoleAssignmentsResource(ks_flask.ResourceBase):
    # TODO(henry-nash): The current implementation does not provide a full
    # first class entity for role-assignment. There is no role_assignment_id
    # and only the list_role_assignment call is supported. Further, since it
    # is not a first class entity, the links for the individual entities
    # reference the individual role grant APIs.

    collection_key = 'role_assignments'
    member_key = 'role_assignment'

    def get(self):
        """List all role assignments.

        GET/HEAD /v3/role_assignments
        """
        if self.query_filter_is_true('include_subtree'):
            return self._list_role_assignments_for_tree()
        return self._list_role_assignments()

    def _list_role_assignments(self):
        filters = [
            'group.id', 'role.id', 'scope.domain.id', 'scope.project.id',
            'scope.OS-INHERIT:inherited_to', 'user.id', 'scope.system'
        ]
        target = None
        if self.oslo_context.domain_id:
            target = {'domain_id': self.oslo_context.domain_id}
        ENFORCER.enforce_call(action='identity:list_role_assignments',
                              filters=filters,
                              target_attr=target)

        assignments = self._build_role_assignments_list()

        if self.oslo_context.domain_id:
            domain_assignments = []
            for assignment in assignments['role_assignments']:
                domain_id = assignment['scope'].get('domain', {}).get('id')
                project_id = assignment['scope'].get('project', {}).get('id')
                if domain_id == self.oslo_context.domain_id:
                    domain_assignments.append(assignment)
                    continue
                elif project_id:
                    project = PROVIDERS.resource_api.get_project(project_id)
                    if project.get('domain_id') == self.oslo_context.domain_id:
                        domain_assignments.append(assignment)

            assignments['role_assignments'] = domain_assignments

        return assignments

    def _list_role_assignments_for_tree(self):
        filters = [
            'group.id', 'role.id', 'scope.domain.id', 'scope.project.id',
            'scope.OS-INHERIT:inherited_to', 'user.id'
        ]
        target = None
        if 'scope.project.id' in flask.request.args:
            project_id = flask.request.args['scope.project.id']
            if project_id:
                target = {'project': PROVIDERS.resource_api.get_project(
                    project_id)}
        ENFORCER.enforce_call(action='identity:list_role_assignments_for_tree',
                              filters=filters, target_attr=target)
        if not flask.request.args.get('scope.project.id'):
            msg = _('scope.project.id must be specified if include_subtree '
                    'is also specified')
            raise exception.ValidationError(message=msg)
        return self._build_role_assignments_list(include_subtree=True)

    def _build_role_assignments_list(self, include_subtree=False):
        """List role assignments to user and groups on domains and projects.

        Return a list of all existing role assignments in the system, filtered
        by assignments attributes, if provided.

        If effective option is used and OS-INHERIT extension is enabled, the
        following functions will be applied:
        1) For any group role assignment on a target, replace it by a set of
        role assignments containing one for each user of that group on that
        target;
        2) For any inherited role assignment for an actor on a target, replace
        it by a set of role assignments for that actor on every project under
        that target.

        It means that, if effective mode is used, no group or domain inherited
        assignments will be present in the resultant list. Thus, combining
        effective with them is invalid.

        As a role assignment contains only one actor and one target, providing
        both user and group ids or domain and project ids is invalid as well.
        """
        params = flask.request.args
        include_names = self.query_filter_is_true('include_names')

        self._assert_domain_nand_project()
        self._assert_system_nand_domain()
        self._assert_system_nand_project()
        self._assert_user_nand_group()
        self._assert_effective_filters_if_needed()

        refs = PROVIDERS.assignment_api.list_role_assignments(
            role_id=params.get('role.id'),
            user_id=params.get('user.id'),
            group_id=params.get('group.id'),
            system=params.get('scope.system'),
            domain_id=params.get('scope.domain.id'),
            project_id=params.get('scope.project.id'),
            include_subtree=include_subtree,
            inherited=self._inherited,
            effective=self._effective,
            include_names=include_names)
        formatted_refs = [self._format_entity(ref) for ref in refs]
        return self.wrap_collection(formatted_refs)

    def _assert_domain_nand_project(self):
        if (flask.request.args.get('scope.domain.id') and
                flask.request.args.get('scope.project.id')):
            msg = _('Specify a domain or project, not both')
            raise exception.ValidationError(msg)

    def _assert_system_nand_domain(self):
        if (flask.request.args.get('scope.domain.id') and
                flask.request.args.get('scope.system')):
            msg = _('Specify system or domain, not both')
            raise exception.ValidationError(msg)

    def _assert_system_nand_project(self):
        if (flask.request.args.get('scope.project.id') and
                flask.request.args.get('scope.system')):
            msg = _('Specify system or project, not both')
            raise exception.ValidationError(msg)

    def _assert_user_nand_group(self):
        if (flask.request.args.get('user.id') and
                flask.request.args.get('group.id')):
            msg = _('Specify a user or group, not both')
            raise exception.ValidationError(msg)

    def _assert_effective_filters_if_needed(self):
        """Assert that useless filter combinations are avoided.

        In effective mode, the following filter combinations are useless, since
        they would always return an empty list of role assignments:
        - group id, since no group assignment is returned in effective mode;
        - domain id and inherited, since no domain inherited assignment is
        returned in effective mode.

        """
        if self._effective:
            if flask.request.args.get('group.id'):
                msg = _('Combining effective and group filter will always '
                        'result in an empty list.')
                raise exception.ValidationError(msg)

            if self._inherited and flask.request.args.get('scope.domain.id'):
                msg = _(
                    'Combining effective, domain and inherited filters will '
                    'always result in an empty list.')
                raise exception.ValidationError(msg)

    @property
    def _inherited(self):
        inherited = None
        req_args = flask.request.args
        if 'scope.OS-INHERIT:inherited_to' in req_args:
            inherited = req_args['scope.OS-INHERIT:inherited_to'] == 'projects'
        return inherited

    @classmethod
    def _add_self_referential_link(cls, ref, collection_name=None):
        # NOTE(henry-nash): Since we are not yet a true collection, we override
        # the wrapper as have already included the links in the entities
        pass

    @property
    def _effective(self):
        return self.query_filter_is_true('effective')

    def _format_entity(self, entity):
        """Format an assignment entity for API response.

        The driver layer returns entities as dicts containing the ids of the
        actor (e.g. user or group), target (e.g. domain or project) and role.
        If it is an inherited role, then this is also indicated. Examples:

        For a non-inherited expanded assignment from group membership:
        {'user_id': user_id,
         'project_id': project_id,
         'role_id': role_id,
         'indirect': {'group_id': group_id}}

        or, for a project inherited role:

        {'user_id': user_id,
         'project_id': project_id,
         'role_id': role_id,
         'indirect': {'project_id': parent_id}}

        or, for a role that was implied by a prior role:

        {'user_id': user_id,
         'project_id': project_id,
         'role_id': role_id,
         'indirect': {'role_id': prior role_id}}

        It is possible to deduce if a role assignment came from group
        membership if it has both 'user_id' in the main body of the dict and
        'group_id' in the 'indirect' subdict, as well as it is possible to
        deduce if it has come from inheritance if it contains both a
        'project_id' in the main body of the dict and 'parent_id' in the
        'indirect' subdict.

        This function maps this into the format to be returned via the API,
        e.g. for the second example above:

        {
            'user': {
                {'id': user_id}
            },
            'scope': {
                'project': {
                    {'id': project_id}
                },
                'OS-INHERIT:inherited_to': 'projects'
            },
            'role': {
                {'id': role_id}
            },
            'links': {
                'assignment': '/OS-INHERIT/projects/parent_id/users/user_id/'
                              'roles/role_id/inherited_to_projects'
            }
        }

        """
        formatted_link = ''
        formatted_entity = {'links': {}}
        inherited_assignment = entity.get('inherited_to_projects')

        if 'project_id' in entity:
            if 'project_name' in entity:
                formatted_entity['scope'] = {'project': {
                    'id': entity['project_id'],
                    'name': entity['project_name'],
                    'domain': {'id': entity['project_domain_id'],
                               'name': entity['project_domain_name']}}}
            else:
                formatted_entity['scope'] = {
                    'project': {'id': entity['project_id']}}

            if 'domain_id' in entity.get('indirect', {}):
                inherited_assignment = True
                formatted_link = ('/domains/%s' %
                                  entity['indirect']['domain_id'])
            elif 'project_id' in entity.get('indirect', {}):
                inherited_assignment = True
                formatted_link = ('/projects/%s' %
                                  entity['indirect']['project_id'])
            else:
                formatted_link = '/projects/%s' % entity['project_id']
        elif 'domain_id' in entity:
            if 'domain_name' in entity:
                formatted_entity['scope'] = {
                    'domain': {'id': entity['domain_id'],
                               'name': entity['domain_name']}}
            else:
                formatted_entity['scope'] = {
                    'domain': {'id': entity['domain_id']}}
            formatted_link = '/domains/%s' % entity['domain_id']
        elif 'system' in entity:
            formatted_link = '/system'
            formatted_entity['scope'] = {'system': entity['system']}

        if 'user_id' in entity:
            if 'user_name' in entity:
                formatted_entity['user'] = {
                    'id': entity['user_id'],
                    'name': entity['user_name'],
                    'domain': {'id': entity['user_domain_id'],
                               'name': entity['user_domain_name']}}
            else:
                formatted_entity['user'] = {'id': entity['user_id']}
            if 'group_id' in entity.get('indirect', {}):
                membership_url = (
                    ks_flask.base_url(path='/groups/%s/users/%s' % (
                        entity['indirect']['group_id'], entity['user_id'])))
                formatted_entity['links']['membership'] = membership_url
                formatted_link += '/groups/%s' % entity['indirect']['group_id']
            else:
                formatted_link += '/users/%s' % entity['user_id']
        elif 'group_id' in entity:
            if 'group_name' in entity:
                formatted_entity['group'] = {
                    'id': entity['group_id'],
                    'name': entity['group_name'],
                    'domain': {'id': entity['group_domain_id'],
                               'name': entity['group_domain_name']}}
            else:
                formatted_entity['group'] = {'id': entity['group_id']}
            formatted_link += '/groups/%s' % entity['group_id']

        if 'role_name' in entity:
            formatted_entity['role'] = {'id': entity['role_id'],
                                        'name': entity['role_name']}
            if 'role_domain_id' in entity and 'role_domain_name' in entity:
                formatted_entity['role'].update(
                    {'domain': {'id': entity['role_domain_id'],
                                'name': entity['role_domain_name']}})
        else:
            formatted_entity['role'] = {'id': entity['role_id']}
        prior_role_link = ''
        if 'role_id' in entity.get('indirect', {}):
            formatted_link += '/roles/%s' % entity['indirect']['role_id']
            prior_role_link = (
                '/prior_role/%(prior)s/implies/%(implied)s' % {
                    'prior': entity['role_id'],
                    'implied': entity['indirect']['role_id']
                })
        else:
            formatted_link += '/roles/%s' % entity['role_id']

        if inherited_assignment:
            formatted_entity['scope']['OS-INHERIT:inherited_to'] = (
                'projects')
            formatted_link = ('/OS-INHERIT%s/inherited_to_projects' %
                              formatted_link)

        formatted_entity['links']['assignment'] = ks_flask.base_url(
            path=formatted_link)
        if prior_role_link:
            formatted_entity['links']['prior_role'] = (
                ks_flask.base_url(path=prior_role_link))

        return formatted_entity


class RoleAssignmentsAPI(ks_flask.APIBase):
    _name = 'role_assignments'
    _import_name = __name__
    resources = []
    resource_mapping = [
        ks_flask.construct_resource_map(
            resource=RoleAssignmentsResource,
            url='/role_assignments',
            resource_kwargs={},
            rel='role_assignments')
    ]


APIs = (RoleAssignmentsAPI,)
