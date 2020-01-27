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

"""Main entry point into the Assignment service."""

import copy
import itertools

from oslo_log import log

from keystone.common import cache
from keystone.common import driver_hints
from keystone.common import manager
from keystone.common import provider_api
from keystone.common.resource_options import options as ro_opt
import keystone.conf
from keystone import exception
from keystone.i18n import _
from keystone import notifications


CONF = keystone.conf.CONF
LOG = log.getLogger(__name__)
PROVIDERS = provider_api.ProviderAPIs

# This is a general cache region for assignment administration (CRUD
# operations).
MEMOIZE = cache.get_memoization_decorator(group='role')

# This builds a discrete cache region dedicated to role assignments computed
# for a given user + project/domain pair. Any write operation to add or remove
# any role assignment should invalidate this entire cache region.
COMPUTED_ASSIGNMENTS_REGION = cache.create_region(name='computed assignments')
MEMOIZE_COMPUTED_ASSIGNMENTS = cache.get_memoization_decorator(
    group='role',
    region=COMPUTED_ASSIGNMENTS_REGION)


@notifications.listener
class Manager(manager.Manager):
    """Default pivot point for the Assignment backend.

    See :class:`keystone.common.manager.Manager` for more details on how this
    dynamically calls the backend.

    """

    driver_namespace = 'keystone.assignment'
    _provides_api = 'assignment_api'

    _SYSTEM_SCOPE_TOKEN = 'system'  # nosec
    _USER_SYSTEM = 'UserSystem'
    _GROUP_SYSTEM = 'GroupSystem'
    _PROJECT = 'project'
    _ROLE_REMOVED_FROM_USER = 'role_removed_from_user'
    _INVALIDATION_USER_PROJECT_TOKENS = 'invalidate_user_project_tokens'

    def __init__(self):
        assignment_driver = CONF.assignment.driver
        super(Manager, self).__init__(assignment_driver)

        self.event_callbacks = {
            notifications.ACTIONS.deleted: {
                'domain': [self._delete_domain_assignments],
            },
        }

    def _delete_domain_assignments(self, service, resource_type, operations,
                                   payload):
        domain_id = payload['resource_info']
        self.driver.delete_domain_assignments(domain_id)

    def _get_group_ids_for_user_id(self, user_id):
        # TODO(morganfainberg): Implement a way to get only group_ids
        # instead of the more expensive to_dict() call for each record.
        return [x['id'] for
                x in PROVIDERS.identity_api.list_groups_for_user(user_id)]

    def list_user_ids_for_project(self, project_id):
        PROVIDERS.resource_api.get_project(project_id)
        assignment_list = self.list_role_assignments(
            project_id=project_id, effective=True)
        # Use set() to process the list to remove any duplicates
        return list(set([x['user_id'] for x in assignment_list]))

    def _send_app_cred_notification_for_role_removal(self, role_id):
        """Delete all application credential for a specific role.

        :param role_id: role identifier
        :type role_id: string
        """
        assignments = self.list_role_assignments(role_id=role_id)
        for assignment in assignments:
            if 'user_id' in assignment and 'project_id' in assignment:
                payload = {
                    'user_id': assignment['user_id'],
                    'project_id': assignment['project_id']
                }
                notifications.Audit.internal(
                    notifications.REMOVE_APP_CREDS_FOR_USER, payload
                )

    @MEMOIZE_COMPUTED_ASSIGNMENTS
    def get_roles_for_user_and_project(self, user_id, project_id):
        """Get the roles associated with a user within given project.

        This includes roles directly assigned to the user on the
        project, as well as those by virtue of group membership or
        inheritance.

        :returns: a list of role ids.
        :raises keystone.exception.ProjectNotFound: If the project doesn't
            exist.

        """
        PROVIDERS.resource_api.get_project(project_id)
        assignment_list = self.list_role_assignments(
            user_id=user_id, project_id=project_id, effective=True)
        # Use set() to process the list to remove any duplicates
        return list(set([x['role_id'] for x in assignment_list]))

    @MEMOIZE_COMPUTED_ASSIGNMENTS
    def get_roles_for_trustor_and_project(self, trustor_id, project_id):
        """Get the roles associated with a trustor within given project.

        This includes roles directly assigned to the trustor on the
        project, as well as those by virtue of group membership or
        inheritance, but it doesn't include the domain roles.

        :returns: a list of role ids.
        :raises keystone.exception.ProjectNotFound: If the project doesn't
            exist.

        """
        PROVIDERS.resource_api.get_project(project_id)
        assignment_list = self.list_role_assignments(
            user_id=trustor_id, project_id=project_id, effective=True,
            strip_domain_roles=False)
        # Use set() to process the list to remove any duplicates
        return list(set([x['role_id'] for x in assignment_list]))

    @MEMOIZE_COMPUTED_ASSIGNMENTS
    def get_roles_for_user_and_domain(self, user_id, domain_id):
        """Get the roles associated with a user within given domain.

        :returns: a list of role ids.
        :raises keystone.exception.DomainNotFound: If the domain doesn't exist.

        """
        PROVIDERS.resource_api.get_domain(domain_id)
        assignment_list = self.list_role_assignments(
            user_id=user_id, domain_id=domain_id, effective=True)
        # Use set() to process the list to remove any duplicates
        return list(set([x['role_id'] for x in assignment_list]))

    def get_roles_for_groups(self, group_ids, project_id=None, domain_id=None):
        """Get a list of roles for this group on domain and/or project."""
        # if no group ids were passed, there are no roles. Without this check,
        # all assignments for the project or domain will be fetched,
        # which is not what we want.
        if not group_ids:
            return []
        if project_id is not None:
            PROVIDERS.resource_api.get_project(project_id)
            assignment_list = self.list_role_assignments(
                source_from_group_ids=group_ids, project_id=project_id,
                effective=True)
        elif domain_id is not None:
            assignment_list = self.list_role_assignments(
                source_from_group_ids=group_ids, domain_id=domain_id,
                effective=True)
        else:
            raise AttributeError(_("Must specify either domain or project"))

        role_ids = list(set([x['role_id'] for x in assignment_list]))
        return PROVIDERS.role_api.list_roles_from_ids(role_ids)

    @notifications.role_assignment('created')
    def _add_role_to_user_and_project_adapter(self, role_id, user_id=None,
                                              group_id=None, domain_id=None,
                                              project_id=None,
                                              inherited_to_projects=False,
                                              context=None):

        # The parameters for this method must match the parameters for
        # create_grant so that the notifications.role_assignment decorator
        # will work.

        PROVIDERS.resource_api.get_project(project_id)
        PROVIDERS.role_api.get_role(role_id)
        self.driver.add_role_to_user_and_project(user_id, project_id, role_id)

    def add_role_to_user_and_project(self, user_id, project_id, role_id):
        self._add_role_to_user_and_project_adapter(
            role_id, user_id=user_id, project_id=project_id)
        COMPUTED_ASSIGNMENTS_REGION.invalidate()

    # TODO(henry-nash): We might want to consider list limiting this at some
    # point in the future.
    @MEMOIZE_COMPUTED_ASSIGNMENTS
    def list_projects_for_user(self, user_id):
        # FIXME(lbragstad): Without the use of caching, listing effective role
        # assignments is slow, especially with large data set (lots of users
        # with multiple role assignments). This should serve as a marker in
        # case we have the opportunity to come back and optimize this code so
        # that it can be performant without having a hard dependency on
        # caching. Please see https://bugs.launchpad.net/keystone/+bug/1700852
        # for more details.
        assignment_list = self.list_role_assignments(
            user_id=user_id, effective=True)
        # Use set() to process the list to remove any duplicates
        project_ids = list(set([x['project_id'] for x in assignment_list
                                if x.get('project_id')]))
        return PROVIDERS.resource_api.list_projects_from_ids(project_ids)

    # TODO(henry-nash): We might want to consider list limiting this at some
    # point in the future.
    @MEMOIZE_COMPUTED_ASSIGNMENTS
    def list_domains_for_user(self, user_id):
        assignment_list = self.list_role_assignments(
            user_id=user_id, effective=True)
        # Use set() to process the list to remove any duplicates
        domain_ids = list(set([x['domain_id'] for x in assignment_list
                               if x.get('domain_id')]))
        return PROVIDERS.resource_api.list_domains_from_ids(domain_ids)

    def list_domains_for_groups(self, group_ids):
        assignment_list = self.list_role_assignments(
            source_from_group_ids=group_ids, effective=True)
        domain_ids = list(set([x['domain_id'] for x in assignment_list
                               if x.get('domain_id')]))
        return PROVIDERS.resource_api.list_domains_from_ids(domain_ids)

    def list_projects_for_groups(self, group_ids):
        assignment_list = self.list_role_assignments(
            source_from_group_ids=group_ids, effective=True)
        project_ids = list(set([x['project_id'] for x in assignment_list
                               if x.get('project_id')]))
        return PROVIDERS.resource_api.list_projects_from_ids(project_ids)

    @notifications.role_assignment('deleted')
    def _remove_role_from_user_and_project_adapter(self, role_id, user_id=None,
                                                   group_id=None,
                                                   domain_id=None,
                                                   project_id=None,
                                                   inherited_to_projects=False,
                                                   context=None):

        # The parameters for this method must match the parameters for
        # delete_grant so that the notifications.role_assignment decorator
        # will work.

        self.driver.remove_role_from_user_and_project(user_id, project_id,
                                                      role_id)
        payload = {'user_id': user_id, 'project_id': project_id}
        notifications.Audit.internal(
            notifications.REMOVE_APP_CREDS_FOR_USER,
            payload
        )
        self._invalidate_token_cache(
            role_id, group_id, user_id, project_id, domain_id
        )

    def remove_role_from_user_and_project(self, user_id, project_id, role_id):
        self._remove_role_from_user_and_project_adapter(
            role_id, user_id=user_id, project_id=project_id)
        COMPUTED_ASSIGNMENTS_REGION.invalidate()

    def _invalidate_token_cache(self, role_id, group_id, user_id, project_id,
                                domain_id):
        if group_id:
            actor_type = 'group'
            actor_id = group_id
        elif user_id:
            actor_type = 'user'
            actor_id = user_id

        if domain_id:
            target_type = 'domain'
            target_id = domain_id
        elif project_id:
            target_type = 'project'
            target_id = project_id

        reason = (
            'Invalidating the token cache because role %(role_id)s was '
            'removed from %(actor_type)s %(actor_id)s on %(target_type)s '
            '%(target_id)s.' %
            {'role_id': role_id, 'actor_type': actor_type,
             'actor_id': actor_id, 'target_type': target_type,
             'target_id': target_id}
        )
        notifications.invalidate_token_cache_notification(reason)

    @notifications.role_assignment('created')
    def create_grant(self, role_id, user_id=None, group_id=None,
                     domain_id=None, project_id=None,
                     inherited_to_projects=False,
                     initiator=None):
        role = PROVIDERS.role_api.get_role(role_id)
        if domain_id:
            PROVIDERS.resource_api.get_domain(domain_id)
        if project_id:
            project = PROVIDERS.resource_api.get_project(project_id)

            # For domain specific roles, the domain of the project
            # and role must match
            if role['domain_id'] and project['domain_id'] != role['domain_id']:
                raise exception.DomainSpecificRoleMismatch(
                    role_id=role_id,
                    project_id=project_id)

        self.driver.create_grant(
            role_id, user_id=user_id, group_id=group_id, domain_id=domain_id,
            project_id=project_id, inherited_to_projects=inherited_to_projects
        )
        COMPUTED_ASSIGNMENTS_REGION.invalidate()

    def get_grant(self, role_id, user_id=None, group_id=None,
                  domain_id=None, project_id=None,
                  inherited_to_projects=False):
        role_ref = PROVIDERS.role_api.get_role(role_id)
        if domain_id:
            PROVIDERS.resource_api.get_domain(domain_id)
        if project_id:
            PROVIDERS.resource_api.get_project(project_id)
        self.check_grant_role_id(
            role_id, user_id=user_id, group_id=group_id, domain_id=domain_id,
            project_id=project_id, inherited_to_projects=inherited_to_projects
        )
        return role_ref

    def list_grants(self, user_id=None, group_id=None,
                    domain_id=None, project_id=None,
                    inherited_to_projects=False):
        if domain_id:
            PROVIDERS.resource_api.get_domain(domain_id)
        if project_id:
            PROVIDERS.resource_api.get_project(project_id)
        grant_ids = self.list_grant_role_ids(
            user_id=user_id, group_id=group_id, domain_id=domain_id,
            project_id=project_id, inherited_to_projects=inherited_to_projects
        )
        return PROVIDERS.role_api.list_roles_from_ids(grant_ids)

    @notifications.role_assignment('deleted')
    def delete_grant(self, role_id, user_id=None, group_id=None,
                     domain_id=None, project_id=None,
                     inherited_to_projects=False,
                     initiator=None):

        # check if role exist before any processing
        PROVIDERS.role_api.get_role(role_id)

        if group_id is None:
            # check if role exists on the user before revoke
            self.check_grant_role_id(
                role_id, user_id=user_id, group_id=None, domain_id=domain_id,
                project_id=project_id,
                inherited_to_projects=inherited_to_projects
            )
            self._invalidate_token_cache(
                role_id, group_id, user_id, project_id, domain_id
            )
        else:
            try:
                # check if role exists on the group before revoke
                self.check_grant_role_id(
                    role_id, user_id=None, group_id=group_id,
                    domain_id=domain_id, project_id=project_id,
                    inherited_to_projects=inherited_to_projects
                )
                if CONF.token.revoke_by_id:
                    self._invalidate_token_cache(
                        role_id, group_id, user_id, project_id, domain_id
                    )
            except exception.GroupNotFound:
                LOG.debug('Group %s not found, no tokens to invalidate.',
                          group_id)

        if domain_id:
            PROVIDERS.resource_api.get_domain(domain_id)
        if project_id:
            PROVIDERS.resource_api.get_project(project_id)
        self.driver.delete_grant(
            role_id, user_id=user_id, group_id=group_id, domain_id=domain_id,
            project_id=project_id, inherited_to_projects=inherited_to_projects
        )
        COMPUTED_ASSIGNMENTS_REGION.invalidate()

    # The methods _expand_indirect_assignment, _list_direct_role_assignments
    # and _list_effective_role_assignments below are only used on
    # list_role_assignments, but they are not in its scope as nested functions
    # since it would significantly increase McCabe complexity, that should be
    # kept as it is in order to detect unnecessarily complex code, which is not
    # this case.

    def _expand_indirect_assignment(self, ref, user_id=None, project_id=None,
                                    subtree_ids=None, expand_groups=True):
        """Return a list of expanded role assignments.

        This methods is called for each discovered assignment that either needs
        a group assignment expanded into individual user assignments, or needs
        an inherited assignment to be applied to its children.

        In all cases, if either user_id and/or project_id is specified, then we
        filter the result on those values.

        If project_id is specified and subtree_ids is None, then this
        indicates that we are only interested in that one project. If
        subtree_ids is not None, then this is an indicator that any
        inherited assignments need to be expanded down the tree. The
        actual subtree_ids don't need to be used as a filter here, since we
        already ensured only those assignments that could affect them
        were passed to this method.

        If expand_groups is True then we expand groups out to a list of
        assignments, one for each member of that group.

        """
        def create_group_assignment(base_ref, user_id):
            """Create a group assignment from the provided ref."""
            ref = copy.deepcopy(base_ref)

            ref['user_id'] = user_id

            indirect = ref.setdefault('indirect', {})
            indirect['group_id'] = ref.pop('group_id')

            return ref

        def expand_group_assignment(ref, user_id):
            """Expand group role assignment.

            For any group role assignment on a target, it is replaced by a list
            of role assignments containing one for each user of that group on
            that target.

            An example of accepted ref is::

            {
                'group_id': group_id,
                'project_id': project_id,
                'role_id': role_id
            }

            Once expanded, it should be returned as a list of entities like the
            one below, one for each user_id in the provided group_id.

            ::

            {
                'user_id': user_id,
                'project_id': project_id,
                'role_id': role_id,
                'indirect' : {
                    'group_id': group_id
                }
            }

            Returned list will be formatted by the Controller, which will
            deduce a role assignment came from group membership if it has both
            'user_id' in the main body of the dict and 'group_id' in indirect
            subdict.

            """
            if user_id:
                return [create_group_assignment(ref, user_id=user_id)]

            # Note(prashkre): Try to get the users in a group,
            # if a group wasn't found in the backend, users are set
            # as empty list.
            try:
                users = PROVIDERS.identity_api.list_users_in_group(
                    ref['group_id'])
            except exception.GroupNotFound:
                LOG.warning('Group %(group)s was not found but still has role '
                            'assignments.', {'group': ref['group_id']})
                users = []

            return [create_group_assignment(ref, user_id=m['id'])
                    for m in users]

        def expand_inherited_assignment(ref, user_id, project_id, subtree_ids,
                                        expand_groups):
            """Expand inherited role assignments.

            If expand_groups is True and this is a group role assignment on a
            target, replace it by a list of role assignments containing one for
            each user of that group, on every project under that target. If
            expand_groups is False, then return a group assignment on an
            inherited target.

            If this is a user role assignment on a specific target (i.e.
            project_id is specified, but subtree_ids is None) then simply
            format this as a single assignment (since we are effectively
            filtering on project_id). If however, project_id is None or
            subtree_ids is not None, then replace this one assignment with a
            list of role assignments for that user on every project under
            that target.

            An example of accepted ref is::

            {
                'group_id': group_id,
                'project_id': parent_id,
                'role_id': role_id,
                'inherited_to_projects': 'projects'
            }

            Once expanded, it should be returned as a list of entities like the
            one below, one for each user_id in the provided group_id and
            for each subproject_id in the project_id subtree.

            ::

            {
                'user_id': user_id,
                'project_id': subproject_id,
                'role_id': role_id,
                'indirect' : {
                    'group_id': group_id,
                    'project_id': parent_id
                }
            }

            Returned list will be formatted by the Controller, which will
            deduce a role assignment came from group membership if it has both
            'user_id' in the main body of the dict and 'group_id' in the
            'indirect' subdict, as well as it is possible to deduce if it has
            come from inheritance if it contains both a 'project_id' in the
            main body of the dict and 'parent_id' in the 'indirect' subdict.

            """
            def create_inherited_assignment(base_ref, project_id):
                """Create a project assignment from the provided ref.

                base_ref can either be a project or domain inherited
                assignment ref.

                """
                ref = copy.deepcopy(base_ref)

                indirect = ref.setdefault('indirect', {})
                if ref.get('project_id'):
                    indirect['project_id'] = ref.pop('project_id')
                else:
                    indirect['domain_id'] = ref.pop('domain_id')

                ref['project_id'] = project_id
                ref.pop('inherited_to_projects')

                return ref

            # Define expanded project list to which to apply this assignment
            if project_id:
                # Since ref is an inherited assignment and we are filtering by
                # project(s), we are only going to apply the assignment to the
                # relevant project(s)
                project_ids = [project_id]
                if subtree_ids:
                    project_ids += subtree_ids
                    # If this is a domain inherited assignment, then we know
                    # that all the project_ids will get this assignment. If
                    # it's a project inherited assignment, and the assignment
                    # point is an ancestor of project_id, then we know that
                    # again all the project_ids will get the assignment.  If,
                    # however, the assignment point is within the subtree,
                    # then only a partial tree will get the assignment.
                    resource_api = PROVIDERS.resource_api
                    if ref.get('project_id'):
                        if ref['project_id'] in project_ids:
                            project_ids = (
                                [x['id'] for x in
                                 resource_api.list_projects_in_subtree(
                                     ref['project_id'])])
            elif ref.get('domain_id'):
                # A domain inherited assignment, so apply it to all projects
                # in this domain
                project_ids = (
                    [x['id'] for x in
                        PROVIDERS.resource_api.list_projects_in_domain(
                            ref['domain_id'])])
            else:
                # It must be a project assignment, so apply it to its subtree
                project_ids = (
                    [x['id'] for x in
                        PROVIDERS.resource_api.list_projects_in_subtree(
                            ref['project_id'])])

            new_refs = []
            if 'group_id' in ref:
                if expand_groups:
                    # Expand role assignment to all group members on any
                    # inherited target of any of the projects
                    for ref in expand_group_assignment(ref, user_id):
                        new_refs += [create_inherited_assignment(ref, proj_id)
                                     for proj_id in project_ids]
                else:
                    # Just place the group assignment on any inherited target
                    # of any of the projects
                    new_refs += [create_inherited_assignment(ref, proj_id)
                                 for proj_id in project_ids]
            else:
                # Expand role assignment for all projects
                new_refs += [create_inherited_assignment(ref, proj_id)
                             for proj_id in project_ids]

            return new_refs

        if ref.get('inherited_to_projects') == 'projects':
            return expand_inherited_assignment(
                ref, user_id, project_id, subtree_ids, expand_groups)
        elif 'group_id' in ref and expand_groups:
            return expand_group_assignment(ref, user_id)
        return [ref]

    def add_implied_roles(self, role_refs):
        """Expand out implied roles.

        The role_refs passed in have had all inheritance and group assignments
        expanded out. We now need to look at the role_id in each ref and see
        if it is a prior role for some implied roles. If it is, then we need to
        duplicate that ref, one for each implied role. We store the prior role
        in the indirect dict that is part of such a duplicated ref, so that a
        caller can determine where the assignment came from.

        """
        def _make_implied_ref_copy(prior_ref, implied_role_id):
            # Create a ref for an implied role from the ref of a prior role,
            # setting the new role_id to be the implied role and the indirect
            # role_id to be the prior role
            implied_ref = copy.deepcopy(prior_ref)
            implied_ref['role_id'] = implied_role_id
            indirect = implied_ref.setdefault('indirect', {})
            indirect['role_id'] = prior_ref['role_id']
            return implied_ref

        try:
            implied_roles_cache = {}
            role_refs_to_check = list(role_refs)
            ref_results = list(role_refs)
            checked_role_refs = list()
            while(role_refs_to_check):
                next_ref = role_refs_to_check.pop()
                checked_role_refs.append(next_ref)
                next_role_id = next_ref['role_id']
                if next_role_id in implied_roles_cache:
                    implied_roles = implied_roles_cache[next_role_id]
                else:
                    implied_roles = (
                        PROVIDERS.role_api.list_implied_roles(next_role_id))
                    implied_roles_cache[next_role_id] = implied_roles
                for implied_role in implied_roles:
                    implied_ref = (
                        _make_implied_ref_copy(
                            next_ref, implied_role['implied_role_id']))
                    if implied_ref in checked_role_refs:
                        # Avoid traversing a cycle
                        continue
                    else:
                        ref_results.append(implied_ref)
                        role_refs_to_check.append(implied_ref)
        except exception.NotImplemented:
            LOG.error('Role driver does not support implied roles.')

        return ref_results

    def _filter_by_role_id(self, role_id, ref_results):
        # if we arrive here, we need to filer by role_id.
        filter_results = []
        for ref in ref_results:
            if ref['role_id'] == role_id:
                filter_results.append(ref)
        return filter_results

    def _strip_domain_roles(self, role_refs):
        """Post process assignment list for domain roles.

        Domain roles are only designed to do the job of inferring other roles
        and since that has been done before this method is called, we need to
        remove any assignments that include a domain role.

        """
        def _role_is_global(role_id):
            ref = PROVIDERS.role_api.get_role(role_id)
            return (ref['domain_id'] is None)

        filter_results = []
        for ref in role_refs:
            if _role_is_global(ref['role_id']):
                filter_results.append(ref)
        return filter_results

    def _list_effective_role_assignments(self, role_id, user_id, group_id,
                                         domain_id, project_id, subtree_ids,
                                         inherited, source_from_group_ids,
                                         strip_domain_roles):
        """List role assignments in effective mode.

        When using effective mode, besides the direct assignments, the indirect
        ones that come from grouping or inheritance are retrieved and will then
        be expanded.

        The resulting list of assignments will be filtered by the provided
        parameters. If subtree_ids is not None, then we also want to include
        all subtree_ids in the filter as well. Since we are in effective mode,
        group can never act as a filter (since group assignments are expanded
        into user roles) and domain can only be filter if we want non-inherited
        assignments, since domains can't inherit assignments.

        The goal of this method is to only ask the driver for those
        assignments as could effect the result based on the parameter filters
        specified, hence avoiding retrieving a huge list.

        """
        def list_role_assignments_for_actor(
                role_id, inherited, user_id=None, group_ids=None,
                project_id=None, subtree_ids=None, domain_id=None):
            """List role assignments for actor on target.

            List direct and indirect assignments for an actor, optionally
            for a given target (i.e. projects or domain).

            :param role_id: List for a specific role, can be None meaning all
                            roles
            :param inherited: Indicates whether inherited assignments or only
                              direct assignments are required.  If None, then
                              both are required.
            :param user_id: If not None, list only assignments that affect this
                            user.
            :param group_ids: A list of groups required. Only one of user_id
                              and group_ids can be specified
            :param project_id: If specified, only include those assignments
                               that affect at least this project, with
                               additionally any projects specified in
                               subtree_ids
            :param subtree_ids: The list of projects in the subtree. If
                                specified, also include those assignments that
                                affect these projects. These projects are
                                guaranteed to be in the same domain as the
                                project specified in project_id. subtree_ids
                                can only be specified if project_id has also
                                been specified.
            :param domain_id: If specified, only include those assignments
                              that affect this domain - by definition this will
                              not include any inherited assignments

            :returns: List of assignments matching the criteria. Any inherited
                      or group assignments that could affect the resulting
                      response are included.

            """
            project_ids_of_interest = None
            if project_id:
                if subtree_ids:
                    project_ids_of_interest = subtree_ids + [project_id]
                else:
                    project_ids_of_interest = [project_id]

            # List direct project role assignments
            non_inherited_refs = []
            if inherited is False or inherited is None:
                # Get non inherited assignments
                non_inherited_refs = self.driver.list_role_assignments(
                    role_id=role_id, domain_id=domain_id,
                    project_ids=project_ids_of_interest, user_id=user_id,
                    group_ids=group_ids, inherited_to_projects=False)

            inherited_refs = []
            if inherited is True or inherited is None:
                # Get inherited assignments
                if project_id:
                    # The project and any subtree are guaranteed to be owned by
                    # the same domain, so since we are filtering by these
                    # specific projects, then we can only get inherited
                    # assignments from their common domain or from any of
                    # their parents projects.

                    # List inherited assignments from the project's domain
                    proj_domain_id = PROVIDERS.resource_api.get_project(
                        project_id)['domain_id']
                    inherited_refs += self.driver.list_role_assignments(
                        role_id=role_id, domain_id=proj_domain_id,
                        user_id=user_id, group_ids=group_ids,
                        inherited_to_projects=True)

                    # For inherited assignments from projects, since we know
                    # they are from the same tree the only places these can
                    # come from are from parents of the main project or
                    # inherited assignments on the project or subtree itself.
                    source_ids = [project['id'] for project in
                                  PROVIDERS.resource_api.list_project_parents(
                                      project_id)]
                    if subtree_ids:
                        source_ids += project_ids_of_interest
                    if source_ids:
                        inherited_refs += self.driver.list_role_assignments(
                            role_id=role_id, project_ids=source_ids,
                            user_id=user_id, group_ids=group_ids,
                            inherited_to_projects=True)
                else:
                    # List inherited assignments without filtering by target
                    inherited_refs = self.driver.list_role_assignments(
                        role_id=role_id, user_id=user_id, group_ids=group_ids,
                        inherited_to_projects=True)

            return non_inherited_refs + inherited_refs

        # If filtering by group or inherited domain assignment the list is
        # guaranteed to be empty
        if group_id or (domain_id and inherited):
            return []

        if user_id and source_from_group_ids:
            # You can't do both - and since source_from_group_ids is only used
            # internally, this must be a coding error by the caller.
            msg = _('Cannot list assignments sourced from groups and filtered '
                    'by user ID.')
            raise exception.UnexpectedError(msg)

        # If filtering by domain, then only non-inherited assignments are
        # relevant, since domains don't inherit assignments
        inherited = False if domain_id else inherited

        # List user or explicit group assignments.
        # Due to the need to expand implied roles, this call will skip
        # filtering by role_id and instead return the whole set of roles.
        # Matching on the specified role is performed at the end.
        direct_refs = list_role_assignments_for_actor(
            role_id=None, user_id=user_id, group_ids=source_from_group_ids,
            project_id=project_id, subtree_ids=subtree_ids,
            domain_id=domain_id, inherited=inherited)

        # And those from the user's groups, so long as we are not restricting
        # to a set of source groups (in which case we already got those
        # assignments in the direct listing above).
        group_refs = []
        if not source_from_group_ids and user_id:
            group_ids = self._get_group_ids_for_user_id(user_id)
            if group_ids:
                group_refs = list_role_assignments_for_actor(
                    role_id=None, project_id=project_id,
                    subtree_ids=subtree_ids, group_ids=group_ids,
                    domain_id=domain_id, inherited=inherited)

        # Expand grouping and inheritance on retrieved role assignments
        refs = []
        expand_groups = (source_from_group_ids is None)
        for ref in (direct_refs + group_refs):
            refs += self._expand_indirect_assignment(
                ref, user_id, project_id, subtree_ids, expand_groups)

        refs = self.add_implied_roles(refs)
        if strip_domain_roles:
            refs = self._strip_domain_roles(refs)
        if role_id:
            refs = self._filter_by_role_id(role_id, refs)

        return refs

    def _list_direct_role_assignments(self, role_id, user_id, group_id, system,
                                      domain_id, project_id, subtree_ids,
                                      inherited):
        """List role assignments without applying expansion.

        Returns a list of direct role assignments, where their attributes match
        the provided filters. If subtree_ids is not None, then we also want to
        include all subtree_ids in the filter as well.

        """
        group_ids = [group_id] if group_id else None
        project_ids_of_interest = None
        if project_id:
            if subtree_ids:
                project_ids_of_interest = subtree_ids + [project_id]
            else:
                project_ids_of_interest = [project_id]

        project_and_domain_assignments = []
        if not system:
            project_and_domain_assignments = self.driver.list_role_assignments(
                role_id=role_id, user_id=user_id, group_ids=group_ids,
                domain_id=domain_id, project_ids=project_ids_of_interest,
                inherited_to_projects=inherited)

        system_assignments = []
        if system or (not project_id and not domain_id and not system):
            if user_id:
                assignments = self.list_system_grants_for_user(user_id)
                for assignment in assignments:
                    system_assignments.append(
                        {'system': {'all': True},
                         'user_id': user_id,
                         'role_id': assignment['id']}
                    )
            elif group_id:
                assignments = self.list_system_grants_for_group(group_id)
                for assignment in assignments:
                    system_assignments.append(
                        {'system': {'all': True},
                         'group_id': group_id,
                         'role_id': assignment['id']}
                    )
            else:
                assignments = self.list_all_system_grants()
                for assignment in assignments:
                    a = {}
                    if assignment['type'] == self._GROUP_SYSTEM:
                        a['group_id'] = assignment['actor_id']
                    elif assignment['type'] == self._USER_SYSTEM:
                        a['user_id'] = assignment['actor_id']
                    a['role_id'] = assignment['role_id']
                    a['system'] = {'all': True}
                    system_assignments.append(a)

            if role_id:
                system_assignments = [
                    sa for sa in system_assignments
                    if role_id == sa['role_id']
                ]

        assignments = []
        for assignment in itertools.chain(
                project_and_domain_assignments, system_assignments):
            assignments.append(assignment)

        return assignments

    def list_role_assignments(self, role_id=None, user_id=None, group_id=None,
                              system=None, domain_id=None, project_id=None,
                              include_subtree=False, inherited=None,
                              effective=None, include_names=False,
                              source_from_group_ids=None,
                              strip_domain_roles=True):
        """List role assignments, honoring effective mode and provided filters.

        Returns a list of role assignments, where their attributes match the
        provided filters (role_id, user_id, group_id, domain_id, project_id and
        inherited). If include_subtree is True, then assignments on all
        descendants of the project specified by project_id are also included.
        The inherited filter defaults to None, meaning to get both
        non-inherited and inherited role assignments.

        If effective mode is specified, this means that rather than simply
        return the assignments that match the filters, any group or
        inheritance assignments will be expanded. Group assignments will
        become assignments for all the users in that group, and inherited
        assignments will be shown on the projects below the assignment point.
        Think of effective mode as being the list of assignments that actually
        affect a user, for example the roles that would be placed in a token.

        If include_names is set to true the entities' names are returned
        in addition to their id's.

        source_from_group_ids is a list of group IDs and, if specified, then
        only those assignments that are derived from membership of these groups
        are considered, and any such assignments will not be expanded into
        their user membership assignments. This is different to a group filter
        of the resulting list, instead being a restriction on which assignments
        should be considered before expansion of inheritance. This option is
        only used internally (i.e. it is not exposed at the API level) and is
        only supported in effective mode (since in regular mode there is no
        difference between this and a group filter, other than it is a list of
        groups).

        In effective mode, any domain specific roles are usually stripped from
        the returned assignments (since such roles are not placed in tokens).
        This stripping can be disabled by specifying strip_domain_roles=False,
        which is useful for internal calls like trusts which need to examine
        the full set of roles.
        """
        subtree_ids = None
        if project_id and include_subtree:
            subtree_ids = (
                [x['id'] for x in
                    PROVIDERS.resource_api.list_projects_in_subtree(
                        project_id)])

        if system != 'all':
            system = None

        if effective:
            role_assignments = self._list_effective_role_assignments(
                role_id, user_id, group_id, domain_id, project_id,
                subtree_ids, inherited, source_from_group_ids,
                strip_domain_roles)
        else:
            role_assignments = self._list_direct_role_assignments(
                role_id, user_id, group_id, system, domain_id, project_id,
                subtree_ids, inherited)

        if include_names:
            return self._get_names_from_role_assignments(role_assignments)
        return role_assignments

    def _get_names_from_role_assignments(self, role_assignments):
        role_assign_list = []

        for role_asgmt in role_assignments:
            new_assign = copy.deepcopy(role_asgmt)
            for key, value in role_asgmt.items():
                if key == 'domain_id':
                    _domain = PROVIDERS.resource_api.get_domain(value)
                    new_assign['domain_name'] = _domain['name']
                elif key == 'user_id':
                    try:
                        # Note(knikolla): Try to get the user, otherwise
                        # if the user wasn't found in the backend
                        # use empty values.
                        _user = PROVIDERS.identity_api.get_user(value)
                    except exception.UserNotFound:
                        msg = ('User %(user)s not found in the'
                               ' backend but still has role assignments.')
                        LOG.warning(msg, {'user': value})
                        new_assign['user_name'] = ''
                        new_assign['user_domain_id'] = ''
                        new_assign['user_domain_name'] = ''
                    else:
                        new_assign['user_name'] = _user['name']
                        new_assign['user_domain_id'] = _user['domain_id']
                        new_assign['user_domain_name'] = (
                            PROVIDERS.resource_api.get_domain(
                                _user['domain_id'])['name'])
                elif key == 'group_id':
                    try:
                        # Note(knikolla): Try to get the group, otherwise
                        # if the group wasn't found in the backend
                        # use empty values.
                        _group = PROVIDERS.identity_api.get_group(value)
                    except exception.GroupNotFound:
                        msg = ('Group %(group)s not found in the'
                               ' backend but still has role assignments.')
                        LOG.warning(msg, {'group': value})
                        new_assign['group_name'] = ''
                        new_assign['group_domain_id'] = ''
                        new_assign['group_domain_name'] = ''
                    else:
                        new_assign['group_name'] = _group['name']
                        new_assign['group_domain_id'] = _group['domain_id']
                        new_assign['group_domain_name'] = (
                            PROVIDERS.resource_api.get_domain(
                                _group['domain_id'])['name'])
                elif key == 'project_id':
                    _project = PROVIDERS.resource_api.get_project(value)
                    new_assign['project_name'] = _project['name']
                    new_assign['project_domain_id'] = _project['domain_id']
                    new_assign['project_domain_name'] = (
                        PROVIDERS.resource_api.get_domain(
                            _project['domain_id'])['name'])
                elif key == 'role_id':
                    _role = PROVIDERS.role_api.get_role(value)
                    new_assign['role_name'] = _role['name']
                    if _role['domain_id'] is not None:
                        new_assign['role_domain_id'] = _role['domain_id']
                        new_assign['role_domain_name'] = (
                            PROVIDERS.resource_api.get_domain(
                                _role['domain_id'])['name'])
            role_assign_list.append(new_assign)
        return role_assign_list

    def delete_group_assignments(self, group_id):
        # FIXME(lbragstad): This should be refactored in the Rocky release so
        # that we can pass the group_id to the system assignment backend like
        # we do with the project and domain assignment backend. Holding off on
        # this because it will require an interface change to the backend,
        # making it harder to backport for Queens RC.
        self.driver.delete_group_assignments(group_id)
        system_assignments = self.list_system_grants_for_group(group_id)
        for assignment in system_assignments:
            self.delete_system_grant_for_group(group_id, assignment['id'])

    def delete_user_assignments(self, user_id):
        # FIXME(lbragstad): This should be refactored in the Rocky release so
        # that we can pass the user_id to the system assignment backend like we
        # do with the project and domain assignment backend. Holding off on
        # this because it will require an interface change to the backend,
        # making it harder to backport for Queens RC.
        self.driver.delete_user_assignments(user_id)
        system_assignments = self.list_system_grants_for_user(user_id)
        for assignment in system_assignments:
            self.delete_system_grant_for_user(user_id, assignment['id'])

    def check_system_grant_for_user(self, user_id, role_id):
        """Check if a user has a specific role on the system.

        :param user_id: the ID of the user in the assignment
        :param role_id: the ID of the system role in the assignment

        :raises keystone.exception.RoleAssignmentNotFound: if the user doesn't
            have a role assignment matching the role_id on the system

        """
        target_id = self._SYSTEM_SCOPE_TOKEN
        inherited = False
        return self.driver.check_system_grant(
            role_id, user_id, target_id, inherited
        )

    def list_system_grants_for_user(self, user_id):
        """Return a list of roles the user has on the system.

        :param user_id: the ID of the user

        :returns: a list of role assignments the user has system-wide

        """
        target_id = self._SYSTEM_SCOPE_TOKEN
        assignment_type = self._USER_SYSTEM
        grants = self.driver.list_system_grants(
            user_id, target_id, assignment_type
        )
        grant_ids = []
        for grant in grants:
            grant_ids.append(grant['role_id'])

        return PROVIDERS.role_api.list_roles_from_ids(grant_ids)

    def create_system_grant_for_user(self, user_id, role_id):
        """Grant a user a role on the system.

        :param user_id: the ID of the user
        :param role_id: the ID of the role to grant on the system

        """
        role = PROVIDERS.role_api.get_role(role_id)
        if role.get('domain_id'):
            raise exception.ValidationError(
                'Role %(role_id)s is a domain-specific role. Unable to use '
                'a domain-specific role in a system assignment.' % {
                    'role_id': role_id
                }
            )
        target_id = self._SYSTEM_SCOPE_TOKEN
        assignment_type = self._USER_SYSTEM
        inherited = False
        self.driver.create_system_grant(
            role_id, user_id, target_id, assignment_type, inherited
        )

    def delete_system_grant_for_user(self, user_id, role_id):
        """Remove a system grant from a user.

        :param user_id: the ID of the user
        :param role_id: the ID of the role to remove from the user on the
                        system

        :raises keystone.exception.RoleAssignmentNotFound: if the user doesn't
            have a role assignment with role_id on the system

        """
        target_id = self._SYSTEM_SCOPE_TOKEN
        inherited = False
        self.driver.delete_system_grant(role_id, user_id, target_id, inherited)

    def check_system_grant_for_group(self, group_id, role_id):
        """Check if a group has a specific role on the system.

        :param group_id: the ID of the group in the assignment
        :param role_id: the ID of the system role in the assignment

        :raises keystone.exception.RoleAssignmentNotFound: if the group doesn't
            have a role assignment matching the role_id on the system

        """
        target_id = self._SYSTEM_SCOPE_TOKEN
        inherited = False
        return self.driver.check_system_grant(
            role_id, group_id, target_id, inherited
        )

    def list_system_grants_for_group(self, group_id):
        """Return a list of roles the group has on the system.

        :param group_id: the ID of the group

        :returns: a list of role assignments the group has system-wide

        """
        target_id = self._SYSTEM_SCOPE_TOKEN
        assignment_type = self._GROUP_SYSTEM
        grants = self.driver.list_system_grants(
            group_id, target_id, assignment_type
        )
        grant_ids = []
        for grant in grants:
            grant_ids.append(grant['role_id'])

        return PROVIDERS.role_api.list_roles_from_ids(grant_ids)

    def create_system_grant_for_group(self, group_id, role_id):
        """Grant a group a role on the system.

        :param group_id: the ID of the group
        :param role_id: the ID of the role to grant on the system

        """
        role = PROVIDERS.role_api.get_role(role_id)
        if role.get('domain_id'):
            raise exception.ValidationError(
                'Role %(role_id)s is a domain-specific role. Unable to use '
                'a domain-specific role in a system assignment.' % {
                    'role_id': role_id
                }
            )
        target_id = self._SYSTEM_SCOPE_TOKEN
        assignment_type = self._GROUP_SYSTEM
        inherited = False
        self.driver.create_system_grant(
            role_id, group_id, target_id, assignment_type, inherited
        )

    def delete_system_grant_for_group(self, group_id, role_id):
        """Remove a system grant from a group.

        :param group_id: the ID of the group
        :param role_id: the ID of the role to remove from the group on the
                        system

        :raises keystone.exception.RoleAssignmentNotFound: if the group doesn't
            have a role assignment with role_id on the system

        """
        target_id = self._SYSTEM_SCOPE_TOKEN
        inherited = False
        self.driver.delete_system_grant(
            role_id, group_id, target_id, inherited
        )

    def list_all_system_grants(self):
        """Return a list of all system grants."""
        actor_id = None
        target_id = self._SYSTEM_SCOPE_TOKEN
        assignment_type = None
        return self.driver.list_system_grants(
            actor_id, target_id, assignment_type
        )


class RoleManager(manager.Manager):
    """Default pivot point for the Role backend."""

    driver_namespace = 'keystone.role'
    _provides_api = 'role_api'

    _ROLE = 'role'

    def __init__(self):
        # If there is a specific driver specified for role, then use it.
        # Otherwise retrieve the driver type from the assignment driver.
        role_driver = CONF.role.driver

        if role_driver is None:
            # Explicitly load the assignment manager object
            assignment_driver = CONF.assignment.driver
            assignment_manager_obj = manager.load_driver(
                Manager.driver_namespace,
                assignment_driver)
            role_driver = assignment_manager_obj.default_role_driver()

        super(RoleManager, self).__init__(role_driver)

    @MEMOIZE
    def get_role(self, role_id):
        return self.driver.get_role(role_id)

    def get_unique_role_by_name(self, role_name, hints=None):
        if not hints:
            hints = driver_hints.Hints()
        hints.add_filter("name", role_name, case_sensitive=True)
        found_roles = PROVIDERS.role_api.list_roles(hints)
        if not found_roles:
            raise exception.RoleNotFound(
                _("Role %s is not defined") % role_name
            )
        elif len(found_roles) == 1:
            return {'id': found_roles[0]['id']}
        else:
            raise exception.AmbiguityError(resource='role',
                                           name=role_name)

    def create_role(self, role_id, role, initiator=None):
        # Shallow copy to help mitigate in-line changes that might impact
        # testing. This mirrors create_user, specifically relevant for
        # resource options.
        role = role.copy()
        ret = self.driver.create_role(role_id, role)
        notifications.Audit.created(self._ROLE, role_id, initiator)
        if MEMOIZE.should_cache(ret):
            self.get_role.set(ret, self, role_id)
        return ret

    @manager.response_truncated
    def list_roles(self, hints=None):
        return self.driver.list_roles(hints or driver_hints.Hints())

    def _is_immutable(self, role):
        return role['options'].get(ro_opt.IMMUTABLE_OPT.option_name, False)

    def update_role(self, role_id, role, initiator=None):
        original_role = self.driver.get_role(role_id)
        # Prevent the update of immutable set roles unless the update is
        # exclusively used for
        ro_opt.check_immutable_update(
            original_resource_ref=original_role,
            new_resource_ref=role,
            type='role',
            resource_id=role_id)

        if ('domain_id' in role and
                role['domain_id'] != original_role['domain_id']):
            raise exception.ValidationError(
                message=_('Update of `domain_id` is not allowed.'))

        ret = self.driver.update_role(role_id, role)
        notifications.Audit.updated(self._ROLE, role_id, initiator)
        self.get_role.invalidate(self, role_id)
        return ret

    def delete_role(self, role_id, initiator=None):
        role = self.driver.get_role(role_id)
        # Prevent deletion of immutable roles.
        ro_opt.check_immutable_delete(resource_ref=role,
                                      resource_type='role',
                                      resource_id=role_id)
        PROVIDERS.assignment_api.delete_role_assignments(role_id)
        PROVIDERS.assignment_api._send_app_cred_notification_for_role_removal(
            role_id
        )
        self.driver.delete_role(role_id)
        notifications.Audit.deleted(self._ROLE, role_id, initiator)
        self.get_role.invalidate(self, role_id)
        reason = (
            'Invalidating the token cache because role %(role_id)s has been '
            'removed. Role assignments for users will be recalculated and '
            'enforced accordingly the next time they authenticate or validate '
            'a token' % {'role_id': role_id}
        )
        notifications.invalidate_token_cache_notification(reason)
        COMPUTED_ASSIGNMENTS_REGION.invalidate()

    # TODO(ayoung): Add notification
    def create_implied_role(self, prior_role_id, implied_role_id):
        implied_role = self.driver.get_role(implied_role_id)
        prior_role = self.driver.get_role(prior_role_id)
        if implied_role['name'] in CONF.assignment.prohibited_implied_role:
            raise exception.InvalidImpliedRole(role_id=implied_role_id)
        if prior_role['domain_id'] is None and implied_role['domain_id']:
            msg = _('Global role cannot imply a domain-specific role')
            raise exception.InvalidImpliedRole(msg,
                                               role_id=implied_role_id)
        response = self.driver.create_implied_role(
            prior_role_id, implied_role_id)
        COMPUTED_ASSIGNMENTS_REGION.invalidate()
        return response

    def delete_implied_role(self, prior_role_id, implied_role_id):
        self.driver.delete_implied_role(prior_role_id, implied_role_id)
        COMPUTED_ASSIGNMENTS_REGION.invalidate()
