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

import abc
import copy

from oslo_config import cfg
from oslo_log import log
import six

from keystone.common import cache
from keystone.common import dependency
from keystone.common import driver_hints
from keystone.common import manager
from keystone import exception
from keystone.i18n import _
from keystone.i18n import _LI
from keystone import notifications


CONF = cfg.CONF
LOG = log.getLogger(__name__)
MEMOIZE = cache.get_memoization_decorator(section='role')


@dependency.provider('assignment_api')
@dependency.requires('credential_api', 'identity_api', 'resource_api',
                     'revoke_api', 'role_api')
class Manager(manager.Manager):
    """Default pivot point for the Assignment backend.

    See :mod:`keystone.common.manager.Manager` for more details on how this
    dynamically calls the backend.

    """

    driver_namespace = 'keystone.assignment'

    _PROJECT = 'project'
    _ROLE_REMOVED_FROM_USER = 'role_removed_from_user'
    _INVALIDATION_USER_PROJECT_TOKENS = 'invalidate_user_project_tokens'

    def __init__(self):
        assignment_driver = CONF.assignment.driver

        # If there is no explicit assignment driver specified, we let the
        # identity driver tell us what to use. This is for backward
        # compatibility reasons from the time when identity, resource and
        # assignment were all part of identity.
        if assignment_driver is None:
            identity_driver = dependency.get_provider('identity_api').driver
            assignment_driver = identity_driver.default_assignment_driver()

        super(Manager, self).__init__(assignment_driver)

    def _get_group_ids_for_user_id(self, user_id):
        # TODO(morganfainberg): Implement a way to get only group_ids
        # instead of the more expensive to_dict() call for each record.
        return [x['id'] for
                x in self.identity_api.list_groups_for_user(user_id)]

    def list_user_ids_for_project(self, tenant_id):
        self.resource_api.get_project(tenant_id)
        return self.driver.list_user_ids_for_project(tenant_id)

    def _list_parent_ids_of_project(self, project_id):
        if CONF.os_inherit.enabled:
            return [x['id'] for x in (
                self.resource_api.list_project_parents(project_id))]
        else:
            return []

    def get_roles_for_user_and_project(self, user_id, tenant_id):
        """Get the roles associated with a user within given project.

        This includes roles directly assigned to the user on the
        project, as well as those by virtue of group membership. If
        the OS-INHERIT extension is enabled, then this will also
        include roles inherited from the domain.

        :returns: a list of role ids.
        :raises: keystone.exception.UserNotFound,
                 keystone.exception.ProjectNotFound

        """
        def _get_group_project_roles(user_id, project_ref):
            group_ids = self._get_group_ids_for_user_id(user_id)
            return self.list_role_ids_for_groups_on_project(
                group_ids,
                project_ref['id'],
                project_ref['domain_id'],
                self._list_parent_ids_of_project(project_ref['id']))

        def _get_user_project_roles(user_id, project_ref):
            role_list = []
            try:
                metadata_ref = self._get_metadata(user_id=user_id,
                                                  tenant_id=project_ref['id'])
                role_list = self._roles_from_role_dicts(
                    metadata_ref.get('roles', {}), False)
            except exception.MetadataNotFound:
                pass

            if CONF.os_inherit.enabled:
                # Now get any inherited roles for the owning domain
                try:
                    metadata_ref = self._get_metadata(
                        user_id=user_id, domain_id=project_ref['domain_id'])
                    role_list += self._roles_from_role_dicts(
                        metadata_ref.get('roles', {}), True)
                except (exception.MetadataNotFound, exception.NotImplemented):
                    pass
                # As well inherited roles from parent projects
                for p in self.resource_api.list_project_parents(
                        project_ref['id']):
                    p_roles = self.list_grants(
                        user_id=user_id, project_id=p['id'],
                        inherited_to_projects=True)
                    role_list += [x['id'] for x in p_roles]

            return role_list

        project_ref = self.resource_api.get_project(tenant_id)
        user_role_list = _get_user_project_roles(user_id, project_ref)
        group_role_list = _get_group_project_roles(user_id, project_ref)
        # Use set() to process the list to remove any duplicates
        return list(set(user_role_list + group_role_list))

    def get_roles_for_user_and_domain(self, user_id, domain_id):
        """Get the roles associated with a user within given domain.

        :returns: a list of role ids.
        :raises: keystone.exception.UserNotFound,
                 keystone.exception.DomainNotFound

        """

        def _get_group_domain_roles(user_id, domain_id):
            role_list = []
            group_ids = self._get_group_ids_for_user_id(user_id)
            for group_id in group_ids:
                try:
                    metadata_ref = self._get_metadata(group_id=group_id,
                                                      domain_id=domain_id)
                    role_list += self._roles_from_role_dicts(
                        metadata_ref.get('roles', {}), False)
                except (exception.MetadataNotFound, exception.NotImplemented):
                    # MetadataNotFound implies no group grant, so skip.
                    # Ignore NotImplemented since not all backends support
                    # domains.
                    pass
            return role_list

        def _get_user_domain_roles(user_id, domain_id):
            metadata_ref = {}
            try:
                metadata_ref = self._get_metadata(user_id=user_id,
                                                  domain_id=domain_id)
            except (exception.MetadataNotFound, exception.NotImplemented):
                # MetadataNotFound implies no user grants.
                # Ignore NotImplemented since not all backends support
                # domains
                pass
            return self._roles_from_role_dicts(
                metadata_ref.get('roles', {}), False)

        self.resource_api.get_domain(domain_id)
        user_role_list = _get_user_domain_roles(user_id, domain_id)
        group_role_list = _get_group_domain_roles(user_id, domain_id)
        # Use set() to process the list to remove any duplicates
        return list(set(user_role_list + group_role_list))

    def get_roles_for_groups(self, group_ids, project_id=None, domain_id=None):
        """Get a list of roles for this group on domain and/or project."""

        if project_id is not None:
            project = self.resource_api.get_project(project_id)
            role_ids = self.list_role_ids_for_groups_on_project(
                group_ids, project_id, project['domain_id'],
                self._list_parent_ids_of_project(project_id))
        elif domain_id is not None:
            role_ids = self.list_role_ids_for_groups_on_domain(
                group_ids, domain_id)
        else:
            raise AttributeError(_("Must specify either domain or project"))

        return self.role_api.list_roles_from_ids(role_ids)

    def add_user_to_project(self, tenant_id, user_id):
        """Add user to a tenant by creating a default role relationship.

        :raises: keystone.exception.ProjectNotFound,
                 keystone.exception.UserNotFound

        """
        self.resource_api.get_project(tenant_id)
        try:
            self.role_api.get_role(CONF.member_role_id)
            self.driver.add_role_to_user_and_project(
                user_id,
                tenant_id,
                CONF.member_role_id)
        except exception.RoleNotFound:
            LOG.info(_LI("Creating the default role %s "
                         "because it does not exist."),
                     CONF.member_role_id)
            role = {'id': CONF.member_role_id,
                    'name': CONF.member_role_name}
            try:
                self.role_api.create_role(CONF.member_role_id, role)
            except exception.Conflict:
                LOG.info(_LI("Creating the default role %s failed because it "
                             "was already created"),
                         CONF.member_role_id)
            # now that default role exists, the add should succeed
            self.driver.add_role_to_user_and_project(
                user_id,
                tenant_id,
                CONF.member_role_id)

    @notifications.role_assignment('created')
    def _add_role_to_user_and_project_adapter(self, role_id, user_id=None,
                                              group_id=None, domain_id=None,
                                              project_id=None,
                                              inherited_to_projects=False,
                                              context=None):

        # The parameters for this method must match the parameters for
        # create_grant so that the notifications.role_assignment decorator
        # will work.

        self.resource_api.get_project(project_id)
        self.role_api.get_role(role_id)
        self.driver.add_role_to_user_and_project(user_id, project_id, role_id)

    def add_role_to_user_and_project(self, user_id, tenant_id, role_id):
        self._add_role_to_user_and_project_adapter(
            role_id, user_id=user_id, project_id=tenant_id)

    def remove_user_from_project(self, tenant_id, user_id):
        """Remove user from a tenant

        :raises: keystone.exception.ProjectNotFound,
                 keystone.exception.UserNotFound

        """
        roles = self.get_roles_for_user_and_project(user_id, tenant_id)
        if not roles:
            raise exception.NotFound(tenant_id)
        for role_id in roles:
            try:
                self.driver.remove_role_from_user_and_project(user_id,
                                                              tenant_id,
                                                              role_id)
                self.revoke_api.revoke_by_grant(role_id, user_id=user_id,
                                                project_id=tenant_id)

            except exception.RoleNotFound:
                LOG.debug("Removing role %s failed because it does not exist.",
                          role_id)

    # TODO(henry-nash): We might want to consider list limiting this at some
    # point in the future.
    def list_projects_for_user(self, user_id, hints=None):
        # NOTE(henry-nash): In order to get a complete list of user projects,
        # the driver will need to look at group assignments.  To avoid cross
        # calling between the assignment and identity driver we get the group
        # list here and pass it in. The rest of the detailed logic of listing
        # projects for a user is pushed down into the driver to enable
        # optimization with the various backend technologies (SQL, LDAP etc.).

        group_ids = self._get_group_ids_for_user_id(user_id)
        project_ids = self.list_project_ids_for_user(
            user_id, group_ids, hints or driver_hints.Hints())

        if not CONF.os_inherit.enabled:
            return self.resource_api.list_projects_from_ids(project_ids)

        # Inherited roles are enabled, so check to see if this user has any
        # inherited role (direct or group) on any parent project, in which
        # case we must add in all the projects in that parent's subtree.
        project_ids = set(project_ids)
        project_ids_inherited = self.list_project_ids_for_user(
            user_id, group_ids, hints or driver_hints.Hints(), inherited=True)
        for proj_id in project_ids_inherited:
            project_ids.update(
                (x['id'] for x in
                 self.resource_api.list_projects_in_subtree(proj_id)))

        # Now do the same for any domain inherited roles
        domain_ids = self.list_domain_ids_for_user(
            user_id, group_ids, hints or driver_hints.Hints(),
            inherited=True)
        project_ids.update(
            self.resource_api.list_project_ids_from_domain_ids(domain_ids))

        return self.resource_api.list_projects_from_ids(list(project_ids))

    # TODO(henry-nash): We might want to consider list limiting this at some
    # point in the future.
    def list_domains_for_user(self, user_id, hints=None):
        # NOTE(henry-nash): In order to get a complete list of user domains,
        # the driver will need to look at group assignments.  To avoid cross
        # calling between the assignment and identity driver we get the group
        # list here and pass it in. The rest of the detailed logic of listing
        # projects for a user is pushed down into the driver to enable
        # optimization with the various backend technologies (SQL, LDAP etc.).
        group_ids = self._get_group_ids_for_user_id(user_id)
        domain_ids = self.list_domain_ids_for_user(
            user_id, group_ids, hints or driver_hints.Hints())
        return self.resource_api.list_domains_from_ids(domain_ids)

    def list_domains_for_groups(self, group_ids):
        domain_ids = self.list_domain_ids_for_groups(group_ids)
        return self.resource_api.list_domains_from_ids(domain_ids)

    def list_projects_for_groups(self, group_ids):
        project_ids = (
            self.list_project_ids_for_groups(group_ids, driver_hints.Hints()))
        if not CONF.os_inherit.enabled:
            return self.resource_api.list_projects_from_ids(project_ids)

        # os_inherit extension is enabled, so check to see if these groups have
        # any inherited role assignment on: i) any domain, in which case we
        # must add in all the projects in that domain; ii) any project, in
        # which case we must add in all the subprojects under that project in
        # the hierarchy.

        domain_ids = self.list_domain_ids_for_groups(group_ids, inherited=True)

        project_ids_from_domains = (
            self.resource_api.list_project_ids_from_domain_ids(domain_ids))

        parents_ids = self.list_project_ids_for_groups(group_ids,
                                                       driver_hints.Hints(),
                                                       inherited=True)

        subproject_ids = []
        for parent_id in parents_ids:
            subtree = self.resource_api.list_projects_in_subtree(parent_id)
            subproject_ids += [subproject['id'] for subproject in subtree]

        return self.resource_api.list_projects_from_ids(
            list(set(project_ids + project_ids_from_domains + subproject_ids)))

    def list_role_assignments_for_role(self, role_id=None):
        # NOTE(henry-nash): Currently the efficiency of the key driver
        # implementation (SQL) of list_role_assignments is severely hampered by
        # the existence of the multiple grant tables - hence there is little
        # advantage in pushing the logic of this method down into the driver.
        # Once the single assignment table is implemented, then this situation
        # will be different, and this method should have its own driver
        # implementation.
        return [r for r in self.driver.list_role_assignments()
                if r['role_id'] == role_id]

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
        if project_id:
            self._emit_invalidate_grant_token_persistence(user_id, project_id)
        else:
            self.identity_api.emit_invalidate_user_token_persistence(user_id)
        self.revoke_api.revoke_by_grant(role_id, user_id=user_id,
                                        project_id=project_id)

    def remove_role_from_user_and_project(self, user_id, tenant_id, role_id):
        self._remove_role_from_user_and_project_adapter(
            role_id, user_id=user_id, project_id=tenant_id)

    @notifications.internal(notifications.INVALIDATE_USER_TOKEN_PERSISTENCE)
    def _emit_invalidate_user_token_persistence(self, user_id):
        self.identity_api.emit_invalidate_user_token_persistence(user_id)

    def _emit_invalidate_grant_token_persistence(self, user_id, project_id):
        self.identity_api.emit_invalidate_grant_token_persistence(
            {'user_id': user_id, 'project_id': project_id}
        )

    @notifications.role_assignment('created')
    def create_grant(self, role_id, user_id=None, group_id=None,
                     domain_id=None, project_id=None,
                     inherited_to_projects=False, context=None):
        self.role_api.get_role(role_id)
        if domain_id:
            self.resource_api.get_domain(domain_id)
        if project_id:
            self.resource_api.get_project(project_id)
        self.driver.create_grant(role_id, user_id, group_id, domain_id,
                                 project_id, inherited_to_projects)

    def get_grant(self, role_id, user_id=None, group_id=None,
                  domain_id=None, project_id=None,
                  inherited_to_projects=False):
        role_ref = self.role_api.get_role(role_id)
        if domain_id:
            self.resource_api.get_domain(domain_id)
        if project_id:
            self.resource_api.get_project(project_id)
        self.check_grant_role_id(
            role_id, user_id, group_id, domain_id, project_id,
            inherited_to_projects)
        return role_ref

    def list_grants(self, user_id=None, group_id=None,
                    domain_id=None, project_id=None,
                    inherited_to_projects=False):
        if domain_id:
            self.resource_api.get_domain(domain_id)
        if project_id:
            self.resource_api.get_project(project_id)
        grant_ids = self.list_grant_role_ids(
            user_id, group_id, domain_id, project_id, inherited_to_projects)
        return self.role_api.list_roles_from_ids(grant_ids)

    @notifications.role_assignment('deleted')
    def _emit_revoke_user_grant(self, role_id, user_id, domain_id, project_id,
                                inherited_to_projects, context):
        self._emit_invalidate_grant_token_persistence(user_id, project_id)

    def delete_grant(self, role_id, user_id=None, group_id=None,
                     domain_id=None, project_id=None,
                     inherited_to_projects=False, context=None):
        if group_id is None:
            self.revoke_api.revoke_by_grant(user_id=user_id,
                                            role_id=role_id,
                                            domain_id=domain_id,
                                            project_id=project_id)
            self._emit_revoke_user_grant(
                role_id, user_id, domain_id, project_id,
                inherited_to_projects, context)
        else:
            try:
                # Group may contain a lot of users so revocation will be
                # by role & domain/project
                if domain_id is None:
                    self.revoke_api.revoke_by_project_role_assignment(
                        project_id, role_id
                    )
                else:
                    self.revoke_api.revoke_by_domain_role_assignment(
                        domain_id, role_id
                    )
                if CONF.token.revoke_by_id:
                    # NOTE(morganfainberg): The user ids are the important part
                    # for invalidating tokens below, so extract them here.
                    for user in self.identity_api.list_users_in_group(
                            group_id):
                        self._emit_revoke_user_grant(
                            role_id, user['id'], domain_id, project_id,
                            inherited_to_projects, context)
            except exception.GroupNotFound:
                LOG.debug('Group %s not found, no tokens to invalidate.',
                          group_id)

        # TODO(henry-nash): While having the call to get_role here mimics the
        # previous behavior (when it was buried inside the driver delete call),
        # this seems an odd place to have this check, given what we have
        # already done so far in this method. See Bug #1406776.
        self.role_api.get_role(role_id)

        if domain_id:
            self.resource_api.get_domain(domain_id)
        if project_id:
            self.resource_api.get_project(project_id)
        self.driver.delete_grant(role_id, user_id, group_id, domain_id,
                                 project_id, inherited_to_projects)

    # The methods _expand_indirect_assignment, _list_direct_role_assignments
    # and _list_effective_role_assignments below are only used on
    # list_role_assignments, but they are not in its scope as nested functions
    # since it would significantly increase McCabe complexity, that should be
    # kept as it is in order to detect unnecessarily complex code, which is not
    # this case.

    def _expand_indirect_assignment(self, ref, user_id=None,
                                    project_id=None):
        """Returns a list of expanded role assignments.

        This methods is called for each discovered assignment that either needs
        a group assignment expanded into individual user assignments, or needs
        an inherited assignment to be applied to its children.

        In all cases, if either user_id and/or project_id is specified, then we
        filter the result on those values.

        """

        def create_group_assignment(base_ref, user_id):
            """Creates a group assignment from the provided ref."""

            ref = copy.deepcopy(base_ref)

            ref['user_id'] = user_id

            indirect = ref.setdefault('indirect', {})
            indirect['group_id'] = ref.pop('group_id')

            return ref

        def expand_group_assignment(ref, user_id):
            """Expands group role assignment.

            For any group role assignment on a target, it is replaced by a list
            of role assignments containing one for each user of that group on
            that target.

            An example of accepted ref is:

            {
                'group_id': group_id,
                'project_id': project_id,
                'role_id': role_id
            }

            Once expanded, it should be returned as a list of entities like the
            one below, one for each each user_id in the provided group_id.

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

            return [create_group_assignment(ref, user_id=m['id'])
                    for m in self.identity_api.list_users_in_group(
                        ref['group_id'])]

        def expand_inherited_assignment(ref, user_id, project_id=None):
            """Expands inherited role assignments.

            If this is a group role assignment on a target, replace it by a
            list of role assignments containing one for each user of that
            group, on every project under that target.

            If this is a user role assignment on a target, replace it by a
            list of role assignments for that user on every project under
            that target.

            An example of accepted ref is:

            {
                'group_id': group_id,
                'project_id': parent_id,
                'role_id': role_id,
                'inherited_to_projects': 'projects'
            }

            Once expanded, it should be returned as a list of entities like the
            one below, one for each each user_id in the provided group_id and
            for each subproject_id in the project_id subtree.

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
                """Creates a project assignment from the provided ref.

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
                # Since ref is an inherited assignment, it must have come from
                # the domain or a parent. We only need apply it to the project
                # requested.
                project_ids = [project_id]
            elif ref.get('domain_id'):
                # A domain inherited assignment, so apply it to all projects
                # in this domain
                project_ids = (
                    [x['id'] for x in
                        self.resource_api.list_projects_in_domain(
                            ref['domain_id'])])
            else:
                # It must be a project assignment, so apply it to the subtree
                project_ids = (
                    [x['id'] for x in
                        self.resource_api.list_projects_in_subtree(
                            ref['project_id'])])

            new_refs = []
            if 'group_id' in ref:
                # Expand role assignment for all members and for all projects
                for ref in expand_group_assignment(ref, user_id):
                    new_refs += [create_inherited_assignment(ref, proj_id)
                                 for proj_id in project_ids]
            else:
                # Expand role assignment for all projects
                new_refs += [create_inherited_assignment(ref, proj_id)
                             for proj_id in project_ids]

            return new_refs

        if ref.get('inherited_to_projects') == 'projects':
            return expand_inherited_assignment(ref, user_id, project_id)
        elif 'group_id' in ref:
            return expand_group_assignment(ref, user_id)
        return [ref]

    def _list_effective_role_assignments(self, role_id, user_id, group_id,
                                         domain_id, project_id, inherited):
        """List role assignments in effective mode.

        When using effective mode, besides the direct assignments, the indirect
        ones that come from grouping or inheritance are retrieved and will then
        be expanded.

        The resulting list of assignments will be filtered by the provided
        parameters, although since we are in effective mode, group can never
        act as a filter (since group assignments are expanded into user roles)
        and domain can only be filter if we want non-inherited assignments,
        since domains can't inherit assignments.

        The goal of this method is to only ask the driver for those
        assignments as could effect the result based on the parameter filters
        specified, hence avoiding retrieving a huge list.

        """

        def list_role_assignments_for_actor(
                role_id, inherited, user_id=None,
                group_ids=None, project_id=None, domain_id=None):
            """List role assignments for actor on target.

            List direct and indirect assignments for an actor, optionally
            for a given target (i.e. project or domain).

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
                               that affect this project
            :param domain_id: If specified, only include those assignments
                              that affect this domain - by definition this will
                              not include any inherited assignments

            :returns: List of assignments matching the criteria. Any inherited
                      or group assignments that could affect the resulting
                      response are included.

            """

            # List direct project role assignments
            project_ids = [project_id] if project_id else None

            non_inherited_refs = []
            if inherited is False or inherited is None:
                # Get non inherited assignments
                non_inherited_refs = self.driver.list_role_assignments(
                    role_id=role_id, domain_id=domain_id,
                    project_ids=project_ids, user_id=user_id,
                    group_ids=group_ids, inherited_to_projects=False)

            inherited_refs = []
            if inherited is True or inherited is None:
                # Get inherited assignments
                if project_id:
                    # If we are filtering by a specific project, then we can
                    # only get inherited assignments from its domain or from
                    # any of its parents.

                    # List inherited assignments from the project's domain
                    proj_domain_id = self.resource_api.get_project(
                        project_id)['domain_id']
                    inherited_refs += self.driver.list_role_assignments(
                        role_id=role_id, domain_id=proj_domain_id,
                        user_id=user_id, group_ids=group_ids,
                        inherited_to_projects=True)

                    # And those assignments that could be inherited from the
                    # project's parents.
                    parent_ids = [project['id'] for project in
                                  self.resource_api.list_project_parents(
                                      project_id)]
                    if parent_ids:
                        inherited_refs += self.driver.list_role_assignments(
                            role_id=role_id, project_ids=parent_ids,
                            user_id=user_id, group_ids=group_ids,
                            inherited_to_projects=True)
                else:
                    # List inherited assignments without filtering by target
                    inherited_refs = self.driver.list_role_assignments(
                        role_id=role_id, user_id=user_id, group_ids=group_ids,
                        inherited_to_projects=True)

            return non_inherited_refs + inherited_refs

        # If filtering by group or inherited domain assignment the list is
        # guranteed to be empty
        if group_id or (domain_id and inherited):
            return []

        # If filtering by domain, then only non-inherited assignments are
        # relevant, since domains don't inherit assignments
        inherited = False if domain_id else inherited

        # List user assignments
        direct_refs = list_role_assignments_for_actor(
            role_id=role_id, user_id=user_id, project_id=project_id,
            domain_id=domain_id, inherited=inherited)

        # And those from the user's groups
        group_refs = []
        if user_id:
            group_ids = self._get_group_ids_for_user_id(user_id)
            if group_ids:
                group_refs = list_role_assignments_for_actor(
                    role_id=role_id, project_id=project_id,
                    group_ids=group_ids, domain_id=domain_id,
                    inherited=inherited)

        # Expand grouping and inheritance on retrieved role assignments
        refs = []
        for ref in (direct_refs + group_refs):
            refs += self._expand_indirect_assignment(ref=ref, user_id=user_id,
                                                     project_id=project_id)

        return refs

    def _list_direct_role_assignments(self, role_id, user_id, group_id,
                                      domain_id, project_id, inherited):
        """List role assignments without applying expansion.

        Returns a list of direct role assignments, where their attributes match
        the provided filters.

        """
        group_ids = [group_id] if group_id else None
        project_ids = [project_id] if project_id else None

        return self.driver.list_role_assignments(
            role_id=role_id, user_id=user_id, group_ids=group_ids,
            domain_id=domain_id, project_ids=project_ids,
            inherited_to_projects=inherited)

    def list_role_assignments(self, role_id=None, user_id=None, group_id=None,
                              domain_id=None, project_id=None, inherited=None,
                              effective=None):
        """List role assignments, honoring effective mode and provided filters.

        Returns a list of role assignments, where their attributes match the
        provided filters (role_id, user_id, group_id, domain_id, project_id and
        inherited). The inherited filter defaults to None, meaning to get both
        non-inherited and inherited role assignments.

        If effective mode is specified, this means that rather than simply
        return the assignments that match the filters, any group or
        inheritance assignments will be expanded. Group assignments will
        become assignments for all the users in that group, and inherited
        assignments will be shown on the projects below the assignment point.
        Think of effective mode as being the list of assignments that actually
        affect a user, for example the roles that would be placed in a token.

        If OS-INHERIT extension is disabled or the used driver does not support
        inherited roles retrieval, inherited role assignments will be ignored.

        """

        if not CONF.os_inherit.enabled:
            if inherited:
                return []
            inherited = False

        if effective:
            return self._list_effective_role_assignments(
                role_id, user_id, group_id, domain_id, project_id, inherited)
        else:
            return self._list_direct_role_assignments(
                role_id, user_id, group_id, domain_id, project_id, inherited)

    def delete_tokens_for_role_assignments(self, role_id):
        assignments = self.list_role_assignments_for_role(role_id=role_id)

        # Iterate over the assignments for this role and build the list of
        # user or user+project IDs for the tokens we need to delete
        user_ids = set()
        user_and_project_ids = list()
        for assignment in assignments:
            # If we have a project assignment, then record both the user and
            # project IDs so we can target the right token to delete. If it is
            # a domain assignment, we might as well kill all the tokens for
            # the user, since in the vast majority of cases all the tokens
            # for a user will be within one domain anyway, so not worth
            # trying to delete tokens for each project in the domain.
            if 'user_id' in assignment:
                if 'project_id' in assignment:
                    user_and_project_ids.append(
                        (assignment['user_id'], assignment['project_id']))
                elif 'domain_id' in assignment:
                    self._emit_invalidate_user_token_persistence(
                        assignment['user_id'])
            elif 'group_id' in assignment:
                # Add in any users for this group, being tolerant of any
                # cross-driver database integrity errors.
                try:
                    users = self.identity_api.list_users_in_group(
                        assignment['group_id'])
                except exception.GroupNotFound:
                    # Ignore it, but log a debug message
                    if 'project_id' in assignment:
                        target = _('Project (%s)') % assignment['project_id']
                    elif 'domain_id' in assignment:
                        target = _('Domain (%s)') % assignment['domain_id']
                    else:
                        target = _('Unknown Target')
                    msg = ('Group (%(group)s), referenced in assignment '
                           'for %(target)s, not found - ignoring.')
                    LOG.debug(msg, {'group': assignment['group_id'],
                                    'target': target})
                    continue

                if 'project_id' in assignment:
                    for user in users:
                        user_and_project_ids.append(
                            (user['id'], assignment['project_id']))
                elif 'domain_id' in assignment:
                    for user in users:
                        self._emit_invalidate_user_token_persistence(
                            user['id'])

        # Now process the built up lists.  Before issuing calls to delete any
        # tokens, let's try and minimize the number of calls by pruning out
        # any user+project deletions where a general token deletion for that
        # same user is also planned.
        user_and_project_ids_to_action = []
        for user_and_project_id in user_and_project_ids:
            if user_and_project_id[0] not in user_ids:
                user_and_project_ids_to_action.append(user_and_project_id)

        for user_id, project_id in user_and_project_ids_to_action:
            self._emit_invalidate_user_project_tokens_notification(
                {'user_id': user_id,
                 'project_id': project_id})

    @notifications.internal(
        notifications.INVALIDATE_USER_PROJECT_TOKEN_PERSISTENCE)
    def _emit_invalidate_user_project_tokens_notification(self, payload):
        # This notification's payload is a dict of user_id and
        # project_id so the token provider can invalidate the tokens
        # from persistence if persistence is enabled.
        pass


@six.add_metaclass(abc.ABCMeta)
class AssignmentDriverV8(object):

    def _role_to_dict(self, role_id, inherited):
        role_dict = {'id': role_id}
        if inherited:
            role_dict['inherited_to'] = 'projects'
        return role_dict

    def _roles_from_role_dicts(self, dict_list, inherited):
        role_list = []
        for d in dict_list:
            if ((not d.get('inherited_to') and not inherited) or
               (d.get('inherited_to') == 'projects' and inherited)):
                role_list.append(d['id'])
        return role_list

    def _get_list_limit(self):
        return CONF.assignment.list_limit or CONF.list_limit

    @abc.abstractmethod
    def list_user_ids_for_project(self, tenant_id):
        """Lists all user IDs with a role assignment in the specified project.

        :returns: a list of user_ids or an empty set.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def add_role_to_user_and_project(self, user_id, tenant_id, role_id):
        """Add a role to a user within given tenant.

        :raises: keystone.exception.Conflict


        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def remove_role_from_user_and_project(self, user_id, tenant_id, role_id):
        """Remove a role from a user within given tenant.

        :raises: keystone.exception.RoleNotFound

        """
        raise exception.NotImplemented()  # pragma: no cover

    # assignment/grant crud

    @abc.abstractmethod
    def create_grant(self, role_id, user_id=None, group_id=None,
                     domain_id=None, project_id=None,
                     inherited_to_projects=False):
        """Creates a new assignment/grant.

        If the assignment is to a domain, then optionally it may be
        specified as inherited to owned projects (this requires
        the OS-INHERIT extension to be enabled).

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_grant_role_ids(self, user_id=None, group_id=None,
                            domain_id=None, project_id=None,
                            inherited_to_projects=False):
        """Lists role ids for assignments/grants."""

        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def check_grant_role_id(self, role_id, user_id=None, group_id=None,
                            domain_id=None, project_id=None,
                            inherited_to_projects=False):
        """Checks an assignment/grant role id.

        :raises: keystone.exception.RoleAssignmentNotFound
        :returns: None or raises an exception if grant not found

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_grant(self, role_id, user_id=None, group_id=None,
                     domain_id=None, project_id=None,
                     inherited_to_projects=False):
        """Deletes assignments/grants.

        :raises: keystone.exception.RoleAssignmentNotFound

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_role_assignments(self, role_id=None,
                              user_id=None, group_ids=None,
                              domain_id=None, project_ids=None,
                              inherited_to_projects=None):
        """Returns a list of role assignments for actors on targets.

        Available parameters represent values in which the returned role
        assignments attributes need to be filtered on.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_project_ids_for_user(self, user_id, group_ids, hints,
                                  inherited=False):
        """List all project ids associated with a given user.

        :param user_id: the user in question
        :param group_ids: the groups this user is a member of.  This list is
                          built in the Manager, so that the driver itself
                          does not have to call across to identity.
        :param hints: filter hints which the driver should
                      implement if at all possible.
        :param inherited: whether assignments marked as inherited should
                          be included.

        :returns: a list of project ids or an empty list.

        This method should not try and expand any inherited assignments,
        just report the projects that have the role for this user. The manager
        method is responsible for expanding out inherited assignments.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_project_ids_for_groups(self, group_ids, hints,
                                    inherited=False):
        """List project ids accessible to specified groups.

        :param group_ids: List of group ids.
        :param hints: filter hints which the driver should
                      implement if at all possible.
        :param inherited: whether assignments marked as inherited should
                          be included.
        :returns: List of project ids accessible to specified groups.

        This method should not try and expand any inherited assignments,
        just report the projects that have the role for this group. The manager
        method is responsible for expanding out inherited assignments.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_domain_ids_for_user(self, user_id, group_ids, hints,
                                 inherited=False):
        """List all domain ids associated with a given user.

        :param user_id: the user in question
        :param group_ids: the groups this user is a member of.  This list is
                          built in the Manager, so that the driver itself
                          does not have to call across to identity.
        :param hints: filter hints which the driver should
                      implement if at all possible.
        :param inherited: whether to return domain_ids that have inherited
                          assignments or not.

        :returns: a list of domain ids or an empty list.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_domain_ids_for_groups(self, group_ids, inherited=False):
        """List domain ids accessible to specified groups.

        :param group_ids: List of group ids.
        :param inherited: whether to return domain_ids that have inherited
                          assignments or not.
        :returns: List of domain ids accessible to specified groups.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_role_ids_for_groups_on_project(
            self, group_ids, project_id, project_domain_id, project_parents):
        """List the group role ids for a specific project.

        Supports the ``OS-INHERIT`` role inheritance from the project's domain
        if supported by the assignment driver.

        :param group_ids: list of group ids
        :type group_ids: list
        :param project_id: project identifier
        :type project_id: str
        :param project_domain_id: project's domain identifier
        :type project_domain_id: str
        :param project_parents: list of parent ids of this project
        :type project_parents: list
        :returns: list of role ids for the project
        :rtype: list
        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def list_role_ids_for_groups_on_domain(self, group_ids, domain_id):
        """List the group role ids for a specific domain.

        :param group_ids: list of group ids
        :type group_ids: list
        :param domain_id: domain identifier
        :type domain_id: str
        :returns: list of role ids for the project
        :rtype: list
        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def delete_project_assignments(self, project_id):
        """Deletes all assignments for a project.

        :raises: keystone.exception.ProjectNotFound

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_role_assignments(self, role_id):
        """Deletes all assignments for a role."""

        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_user_assignments(self, user_id):
        """Deletes all assignments for a user.

        :raises: keystone.exception.RoleNotFound

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_group_assignments(self, group_id):
        """Deletes all assignments for a group.

        :raises: keystone.exception.RoleNotFound

        """
        raise exception.NotImplemented()  # pragma: no cover


Driver = manager.create_legacy_driver(AssignmentDriverV8)


@dependency.provider('role_api')
@dependency.requires('assignment_api')
class RoleManager(manager.Manager):
    """Default pivot point for the Role backend."""

    driver_namespace = 'keystone.role'

    _ROLE = 'role'

    def __init__(self):
        # If there is a specific driver specified for role, then use it.
        # Otherwise retrieve the driver type from the assignment driver.
        role_driver = CONF.role.driver

        if role_driver is None:
            assignment_manager = dependency.get_provider('assignment_api')
            role_driver = assignment_manager.default_role_driver()

        super(RoleManager, self).__init__(role_driver)

    @MEMOIZE
    def get_role(self, role_id):
        return self.driver.get_role(role_id)

    def create_role(self, role_id, role, initiator=None):
        ret = self.driver.create_role(role_id, role)
        notifications.Audit.created(self._ROLE, role_id, initiator)
        if MEMOIZE.should_cache(ret):
            self.get_role.set(ret, self, role_id)
        return ret

    @manager.response_truncated
    def list_roles(self, hints=None):
        return self.driver.list_roles(hints or driver_hints.Hints())

    def update_role(self, role_id, role, initiator=None):
        ret = self.driver.update_role(role_id, role)
        notifications.Audit.updated(self._ROLE, role_id, initiator)
        self.get_role.invalidate(self, role_id)
        return ret

    def delete_role(self, role_id, initiator=None):
        try:
            self.assignment_api.delete_tokens_for_role_assignments(role_id)
        except exception.NotImplemented:
            # FIXME(morganfainberg): Not all backends (ldap) implement
            # `list_role_assignments_for_role` which would have previously
            # caused a NotImplmented error to be raised when called through
            # the controller. Now error or proper action will always come from
            # the `delete_role` method logic. Work needs to be done to make
            # the behavior between drivers consistent (capable of revoking
            # tokens for the same circumstances).  This is related to the bug
            # https://bugs.launchpad.net/keystone/+bug/1221805
            pass
        self.assignment_api.delete_role_assignments(role_id)
        self.driver.delete_role(role_id)
        notifications.Audit.deleted(self._ROLE, role_id, initiator)
        self.get_role.invalidate(self, role_id)


@six.add_metaclass(abc.ABCMeta)
class RoleDriverV8(object):

    def _get_list_limit(self):
        return CONF.role.list_limit or CONF.list_limit

    @abc.abstractmethod
    def create_role(self, role_id, role):
        """Creates a new role.

        :raises: keystone.exception.Conflict

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_roles(self, hints):
        """List roles in the system.

        :param hints: filter hints which the driver should
                      implement if at all possible.

        :returns: a list of role_refs or an empty list.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_roles_from_ids(self, role_ids):
        """List roles for the provided list of ids.

        :param role_ids: list of ids

        :returns: a list of role_refs.

        This method is used internally by the assignment manager to bulk read
        a set of roles given their ids.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def get_role(self, role_id):
        """Get a role by ID.

        :returns: role_ref
        :raises: keystone.exception.RoleNotFound

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def update_role(self, role_id, role):
        """Updates an existing role.

        :raises: keystone.exception.RoleNotFound,
                 keystone.exception.Conflict

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_role(self, role_id):
        """Deletes an existing role.

        :raises: keystone.exception.RoleNotFound

        """
        raise exception.NotImplemented()  # pragma: no cover


RoleDriver = manager.create_legacy_driver(RoleDriverV8)
