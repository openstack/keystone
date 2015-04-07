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

"""Main entry point into the assignment service."""

import abc

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
from keystone.openstack.common import versionutils


CONF = cfg.CONF
LOG = log.getLogger(__name__)
MEMOIZE = cache.get_memoization_decorator(section='role')


def deprecated_to_role_api(f):
    """Specialized deprecation wrapper for assignment to role api.

    This wraps the standard deprecation wrapper and fills in the method
    names automatically.

    """
    @six.wraps(f)
    def wrapper(*args, **kwargs):
        x = versionutils.deprecated(
            what='assignment.' + f.__name__ + '()',
            as_of=versionutils.deprecated.KILO,
            in_favor_of='role.' + f.__name__ + '()')
        return x(f)
    return wrapper()


def deprecated_to_resource_api(f):
    """Specialized deprecation wrapper for assignment to resource api.

    This wraps the standard deprecation wrapper and fills in the method
    names automatically.

    """
    @six.wraps(f)
    def wrapper(*args, **kwargs):
        x = versionutils.deprecated(
            what='assignment.' + f.__name__ + '()',
            as_of=versionutils.deprecated.KILO,
            in_favor_of='resource.' + f.__name__ + '()')
        return x(f)
    return wrapper()


@dependency.provider('assignment_api')
@dependency.requires('credential_api', 'identity_api', 'resource_api',
                     'revoke_api', 'role_api')
class Manager(manager.Manager):
    """Default pivot point for the Assignment backend.

    See :mod:`keystone.common.manager.Manager` for more details on how this
    dynamically calls the backend.

    """
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
                for p in self.list_project_parents(project_ref['id']):
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

        self.get_domain(domain_id)
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
        self.identity_api.emit_invalidate_user_token_persistence(user_id)
        self.revoke_api.revoke_by_grant(role_id, user_id=user_id,
                                        project_id=project_id)

    def remove_role_from_user_and_project(self, user_id, tenant_id, role_id):
        self._remove_role_from_user_and_project_adapter(
            role_id, user_id=user_id, project_id=tenant_id)

    @notifications.internal(notifications.INVALIDATE_USER_TOKEN_PERSISTENCE)
    def _emit_invalidate_user_token_persistence(self, user_id):
        self.identity_api.emit_invalidate_user_token_persistence(user_id)

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
    def delete_grant(self, role_id, user_id=None, group_id=None,
                     domain_id=None, project_id=None,
                     inherited_to_projects=False, context=None):
        if group_id is None:
            self.revoke_api.revoke_by_grant(user_id=user_id,
                                            role_id=role_id,
                                            domain_id=domain_id,
                                            project_id=project_id)
        else:
            try:
                # NOTE(morganfainberg): The user ids are the important part
                # for invalidating tokens below, so extract them here.
                for user in self.identity_api.list_users_in_group(group_id):
                    if user['id'] != user_id:
                        self._emit_invalidate_user_token_persistence(
                            user['id'])
                        self.revoke_api.revoke_by_grant(
                            user_id=user['id'], role_id=role_id,
                            domain_id=domain_id, project_id=project_id)
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
        if user_id is not None:
            self._emit_invalidate_user_token_persistence(user_id)

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

    @deprecated_to_role_api
    def create_role(self, role_id, role):
        return self.role_api.create_role(role_id, role)

    @deprecated_to_role_api
    def get_role(self, role_id):
        return self.role_api.get_role(role_id)

    @deprecated_to_role_api
    def update_role(self, role_id, role):
        return self.role_api.update_role(role_id, role)

    @deprecated_to_role_api
    def delete_role(self, role_id):
        return self.role_api.delete_role(role_id)

    @deprecated_to_role_api
    def list_roles(self, hints=None):
        return self.role_api.list_roles(hints=hints)

    @deprecated_to_resource_api
    def create_project(self, project_id, project):
        return self.resource_api.create_project(project_id, project)

    @deprecated_to_resource_api
    def get_project_by_name(self, tenant_name, domain_id):
        return self.resource_api.get_project_by_name(tenant_name, domain_id)

    @deprecated_to_resource_api
    def get_project(self, project_id):
        return self.resource_api.get_project(project_id)

    @deprecated_to_resource_api
    def update_project(self, project_id, project):
        return self.resource_api.update_project(project_id, project)

    @deprecated_to_resource_api
    def delete_project(self, project_id):
        return self.resource_api.delete_project(project_id)

    @deprecated_to_resource_api
    def list_projects(self, hints=None):
        return self.resource_api.list_projects(hints=hints)

    @deprecated_to_resource_api
    def list_projects_in_domain(self, domain_id):
        return self.resource_api.list_projects_in_domain(domain_id)

    @deprecated_to_resource_api
    def create_domain(self, domain_id, domain):
        return self.resource_api.create_domain(domain_id, domain)

    @deprecated_to_resource_api
    def get_domain_by_name(self, domain_name):
        return self.resource_api.get_domain_by_name(domain_name)

    @deprecated_to_resource_api
    def get_domain(self, domain_id):
        return self.resource_api.get_domain(domain_id)

    @deprecated_to_resource_api
    def update_domain(self, domain_id, domain):
        return self.resource_api.update_domain(domain_id, domain)

    @deprecated_to_resource_api
    def delete_domain(self, domain_id):
        return self.resource_api.delete_domain(domain_id)

    @deprecated_to_resource_api
    def list_domains(self, hints=None):
        return self.resource_api.list_domains(hints=hints)

    @deprecated_to_resource_api
    def assert_domain_enabled(self, domain_id, domain=None):
        return self.resource_api.assert_domain_enabled(domain_id, domain)

    @deprecated_to_resource_api
    def assert_project_enabled(self, project_id, project=None):
        return self.resource_api.assert_project_enabled(project_id, project)

    @deprecated_to_resource_api
    def is_leaf_project(self, project_id):
        return self.resource_api.is_leaf_project(project_id)

    @deprecated_to_resource_api
    def list_project_parents(self, project_id, user_id=None):
        return self.resource_api.list_project_parents(project_id, user_id)

    @deprecated_to_resource_api
    def list_projects_in_subtree(self, project_id, user_id=None):
        return self.resource_api.list_projects_in_subtree(project_id, user_id)


@six.add_metaclass(abc.ABCMeta)
class Driver(object):

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

    def _add_role_to_role_dicts(self, role_id, inherited, dict_list,
                                allow_existing=True):
        # There is a difference in error semantics when trying to
        # assign a role that already exists between the coded v2 and v3
        # API calls.  v2 will error if the assignment already exists,
        # while v3 is silent. Setting the 'allow_existing' parameter
        # appropriately lets this call be used for both.
        role_set = set([frozenset(r.items()) for r in dict_list])
        key = frozenset(self._role_to_dict(role_id, inherited).items())
        if not allow_existing and key in role_set:
            raise KeyError
        role_set.add(key)
        return [dict(r) for r in role_set]

    def _remove_role_from_role_dicts(self, role_id, inherited, dict_list):
        role_set = set([frozenset(r.items()) for r in dict_list])
        role_set.remove(frozenset(self._role_to_dict(role_id,
                                                     inherited).items()))
        return [dict(r) for r in role_set]

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
    def list_role_assignments(self):

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

    # TODO(henry-nash): Rename the following two methods to match the more
    # meaningfully named ones above.

# TODO(ayoung): determine what else these two functions raise
    @abc.abstractmethod
    def delete_user(self, user_id):
        """Deletes all assignments for a user.

        :raises: keystone.exception.RoleNotFound

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_group(self, group_id):
        """Deletes all assignments for a group.

        :raises: keystone.exception.RoleNotFound

        """
        raise exception.NotImplemented()  # pragma: no cover


@dependency.provider('role_api')
@dependency.requires('assignment_api')
class RoleManager(manager.Manager):
    """Default pivot point for the Role backend."""

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
class RoleDriver(object):

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
