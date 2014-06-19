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

import six

from keystone import clean
from keystone.common import cache
from keystone.common import dependency
from keystone.common import driver_hints
from keystone.common import manager
from keystone import config
from keystone import exception
from keystone import notifications
from keystone.openstack.common.gettextutils import _
from keystone.openstack.common import log


CONF = config.CONF
LOG = log.getLogger(__name__)
SHOULD_CACHE = cache.should_cache_fn('assignment')

# NOTE(blk-u): The config option is not available at import time.
EXPIRATION_TIME = lambda: CONF.assignment.cache_time


def calc_default_domain():
    return {'description':
            (u'Owns users and tenants (i.e. projects)'
                ' available on Identity API v2.'),
            'enabled': True,
            'id': CONF.identity.default_domain_id,
            'name': u'Default'}


@dependency.provider('assignment_api')
@dependency.optional('revoke_api')
@dependency.requires('credential_api', 'identity_api', 'token_api')
class Manager(manager.Manager):
    """Default pivot point for the Assignment backend.

    See :mod:`keystone.common.manager.Manager` for more details on how this
    dynamically calls the backend.
    assignment.Manager() and identity.Manager() have a circular dependency.
    The late import works around this.  The if block prevents creation of the
    api object by both managers.
    """
    _PROJECT = 'project'

    def __init__(self):
        assignment_driver = CONF.assignment.driver

        if assignment_driver is None:
            identity_driver = dependency.REGISTRY['identity_api'].driver
            assignment_driver = identity_driver.default_assignment_driver()

        super(Manager, self).__init__(assignment_driver)

    @notifications.created(_PROJECT)
    def create_project(self, tenant_id, tenant):
        tenant = tenant.copy()
        tenant.setdefault('enabled', True)
        tenant['enabled'] = clean.project_enabled(tenant['enabled'])
        tenant.setdefault('description', '')
        ret = self.driver.create_project(tenant_id, tenant)
        if SHOULD_CACHE(ret):
            self.get_project.set(ret, self, tenant_id)
            self.get_project_by_name.set(ret, self, ret['name'],
                                         ret['domain_id'])
        return ret

    @notifications.disabled(_PROJECT, public=False)
    def _disable_project(self, tenant_id):
        return self.token_api.delete_tokens_for_users(
            self.list_user_ids_for_project(tenant_id),
            project_id=tenant_id)

    @notifications.updated(_PROJECT)
    def update_project(self, tenant_id, tenant):
        original_tenant = self.driver.get_project(tenant_id)
        tenant = tenant.copy()
        if 'enabled' in tenant:
            tenant['enabled'] = clean.project_enabled(tenant['enabled'])
        if not tenant.get('enabled', True):
            self._disable_project(tenant_id)
        ret = self.driver.update_project(tenant_id, tenant)
        self.get_project.invalidate(self, tenant_id)
        self.get_project_by_name.invalidate(self, original_tenant['name'],
                                            original_tenant['domain_id'])
        return ret

    @notifications.deleted(_PROJECT)
    def delete_project(self, tenant_id):
        project = self.driver.get_project(tenant_id)
        user_ids = self.list_user_ids_for_project(tenant_id)
        self.token_api.delete_tokens_for_users(user_ids, project_id=tenant_id)
        ret = self.driver.delete_project(tenant_id)
        self.get_project.invalidate(self, tenant_id)
        self.get_project_by_name.invalidate(self, project['name'],
                                            project['domain_id'])
        self.credential_api.delete_credentials_for_project(tenant_id)
        return ret

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
            role_list = []
            group_refs = self.identity_api.list_groups_for_user(user_id)
            for x in group_refs:
                try:
                    metadata_ref = self._get_metadata(
                        group_id=x['id'], tenant_id=project_ref['id'])
                    role_list += self._roles_from_role_dicts(
                        metadata_ref.get('roles', {}), False)
                except exception.MetadataNotFound:
                    # no group grant, skip
                    pass

                if CONF.os_inherit.enabled:
                    # Now get any inherited group roles for the owning domain
                    try:
                        metadata_ref = self._get_metadata(
                            group_id=x['id'],
                            domain_id=project_ref['domain_id'])
                        role_list += self._roles_from_role_dicts(
                            metadata_ref.get('roles', {}), True)
                    except (exception.MetadataNotFound,
                            exception.NotImplemented):
                        pass

            return role_list

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

            return role_list

        project_ref = self.get_project(tenant_id)
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
            group_refs = self.identity_api.list_groups_for_user(user_id)
            for x in group_refs:
                try:
                    metadata_ref = self._get_metadata(group_id=x['id'],
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

    def add_user_to_project(self, tenant_id, user_id):
        """Add user to a tenant by creating a default role relationship.

        :raises: keystone.exception.ProjectNotFound,
                 keystone.exception.UserNotFound

        """
        try:
            self.driver.add_role_to_user_and_project(
                user_id,
                tenant_id,
                config.CONF.member_role_id)
        except exception.RoleNotFound:
            LOG.info(_("Creating the default role %s "
                       "because it does not exist."),
                     config.CONF.member_role_id)
            role = {'id': CONF.member_role_id,
                    'name': CONF.member_role_name}
            self.driver.create_role(config.CONF.member_role_id, role)
            #now that default role exists, the add should succeed
            self.driver.add_role_to_user_and_project(
                user_id,
                tenant_id,
                config.CONF.member_role_id)

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
                if self.revoke_api:
                    self.revoke_api.revoke_by_grant(role_id, user_id=user_id,
                                                    project_id=tenant_id)

            except exception.RoleNotFound:
                LOG.debug(_("Removing role %s failed because it does not "
                            "exist."),
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

        group_ids = [x['id'] for
                     x in self.identity_api.list_groups_for_user(user_id)]
        return self.driver.list_projects_for_user(
            user_id, group_ids, hints or driver_hints.Hints())

    @cache.on_arguments(should_cache_fn=SHOULD_CACHE,
                        expiration_time=EXPIRATION_TIME)
    def get_domain(self, domain_id):
        return self.driver.get_domain(domain_id)

    @cache.on_arguments(should_cache_fn=SHOULD_CACHE,
                        expiration_time=EXPIRATION_TIME)
    def get_domain_by_name(self, domain_name):
        return self.driver.get_domain_by_name(domain_name)

    @notifications.created('domain')
    def create_domain(self, domain_id, domain):
        domain.setdefault('enabled', True)
        domain['enabled'] = clean.domain_enabled(domain['enabled'])
        ret = self.driver.create_domain(domain_id, domain)
        if SHOULD_CACHE(ret):
            self.get_domain.set(ret, self, domain_id)
            self.get_domain_by_name.set(ret, self, ret['name'])
        return ret

    @manager.response_truncated
    def list_domains(self, hints=None):
        return self.driver.list_domains(hints or driver_hints.Hints())

    @notifications.disabled('domain', public=False)
    def _disable_domain(self, domain_id):
        self.token_api.delete_tokens_for_domain(domain_id)

    @notifications.updated('domain')
    def update_domain(self, domain_id, domain):
        original_domain = self.driver.get_domain(domain_id)
        if 'enabled' in domain:
            domain['enabled'] = clean.domain_enabled(domain['enabled'])
        ret = self.driver.update_domain(domain_id, domain)
        # disable owned users & projects when the API user specifically set
        #     enabled=False
        if not domain.get('enabled', True):
            self._disable_domain(domain_id)
        self.get_domain.invalidate(self, domain_id)
        self.get_domain_by_name.invalidate(self, original_domain['name'])
        return ret

    @notifications.deleted('domain')
    def delete_domain(self, domain_id):
        # explicitly forbid deleting the default domain (this should be a
        # carefully orchestrated manual process involving configuration
        # changes, etc)
        if domain_id == CONF.identity.default_domain_id:
            raise exception.ForbiddenAction(action=_('delete the default '
                                                     'domain'))

        domain = self.driver.get_domain(domain_id)

        # To help avoid inadvertent deletes, we insist that the domain
        # has been previously disabled.  This also prevents a user deleting
        # their own domain since, once it is disabled, they won't be able
        # to get a valid token to issue this delete.
        if domain['enabled']:
            raise exception.ForbiddenAction(
                action=_('cannot delete a domain that is enabled, '
                         'please disable it first.'))

        self._delete_domain_contents(domain_id)
        self.driver.delete_domain(domain_id)
        self.get_domain.invalidate(self, domain_id)
        self.get_domain_by_name.invalidate(self, domain['name'])

    def _delete_domain_contents(self, domain_id):
        """Delete the contents of a domain.

        Before we delete a domain, we need to remove all the entities
        that are owned by it, i.e. Users, Groups & Projects. To do this we
        call the respective delete functions for these entities, which are
        themselves responsible for deleting any credentials and role grants
        associated with them as well as revoking any relevant tokens.

        The order we delete entities is also important since some types
        of backend may need to maintain referential integrity
        throughout, and many of the entities have relationship with each
        other. The following deletion order is therefore used:

        Projects: Reference user and groups for grants
        Groups: Reference users for membership and domains for grants
        Users: Reference domains for grants

        """
        user_refs = self.identity_api.list_users()
        proj_refs = self.list_projects()
        group_refs = self.identity_api.list_groups()

        # First delete the projects themselves
        for project in proj_refs:
            if project['domain_id'] == domain_id:
                try:
                    self.delete_project(project['id'])
                except exception.ProjectNotFound:
                    LOG.debug(_('Project %(projectid)s not found when '
                                'deleting domain contents for %(domainid)s, '
                                'continuing with cleanup.'),
                              {'projectid': project['id'],
                               'domainid': domain_id})

        for group in group_refs:
            # Cleanup any existing groups.
            if group['domain_id'] == domain_id:
                try:
                    self.identity_api.delete_group(group['id'],
                                                   domain_scope=domain_id)
                except exception.GroupNotFound:
                    LOG.debug(_('Group %(groupid)s not found when deleting '
                                'domain contents for %(domainid)s, continuing '
                                'with cleanup.'),
                              {'groupid': group['id'], 'domainid': domain_id})

        # And finally, delete the users themselves
        for user in user_refs:
            if user['domain_id'] == domain_id:
                try:
                    self.identity_api.delete_user(user['id'],
                                                  domain_scope=domain_id)
                except exception.UserNotFound:
                    LOG.debug(_('User %(userid)s not found when '
                                'deleting domain contents for %(domainid)s, '
                                'continuing with cleanup.'),
                              {'userid': user['id'],
                               'domainid': domain_id})

    @manager.response_truncated
    def list_projects(self, hints=None):
        return self.driver.list_projects(hints or driver_hints.Hints())

    # NOTE(henry-nash): list_projects_in_domain is actually an internal method
    # and not exposed via the API.  Therefore there is no need to support
    # driver hints for it.
    def list_projects_in_domain(self, domain_id):
        return self.driver.list_projects_in_domain(domain_id)

    def list_user_projects(self, user_id, hints=None):
        return self.driver.list_user_projects(
            user_id, hints or driver_hints.Hints())

    @cache.on_arguments(should_cache_fn=SHOULD_CACHE,
                        expiration_time=EXPIRATION_TIME)
    def get_project(self, project_id):
        return self.driver.get_project(project_id)

    @cache.on_arguments(should_cache_fn=SHOULD_CACHE,
                        expiration_time=EXPIRATION_TIME)
    def get_project_by_name(self, tenant_name, domain_id):
        return self.driver.get_project_by_name(tenant_name, domain_id)

    @cache.on_arguments(should_cache_fn=SHOULD_CACHE,
                        expiration_time=EXPIRATION_TIME)
    def get_role(self, role_id):
        return self.driver.get_role(role_id)

    @notifications.created('role')
    def create_role(self, role_id, role):
        ret = self.driver.create_role(role_id, role)
        if SHOULD_CACHE(ret):
            self.get_role.set(ret, self, role_id)
        return ret

    @manager.response_truncated
    def list_roles(self, hints=None):
        return self.driver.list_roles(hints or driver_hints.Hints())

    @notifications.updated('role')
    def update_role(self, role_id, role):
        ret = self.driver.update_role(role_id, role)
        self.get_role.invalidate(self, role_id)
        return ret

    @notifications.deleted('role')
    def delete_role(self, role_id):
        try:
            self._delete_tokens_for_role(role_id)
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
        self.driver.delete_role(role_id)
        self.get_role.invalidate(self, role_id)

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

    def remove_role_from_user_and_project(self, user_id, tenant_id, role_id):
        self.driver.remove_role_from_user_and_project(user_id, tenant_id,
                                                      role_id)
        if CONF.token.revoke_by_id:
            self.token_api.delete_tokens_for_user(user_id)
        if self.revoke_api:
            self.revoke_api.revoke_by_grant(role_id, user_id=user_id,
                                            project_id=tenant_id)

    def delete_grant(self, role_id, user_id=None, group_id=None,
                     domain_id=None, project_id=None,
                     inherited_to_projects=False):
        user_ids = []
        if group_id is None:
            if self.revoke_api:
                self.revoke_api.revoke_by_grant(user_id=user_id,
                                                role_id=role_id,
                                                domain_id=domain_id,
                                                project_id=project_id)
        else:
            try:
                # NOTE(morganfainberg): The user ids are the important part
                # for invalidating tokens below, so extract them here.
                for user in self.identity_api.list_users_in_group(group_id,
                                                                  domain_id):
                    if user['id'] != user_id:
                        user_ids.append(user['id'])
                        if self.revoke_api:
                            self.revoke_api.revoke_by_grant(
                                user_id=user['id'], role_id=role_id,
                                domain_id=domain_id, project_id=project_id)
            except exception.GroupNotFound:
                LOG.debug(_('Group %s not found, no tokens to invalidate.'),
                          group_id)

        self.driver.delete_grant(role_id, user_id, group_id, domain_id,
                                 project_id, inherited_to_projects)
        if user_id is not None:
            user_ids.append(user_id)
        self.token_api.delete_tokens_for_users(user_ids)

    def _delete_tokens_for_role(self, role_id):
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
                    user_ids.add(assignment['user_id'])
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
                    msg = _('Group (%(group)s), referenced in assignment '
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
                        user_ids.add(user['id'])

        # Now process the built up lists.  Before issuing calls to delete any
        # tokens, let's try and minimize the number of calls by pruning out
        # any user+project deletions where a general token deletion for that
        # same user is also planned.
        user_and_project_ids_to_action = []
        for user_and_project_id in user_and_project_ids:
            if user_and_project_id[0] not in user_ids:
                user_and_project_ids_to_action.append(user_and_project_id)

        self.token_api.delete_tokens_for_users(user_ids)
        for user_id, project_id in user_and_project_ids_to_action:
            self.token_api.delete_tokens_for_user(user_id, project_id)


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
    def get_project_by_name(self, tenant_name, domain_id):
        """Get a tenant by name.

        :returns: tenant_ref
        :raises: keystone.exception.ProjectNotFound

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def list_user_ids_for_project(self, tenant_id):
        """Lists all user IDs with a role assignment in the specified project.

        :returns: a list of user_ids or an empty set.
        :raises: keystone.exception.ProjectNotFound

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def add_role_to_user_and_project(self, user_id, tenant_id, role_id):
        """Add a role to a user within given tenant.

        :raises: keystone.exception.UserNotFound,
                 keystone.exception.ProjectNotFound,
                 keystone.exception.RoleNotFound
        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def remove_role_from_user_and_project(self, user_id, tenant_id, role_id):
        """Remove a role from a user within given tenant.

        :raises: keystone.exception.UserNotFound,
                 keystone.exception.ProjectNotFound,
                 keystone.exception.RoleNotFound

        """
        raise exception.NotImplemented()

    # assignment/grant crud

    @abc.abstractmethod
    def create_grant(self, role_id, user_id=None, group_id=None,
                     domain_id=None, project_id=None,
                     inherited_to_projects=False):
        """Creates a new assignment/grant.

        If the assignment is to a domain, then optionally it may be
        specified as inherited to owned projects (this requires
        the OS-INHERIT extension to be enabled).

        :raises: keystone.exception.DomainNotFound,
                 keystone.exception.ProjectNotFound,
                 keystone.exception.RoleNotFound

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def list_grants(self, user_id=None, group_id=None,
                    domain_id=None, project_id=None,
                    inherited_to_projects=False):
        """Lists assignments/grants.

        :raises: keystone.exception.UserNotFound,
                 keystone.exception.GroupNotFound,
                 keystone.exception.ProjectNotFound,
                 keystone.exception.DomainNotFound,
                 keystone.exception.RoleNotFound

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def get_grant(self, role_id, user_id=None, group_id=None,
                  domain_id=None, project_id=None,
                  inherited_to_projects=False):
        """Lists assignments/grants.

        :raises: keystone.exception.UserNotFound,
                 keystone.exception.GroupNotFound,
                 keystone.exception.ProjectNotFound,
                 keystone.exception.DomainNotFound,
                 keystone.exception.RoleNotFound

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def delete_grant(self, role_id, user_id=None, group_id=None,
                     domain_id=None, project_id=None,
                     inherited_to_projects=False):
        """Deletes assignments/grants.

        :raises: keystone.exception.ProjectNotFound,
                 keystone.exception.DomainNotFound,
                 keystone.exception.RoleNotFound

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def list_role_assignments(self):

        raise exception.NotImplemented()

    # domain crud
    @abc.abstractmethod
    def create_domain(self, domain_id, domain):
        """Creates a new domain.

        :raises: keystone.exception.Conflict

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def list_domains(self, hints):
        """List domains in the system.

        :param hints: filter hints which the driver should
                      implement if at all possible.

        :returns: a list of domain_refs or an empty list.

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def get_domain(self, domain_id):
        """Get a domain by ID.

        :returns: domain_ref
        :raises: keystone.exception.DomainNotFound

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def get_domain_by_name(self, domain_name):
        """Get a domain by name.

        :returns: domain_ref
        :raises: keystone.exception.DomainNotFound

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def update_domain(self, domain_id, domain):
        """Updates an existing domain.

        :raises: keystone.exception.DomainNotFound,
                 keystone.exception.Conflict

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def delete_domain(self, domain_id):
        """Deletes an existing domain.

        :raises: keystone.exception.DomainNotFound

        """
        raise exception.NotImplemented()

    # project crud
    @abc.abstractmethod
    def create_project(self, project_id, project):
        """Creates a new project.

        :raises: keystone.exception.Conflict

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def list_projects(self, hints):
        """List projects in the system.

        :param hints: filter hints which the driver should
                      implement if at all possible.

        :returns: a list of project_refs or an empty list.

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def list_projects_in_domain(self, domain_id):
        """List projects in the domain.

        :param domain_id: the driver MUST only return projects
                          within this domain.

        :returns: a list of project_refs or an empty list.

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def list_projects_for_user(self, user_id, group_ids, hints):
        """List all projects associated with a given user.

        :param user_id: the user in question
        :param group_ids: the groups this user is a member of.  This list is
                          built in the Manager, so that the driver itself
                          does not have to call across to identity.
        :param hints: filter hints which the driver should
                      implement if at all possible.

        :returns: a list of project_refs or an empty list.

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def get_roles_for_groups(self, group_ids, project_id=None, domain_id=None):
        """List all the roles assigned to groups on either domain or
        project.

        If the project_id is not None, this value will be used, no matter what
        was specified in the domain_id.

        :param group_ids: iterable with group ids
        :param project_id: id of the project
        :param domain_id: id of the domain

        :raises: AttributeError: In case both project_id and domain_id are set
                                 to None

        :returns: a list of Role entities matching groups and
                  project_id or domain_id

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def list_projects_for_groups(self, group_ids):
        """List projects accessible to specified groups.

        :param group_ids: List of group ids.
        :returns: List of projects accessible to specified groups.

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def list_domains_for_groups(self, group_ids):
        """List domains accessible to specified groups.

        :param group_ids: List of group ids.
        :returns: List of domains accessible to specified groups.

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def get_project(self, project_id):
        """Get a project by ID.

        :returns: project_ref
        :raises: keystone.exception.ProjectNotFound

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def update_project(self, project_id, project):
        """Updates an existing project.

        :raises: keystone.exception.ProjectNotFound,
                 keystone.exception.Conflict

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def delete_project(self, project_id):
        """Deletes an existing project.

        :raises: keystone.exception.ProjectNotFound

        """
        raise exception.NotImplemented()

    # role crud

    @abc.abstractmethod
    def create_role(self, role_id, role):
        """Creates a new role.

        :raises: keystone.exception.Conflict

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def list_roles(self, hints):
        """List roles in the system.

        :param hints: filter hints which the driver should
                      implement if at all possible.

        :returns: a list of role_refs or an empty list.

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def get_role(self, role_id):
        """Get a role by ID.

        :returns: role_ref
        :raises: keystone.exception.RoleNotFound

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def update_role(self, role_id, role):
        """Updates an existing role.

        :raises: keystone.exception.RoleNotFound,
                 keystone.exception.Conflict

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def delete_role(self, role_id):
        """Deletes an existing role.

        :raises: keystone.exception.RoleNotFound

        """
        raise exception.NotImplemented()

#TODO(ayoung): determine what else these two functions raise
    @abc.abstractmethod
    def delete_user(self, user_id):
        """Deletes all assignments for a user.

        :raises: keystone.exception.RoleNotFound

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def delete_group(self, group_id):
        """Deletes all assignments for a group.

        :raises: keystone.exception.RoleNotFound

        """
        raise exception.NotImplemented()

    #domain management functions for backends that only allow a single domain.
    #currently, this is only LDAP, but might be used by PAM or other backends
    #as well.  This is used by both identity and assignment drivers.
    def _set_default_domain(self, ref):
        """If the domain ID has not been set, set it to the default."""
        if isinstance(ref, dict):
            if 'domain_id' not in ref:
                ref = ref.copy()
                ref['domain_id'] = CONF.identity.default_domain_id
            return ref
        elif isinstance(ref, list):
            return [self._set_default_domain(x) for x in ref]
        else:
            raise ValueError(_('Expected dict or list: %s') % type(ref))

    def _validate_default_domain(self, ref):
        """Validate that either the default domain or nothing is specified.

        Also removes the domain from the ref so that LDAP doesn't have to
        persist the attribute.

        """
        ref = ref.copy()
        domain_id = ref.pop('domain_id', CONF.identity.default_domain_id)
        self._validate_default_domain_id(domain_id)
        return ref

    def _validate_default_domain_id(self, domain_id):
        """Validate that the domain ID specified belongs to the default domain.

        """
        if domain_id != CONF.identity.default_domain_id:
            raise exception.DomainNotFound(domain_id=domain_id)
