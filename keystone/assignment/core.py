# vim: tabstop=4 shiftwidth=4 softtabstop=4

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


from keystone import clean
from keystone.common import cache
from keystone.common import dependency
from keystone.common import manager
from keystone import config
from keystone import exception
from keystone import notifications
from keystone.openstack.common import log as logging


CONF = config.CONF
LOG = logging.getLogger(__name__)
SHOULD_CACHE = cache.should_cache_fn('assignment')

DEFAULT_DOMAIN = {'description':
                  (u'Owns users and tenants (i.e. projects)'
                   ' available on Identity API v2.'),
                  'enabled': True,
                  'id': CONF.identity.default_domain_id,
                  'name': u'Default'}


@dependency.provider('assignment_api')
@dependency.requires('identity_api')
class Manager(manager.Manager):
    """Default pivot point for the Assignment backend.

    See :mod:`keystone.common.manager.Manager` for more details on how this
    dynamically calls the backend.
    assignment.Manager() and identity.Manager() have a circular dependency.
    The late import works around this.  THe if block prevents creation of the
    api object by both managers.
    """

    def __init__(self):
        assignment_driver = CONF.assignment.driver

        if assignment_driver is None:
            identity_driver = dependency.REGISTRY['identity_api'].driver
            assignment_driver = identity_driver.default_assignment_driver()

        super(Manager, self).__init__(assignment_driver)

    @notifications.created('project')
    def create_project(self, tenant_id, tenant_ref):
        tenant = tenant_ref.copy()
        tenant.setdefault('enabled', True)
        tenant['enabled'] = clean.project_enabled(tenant['enabled'])
        tenant.setdefault('description', '')
        ret = self.driver.create_project(tenant_id, tenant_ref)
        if SHOULD_CACHE(ret):
            self.get_project.set(ret, self, tenant_id)
            self.get_project_by_name.set(ret, self, ret['name'],
                                         ret['domain_id'])
        return ret

    @notifications.updated('project')
    def update_project(self, tenant_id, tenant_ref):
        tenant = tenant_ref.copy()
        if 'enabled' in tenant:
            tenant['enabled'] = clean.project_enabled(tenant['enabled'])
        ret = self.driver.update_project(tenant_id, tenant_ref)
        self.get_project.invalidate(self, tenant_id)
        self.get_project_by_name.invalidate(self, ret['name'],
                                            ret['domain_id'])
        return ret

    @notifications.deleted('project')
    def delete_project(self, tenant_id):
        project = self.driver.get_project(tenant_id)
        ret = self.driver.delete_project(tenant_id)
        self.get_project.invalidate(self, tenant_id)
        self.get_project_by_name.invalidate(self, project['name'],
                                            project['domain_id'])
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
                       "because it does not exist.") %
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
            self.driver.remove_role_from_user_and_project(user_id, tenant_id,
                                                          role_id)

    def list_projects_for_user(self, user_id):
        # NOTE(henry-nash): In order to get a complete list of user projects,
        # the driver will need to look at group assignments.  To avoid cross
        # calling between the assignment and identity driver we get the group
        # list here and pass it in. The rest of the detailed logic of listing
        # projects for a user is pushed down into the driver to enable
        # optimization with the various backend technologies (SQL, LDAP etc.).

        group_ids = [x['id'] for
                     x in self.identity_api.list_groups_for_user(user_id)]
        return self.driver.list_projects_for_user(user_id, group_ids)

    @cache.on_arguments(should_cache_fn=SHOULD_CACHE,
                        expiration_time=CONF.assignment.cache_time)
    def get_domain(self, domain_id):
        return self.driver.get_domain(domain_id)

    @cache.on_arguments(should_cache_fn=SHOULD_CACHE,
                        expiration_time=CONF.assignment.cache_time)
    def get_domain_by_name(self, domain_name):
        return self.driver.get_domain_by_name(domain_name)

    def create_domain(self, domain_id, domain):
        ret = self.driver.create_domain(domain_id, domain)
        if SHOULD_CACHE(ret):
            self.get_domain.set(ret, self, domain_id)
            self.get_domain_by_name.set(ret, self, ret['name'])
        return ret

    def update_domain(self, domain_id, domain):
        ret = self.driver.update_domain(domain_id, domain)
        self.get_domain.invalidate(self, domain_id)
        self.get_domain_by_name.invalidate(self, ret['name'])
        return ret

    def delete_domain(self, domain_id):
        domain = self.driver.get_domain(domain_id)
        self.driver.delete_domain(domain_id)
        self.get_domain.invalidate(self, domain_id)
        self.get_domain_by_name.invalidate(self, domain['name'])

    @cache.on_arguments(should_cache_fn=SHOULD_CACHE,
                        expiration_time=CONF.assignment.cache_time)
    def get_project(self, project_id):
        return self.driver.get_project(project_id)

    @cache.on_arguments(should_cache_fn=SHOULD_CACHE,
                        expiration_time=CONF.assignment.cache_time)
    def get_project_by_name(self, tenant_name, domain_id):
        return self.driver.get_project_by_name(tenant_name, domain_id)

    @cache.on_arguments(should_cache_fn=SHOULD_CACHE,
                        expiration_time=CONF.assignment.cache_time)
    def get_role(self, role_id):
        return self.driver.get_role(role_id)

    def create_role(self, role_id, role):
        ret = self.driver.create_role(role_id, role)
        if SHOULD_CACHE(ret):
            self.get_role.set(ret, self, role_id)
        return ret

    def update_role(self, role_id, role):
        ret = self.driver.update_role(role_id, role)
        self.get_role.invalidate(self, role_id)
        return ret

    def delete_role(self, role_id):
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

    def get_project_by_name(self, tenant_name, domain_id):
        """Get a tenant by name.

        :returns: tenant_ref
        :raises: keystone.exception.ProjectNotFound

        """
        raise exception.NotImplemented()

    def list_user_ids_for_project(self, tenant_id):
        """Lists all user IDs with a role assignment in the specified project.

        :returns: a list of user_ids or an empty set.
        :raises: keystone.exception.ProjectNotFound

        """
        raise exception.NotImplemented()

    def add_role_to_user_and_project(self, user_id, tenant_id, role_id):
        """Add a role to a user within given tenant.

        :raises: keystone.exception.UserNotFound,
                 keystone.exception.ProjectNotFound,
                 keystone.exception.RoleNotFound
        """
        raise exception.NotImplemented()

    def remove_role_from_user_and_project(self, user_id, tenant_id, role_id):
        """Remove a role from a user within given tenant.

        :raises: keystone.exception.UserNotFound,
                 keystone.exception.ProjectNotFound,
                 keystone.exception.RoleNotFound

        """
        raise exception.NotImplemented()

    # assignment/grant crud

    def create_grant(self, role_id, user_id=None, group_id=None,
                     domain_id=None, project_id=None,
                     inherited_to_projects=False):
        """Creates a new assignment/grant.

        If the assignment is to a domain, then optionally it may be
        specified as inherited to owned projects (this requires
        the OS-INHERIT extension to be enabled).

        :raises: keystone.exception.UserNotFound,
                 keystone.exception.GroupNotFound,
                 keystone.exception.ProjectNotFound,
                 keystone.exception.DomainNotFound,
                 keystone.exception.ProjectNotFound,
                 keystone.exception.RoleNotFound

        """
        raise exception.NotImplemented()

    def list_grants(self, user_id=None, group_id=None,
                    domain_id=None, project_id=None,
                    inherited_to_projects=False):
        """Lists assignments/grants.

        :raises: keystone.exception.UserNotFound,
                 keystone.exception.GroupNotFound,
                 keystone.exception.ProjectNotFound,
                 keystone.exception.DomainNotFound,
                 keystone.exception.ProjectNotFound,
                 keystone.exception.RoleNotFound

        """
        raise exception.NotImplemented()

    def get_grant(self, role_id, user_id=None, group_id=None,
                  domain_id=None, project_id=None,
                  inherited_to_projects=False):
        """Lists assignments/grants.

        :raises: keystone.exception.UserNotFound,
                 keystone.exception.GroupNotFound,
                 keystone.exception.ProjectNotFound,
                 keystone.exception.DomainNotFound,
                 keystone.exception.ProjectNotFound,
                 keystone.exception.RoleNotFound

        """
        raise exception.NotImplemented()

    def delete_grant(self, role_id, user_id=None, group_id=None,
                     domain_id=None, project_id=None,
                     inherited_to_projects=False):
        """Lists assignments/grants.

        :raises: keystone.exception.UserNotFound,
                 keystone.exception.GroupNotFound,
                 keystone.exception.ProjectNotFound,
                 keystone.exception.DomainNotFound,
                 keystone.exception.ProjectNotFound,
                 keystone.exception.RoleNotFound

        """
        raise exception.NotImplemented()

    def list_role_assignments(self):

        raise exception.NotImplemented()

    # domain crud
    def create_domain(self, domain_id, domain):
        """Creates a new domain.

        :raises: keystone.exception.Conflict

        """
        raise exception.NotImplemented()

    def list_domains(self):
        """List all domains in the system.

        :returns: a list of domain_refs or an empty list.

        """
        raise exception.NotImplemented()

    def get_domain(self, domain_id):
        """Get a domain by ID.

        :returns: domain_ref
        :raises: keystone.exception.DomainNotFound

        """
        raise exception.NotImplemented()

    def get_domain_by_name(self, domain_name):
        """Get a domain by name.

        :returns: domain_ref
        :raises: keystone.exception.DomainNotFound

        """
        raise exception.NotImplemented()

    def update_domain(self, domain_id, domain):
        """Updates an existing domain.

        :raises: keystone.exception.DomainNotFound,
                 keystone.exception.Conflict

        """
        raise exception.NotImplemented()

    def delete_domain(self, domain_id):
        """Deletes an existing domain.

        :raises: keystone.exception.DomainNotFound

        """
        raise exception.NotImplemented()

    # project crud
    def create_project(self, project_id, project):
        """Creates a new project.

        :raises: keystone.exception.Conflict

        """
        raise exception.NotImplemented()

    def list_projects(self, domain_id=None):
        """List all projects in the system.

        :returns: a list of project_refs or an empty list.

        """
        raise exception.NotImplemented()

    def list_projects_for_user(self, user_id, group_ids):
        """List all projects associated with a given user.

        :param user_id: the user in question
        :param group_ids: the groups this user is a member of.  This list is
                          built in the Manager, so that the driver itself
                          does not have to call across to identity.

        :returns: a list of project_refs or an empty list.

        """
        raise exception.NotImplemented()

    def get_project(self, project_id):
        """Get a project by ID.

        :returns: project_ref
        :raises: keystone.exception.ProjectNotFound

        """
        raise exception.NotImplemented()

    def update_project(self, project_id, project):
        """Updates an existing project.

        :raises: keystone.exception.ProjectNotFound,
                 keystone.exception.Conflict

        """
        raise exception.NotImplemented()

    def delete_project(self, project_id):
        """Deletes an existing project.

        :raises: keystone.exception.ProjectNotFound

        """
        raise exception.NotImplemented()

    """Interface description for an assignment driver."""
    # role crud

    def create_role(self, role_id, role):
        """Creates a new role.

        :raises: keystone.exception.Conflict

        """
        raise exception.NotImplemented()

    def list_roles(self):
        """List all roles in the system.

        :returns: a list of role_refs or an empty list.

        """
        raise exception.NotImplemented()

    def get_role(self, role_id):
        """Get a role by ID.

        :returns: role_ref
        :raises: keystone.exception.RoleNotFound

        """
        raise exception.NotImplemented()

    def update_role(self, role_id, role):
        """Updates an existing role.

        :raises: keystone.exception.RoleNotFound,
                 keystone.exception.Conflict

        """
        raise exception.NotImplemented()

    def delete_role(self, role_id):
        """Deletes an existing role.

        :raises: keystone.exception.RoleNotFound

        """
        raise exception.NotImplemented()

#TODO(ayoung): determine what else these two functions raise
    def delete_user(self, user_id):
        """Deletes all assignments for a user.

        :raises: keystone.exception.RoleNotFound

        """
        raise exception.NotImplemented()

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
