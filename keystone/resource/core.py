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

"""Main entry point into the resource service."""

import abc

import six

from keystone import clean
from keystone.common import cache
from keystone.common import dependency
from keystone.common import driver_hints
from keystone.common import manager
from keystone import config
from keystone import exception
from keystone.i18n import _, _LE
from keystone import notifications
from keystone.openstack.common import log


CONF = config.CONF
LOG = log.getLogger(__name__)
SHOULD_CACHE = cache.should_cache_fn('resource')

# NOTE(blk-u): The config options are not available at import time.
EXPIRATION_TIME = lambda: CONF.resource.cache_time


def calc_default_domain():
    return {'description':
            (u'Owns users and tenants (i.e. projects)'
                ' available on Identity API v2.'),
            'enabled': True,
            'id': CONF.identity.default_domain_id,
            'name': u'Default'}


@dependency.provider('resource_api')
@dependency.optional('revoke_api')
@dependency.requires('assignment_api', 'credential_api', 'identity_api')
class Manager(manager.Manager):
    """Default pivot point for the resource backend.

    See :mod:`keystone.common.manager.Manager` for more details on how this
    dynamically calls the backend.

    """
    _PROJECT = 'project'

    def __init__(self):
        # If there is a specific driver specified for resource, then use it.
        # Otherwise retrieve the driver type from the assignment driver.
        resource_driver = CONF.resource.driver

        if resource_driver is None:
            assignment_driver = (
                dependency.get_provider('assignment_api').driver)
            resource_driver = assignment_driver.default_resource_driver()

        super(Manager, self).__init__(resource_driver)

    def _get_hierarchy_depth(self, parents_list):
        return len(parents_list) + 1

    def _assert_max_hierarchy_depth(self, project_id, parents_list=None):
        if parents_list is None:
            parents_list = self.list_project_parents(project_id)
        max_depth = CONF.max_project_tree_depth
        if self._get_hierarchy_depth(parents_list) > max_depth:
            raise exception.ForbiddenAction(
                action=_('max hierarchy depth reached for '
                         '%s branch.') % project_id)

    @notifications.created(_PROJECT)
    def create_project(self, tenant_id, tenant):
        tenant = tenant.copy()
        tenant.setdefault('enabled', True)
        tenant['enabled'] = clean.project_enabled(tenant['enabled'])
        tenant.setdefault('description', '')
        tenant.setdefault('parent_id', None)

        if tenant.get('parent_id') is not None:
            parent_ref = self.get_project(tenant.get('parent_id'))
            parents_list = self.list_project_parents(parent_ref['id'])
            parents_list.append(parent_ref)
            for ref in parents_list:
                if ref.get('domain_id') != tenant.get('domain_id'):
                    raise exception.ForbiddenAction(
                        action=_('cannot create a project within a different '
                                 'domain than its parents.'))
                if not ref.get('enabled', True):
                    raise exception.ForbiddenAction(
                        action=_('cannot create a project in a '
                                 'branch containing a disabled '
                                 'project: %s') % ref['id'])
            self._assert_max_hierarchy_depth(tenant.get('parent_id'),
                                             parents_list)

        ret = self.driver.create_project(tenant_id, tenant)
        if SHOULD_CACHE(ret):
            self.get_project.set(ret, self, tenant_id)
            self.get_project_by_name.set(ret, self, ret['name'],
                                         ret['domain_id'])
        return ret

    def assert_domain_enabled(self, domain_id, domain=None):
        """Assert the Domain is enabled.

        :raise AssertionError if domain is disabled.
        """
        if domain is None:
            domain = self.get_domain(domain_id)
        if not domain.get('enabled', True):
            raise AssertionError(_('Domain is disabled: %s') % domain_id)

    def assert_project_enabled(self, project_id, project=None):
        """Assert the project is enabled and its associated domain is enabled.

        :raise AssertionError if the project or domain is disabled.
        """
        if project is None:
            project = self.get_project(project_id)
        self.assert_domain_enabled(domain_id=project['domain_id'])
        if not project.get('enabled', True):
            raise AssertionError(_('Project is disabled: %s') % project_id)

    @notifications.disabled(_PROJECT, public=False)
    def _disable_project(self, project_id):
        """Emit a notification to the callback system project is been disabled.

        This method, and associated callback listeners, removes the need for
        making direct calls to other managers to take action (e.g. revoking
        project scoped tokens) when a project is disabled.

        :param project_id: project identifier
        :type project_id: string
        """
        pass

    def _assert_all_parents_are_enabled(self, project_id):
        parents_list = self.list_project_parents(project_id)
        for project in parents_list:
            if not project.get('enabled', True):
                raise exception.ForbiddenAction(
                    action=_('cannot enable project %s since it has '
                             'disabled parents') % project_id)

    def _assert_whole_subtree_is_disabled(self, project_id):
        subtree_list = self.driver.list_projects_in_subtree(project_id)
        for ref in subtree_list:
            if ref.get('enabled', True):
                raise exception.ForbiddenAction(
                    action=_('cannot disable project %s since '
                             'its subtree contains enabled '
                             'projects') % project_id)

    @notifications.updated(_PROJECT)
    def update_project(self, tenant_id, tenant):
        original_tenant = self.driver.get_project(tenant_id)
        tenant = tenant.copy()

        parent_id = original_tenant.get('parent_id')
        if 'parent_id' in tenant and tenant.get('parent_id') != parent_id:
            raise exception.ForbiddenAction(
                action=_('Update of `parent_id` is not allowed.'))

        if 'enabled' in tenant:
            tenant['enabled'] = clean.project_enabled(tenant['enabled'])

        # NOTE(rodrigods): for the current implementation we only allow to
        # disable a project if all projects below it in the hierarchy are
        # already disabled. This also means that we can not enable a
        # project that has disabled parents.
        original_tenant_enabled = original_tenant.get('enabled', True)
        tenant_enabled = tenant.get('enabled', True)
        if not original_tenant_enabled and tenant_enabled:
            self._assert_all_parents_are_enabled(tenant_id)
        if original_tenant_enabled and not tenant_enabled:
            self._assert_whole_subtree_is_disabled(tenant_id)
            self._disable_project(tenant_id)

        ret = self.driver.update_project(tenant_id, tenant)
        self.get_project.invalidate(self, tenant_id)
        self.get_project_by_name.invalidate(self, original_tenant['name'],
                                            original_tenant['domain_id'])
        return ret

    @notifications.deleted(_PROJECT)
    def delete_project(self, tenant_id):
        if not self.driver.is_leaf_project(tenant_id):
            raise exception.ForbiddenAction(
                action=_('cannot delete the project %s since it is not '
                         'a leaf in the hierarchy.') % tenant_id)

        project = self.driver.get_project(tenant_id)
        project_user_ids = (
            self.assignment_api.list_user_ids_for_project(tenant_id))
        for user_id in project_user_ids:
            payload = {'user_id': user_id, 'project_id': tenant_id}
            self._emit_invalidate_user_project_tokens_notification(payload)
        ret = self.driver.delete_project(tenant_id)
        self.assignment_api.delete_project_assignments(tenant_id)
        self.get_project.invalidate(self, tenant_id)
        self.get_project_by_name.invalidate(self, project['name'],
                                            project['domain_id'])
        self.credential_api.delete_credentials_for_project(tenant_id)
        return ret

    def _filter_projects_list(self, projects_list, user_id):
        user_projects = self.assignment_api.list_projects_for_user(user_id)
        user_projects_ids = set([proj['id'] for proj in user_projects])
        # Keep only the projects present in user_projects
        projects_list = [proj for proj in projects_list
                         if proj['id'] in user_projects_ids]

    def list_project_parents(self, project_id, user_id=None):
        parents = self.driver.list_project_parents(project_id)
        # If a user_id was provided, the returned list should be filtered
        # against the projects this user has access to.
        if user_id:
            self._filter_projects_list(parents, user_id)
        return parents

    def _build_parents_as_ids_dict(self, project, parents_by_id):
        # NOTE(rodrigods): we don't rely in the order of the projects returned
        # by the list_project_parents() method. Thus, we create a project cache
        # (parents_by_id) in order to access each parent in constant time and
        # traverse up the hierarchy.
        def traverse_parents_hierarchy(project):
            parent_id = project.get('parent_id')
            if not parent_id:
                return None

            parent = parents_by_id[parent_id]
            return {parent_id: traverse_parents_hierarchy(parent)}

        return traverse_parents_hierarchy(project)

    def get_project_parents_as_ids(self, project):
        """Gets the IDs from the parents from a given project.

        The project IDs are returned as a structured dictionary traversing up
        the hierarchy to the top level project. For example, considering the
        following project hierarchy::

                                    A
                                    |
                                  +-B-+
                                  |   |
                                  C   D

        If we query for project C parents, the expected return is the following
        dictionary::

            'parents': {
                B['id']: {
                    A['id']: None
                }
            }

        """
        parents_list = self.list_project_parents(project['id'])
        parents_as_ids = self._build_parents_as_ids_dict(
            project, {proj['id']: proj for proj in parents_list})
        return parents_as_ids

    def list_projects_in_subtree(self, project_id, user_id=None):
        subtree = self.driver.list_projects_in_subtree(project_id)
        # If a user_id was provided, the returned list should be filtered
        # against the projects this user has access to.
        if user_id:
            self._filter_projects_list(subtree, user_id)
        return subtree

    def _build_subtree_as_ids_dict(self, project_id, subtree_by_parent):
        # NOTE(rodrigods): we perform a depth first search to construct the
        # dictionaries representing each level of the subtree hierarchy. In
        # order to improve this traversal performance, we create a cache of
        # projects (subtree_py_parent) that accesses in constant time the
        # direct children of a given project.
        def traverse_subtree_hierarchy(project_id):
            children = subtree_by_parent.get(project_id)
            if not children:
                return None

            children_ids = {}
            for child in children:
                children_ids[child['id']] = traverse_subtree_hierarchy(
                    child['id'])
            return children_ids

        return traverse_subtree_hierarchy(project_id)

    def get_projects_in_subtree_as_ids(self, project_id):
        """Gets the IDs from the projects in the subtree from a given project.

        The project IDs are returned as a structured dictionary representing
        their hierarchy. For example, considering the following project
        hierarchy::

                                    A
                                    |
                                  +-B-+
                                  |   |
                                  C   D

        If we query for project A subtree, the expected return is the following
        dictionary::

            'subtree': {
                B['id']: {
                    C['id']: None,
                    D['id']: None
                }
            }

        """
        def _projects_indexed_by_parent(projects_list):
            projects_by_parent = {}
            for proj in projects_list:
                parent_id = proj.get('parent_id')
                if parent_id:
                    if parent_id in projects_by_parent:
                        projects_by_parent[parent_id].append(proj)
                    else:
                        projects_by_parent[parent_id] = [proj]
            return projects_by_parent

        subtree_list = self.list_projects_in_subtree(project_id)
        subtree_as_ids = self._build_subtree_as_ids_dict(
            project_id, _projects_indexed_by_parent(subtree_list))
        return subtree_as_ids

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
        if (not self.identity_api.multiple_domains_supported and
                domain_id != CONF.identity.default_domain_id):
            raise exception.Forbidden(_('Multiple domains are not supported'))
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
        """Emit a notification to the callback system domain is been disabled.

        This method, and associated callback listeners, removes the need for
        making direct calls to other managers to take action (e.g. revoking
        domain scoped tokens) when a domain is disabled.

        :param domain_id: domain identifier
        :type domain_id: string
        """
        pass

    @notifications.updated('domain')
    def update_domain(self, domain_id, domain):
        original_domain = self.driver.get_domain(domain_id)
        if 'enabled' in domain:
            domain['enabled'] = clean.domain_enabled(domain['enabled'])
        ret = self.driver.update_domain(domain_id, domain)
        # disable owned users & projects when the API user specifically set
        #     enabled=False
        if (original_domain.get('enabled', True) and
                not domain.get('enabled', True)):
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
        # TODO(henry-nash): Although the controller will ensure deletion of
        # all users & groups within the domain (which will cause all
        # assignments for those users/groups to also be deleted), there
        # could still be assignments on this domain for users/groups in
        # other domains - so we should delete these here by making a call
        # to the backend to delete all assignments for this domain.
        # (see Bug #1277847)
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

        def _delete_projects(project, projects, examined):
            if project['id'] in examined:
                msg = _LE('Circular reference or a repeated entry found '
                          'projects hierarchy - %(project_id)s.')
                LOG.error(msg, {'project_id': project['id']})
                return

            examined.add(project['id'])
            children = [proj for proj in projects
                        if proj.get('parent_id') == project['id']]
            for proj in children:
                _delete_projects(proj, projects, examined)

            try:
                self.delete_project(project['id'])
            except exception.ProjectNotFound:
                LOG.debug(('Project %(projectid)s not found when '
                           'deleting domain contents for %(domainid)s, '
                           'continuing with cleanup.'),
                          {'projectid': project['id'],
                           'domainid': domain_id})

        user_refs = self.identity_api.list_users(domain_scope=domain_id)
        proj_refs = self.list_projects_in_domain(domain_id)
        group_refs = self.identity_api.list_groups(domain_scope=domain_id)

        # Deleting projects recursively
        roots = [x for x in proj_refs if x.get('parent_id') is None]
        examined = set()
        for project in roots:
            _delete_projects(project, proj_refs, examined)

        for group in group_refs:
            # Cleanup any existing groups.
            if group['domain_id'] == domain_id:
                try:
                    self.identity_api.delete_group(group['id'])
                except exception.GroupNotFound:
                    LOG.debug(('Group %(groupid)s not found when deleting '
                               'domain contents for %(domainid)s, continuing '
                               'with cleanup.'),
                              {'groupid': group['id'], 'domainid': domain_id})

        # And finally, delete the users themselves
        for user in user_refs:
            if user['domain_id'] == domain_id:
                try:
                    self.identity_api.delete_user(user['id'])
                except exception.UserNotFound:
                    LOG.debug(('User %(userid)s not found when '
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

    @cache.on_arguments(should_cache_fn=SHOULD_CACHE,
                        expiration_time=EXPIRATION_TIME)
    def get_project(self, project_id):
        return self.driver.get_project(project_id)

    @cache.on_arguments(should_cache_fn=SHOULD_CACHE,
                        expiration_time=EXPIRATION_TIME)
    def get_project_by_name(self, tenant_name, domain_id):
        return self.driver.get_project_by_name(tenant_name, domain_id)

    @notifications.internal(
        notifications.INVALIDATE_USER_PROJECT_TOKEN_PERSISTENCE)
    def _emit_invalidate_user_project_tokens_notification(self, payload):
        # This notification's payload is a dict of user_id and
        # project_id so the token provider can invalidate the tokens
        # from persistence if persistence is enabled.
        pass


@six.add_metaclass(abc.ABCMeta)
class Driver(object):

    def _get_list_limit(self):
        return CONF.resource.list_limit or CONF.list_limit

    @abc.abstractmethod
    def get_project_by_name(self, tenant_name, domain_id):
        """Get a tenant by name.

        :returns: tenant_ref
        :raises: keystone.exception.ProjectNotFound

        """
        raise exception.NotImplemented()  # pragma: no cover

    # domain crud
    @abc.abstractmethod
    def create_domain(self, domain_id, domain):
        """Creates a new domain.

        :raises: keystone.exception.Conflict

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_domains(self, hints):
        """List domains in the system.

        :param hints: filter hints which the driver should
                      implement if at all possible.

        :returns: a list of domain_refs or an empty list.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_domains_from_ids(self, domain_ids):
        """List domains for the provided list of ids.

        :param domain_ids: list of ids

        :returns: a list of domain_refs.

        This method is used internally by the assignment manager to bulk read
        a set of domains given their ids.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def get_domain(self, domain_id):
        """Get a domain by ID.

        :returns: domain_ref
        :raises: keystone.exception.DomainNotFound

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def get_domain_by_name(self, domain_name):
        """Get a domain by name.

        :returns: domain_ref
        :raises: keystone.exception.DomainNotFound

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def update_domain(self, domain_id, domain):
        """Updates an existing domain.

        :raises: keystone.exception.DomainNotFound,
                 keystone.exception.Conflict

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_domain(self, domain_id):
        """Deletes an existing domain.

        :raises: keystone.exception.DomainNotFound

        """
        raise exception.NotImplemented()  # pragma: no cover

    # project crud
    @abc.abstractmethod
    def create_project(self, project_id, project):
        """Creates a new project.

        :raises: keystone.exception.Conflict

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_projects(self, hints):
        """List projects in the system.

        :param hints: filter hints which the driver should
                      implement if at all possible.

        :returns: a list of project_refs or an empty list.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_projects_from_ids(self, project_ids):
        """List projects for the provided list of ids.

        :param project_ids: list of ids

        :returns: a list of project_refs.

        This method is used internally by the assignment manager to bulk read
        a set of projects given their ids.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_project_ids_from_domain_ids(self, domain_ids):
        """List project ids for the provided list of domain ids.

        :param domain_ids: list of domain ids

        :returns: a list of project ids owned by the specified domain ids.

        This method is used internally by the assignment manager to bulk read
        a set of project ids given a list of domain ids.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_projects_in_domain(self, domain_id):
        """List projects in the domain.

        :param domain_id: the driver MUST only return projects
                          within this domain.

        :returns: a list of project_refs or an empty list.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def get_project(self, project_id):
        """Get a project by ID.

        :returns: project_ref
        :raises: keystone.exception.ProjectNotFound

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def update_project(self, project_id, project):
        """Updates an existing project.

        :raises: keystone.exception.ProjectNotFound,
                 keystone.exception.Conflict

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_project(self, project_id):
        """Deletes an existing project.

        :raises: keystone.exception.ProjectNotFound

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_project_parents(self, project_id):
        """List all parents from a project by its ID.

        :param project_id: the driver will list the parents of this
                           project.

        :returns: a list of project_refs or an empty list.
        :raises: keystone.exception.ProjectNotFound

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def list_projects_in_subtree(self, project_id):
        """List all projects in the subtree below the hierarchy of the
        given project.

        :param project_id: the driver will get the subtree under
                           this project.

        :returns: a list of project_refs or an empty list
        :raises: keystone.exception.ProjectNotFound

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def is_leaf_project(self, project_id):
        """Checks if a project is a leaf in the hierarchy.

        :param project_id: the driver will check if this project
                           is a leaf in the hierarchy.

        :raises: keystone.exception.ProjectNotFound

        """
        raise exception.NotImplemented()

    # Domain management functions for backends that only allow a single
    # domain.  Currently, this is only LDAP, but might be used by other
    # backends in the future.
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
