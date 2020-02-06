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

"""Main entry point into the Resource service."""

from oslo_log import log

from keystone import assignment
from keystone.common import cache
from keystone.common import driver_hints
from keystone.common import manager
from keystone.common import provider_api
from keystone.common.resource_options import options as ro_opt
from keystone.common import utils
import keystone.conf
from keystone import exception
from keystone.i18n import _
from keystone import notifications
from keystone.resource.backends import base
from keystone.token import provider as token_provider

CONF = keystone.conf.CONF
LOG = log.getLogger(__name__)
MEMOIZE = cache.get_memoization_decorator(group='resource')
PROVIDERS = provider_api.ProviderAPIs


TAG_SEARCH_FILTERS = ('tags', 'tags-any', 'not-tags', 'not-tags-any')


class Manager(manager.Manager):
    """Default pivot point for the Resource backend.

    See :mod:`keystone.common.manager.Manager` for more details on how this
    dynamically calls the backend.

    """

    driver_namespace = 'keystone.resource'
    _provides_api = 'resource_api'

    _DOMAIN = 'domain'
    _PROJECT = 'project'
    _PROJECT_TAG = 'project tag'

    def __init__(self):
        resource_driver = CONF.resource.driver
        super(Manager, self).__init__(resource_driver)

    def _get_hierarchy_depth(self, parents_list):
        return len(parents_list) + 1

    def _assert_max_hierarchy_depth(self, project_id, parents_list=None):
        if parents_list is None:
            parents_list = self.list_project_parents(project_id)
        # NOTE(henry-nash): In upgrading to a scenario where domains are
        # represented as projects acting as domains, we will effectively
        # increase the depth of any existing project hierarchy by one. To avoid
        # pushing any existing hierarchies over the limit, we add one to the
        # maximum depth allowed, as specified in the configuration file.
        max_depth = CONF.max_project_tree_depth + 1

        # NOTE(wxy): If the hierarchical limit enforcement model is used, the
        # project depth should be not greater than the model's limit as well.
        #
        # TODO(wxy): Deprecate and remove CONF.max_project_tree_depth, let the
        # depth check only based on the limit enforcement model.
        limit_model = PROVIDERS.unified_limit_api.enforcement_model
        if limit_model.MAX_PROJECT_TREE_DEPTH is not None:
            max_depth = min(max_depth, limit_model.MAX_PROJECT_TREE_DEPTH + 1)
        if self._get_hierarchy_depth(parents_list) > max_depth:
            raise exception.ForbiddenNotSecurity(
                _('Max hierarchy depth reached for %s branch.') % project_id)

    def _assert_is_domain_project_constraints(self, project_ref):
        """Enforce specific constraints of projects that act as domains.

        Called when is_domain is true, this method ensures that:

        * multiple domains are enabled
        * the project name is not the reserved name for a federated domain
        * the project is a root project

        :raises keystone.exception.ValidationError: If one of the constraints
            was not satisfied.
        """
        if (not PROVIDERS.identity_api.multiple_domains_supported and
                project_ref['id'] != CONF.identity.default_domain_id and
                project_ref['id'] != base.NULL_DOMAIN_ID):
            raise exception.ValidationError(
                message=_('Multiple domains are not supported'))

        self.assert_domain_not_federated(project_ref['id'], project_ref)

        if project_ref['parent_id']:
            raise exception.ValidationError(
                message=_('only root projects are allowed to act as '
                          'domains.'))

    def _assert_regular_project_constraints(self, project_ref):
        """Enforce regular project hierarchy constraints.

        Called when is_domain is false. The project must contain a valid
        domain_id and parent_id. The goal of this method is to check
        that the domain_id specified is consistent with the domain of its
        parent.

        :raises keystone.exception.ValidationError: If one of the constraints
            was not satisfied.
        :raises keystone.exception.DomainNotFound: In case the domain is not
            found.
        """
        # Ensure domain_id is valid, and by inference will not be None.
        domain = self.get_domain(project_ref['domain_id'])
        parent_ref = self.get_project(project_ref['parent_id'])

        if parent_ref['is_domain']:
            if parent_ref['id'] != domain['id']:
                raise exception.ValidationError(
                    message=_('Cannot create project, the parent '
                              '(%(parent_id)s) is acting as a domain, '
                              'but this project\'s domain id (%(domain_id)s) '
                              'does not match the parent\'s id.')
                    % {'parent_id': parent_ref['id'],
                       'domain_id': domain['id']})
        else:
            parent_domain_id = parent_ref.get('domain_id')
            if parent_domain_id != domain['id']:
                raise exception.ValidationError(
                    message=_('Cannot create project, since it specifies '
                              'its domain_id %(domain_id)s, but '
                              'specifies a parent in a different domain '
                              '(%(parent_domain_id)s).')
                    % {'domain_id': domain['id'],
                       'parent_domain_id': parent_domain_id})

    def _enforce_project_constraints(self, project_ref):
        if project_ref.get('is_domain'):
            self._assert_is_domain_project_constraints(project_ref)
        else:
            self._assert_regular_project_constraints(project_ref)
            # The whole hierarchy (upwards) must be enabled
            parent_id = project_ref['parent_id']
            parents_list = self.list_project_parents(parent_id)
            parent_ref = self.get_project(parent_id)
            parents_list.append(parent_ref)
            for ref in parents_list:
                if not ref.get('enabled', True):
                    raise exception.ValidationError(
                        message=_('cannot create a project in a '
                                  'branch containing a disabled '
                                  'project: %s') % ref['id'])

            self._assert_max_hierarchy_depth(project_ref.get('parent_id'),
                                             parents_list)

    def _raise_reserved_character_exception(self, entity_type, name):
        msg = _('%(entity)s name cannot contain the following reserved '
                'characters: %(chars)s')
        raise exception.ValidationError(
            message=msg % {
                'entity': entity_type,
                'chars': utils.list_url_unsafe_chars(name)
            })

    def _generate_project_name_conflict_msg(self, project):
        if project['is_domain']:
            return _('it is not permitted to have two projects '
                     'acting as domains with the same name: %s'
                     ) % project['name']
        else:
            return _('it is not permitted to have two projects '
                     'with either the same name or same id in '
                     'the same domain: '
                     'name is %(name)s, project id %(id)s'
                     ) % project

    def create_project(self, project_id, project, initiator=None):
        project = project.copy()

        if (CONF.resource.project_name_url_safe != 'off' and
                utils.is_not_url_safe(project['name'])):
            self._raise_reserved_character_exception('Project',
                                                     project['name'])

        project.setdefault('enabled', True)
        project['name'] = project['name'].strip()
        project.setdefault('description', '')

        # For regular projects, the controller will ensure we have a valid
        # domain_id. For projects acting as a domain, the project_id
        # is, effectively, the domain_id - and for such projects we don't
        # bother to store a copy of it in the domain_id attribute.
        project.setdefault('domain_id', None)
        project.setdefault('parent_id', None)
        if not project['parent_id']:
            project['parent_id'] = project['domain_id']
        project.setdefault('is_domain', False)

        self._enforce_project_constraints(project)

        # We leave enforcing name uniqueness to the underlying driver (instead
        # of doing it in code in the project_constraints above), so as to allow
        # this check to be done at the storage level, avoiding race conditions
        # in multi-process keystone configurations.
        try:
            ret = self.driver.create_project(project_id, project)
        except exception.Conflict:
            raise exception.Conflict(
                type='project',
                details=self._generate_project_name_conflict_msg(project))

        if project.get('is_domain'):
            notifications.Audit.created(self._DOMAIN, project_id, initiator)
        else:
            notifications.Audit.created(self._PROJECT, project_id, initiator)
        if MEMOIZE.should_cache(ret):
            self.get_project.set(ret, self, project_id)
            self.get_project_by_name.set(ret, self, ret['name'],
                                         ret['domain_id'])

        assignment.COMPUTED_ASSIGNMENTS_REGION.invalidate()

        return ret

    def assert_domain_enabled(self, domain_id, domain=None):
        """Assert the Domain is enabled.

        :raise AssertionError: if domain is disabled.
        """
        if domain is None:
            domain = self.get_domain(domain_id)
        if not domain.get('enabled', True):
            raise AssertionError(_('Domain is disabled: %s') % domain_id)

    def assert_domain_not_federated(self, domain_id, domain):
        """Assert the Domain's name and id do not match the reserved keyword.

        Note that the reserved keyword is defined in the configuration file,
        by default, it is 'Federated', it is also case insensitive.
        If config's option is empty the default hardcoded value 'Federated'
        will be used.

        :raise AssertionError: if domain named match the value in the config.

        """
        # NOTE(marek-denis): We cannot create this attribute in the __init__ as
        # config values are always initialized to default value.
        federated_domain = CONF.federation.federated_domain_name.lower()
        if (domain.get('name') and domain['name'].lower() == federated_domain):
            raise AssertionError(_('Domain cannot be named %s')
                                 % domain['name'])
        if (domain_id.lower() == federated_domain):
            raise AssertionError(_('Domain cannot have ID %s')
                                 % domain_id)

    def assert_project_enabled(self, project_id, project=None):
        """Assert the project is enabled and its associated domain is enabled.

        :raise AssertionError: if the project or domain is disabled.
        """
        if project is None:
            project = self.get_project(project_id)
        # If it's a regular project (i.e. it has a domain_id), we need to make
        # sure the domain itself is not disabled
        if project['domain_id']:
            self.assert_domain_enabled(domain_id=project['domain_id'])
        if not project.get('enabled', True):
            raise AssertionError(_('Project is disabled: %s') % project_id)

    def _assert_all_parents_are_enabled(self, project_id):
        parents_list = self.list_project_parents(project_id)
        for project in parents_list:
            if not project.get('enabled', True):
                raise exception.ForbiddenNotSecurity(
                    _('Cannot enable project %s since it has disabled '
                      'parents') % project_id)

    def _is_immutable(self, project_ref):
        return project_ref['options'].get(
            ro_opt.IMMUTABLE_OPT.option_name, False)

    def _check_whole_subtree_is_disabled(self, project_id, subtree_list=None):
        if not subtree_list:
            subtree_list = self.list_projects_in_subtree(project_id)
        subtree_enabled = [ref.get('enabled', True) for ref in subtree_list]
        return (not any(subtree_enabled))

    def _update_project(self, project_id, project, initiator=None,
                        cascade=False):
        # Use the driver directly to prevent using old cached value.
        original_project = self.driver.get_project(project_id)
        project = project.copy()
        self._require_matching_domain_id(project, original_project)

        if original_project['is_domain']:
            # prevent updates to immutable domains
            ro_opt.check_immutable_update(
                original_resource_ref=original_project,
                new_resource_ref=project,
                type='domain',
                resource_id=project_id)
            domain = self._get_domain_from_project(original_project)
            self.assert_domain_not_federated(project_id, domain)
            url_safe_option = CONF.resource.domain_name_url_safe
            exception_entity = 'Domain'
        else:
            # prevent updates to immutable projects
            ro_opt.check_immutable_update(
                original_resource_ref=original_project,
                new_resource_ref=project,
                type='project',
                resource_id=project_id)
            url_safe_option = CONF.resource.project_name_url_safe
            exception_entity = 'Project'

        project_name_changed = ('name' in project and project['name'] !=
                                original_project['name'])
        if (url_safe_option != 'off' and project_name_changed and
                utils.is_not_url_safe(project['name'])):
            self._raise_reserved_character_exception(exception_entity,
                                                     project['name'])
        elif project_name_changed:
            project['name'] = project['name'].strip()
        parent_id = original_project.get('parent_id')
        if 'parent_id' in project and project.get('parent_id') != parent_id:
            raise exception.ForbiddenNotSecurity(
                _('Update of `parent_id` is not allowed.'))

        if ('is_domain' in project and
                project['is_domain'] != original_project['is_domain']):
            raise exception.ValidationError(
                message=_('Update of `is_domain` is not allowed.'))

        original_project_enabled = original_project.get('enabled', True)
        project_enabled = project.get('enabled', True)
        if not original_project_enabled and project_enabled:
            self._assert_all_parents_are_enabled(project_id)
        if original_project_enabled and not project_enabled:
            # NOTE(htruta): In order to disable a regular project, all its
            # children must already be disabled. However, to keep
            # compatibility with the existing domain behaviour, we allow a
            # project acting as a domain to be disabled irrespective of the
            # state of its children. Disabling a project acting as domain
            # effectively disables its children.
            if (not original_project.get('is_domain') and not cascade and not
                    self._check_whole_subtree_is_disabled(project_id)):
                raise exception.ForbiddenNotSecurity(
                    _('Cannot disable project %(project_id)s since its '
                      'subtree contains enabled projects.')
                    % {'project_id': project_id})

            notifications.Audit.disabled(self._PROJECT, project_id,
                                         public=False)
            # Drop the computed assignments if the project is being disabled.
            # This ensures an accurate list of projects is returned when
            # listing projects/domains for a user based on role assignments.
            assignment.COMPUTED_ASSIGNMENTS_REGION.invalidate()

        if cascade:
            self._only_allow_enabled_to_update_cascade(project,
                                                       original_project)
            self._update_project_enabled_cascade(project_id, project_enabled)

        try:
            project['is_domain'] = (project.get('is_domain') or
                                    original_project['is_domain'])
            ret = self.driver.update_project(project_id, project)
        except exception.Conflict:
            raise exception.Conflict(
                type='project',
                details=self._generate_project_name_conflict_msg(project))

        try:
            self.get_project.invalidate(self, project_id)
            self.get_project_by_name.invalidate(self, original_project['name'],
                                                original_project['domain_id'])
            if ('domain_id' in project and
               project['domain_id'] != original_project['domain_id']):
                # If the project's domain_id has been updated, invalidate user
                # role assignments cache region, as it may be caching inherited
                # assignments from the old domain to the specified project
                assignment.COMPUTED_ASSIGNMENTS_REGION.invalidate()
        finally:
            # attempt to send audit event even if the cache invalidation raises
            notifications.Audit.updated(self._PROJECT, project_id, initiator)
            if original_project['is_domain']:
                notifications.Audit.updated(self._DOMAIN, project_id,
                                            initiator)
                # If the domain is being disabled, issue the disable
                # notification as well
                if original_project_enabled and not project_enabled:
                    # NOTE(lbragstad): When a domain is disabled, we have to
                    # invalidate the entire token cache. With persistent
                    # tokens, we did something similar where all tokens for a
                    # specific domain were deleted when that domain was
                    # disabled. This effectively offers the same behavior for
                    # non-persistent tokens by removing them from the cache and
                    # requiring the authorization context to be rebuilt the
                    # next time they're validated.
                    token_provider.TOKENS_REGION.invalidate()
                    notifications.Audit.disabled(self._DOMAIN, project_id,
                                                 public=False)

        return ret

    def _only_allow_enabled_to_update_cascade(self, project, original_project):
        for attr in project:
            if attr != 'enabled':
                if project.get(attr) != original_project.get(attr):
                    raise exception.ValidationError(
                        message=_('Cascade update is only allowed for '
                                  'enabled attribute.'))

    def _update_project_enabled_cascade(self, project_id, enabled):
        subtree = self.list_projects_in_subtree(project_id)
        # Update enabled only if different from original value
        subtree_to_update = [child for child in subtree
                             if child['enabled'] != enabled]
        for child in subtree_to_update:
            child['enabled'] = enabled

            if not enabled:
                # Does not in fact disable the project, only emits a
                # notification that it was disabled. The actual disablement
                # is done in the next line.
                notifications.Audit.disabled(self._PROJECT, child['id'],
                                             public=False)

            self.driver.update_project(child['id'], child)

    def update_project(self, project_id, project, initiator=None,
                       cascade=False):
        ret = self._update_project(project_id, project, initiator, cascade)
        if ret['is_domain']:
            self.get_domain.invalidate(self, project_id)
            self.get_domain_by_name.invalidate(self, ret['name'])

        return ret

    def _post_delete_cleanup_project(self, project_id, project,
                                     initiator=None):
        try:
            self.get_project.invalidate(self, project_id)
            self.get_project_by_name.invalidate(self, project['name'],
                                                project['domain_id'])
            PROVIDERS.assignment_api.delete_project_assignments(project_id)
            # Invalidate user role assignments cache region, as it may
            # be caching role assignments where the target is
            # the specified project
            assignment.COMPUTED_ASSIGNMENTS_REGION.invalidate()
            PROVIDERS.credential_api.delete_credentials_for_project(project_id)
            PROVIDERS.trust_api.delete_trusts_for_project(project_id)
            PROVIDERS.unified_limit_api.delete_limits_for_project(project_id)
        finally:
            # attempt to send audit event even if the cache invalidation raises
            notifications.Audit.deleted(self._PROJECT, project_id, initiator)

    def delete_project(self, project_id, initiator=None, cascade=False):
        """Delete one project or a subtree.

        :param cascade: If true, the specified project and all its
                        sub-projects are deleted. Otherwise, only the specified
                        project is deleted.
        :type cascade: boolean
        :raises keystone.exception.ValidationError: if project is a domain
        :raises keystone.exception.Forbidden: if project is not a leaf
        """
        project = self.driver.get_project(project_id)
        if project.get('is_domain'):
            self._delete_domain(project, initiator)
        else:
            self._delete_project(project, initiator, cascade)

    def _delete_project(self, project, initiator=None, cascade=False):
        # Prevent deletion of immutable projects
        ro_opt.check_immutable_delete(
            resource_ref=project,
            resource_type='project',
            resource_id=project['id'])
        project_id = project['id']
        if project['is_domain'] and project['enabled']:
            raise exception.ValidationError(
                message=_('cannot delete an enabled project acting as a '
                          'domain. Please disable the project %s first.')
                % project.get('id'))

        if not self.is_leaf_project(project_id) and not cascade:
            raise exception.ForbiddenNotSecurity(
                _('Cannot delete the project %s since it is not a leaf in the '
                  'hierarchy. Use the cascade option if you want to delete a '
                  'whole subtree.')
                % project_id)

        if cascade:
            # Getting reversed project's subtrees list, i.e. from the leaves
            # to the root, so we do not break parent_id FK.
            subtree_list = self.list_projects_in_subtree(project_id)
            subtree_list.reverse()
            if not self._check_whole_subtree_is_disabled(
                    project_id, subtree_list=subtree_list):
                raise exception.ForbiddenNotSecurity(
                    _('Cannot delete project %(project_id)s since its subtree '
                      'contains enabled projects.')
                    % {'project_id': project_id})

            project_list = subtree_list + [project]
            projects_ids = [x['id'] for x in project_list]

            ret = self.driver.delete_projects_from_ids(projects_ids)
            for prj in project_list:
                self._post_delete_cleanup_project(prj['id'], prj, initiator)
        else:
            ret = self.driver.delete_project(project_id)
            self._post_delete_cleanup_project(project_id, project, initiator)

        reason = (
            'The token cache is being invalidate because project '
            '%(project_id)s was deleted. Authorization will be recalculated '
            'and enforced accordingly the next time users authenticate or '
            'validate a token.' % {'project_id': project_id}
        )
        notifications.invalidate_token_cache_notification(reason)
        return ret

    def _filter_projects_list(self, projects_list, user_id):
        user_projects = PROVIDERS.assignment_api.list_projects_for_user(
            user_id
        )
        user_projects_ids = set([proj['id'] for proj in user_projects])
        # Keep only the projects present in user_projects
        return [proj for proj in projects_list
                if proj['id'] in user_projects_ids]

    def _assert_valid_project_id(self, project_id):
        if project_id is None:
            msg = _('Project field is required and cannot be empty.')
            raise exception.ValidationError(message=msg)
        # Check if project_id exists
        self.get_project(project_id)

    def _include_limits(self, projects):
        """Modify a list of projects to include limit information.

        :param projects: a list of project references including an `id`
        :type projects: list of dictionaries
        """
        for project in projects:
            hints = driver_hints.Hints()
            hints.add_filter('project_id', project['id'])
            limits = PROVIDERS.unified_limit_api.list_limits(hints)
            project['limits'] = limits

    def list_project_parents(self, project_id, user_id=None,
                             include_limits=False):
        self._assert_valid_project_id(project_id)
        parents = self.driver.list_project_parents(project_id)
        # If a user_id was provided, the returned list should be filtered
        # against the projects this user has access to.
        if user_id:
            parents = self._filter_projects_list(parents, user_id)
        if include_limits:
            self._include_limits(parents)
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
        """Get the IDs from the parents from a given project.

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

    def list_projects_in_subtree(self, project_id, user_id=None,
                                 include_limits=False):
        self._assert_valid_project_id(project_id)
        subtree = self.driver.list_projects_in_subtree(project_id)
        # If a user_id was provided, the returned list should be filtered
        # against the projects this user has access to.
        if user_id:
            subtree = self._filter_projects_list(subtree, user_id)
        if include_limits:
            self._include_limits(subtree)
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
        """Get the IDs from the projects in the subtree from a given project.

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

    def list_domains_from_ids(self, domain_ids):
        """List domains for the provided list of ids.

        :param domain_ids: list of ids

        :returns: a list of domain_refs.

        This method is used internally by the assignment manager to bulk read
        a set of domains given their ids.

        """
        # Retrieve the projects acting as domains get their correspondent
        # domains
        projects = self.list_projects_from_ids(domain_ids)
        domains = [self._get_domain_from_project(project)
                   for project in projects]

        return domains

    @MEMOIZE
    def get_domain(self, domain_id):
        try:
            # Retrieve the corresponding project that acts as a domain
            project = self.driver.get_project(domain_id)
            # the DB backend might not operate in case sensitive mode,
            # therefore verify for exact match of IDs
            if domain_id != project['id']:
                raise exception.DomainNotFound(domain_id=domain_id)
        except exception.ProjectNotFound:
            raise exception.DomainNotFound(domain_id=domain_id)

        # Return its correspondent domain
        return self._get_domain_from_project(project)

    @MEMOIZE
    def get_domain_by_name(self, domain_name):
        try:
            # Retrieve the corresponding project that acts as a domain
            project = self.driver.get_project_by_name(domain_name,
                                                      domain_id=None)
        except exception.ProjectNotFound:
            raise exception.DomainNotFound(domain_id=domain_name)

        # Return its correspondent domain
        return self._get_domain_from_project(project)

    def _get_domain_from_project(self, project_ref):
        """Create a domain ref from a project ref.

        Based on the provided project ref, create a domain ref, so that the
        result can be returned in response to a domain API call.
        """
        if not project_ref['is_domain']:
            LOG.error('Asked to convert a non-domain project into a '
                      'domain - Domain: %(domain_id)s, Project ID: '
                      '%(id)s, Project Name: %(project_name)s',
                      {'domain_id': project_ref['domain_id'],
                       'id': project_ref['id'],
                       'project_name': project_ref['name']})
            raise exception.DomainNotFound(domain_id=project_ref['id'])

        domain_ref = project_ref.copy()
        # As well as the project specific attributes that we need to remove,
        # there is an old compatibility issue in that update project (as well
        # as extracting an extra attributes), also includes a copy of the
        # actual extra dict as well - something that update domain does not do.
        for k in ['parent_id', 'domain_id', 'is_domain', 'extra']:
            domain_ref.pop(k, None)

        return domain_ref

    def create_domain(self, domain_id, domain, initiator=None):
        if (CONF.resource.domain_name_url_safe != 'off' and
                utils.is_not_url_safe(domain['name'])):
            self._raise_reserved_character_exception('Domain', domain['name'])
        project_from_domain = base.get_project_from_domain(domain)
        is_domain_project = self.create_project(
            domain_id, project_from_domain, initiator)

        return self._get_domain_from_project(is_domain_project)

    @manager.response_truncated
    def list_domains(self, hints=None):
        projects = self.list_projects_acting_as_domain(hints)
        domains = [self._get_domain_from_project(project)
                   for project in projects]
        return domains

    def update_domain(self, domain_id, domain, initiator=None):
        # TODO(henry-nash): We shouldn't have to check for the federated domain
        # here as well as _update_project, but currently our tests assume the
        # checks are done in a specific order. The tests should be refactored.
        self.assert_domain_not_federated(domain_id, domain)
        project = base.get_project_from_domain(domain)
        try:
            original_domain = self.driver.get_project(domain_id)
            project = self._update_project(domain_id, project, initiator)
        except exception.ProjectNotFound:
            raise exception.DomainNotFound(domain_id=domain_id)

        domain_from_project = self._get_domain_from_project(project)
        self.get_domain.invalidate(self, domain_id)
        self.get_domain_by_name.invalidate(self, original_domain['name'])

        return domain_from_project

    def delete_domain(self, domain_id, initiator=None):
        # Use the driver directly to get the project that acts as a domain and
        # prevent using old cached value.
        try:
            domain = self.driver.get_project(domain_id)
        except exception.ProjectNotFound:
            raise exception.DomainNotFound(domain_id=domain_id)
        self._delete_domain(domain, initiator)

    def _delete_domain(self, domain, initiator=None):
        # Disallow deletion of immutable domains
        ro_opt.check_immutable_delete(
            resource_ref=domain,
            resource_type='domain',
            resource_id=domain['id'])
        # To help avoid inadvertent deletes, we insist that the domain
        # has been previously disabled.  This also prevents a user deleting
        # their own domain since, once it is disabled, they won't be able
        # to get a valid token to issue this delete.
        if domain['enabled']:
            raise exception.ForbiddenNotSecurity(
                _('Cannot delete a domain that is enabled, please disable it '
                  'first.'))

        domain_id = domain['id']
        self._delete_domain_contents(domain_id)
        notifications.Audit.internal(
            notifications.DOMAIN_DELETED, domain_id
        )
        self._delete_project(domain, initiator)
        try:
            self.get_domain.invalidate(self, domain_id)
            self.get_domain_by_name.invalidate(self, domain['name'])
            # Delete any database stored domain config
            PROVIDERS.domain_config_api.delete_config_options(domain_id)
            PROVIDERS.domain_config_api.release_registration(domain_id)
        finally:
            # attempt to send audit event even if the cache invalidation raises
            notifications.Audit.deleted(self._DOMAIN, domain_id, initiator)

    def _delete_domain_contents(self, domain_id):
        """Delete the contents of a domain.

        Before we delete a domain, we need to remove all the entities
        that are owned by it, i.e. Projects. To do this we
        call the delete function for these entities, which are
        themselves responsible for deleting any credentials and role grants
        associated with them as well as revoking any relevant tokens.

        """
        def _delete_projects(project, projects, examined):
            if project['id'] in examined:
                msg = ('Circular reference or a repeated entry found '
                       'projects hierarchy - %(project_id)s.')
                LOG.error(msg, {'project_id': project['id']})
                return

            examined.add(project['id'])
            children = [proj for proj in projects
                        if proj.get('parent_id') == project['id']]
            for proj in children:
                _delete_projects(proj, projects, examined)

            try:
                self._delete_project(project, initiator=None)
            except exception.ProjectNotFound:
                LOG.debug(('Project %(projectid)s not found when '
                           'deleting domain contents for %(domainid)s, '
                           'continuing with cleanup.'),
                          {'projectid': project['id'],
                           'domainid': domain_id})

        proj_refs = self.list_projects_in_domain(domain_id)

        # Deleting projects recursively
        roots = [x for x in proj_refs if x.get('parent_id') == domain_id]
        examined = set()
        for project in roots:
            _delete_projects(project, proj_refs, examined)

    @manager.response_truncated
    def list_projects(self, hints=None):
        if hints:
            tag_filters = {}
            # Handle project tag filters separately
            for f in list(hints.filters):
                if f['name'] in TAG_SEARCH_FILTERS:
                    tag_filters[f['name']] = f['value']
                    hints.filters.remove(f)
            if tag_filters:
                tag_refs = self.driver.list_projects_by_tags(tag_filters)
                project_refs = self.driver.list_projects(hints)
                ref_ids = [ref['id'] for ref in tag_refs]
                return [ref for ref in project_refs if ref['id'] in ref_ids]
        return self.driver.list_projects(hints or driver_hints.Hints())

    # NOTE(henry-nash): list_projects_in_domain is actually an internal method
    # and not exposed via the API.  Therefore there is no need to support
    # driver hints for it.
    def list_projects_in_domain(self, domain_id):
        return self.driver.list_projects_in_domain(domain_id)

    def list_projects_acting_as_domain(self, hints=None):
        return self.driver.list_projects_acting_as_domain(
            hints or driver_hints.Hints())

    @MEMOIZE
    def get_project(self, project_id):
        return self.driver.get_project(project_id)

    @MEMOIZE
    def get_project_by_name(self, project_name, domain_id):
        return self.driver.get_project_by_name(project_name, domain_id)

    def _require_matching_domain_id(self, new_ref, orig_ref):
        """Ensure the current domain ID matches the reference one, if any.

        Provided we want domain IDs to be immutable, check whether any
        domain_id specified in the ref dictionary matches the existing
        domain_id for this entity.

        :param new_ref: the dictionary of new values proposed for this entity
        :param orig_ref: the dictionary of original values proposed for this
                         entity
        :raises: :class:`keystone.exception.ValidationError`
        """
        if 'domain_id' in new_ref:
            if new_ref['domain_id'] != orig_ref['domain_id']:
                raise exception.ValidationError(_('Cannot change Domain ID'))

    def create_project_tag(self, project_id, tag, initiator=None):
        """Create a new tag on project.

        :param project_id: ID of a project to create a tag for
        :param tag: The string value of a tag to add

        :returns: The value of the created tag
        """
        project = self.driver.get_project(project_id)
        if ro_opt.check_resource_immutable(resource_ref=project):
            raise exception.ResourceUpdateForbidden(
                message=_(
                    'Cannot create project tags for %(project_id)s, project '
                    'is immutable. Set "immutable" option to false before '
                    'creating project tags.') % {'project_id': project_id})
        tag_name = tag.strip()
        project['tags'].append(tag_name)
        self.update_project(project_id, {'tags': project['tags']})

        notifications.Audit.created(
            self._PROJECT_TAG, tag_name, initiator)
        return tag_name

    def get_project_tag(self, project_id, tag_name):
        """Return information for a single tag on a project.

        :param project_id: ID of a project to retrive a tag from
        :param tag_name: Name of a tag to return

        :raises keystone.exception.ProjectTagNotFound: If the tag name
            does not exist on the project
        :returns: The tag value
        """
        project = self.driver.get_project(project_id)
        if tag_name not in project.get('tags'):
            raise exception.ProjectTagNotFound(project_tag=tag_name)
        return tag_name

    def list_project_tags(self, project_id):
        """List all tags on project.

        :param project_id: The ID of a project

        :returns: A list of tags from a project
        """
        project = self.driver.get_project(project_id)
        return project.get('tags', [])

    def update_project_tags(self, project_id, tags, initiator=None):
        """Update all tags on a project.

        :param project_id: The ID of the project to update
        :param tags: A list of tags to update on the project

        :returns: A list of tags
        """
        project = self.driver.get_project(project_id)
        if ro_opt.check_resource_immutable(resource_ref=project):
            raise exception.ResourceUpdateForbidden(
                message=_(
                    'Cannot update project tags for %(project_id)s, project '
                    'is immutable. Set "immutable" option to false before '
                    'creating project tags.') % {'project_id': project_id})
        tag_list = [t.strip() for t in tags]
        project = {'tags': tag_list}
        self.update_project(project_id, project)
        return tag_list

    def delete_project_tag(self, project_id, tag):
        """Delete single tag from project.

        :param project_id: The ID of the project
        :param tag: The tag value to delete

        :raises keystone.exception.ProjectTagNotFound: If the tag name
            does not exist on the project
        """
        project = self.driver.get_project(project_id)
        if ro_opt.check_resource_immutable(resource_ref=project):
            raise exception.ResourceUpdateForbidden(
                message=_(
                    'Cannot delete project tags for %(project_id)s, project '
                    'is immutable. Set "immutable" option to false before '
                    'creating project tags.') % {'project_id': project_id})
        try:
            project['tags'].remove(tag)
        except ValueError:
            raise exception.ProjectTagNotFound(project_tag=tag)
        self.update_project(project_id, project)
        notifications.Audit.deleted(self._PROJECT_TAG, tag)

    def check_project_depth(self, max_depth=None):
        """Check project depth whether greater than input or not."""
        if max_depth:
            exceeded_project_ids = self.driver.check_project_depth(max_depth)
            if exceeded_project_ids:
                raise exception.LimitTreeExceedError(exceeded_project_ids,
                                                     max_depth)


MEMOIZE_CONFIG = cache.get_memoization_decorator(group='domain_config')


class DomainConfigManager(manager.Manager):
    """Default pivot point for the Domain Config backend."""

    # NOTE(henry-nash): In order for a config option to be stored in the
    # standard table, it must be explicitly whitelisted. Options marked as
    # sensitive are stored in a separate table. Attempting to store options
    # that are not listed as either whitelisted or sensitive will raise an
    # exception.
    #
    # Only those options that affect the domain-specific driver support in
    # the identity manager are supported.

    driver_namespace = 'keystone.resource.domain_config'
    _provides_api = 'domain_config_api'

    # We explicitly state each whitelisted option instead of pulling all ldap
    # options from CONF and selectively pruning them to prevent a security
    # lapse. That way if a new ldap CONF key/value were to be added it wouldn't
    # automatically be added to the whitelisted options unless that is what was
    # intended. In which case, we explicitly add it to the list ourselves.
    whitelisted_options = {
        'identity': ['driver', 'list_limit'],
        'ldap': [
            'url', 'user', 'suffix', 'query_scope', 'page_size',
            'alias_dereferencing', 'debug_level', 'chase_referrals',
            'user_tree_dn', 'user_filter', 'user_objectclass',
            'user_id_attribute', 'user_name_attribute', 'user_mail_attribute',
            'user_description_attribute', 'user_pass_attribute',
            'user_enabled_attribute', 'user_enabled_invert',
            'user_enabled_mask', 'user_enabled_default',
            'user_attribute_ignore', 'user_default_project_id_attribute',
            'user_enabled_emulation', 'user_enabled_emulation_dn',
            'user_enabled_emulation_use_group_config',
            'user_additional_attribute_mapping', 'group_tree_dn',
            'group_filter', 'group_objectclass', 'group_id_attribute',
            'group_name_attribute', 'group_members_are_ids',
            'group_member_attribute', 'group_desc_attribute',
            'group_attribute_ignore', 'group_additional_attribute_mapping',
            'tls_cacertfile', 'tls_cacertdir', 'use_tls', 'tls_req_cert',
            'use_pool', 'pool_size', 'pool_retry_max', 'pool_retry_delay',
            'pool_connection_timeout', 'pool_connection_lifetime',
            'use_auth_pool', 'auth_pool_size', 'auth_pool_connection_lifetime'
        ]
    }
    sensitive_options = {
        'identity': [],
        'ldap': ['password']
    }

    def __init__(self):
        super(DomainConfigManager, self).__init__(CONF.domain_config.driver)

    def _assert_valid_config(self, config):
        """Ensure the options in the config are valid.

        This method is called to validate the request config in create and
        update manager calls.

        :param config: config structure being created or updated

        """
        # Something must be defined in the request
        if not config:
            raise exception.InvalidDomainConfig(
                reason=_('No options specified'))

        # Make sure the groups/options defined in config itself are valid
        for group in config:
            if (not config[group] or not
                    isinstance(config[group], dict)):
                msg = _('The value of group %(group)s specified in the '
                        'config should be a dictionary of options') % {
                            'group': group}
                raise exception.InvalidDomainConfig(reason=msg)
            for option in config[group]:
                self._assert_valid_group_and_option(group, option)

    def _assert_valid_group_and_option(self, group, option):
        """Ensure the combination of group and option is valid.

        :param group: optional group name, if specified it must be one
                      we support
        :param option: optional option name, if specified it must be one
                       we support and a group must also be specified

        """
        if not group and not option:
            # For all calls, it's OK for neither to be defined, it means you
            # are operating on all config options for that domain.
            return

        if not group and option:
            # Our API structure should prevent this from ever happening, so if
            # it does, then this is coding error.
            msg = _('Option %(option)s found with no group specified while '
                    'checking domain configuration request') % {
                        'option': option}
            raise exception.UnexpectedError(exception=msg)

        if (group and group not in self.whitelisted_options and
                group not in self.sensitive_options):
            msg = _('Group %(group)s is not supported '
                    'for domain specific configurations') % {'group': group}
            raise exception.InvalidDomainConfig(reason=msg)

        if option:
            if (option not in self.whitelisted_options[group] and option not in
                    self.sensitive_options[group]):
                msg = _('Option %(option)s in group %(group)s is not '
                        'supported for domain specific configurations') % {
                            'group': group, 'option': option}
                raise exception.InvalidDomainConfig(reason=msg)

    def _is_sensitive(self, group, option):
        return option in self.sensitive_options[group]

    def _config_to_list(self, config):
        """Build list of options for use by backend drivers."""
        option_list = []
        for group in config:
            for option in config[group]:
                option_list.append({
                    'group': group, 'option': option,
                    'value': config[group][option],
                    'sensitive': self._is_sensitive(group, option)})

        return option_list

    def _option_dict(self, group, option):
        group_attr = getattr(CONF, group)
        return {'group': group, 'option': option,
                'value': getattr(group_attr, option)}

    def _list_to_config(self, whitelisted, sensitive=None, req_option=None):
        """Build config dict from a list of option dicts.

        :param whitelisted: list of dicts containing options and their groups,
                            this has already been filtered to only contain
                            those options to include in the output.
        :param sensitive: list of dicts containing sensitive options and their
                          groups, this has already been filtered to only
                          contain those options to include in the output.
        :param req_option: the individual option requested

        :returns: a config dict, including sensitive if specified

        """
        the_list = whitelisted + (sensitive or [])
        if not the_list:
            return {}

        if req_option:
            # The request was specific to an individual option, so
            # no need to include the group in the output. We first check that
            # there is only one option in the answer (and that it's the right
            # one) - if not, something has gone wrong and we raise an error
            if len(the_list) > 1 or the_list[0]['option'] != req_option:
                LOG.error('Unexpected results in response for domain '
                          'config - %(count)s responses, first option is '
                          '%(option)s, expected option %(expected)s',
                          {'count': len(the_list), 'option': list[0]['option'],
                           'expected': req_option})
                raise exception.UnexpectedError(
                    _('An unexpected error occurred when retrieving domain '
                      'configs'))
            return {the_list[0]['option']: the_list[0]['value']}

        config = {}
        for option in the_list:
            config.setdefault(option['group'], {})
            config[option['group']][option['option']] = option['value']

        return config

    def create_config(self, domain_id, config):
        """Create config for a domain.

        :param domain_id: the domain in question
        :param config: the dict of config groups/options to assign to the
                       domain

        Creates a new config, overwriting any previous config (no Conflict
        error will be generated).

        :returns: a dict of group dicts containing the options, with any that
                  are sensitive removed
        :raises keystone.exception.InvalidDomainConfig: when the config
                contains options we do not support

        """
        self._assert_valid_config(config)
        option_list = self._config_to_list(config)
        self.create_config_options(domain_id, option_list)
        # Since we are caching on the full substituted config, we just
        # invalidate here, rather than try and create the right result to
        # cache.
        self.get_config_with_sensitive_info.invalidate(self, domain_id)
        return self._list_to_config(self.list_config_options(domain_id))

    def get_config(self, domain_id, group=None, option=None):
        """Get config, or partial config, for a domain.

        :param domain_id: the domain in question
        :param group: an optional specific group of options
        :param option: an optional specific option within the group

        :returns: a dict of group dicts containing the whitelisted options,
                  filtered by group and option specified
        :raises keystone.exception.DomainConfigNotFound: when no config found
                that matches domain_id, group and option specified
        :raises keystone.exception.InvalidDomainConfig: when the config
                and group/option parameters specify an option we do not
                support

        An example response::

            {
                'ldap': {
                    'url': 'myurl'
                    'user_tree_dn': 'OU=myou'},
                'identity': {
                    'driver': 'ldap'}

            }

        """
        self._assert_valid_group_and_option(group, option)
        whitelisted = self.list_config_options(domain_id, group, option)
        if whitelisted:
            return self._list_to_config(whitelisted, req_option=option)

        if option:
            msg = _('option %(option)s in group %(group)s') % {
                'group': group, 'option': option}
        elif group:
            msg = _('group %(group)s') % {'group': group}
        else:
            msg = _('any options')
        raise exception.DomainConfigNotFound(
            domain_id=domain_id, group_or_option=msg)

    def get_security_compliance_config(self, domain_id, group, option=None):
        r"""Get full or partial security compliance config from configuration.

        :param domain_id: the domain in question
        :param group: a specific group of options
        :param option: an optional specific option within the group

        :returns: a dict of group dicts containing the whitelisted options,
                  filtered by group and option specified
        :raises keystone.exception.InvalidDomainConfig: when the config
                and group/option parameters specify an option we do not
                support

        An example response::

            {
                'security_compliance': {
                    'password_regex': '^(?=.*\d)(?=.*[a-zA-Z]).{7,}$'
                    'password_regex_description':
                        'A password must consist of at least 1 letter, '
                        '1 digit, and have a minimum length of 7 characters'
                    }
            }

        """
        if domain_id != CONF.identity.default_domain_id:
            msg = _('Reading security compliance information for any domain '
                    'other than the default domain is not allowed or '
                    'supported.')
            raise exception.InvalidDomainConfig(reason=msg)

        config_list = []
        readable_options = ['password_regex', 'password_regex_description']
        if option and option not in readable_options:
            msg = _('Reading security compliance values other than '
                    'password_regex and password_regex_description is not '
                    'allowed.')
            raise exception.InvalidDomainConfig(reason=msg)
        elif option and option in readable_options:
            config_list.append(self._option_dict(group, option))
        elif not option:
            for op in readable_options:
                config_list.append(self._option_dict(group, op))
        # We already validated that the group is the security_compliance group
        # so we can move along and start validating the options
        return self._list_to_config(config_list, req_option=option)

    def update_config(self, domain_id, config, group=None, option=None):
        """Update config, or partial config, for a domain.

        :param domain_id: the domain in question
        :param config: the config dict containing and groups/options being
                       updated
        :param group: an optional specific group of options, which if specified
                      must appear in config, with no other groups
        :param option: an optional specific option within the group, which if
                       specified must appear in config, with no other options

        The contents of the supplied config will be merged with the existing
        config for this domain, updating or creating new options if these did
        not previously exist. If group or option is specified, then the update
        will be limited to those specified items and the inclusion of other
        options in the supplied config will raise an exception, as will the
        situation when those options do not already exist in the current
        config.

        :returns: a dict of groups containing all whitelisted options
        :raises keystone.exception.InvalidDomainConfig: when the config
                and group/option parameters specify an option we do not
                support or one that does not exist in the original config

        """
        def _assert_valid_update(domain_id, config, group=None, option=None):
            """Ensure the combination of config, group and option is valid."""
            self._assert_valid_config(config)
            self._assert_valid_group_and_option(group, option)

            # If a group has been specified, then the request is to
            # explicitly only update the options in that group - so the config
            # must not contain anything else. Further, that group must exist in
            # the original config. Likewise, if an option has been specified,
            # then the group in the config must only contain that option and it
            # also must exist in the original config.
            if group:
                if len(config) != 1 or (option and len(config[group]) != 1):
                    if option:
                        msg = _('Trying to update option %(option)s in group '
                                '%(group)s, so that, and only that, option '
                                'must be specified  in the config') % {
                                    'group': group, 'option': option}
                    else:
                        msg = _('Trying to update group %(group)s, so that, '
                                'and only that, group must be specified in '
                                'the config') % {'group': group}
                    raise exception.InvalidDomainConfig(reason=msg)

                # So we now know we have the right number of entries in the
                # config that align with a group/option being specified, but we
                # must also make sure they match.
                if group not in config:
                    msg = _('request to update group %(group)s, but config '
                            'provided contains group %(group_other)s '
                            'instead') % {
                                'group': group,
                                'group_other': list(config.keys())[0]}
                    raise exception.InvalidDomainConfig(reason=msg)
                if option and option not in config[group]:
                    msg = _('Trying to update option %(option)s in group '
                            '%(group)s, but config provided contains option '
                            '%(option_other)s instead') % {
                                'group': group, 'option': option,
                                'option_other': list(config[group].keys())[0]}
                    raise exception.InvalidDomainConfig(reason=msg)

                # Finally, we need to check if the group/option specified
                # already exists in the original config - since if not, to keep
                # with the semantics of an update, we need to fail with
                # a DomainConfigNotFound
                if not self._get_config_with_sensitive_info(domain_id,
                                                            group, option):
                    if option:
                        msg = _('option %(option)s in group %(group)s') % {
                            'group': group, 'option': option}
                        raise exception.DomainConfigNotFound(
                            domain_id=domain_id, group_or_option=msg)
                    else:
                        msg = _('group %(group)s') % {'group': group}
                        raise exception.DomainConfigNotFound(
                            domain_id=domain_id, group_or_option=msg)

        update_config = config
        if group and option:
            # The config will just be a dict containing the option and
            # its value, so make it look like a single option under the
            # group in question
            update_config = {group: config}

        _assert_valid_update(domain_id, update_config, group, option)

        option_list = self._config_to_list(update_config)
        self.update_config_options(domain_id, option_list)

        self.get_config_with_sensitive_info.invalidate(self, domain_id)
        return self.get_config(domain_id)

    def delete_config(self, domain_id, group=None, option=None):
        """Delete config, or partial config, for the domain.

        :param domain_id: the domain in question
        :param group: an optional specific group of options
        :param option: an optional specific option within the group

        If group and option are None, then the entire config for the domain
        is deleted. If group is not None, then just that group of options will
        be deleted. If group and option are both specified, then just that
        option is deleted.

        :raises keystone.exception.InvalidDomainConfig: when group/option
                parameters specify an option we do not support or one that
                does not exist in the original config.

        """
        self._assert_valid_group_and_option(group, option)
        if group:
            # As this is a partial delete, then make sure the items requested
            # are valid and exist in the current config
            current_config = self._get_config_with_sensitive_info(domain_id)
            # Raise an exception if the group/options specified don't exist in
            # the current config so that the delete method provides the
            # correct error semantics.
            current_group = current_config.get(group)
            if not current_group:
                msg = _('group %(group)s') % {'group': group}
                raise exception.DomainConfigNotFound(
                    domain_id=domain_id, group_or_option=msg)
            if option and not current_group.get(option):
                msg = _('option %(option)s in group %(group)s') % {
                    'group': group, 'option': option}
                raise exception.DomainConfigNotFound(
                    domain_id=domain_id, group_or_option=msg)

        self.delete_config_options(domain_id, group, option)
        self.get_config_with_sensitive_info.invalidate(self, domain_id)

    def _get_config_with_sensitive_info(self, domain_id, group=None,
                                        option=None):
        """Get config for a domain/group/option with sensitive info included.

        This is only used by the methods within this class, which may need to
        check individual groups or options.

        """
        whitelisted = self.list_config_options(domain_id, group, option)
        sensitive = self.list_config_options(domain_id, group, option,
                                             sensitive=True)

        # Check if there are any sensitive substitutions needed. We first try
        # and simply ensure any sensitive options that have valid substitution
        # references in the whitelisted options are substituted. We then check
        # the resulting whitelisted option and raise a warning if there
        # appears to be an unmatched or incorrectly constructed substitution
        # reference. To avoid the risk of logging any sensitive options that
        # have already been substituted, we first take a copy of the
        # whitelisted option.

        # Build a dict of the sensitive options ready to try substitution
        sensitive_dict = {s['option']: s['value'] for s in sensitive}

        for each_whitelisted in whitelisted:
            if not isinstance(each_whitelisted['value'], str):
                # We only support substitutions into string types, if its an
                # integer, list etc. then just continue onto the next one
                continue

            # Store away the original value in case we need to raise a warning
            # after substitution.
            original_value = each_whitelisted['value']
            warning_msg = ''
            try:
                each_whitelisted['value'] = (
                    each_whitelisted['value'] % sensitive_dict)
            except KeyError:
                warning_msg = (
                    'Found what looks like an unmatched config option '
                    'substitution reference - domain: %(domain)s, group: '
                    '%(group)s, option: %(option)s, value: %(value)s. Perhaps '
                    'the config option to which it refers has yet to be '
                    'added?')
            except (ValueError, TypeError):
                warning_msg = (
                    'Found what looks like an incorrectly constructed '
                    'config option substitution reference - domain: '
                    '%(domain)s, group: %(group)s, option: %(option)s, '
                    'value: %(value)s.')

            if warning_msg:
                LOG.warning(warning_msg, {
                    'domain': domain_id,
                    'group': each_whitelisted['group'],
                    'option': each_whitelisted['option'],
                    'value': original_value})

        return self._list_to_config(whitelisted, sensitive)

    @MEMOIZE_CONFIG
    def get_config_with_sensitive_info(self, domain_id):
        """Get config for a domain with sensitive info included.

        This method is not exposed via the public API, but is used by the
        identity manager to initialize a domain with the fully formed config
        options.

        """
        return self._get_config_with_sensitive_info(domain_id)

    def get_config_default(self, group=None, option=None):
        """Get default config, or partial default config.

        :param group: an optional specific group of options
        :param option: an optional specific option within the group

        :returns: a dict of group dicts containing the default options,
                  filtered by group and option if specified
        :raises keystone.exception.InvalidDomainConfig: when the config
                and group/option parameters specify an option we do not
                support (or one that is not whitelisted).

        An example response::

            {
                'ldap': {
                    'url': 'myurl',
                    'user_tree_dn': 'OU=myou',
                    ....},
                'identity': {
                    'driver': 'ldap'}

            }

        """
        self._assert_valid_group_and_option(group, option)
        config_list = []
        if group:
            if option:
                if option not in self.whitelisted_options[group]:
                    msg = _('Reading the default for option %(option)s in '
                            'group %(group)s is not supported') % {
                                'option': option, 'group': group}
                    raise exception.InvalidDomainConfig(reason=msg)
                config_list.append(self._option_dict(group, option))
            else:
                for each_option in self.whitelisted_options[group]:
                    config_list.append(self._option_dict(group, each_option))
        else:
            for each_group in self.whitelisted_options:
                for each_option in self.whitelisted_options[each_group]:
                    config_list.append(
                        self._option_dict(each_group, each_option)
                    )

        return self._list_to_config(config_list, req_option=option)
