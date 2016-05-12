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

import abc
import copy

from oslo_config import cfg
from oslo_log import log
from oslo_log import versionutils
import six

from keystone import exception
from keystone.i18n import _
from keystone.i18n import _LE


CONF = cfg.CONF
LOG = log.getLogger(__name__)


def get_project_from_domain(domain_ref):
    """Create a project ref from the provided domain ref."""
    project_ref = domain_ref.copy()
    project_ref['is_domain'] = True
    project_ref['domain_id'] = None
    project_ref['parent_id'] = None

    return project_ref


# The ResourceDriverBase class is the set of driver methods from earlier
# drivers that we still support, that have not been removed or modified. This
# class is then used to created the augmented V8 and V9 version abstract driver
# classes, without having to duplicate a lot of abstract method signatures.
# If you remove a method from V9, then move the abstract methods from this Base
# class to the V8 class. Do not modify any of the method signatures in the Base
# class - changes should only be made in the V8 and subsequent classes.

# Starting with V9, some drivers use a special value to represent a domain_id
# of None. See comment in Project class of resource/backends/sql.py for more
# details.
NULL_DOMAIN_ID = '<<keystone.domain.root>>'


@six.add_metaclass(abc.ABCMeta)
class ResourceDriverBase(object):

    def _get_list_limit(self):
        return CONF.resource.list_limit or CONF.list_limit

    # project crud
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
        :raises keystone.exception.ProjectNotFound: if project_id does not
                                                    exist

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def update_project(self, project_id, project):
        """Update an existing project.

        :raises keystone.exception.ProjectNotFound: if project_id does not
                                                    exist
        :raises keystone.exception.Conflict: if project name already exists

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_project(self, project_id):
        """Delete an existing project.

        :raises keystone.exception.ProjectNotFound: if project_id does not
                                                    exist

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_project_parents(self, project_id):
        """List all parents from a project by its ID.

        :param project_id: the driver will list the parents of this
                           project.

        :returns: a list of project_refs or an empty list.
        :raises keystone.exception.ProjectNotFound: if project_id does not
                                                    exist

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def list_projects_in_subtree(self, project_id):
        """List all projects in the subtree of a given project.

        :param project_id: the driver will get the subtree under
                           this project.

        :returns: a list of project_refs or an empty list
        :raises keystone.exception.ProjectNotFound: if project_id does not
                                                    exist

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def is_leaf_project(self, project_id):
        """Check if a project is a leaf in the hierarchy.

        :param project_id: the driver will check if this project
                           is a leaf in the hierarchy.

        :raises keystone.exception.ProjectNotFound: if project_id does not
                                                    exist

        """
        raise exception.NotImplemented()

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
        """Validate that the domain ID belongs to the default domain."""
        if domain_id != CONF.identity.default_domain_id:
            raise exception.DomainNotFound(domain_id=domain_id)


class ResourceDriverV8(ResourceDriverBase):
    """Removed or redefined methods from V8.

    Move the abstract methods of any methods removed or modified in later
    versions of the driver from ResourceDriverBase to here. We maintain this
    so that legacy drivers, which will be a subclass of ResourceDriverV8, can
    still reference them.

    """

    @abc.abstractmethod
    def create_project(self, tenant_id, tenant):
        """Create a new project.

        :param tenant_id: This parameter can be ignored.
        :param dict tenant: The new project

        Project schema::

            type: object
            properties:
                id:
                    type: string
                name:
                    type: string
                domain_id:
                    type: string
                description:
                    type: string
                enabled:
                    type: boolean
                parent_id:
                    type: string
                is_domain:
                    type: boolean
            required: [id, name, domain_id]
            additionalProperties: true

        If project doesn't match the schema the behavior is undefined.

        The driver can impose requirements such as the maximum length of a
        field. If these requirements are not met the behavior is undefined.

        :raises keystone.exception.Conflict: if the project id already exists
            or the name already exists for the domain_id.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def get_project_by_name(self, tenant_name, domain_id):
        """Get a tenant by name.

        :returns: tenant_ref
        :raises keystone.exception.ProjectNotFound: if a project with the
                             tenant_name does not exist within the domain

        """
        raise exception.NotImplemented()  # pragma: no cover

    # Domain management functions for backends that only allow a single
    # domain.  Although we no longer use this, a custom legacy driver might
    # have made use of it, so keep it here in case.
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

    # domain crud
    @abc.abstractmethod
    def create_domain(self, domain_id, domain):
        """Create a new domain.

        :raises keystone.exception.Conflict: if the domain_id or domain name
                                             already exists

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
        :raises keystone.exception.DomainNotFound: if domain_id does not exist

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def get_domain_by_name(self, domain_name):
        """Get a domain by name.

        :returns: domain_ref
        :raises keystone.exception.DomainNotFound: if domain_name does not
                                                   exist

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def update_domain(self, domain_id, domain):
        """Update an existing domain.

        :raises keystone.exception.DomainNotFound: if domain_id does not exist
        :raises keystone.exception.Conflict: if domain name already exists

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_domain(self, domain_id):
        """Delete an existing domain.

        :raises keystone.exception.DomainNotFound: if domain_id does not exist

        """
        raise exception.NotImplemented()  # pragma: no cover


class ResourceDriverV9(ResourceDriverBase):
    """New or redefined methods from V8.

    Add any new V9 abstract methods (or those with modified signatures) to
    this class.

    """

    @abc.abstractmethod
    def create_project(self, project_id, project):
        """Create a new project.

        :param project_id: This parameter can be ignored.
        :param dict project: The new project

        Project schema::

            type: object
            properties:
                id:
                    type: string
                name:
                    type: string
                domain_id:
                    type: [string, null]
                description:
                    type: string
                enabled:
                    type: boolean
                parent_id:
                    type: string
                is_domain:
                    type: boolean
            required: [id, name, domain_id]
            additionalProperties: true

        If the project doesn't match the schema the behavior is undefined.

        The driver can impose requirements such as the maximum length of a
        field. If these requirements are not met the behavior is undefined.

        :raises keystone.exception.Conflict: if the project id already exists
            or the name already exists for the domain_id.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def get_project_by_name(self, project_name, domain_id):
        """Get a project by name.

        :returns: project_ref
        :raises keystone.exception.ProjectNotFound: if a project with the
                             project_name does not exist within the domain

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_projects_from_ids(self, project_ids):
        """Delete a given list of projects.

        Deletes a list of projects. Ensures no project on the list exists
        after it is successfully called. If an empty list is provided,
        the it is silently ignored. In addition, if a project ID in the list
        of project_ids is not found in the backend, no exception is raised,
        but a message is logged.
        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_projects_acting_as_domain(self, hints):
        """List all projects acting as domains.

        :param hints: filter hints which the driver should
                      implement if at all possible.

        :returns: a list of project_refs or an empty list.

        """
        raise exception.NotImplemented()  # pragma: no cover


class V9ResourceWrapperForV8Driver(ResourceDriverV9):
    """Wrapper class to supported a V8 legacy driver.

    In order to support legacy drivers without having to make the manager code
    driver-version aware, we wrap legacy drivers so that they look like the
    latest version. For the various changes made in a new driver, here are the
    actions needed in this wrapper:

    Method removed from new driver - remove the call-through method from this
                                     class, since the manager will no longer be
                                     calling it.
    Method signature (or meaning) changed - wrap the old method in a new
                                            signature here, and munge the input
                                            and output parameters accordingly.
    New method added to new driver - add a method to implement the new
                                     functionality here if possible. If that is
                                     not possible, then return NotImplemented,
                                     since we do not guarantee to support new
                                     functionality with legacy drivers.

    This wrapper contains the following support for newer manager code:

    - The current manager code expects domains to be represented as projects
      acting as domains, something that may not be possible in a legacy driver.
      Hence the wrapper will map any calls for projects acting as a domain back
      onto the driver domain methods. The caveat for this, is that this assumes
      that there can not be a clash between a project_id and a domain_id, in
      which case it may not be able to locate the correct entry.

    """

    @versionutils.deprecated(
        as_of=versionutils.deprecated.MITAKA,
        what='keystone.resource.ResourceDriverV8',
        in_favor_of='keystone.resource.ResourceDriverV9',
        remove_in=+2)
    def __init__(self, wrapped_driver):
        self.driver = wrapped_driver

    def _get_domain_from_project(self, project_ref):
        """Create a domain ref from a project ref.

        Based on the provided project ref (or partial ref), creates a
        domain ref, so that the result can be passed to the driver
        domain methods.
        """
        domain_ref = project_ref.copy()
        for k in ['parent_id', 'domain_id', 'is_domain']:
            domain_ref.pop(k, None)
        return domain_ref

    def get_project_by_name(self, project_name, domain_id):
        if domain_id is None:
            try:
                domain_ref = self.driver.get_domain_by_name(project_name)
                return get_project_from_domain(domain_ref)
            except exception.DomainNotFound:
                raise exception.ProjectNotFound(project_id=project_name)
        else:
            return self.driver.get_project_by_name(project_name, domain_id)

    def create_project(self, project_id, project):
        if project['is_domain']:
            new_domain = self._get_domain_from_project(project)
            domain_ref = self.driver.create_domain(project_id, new_domain)
            return get_project_from_domain(domain_ref)
        else:
            return self.driver.create_project(project_id, project)

    def list_projects(self, hints):
        """List projects and/or domains.

        We use the hints filter to determine whether we are listing projects,
        domains or both.

        If the filter includes domain_id==None, then we should only list
        domains (convert to a project acting as a domain) since regular
        projcets always have a non-None value for domain_id.

        Likewise, if the filter includes domain_id==<non-None value>, then we
        should only list projects.

        If there is no domain_id filter, then we need to do a combained listing
        of domains and projects, converting domains to projects acting as a
        domain.

        """
        domain_listing_filter = None
        for f in hints.filters:
            if (f['name'] == 'domain_id'):
                domain_listing_filter = f

        if domain_listing_filter is not None:
            if domain_listing_filter['value'] is not None:
                proj_list = self.driver.list_projects(hints)
            else:
                domains = self.driver.list_domains(hints)
                proj_list = [get_project_from_domain(p) for p in domains]
            hints.filters.remove(domain_listing_filter)
            return proj_list
        else:
            # No domain_id filter, so combine domains and projects. Although
            # we hand any remaining filters into each driver, since each filter
            # might need to be carried out more than once, we use copies of the
            # filters, allowing the original filters to be passed back up to
            # controller level where a final filter will occur.
            local_hints = copy.deepcopy(hints)
            proj_list = self.driver.list_projects(local_hints)
            local_hints = copy.deepcopy(hints)
            domains = self.driver.list_domains(local_hints)
            for domain in domains:
                proj_list.append(get_project_from_domain(domain))
            return proj_list

    def list_projects_from_ids(self, project_ids):
        return [self.get_project(id) for id in project_ids]

    def list_project_ids_from_domain_ids(self, domain_ids):
        return self.driver.list_project_ids_from_domain_ids(domain_ids)

    def list_projects_in_domain(self, domain_id):
            return self.driver.list_projects_in_domain(domain_id)

    def get_project(self, project_id):
        try:
            domain_ref = self.driver.get_domain(project_id)
            return get_project_from_domain(domain_ref)
        except exception.DomainNotFound:
            return self.driver.get_project(project_id)

    def _is_domain(self, project_id):
        ref = self.get_project(project_id)
        return ref.get('is_domain', False)

    def update_project(self, project_id, project):
        if self._is_domain(project_id):
            update_domain = self._get_domain_from_project(project)
            domain_ref = self.driver.update_domain(project_id, update_domain)
            return get_project_from_domain(domain_ref)
        else:
            return self.driver.update_project(project_id, project)

    def delete_project(self, project_id):
        if self._is_domain(project_id):
            try:
                self.driver.delete_domain(project_id)
            except exception.DomainNotFound:
                raise exception.ProjectNotFound(project_id=project_id)
        else:
            self.driver.delete_project(project_id)

    def delete_projects_from_ids(self, project_ids):
        raise exception.NotImplemented()  # pragma: no cover

    def list_project_parents(self, project_id):
        """List a project's ancestors.

        The current manager expects the ancestor tree to end with the project
        acting as the domain (since that's now the top of the tree), but a
        legacy driver will not have that top project in their projects table,
        since it's still in the domain table. Hence we lift the algorithm for
        traversing up the tree from the driver to here, so that our version of
        get_project() is called, which will fetch the "project" from the right
        table.

        """
        project = self.get_project(project_id)
        parents = []
        examined = set()
        while project.get('parent_id') is not None:
            if project['id'] in examined:
                msg = _LE('Circular reference or a repeated '
                          'entry found in projects hierarchy - '
                          '%(project_id)s.')
                LOG.error(msg, {'project_id': project['id']})
                return

            examined.add(project['id'])
            parent_project = self.get_project(project['parent_id'])
            parents.append(parent_project)
            project = parent_project
        return parents

    def list_projects_in_subtree(self, project_id):
        return self.driver.list_projects_in_subtree(project_id)

    def is_leaf_project(self, project_id):
        return self.driver.is_leaf_project(project_id)

    def list_projects_acting_as_domain(self, hints):
        refs = self.driver.list_domains(hints)
        return [get_project_from_domain(p) for p in refs]
