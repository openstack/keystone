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

import keystone.conf
from keystone import exception


CONF = keystone.conf.CONF


def get_project_from_domain(domain_ref):
    """Create a project ref from the provided domain ref."""
    project_ref = domain_ref.copy()
    project_ref['is_domain'] = True
    project_ref['domain_id'] = None
    project_ref['parent_id'] = None

    return project_ref


# The provided SQL driver uses a special value to represent a domain_id of
# None. See comment in Project class of resource/backends/sql.py for more
# details.
NULL_DOMAIN_ID = '<<keystone.domain.root>>'


class ResourceDriverBase(object, metaclass=abc.ABCMeta):

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

    def check_project_depth(self, max_depth):
        """Check the projects depth in the backend whether exceed the limit.

        :param max_depth: the limit depth that project depth should not exceed.
        :type max_depth: integer

        :returns: the exceeded project's id or None if no exceeding.

        """
        raise exception.NotImplemented()  # pragma: no cover
