# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 OpenStack Foundation
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

import six

from keystone.common import dependency
from keystone.common import extension
from keystone.common import manager
from keystone import config
from keystone import exception
from keystone.openstack.common import log as logging


CONF = config.CONF
LOG = logging.getLogger(__name__)

extension_data = {
    'name': 'Openstack Keystone Endpoint Filter API',
    'namespace': 'http://docs.openstack.org/identity/api/ext/'
                 'OS-EP-FILTER/v1.0',
    'alias': 'OS-EP-FILTER',
    'updated': '2013-07-23T12:00:0-00:00',
    'description': 'Openstack Keystone Endpoint Filter API.',
    'links': [
        {
            'rel': 'describedby',
            # TODO(ayoung): needs a description
            'type': 'text/html',
            'href': 'https://github.com/openstack/identity-api/blob/master'
                    '/openstack-identity-api/v3/src/markdown/'
                    'identity-api-v3-os-ep-filter-ext.md',
        }
    ]}
extension.register_admin_extension(extension_data['alias'], extension_data)


@dependency.provider('endpoint_filter_api')
class Manager(manager.Manager):
    """Default pivot point for the Endpoint Filter backend.

    See :mod:`keystone.common.manager.Manager` for more details on how this
    dynamically calls the backend.

    """

    def __init__(self):
        super(Manager, self).__init__(CONF.endpoint_filter.driver)


@six.add_metaclass(abc.ABCMeta)
class Driver(object):
    """Interface description for an Endpoint Filter driver."""

    @abc.abstractmethod
    def add_endpoint_to_project(self, endpoint_id, project_id):
        """Creates an endpoint to project association.

        :param endpoint_id: identity of endpoint to associate
        :type endpoint_id: string
        :param project_id: identity of the project to be associated with
        :type project_id: string
        :raises: keystone.exception.Conflict,
        :returns: None.

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def remove_endpoint_from_project(self, endpoint_id, project_id):
        """Removes an endpoint to project association.

        :param endpoint_id: identity of endpoint to remove
        :type endpoint_id: string
        :param project_id: identity of the project associated with
        :type project_id: string
        :raises: exception.NotFound
        :returns: None.

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def check_endpoint_in_project(self, endpoint_id, project_id):
        """Checks if an endpoint is associated with a project.

        :param endpoint_id: identity of endpoint to check
        :type endpoint_id: string
        :param project_id: identity of the project associated with
        :type project_id: string
        :raises: exception.NotFound
        :returns: None.

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def list_endpoints_for_project(self, project_id):
        """List all endpoints associated with a project.

        :param project_id: identity of the project to check
        :type project_id: string
        :returns: a list of identity endpoint ids or an empty list.

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def list_projects_for_endpoint(self, endpoint_id):
        """List all projects associated with an endpoint.

        :param endpoint_id: identity of endpoint to check
        :type endpoint_id: string
        :returns: a list of projects or an empty list.

        """
        raise exception.NotImplemented()
