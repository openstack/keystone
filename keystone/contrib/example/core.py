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

"""Main entry point into this Example service."""

from oslo_log import log

from keystone.common import dependency
from keystone.common import manager
from keystone import exception
from keystone.i18n import _LI
from keystone import notifications


LOG = log.getLogger(__name__)


@notifications.listener  # NOTE(dstanek): only needed if using event_callbacks
@dependency.provider('example_api')
class ExampleManager(manager.Manager):
    """Default pivot point for this Example backend.

    See :mod:`keystone.common.manager.Manager` for more details on
    how this dynamically calls the backend.

    """

    driver_namespace = 'keystone.example'

    def __init__(self):
        # The following is an example of event callbacks. In this setup,
        # ExampleManager's data model is depended on project's data model.
        # It must create additional aggregates when a new project is created,
        # and it must cleanup data related to the project whenever a project
        # has been deleted.
        #
        # In this example, the project_deleted_callback will be invoked
        # whenever a project has been deleted. Similarly, the
        # project_created_callback will be invoked whenever a new project is
        # created.

        # This information is used when the @notifications.listener decorator
        # acts on the class.
        self.event_callbacks = {
            notifications.ACTIONS.deleted: {
                'project': [self.project_deleted_callback],
            },
            notifications.ACTIONS.created: {
                'project': [self.project_created_callback],
            },
        }
        super(ExampleManager, self).__init__(
            'keystone.contrib.example.core.ExampleDriver')

    def project_deleted_callback(self, service, resource_type, operation,
                                 payload):
        # The code below is merely an example.
        msg = _LI('Received the following notification: service %(service)s, '
                  'resource_type: %(resource_type)s, operation %(operation)s '
                  'payload %(payload)s')
        LOG.info(msg, {'service': service, 'resource_type': resource_type,
                       'operation': operation, 'payload': payload})

    def project_created_callback(self, service, resource_type, operation,
                                 payload):
        # The code below is merely an example.
        msg = _LI('Received the following notification: service %(service)s, '
                  'resource_type: %(resource_type)s, operation %(operation)s '
                  'payload %(payload)s')
        LOG.info(msg, {'service': service, 'resource_type': resource_type,
                       'operation': operation, 'payload': payload})


class ExampleDriver(object):
    """Interface description for Example driver."""

    def do_something(self, data):
        """Do something

        :param data: example data
        :type data: string
        :raises: keystone.exception,
        :returns: None.

        """
        raise exception.NotImplemented()
