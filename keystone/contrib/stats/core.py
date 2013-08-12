# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
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

from keystone.common import extension
from keystone.common import manager
from keystone.common import wsgi
from keystone import config
from keystone import exception
from keystone import identity
from keystone.openstack.common import log as logging
from keystone import policy
from keystone import token


CONF = config.CONF
LOG = logging.getLogger(__name__)

extension_data = {
    'name': 'Openstack Keystone Stats API',
    'namespace': 'http://docs.openstack.org/identity/api/ext/'
                 'OS-STATS/v1.0',
    'alias': 'OS-STATS',
    'updated': '2013-07-07T12:00:0-00:00',
    'description': 'Openstack Keystone Stats API.',
    'links': [
        {
            'rel': 'describedby',
            # TODO(ayoung): needs a description
            'type': 'text/html',
            'href': 'https://github.com/openstack/identity-api',
        }
    ]}
extension.register_admin_extension(extension_data['alias'], extension_data)


class Manager(manager.Manager):
    """Default pivot point for the Stats backend.

    See :mod:`keystone.common.manager.Manager` for more details on how this
    dynamically calls the backend.

    """

    def __init__(self):
        super(Manager, self).__init__(CONF.stats.driver)


class Driver(object):
    """Interface description for a Stats driver."""

    def get_stats(self, api):
        """Retrieve all previously-captured statistics for an interface."""
        raise exception.NotImplemented()

    def set_stats(self, api, stats_ref):
        """Update statistics for an interface."""
        raise exception.NotImplemented()

    def increment_stat(self, api, category, value):
        """Increment the counter for an individual statistic."""
        raise exception.NotImplemented()


class StatsExtension(wsgi.ExtensionRouter):
    """Reports on previously-collected request/response statistics."""

    def add_routes(self, mapper):
        stats_controller = StatsController()

        mapper.connect(
            '/OS-STATS/stats',
            controller=stats_controller,
            action='get_stats',
            conditions=dict(method=['GET']))
        mapper.connect(
            '/OS-STATS/stats',
            controller=stats_controller,
            action='reset_stats',
            conditions=dict(method=['DELETE']))


class StatsController(wsgi.Application):
    def __init__(self):
        self.identity_api = identity.Manager()
        self.policy_api = policy.Manager()
        self.stats_api = Manager()
        self.token_api = token.Manager()
        super(StatsController, self).__init__()

    def get_stats(self, context):
        self.assert_admin(context)
        return {
            'OS-STATS:stats': [
                {
                    'type': 'identity',
                    'api': 'admin',
                    'extra': self.stats_api.get_stats('admin'),
                },
                {
                    'type': 'identity',
                    'api': 'public',
                    'extra': self.stats_api.get_stats('public'),
                },
            ]
        }

    def reset_stats(self, context):
        self.assert_admin(context)
        self.stats_api.set_stats('public', dict())
        self.stats_api.set_stats('admin', dict())


class StatsMiddleware(wsgi.Middleware):
    """Monitors various request/response attribute statistics."""

    request_attributes = ['application_url',
                          'method',
                          'path',
                          'path_qs',
                          'remote_addr']

    response_attributes = ['status_int']

    def __init__(self, *args, **kwargs):
        self.stats_api = Manager()
        return super(StatsMiddleware, self).__init__(*args, **kwargs)

    def _resolve_api(self, host):
        if host.endswith(':%s' % (CONF.admin_port)):
            return 'admin'
        elif host.endswith(':%s' % (CONF.public_port)):
            return 'public'
        else:
            return host

    def capture_stats(self, host, obj, attributes):
        """Collect each attribute from the given object."""
        for attribute in attributes:
            self.stats_api.increment_stat(
                self._resolve_api(host), attribute, getattr(obj, attribute))

    def process_request(self, request):
        """Monitor incoming request attributes."""
        self.capture_stats(request.host, request, self.request_attributes)

    def process_response(self, request, response):
        """Monitor outgoing response attributes."""
        self.capture_stats(request.host, response, self.response_attributes)
        return response
