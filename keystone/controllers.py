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

from keystone.common import logging
from keystone.common import wsgi
from keystone import config
from keystone import exception


LOG = logging.getLogger(__name__)
CONF = config.CONF

MEDIA_TYPE_JSON = 'application/vnd.openstack.identity-%s+json'
MEDIA_TYPE_XML = 'application/vnd.openstack.identity-%s+xml'

_VERSIONS = []


class Extensions(wsgi.Application):
    """Base extensions controller to be extended by public and admin API's."""

    def __init__(self, extensions=None):
        super(Extensions, self).__init__()

        self.extensions = extensions or {}

    def get_extensions_info(self, context):
        return {'extensions': {'values': self.extensions.values()}}

    def get_extension_info(self, context, extension_alias):
        try:
            return {'extension': self.extensions[extension_alias]}
        except KeyError:
            raise exception.NotFound(target=extension_alias)


class AdminExtensions(Extensions):
    def __init__(self, *args, **kwargs):
        super(AdminExtensions, self).__init__(*args, **kwargs)

        # TODO(dolph): Extensions should obviously provide this information
        #               themselves, but hardcoding it here allows us to match
        #               the API spec in the short term with minimal complexity.
        self.extensions['OS-KSADM'] = {
            'name': 'Openstack Keystone Admin',
            'namespace': 'http://docs.openstack.org/identity/api/ext/'
                         'OS-KSADM/v1.0',
            'alias': 'OS-KSADM',
            'updated': '2011-08-19T13:25:27-06:00',
            'description': 'Openstack extensions to Keystone v2.0 API '
                           'enabling Admin Operations.',
            'links': [
                {
                    'rel': 'describedby',
                    # TODO(dolph): link needs to be revised after
                    #              bug 928059 merges
                    'type': 'text/html',
                    'href': 'https://github.com/openstack/identity-api',
                }
            ]
        }


class PublicExtensions(Extensions):
    pass


def register_version(version):
    _VERSIONS.append(version)


class Version(wsgi.Application):

    def __init__(self, version_type):
        self.endpoint_url_type = version_type

        super(Version, self).__init__()

    def _get_identity_url(self, version='v2.0'):
        """Returns a URL to keystone's own endpoint."""
        url = CONF['%s_endpoint' % self.endpoint_url_type] % CONF
        if url[-1] != '/':
            url += '/'
        return '%s%s/' % (url, version)

    def _get_versions_list(self, context):
        """The list of versions is dependent on the context."""
        versions = {}
        if 'v2.0' in _VERSIONS:
            versions['v2.0'] = {
                'id': 'v2.0',
                'status': 'stable',
                'updated': '2013-03-06T00:00:00Z',
                'links': [
                    {
                        'rel': 'self',
                        'href': self._get_identity_url(version='v2.0'),
                    }, {
                        'rel': 'describedby',
                        'type': 'text/html',
                        'href': 'http://docs.openstack.org/api/openstack-'
                                'identity-service/2.0/content/'
                    }, {
                        'rel': 'describedby',
                        'type': 'application/pdf',
                        'href': 'http://docs.openstack.org/api/openstack-'
                                'identity-service/2.0/identity-dev-guide-'
                                '2.0.pdf'
                    }
                ],
                'media-types': [
                    {
                        'base': 'application/json',
                        'type': MEDIA_TYPE_JSON % 'v2.0'
                    }, {
                        'base': 'application/xml',
                        'type': MEDIA_TYPE_XML % 'v2.0'
                    }
                ]
            }

        if 'v3' in _VERSIONS:
            versions['v3'] = {
                'id': 'v3.0',
                'status': 'stable',
                'updated': '2013-03-06T00:00:00Z',
                'links': [
                    {
                        'rel': 'self',
                        'href': self._get_identity_url(version='v3'),
                    }
                ],
                'media-types': [
                    {
                        'base': 'application/json',
                        'type': MEDIA_TYPE_JSON % 'v3'
                    }, {
                        'base': 'application/xml',
                        'type': MEDIA_TYPE_XML % 'v3'
                    }
                ]
            }

        return versions

    def get_versions(self, context):
        versions = self._get_versions_list(context)
        return wsgi.render_response(status=(300, 'Multiple Choices'), body={
            'versions': {
                'values': versions.values()
            }
        })

    def get_version_v2(self, context):
        versions = self._get_versions_list(context)
        if 'v2.0' in _VERSIONS:
            return wsgi.render_response(body={
                'version': versions['v2.0']
            })
        else:
            raise exception.VersionNotFound(version='v2.0')

    def get_version_v3(self, context):
        versions = self._get_versions_list(context)
        if 'v3' in _VERSIONS:
            return wsgi.render_response(body={
                'version': versions['v3']
            })
        else:
            raise exception.VersionNotFound(version='v3')
