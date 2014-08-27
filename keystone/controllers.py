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

from keystone.common import extension
from keystone.common import wsgi
from keystone import exception
from keystone.openstack.common import log


LOG = log.getLogger(__name__)

MEDIA_TYPE_JSON = 'application/vnd.openstack.identity-%s+json'
MEDIA_TYPE_XML = 'application/vnd.openstack.identity-%s+xml'

_VERSIONS = []


class Extensions(wsgi.Application):
    """Base extensions controller to be extended by public and admin API's."""

    # extend in subclass to specify the set of extensions
    @property
    def extensions(self):
        return None

    def get_extensions_info(self, context):
        return {'extensions': {'values': self.extensions.values()}}

    def get_extension_info(self, context, extension_alias):
        try:
            return {'extension': self.extensions[extension_alias]}
        except KeyError:
            raise exception.NotFound(target=extension_alias)


class AdminExtensions(Extensions):
    @property
    def extensions(self):
        return extension.ADMIN_EXTENSIONS


class PublicExtensions(Extensions):
    @property
    def extensions(self):
        return extension.PUBLIC_EXTENSIONS


def register_version(version):
    _VERSIONS.append(version)


class MimeTypes:
    JSON = 'application/json'
    JSON_HOME = 'application/json-home'


def v3_mime_type_best_match(context):

    # accept_header is a WebOb MIMEAccept object so supports best_match.
    accept_header = context['accept_header']

    if not accept_header:
        return MimeTypes.JSON

    SUPPORTED_TYPES = [MimeTypes.JSON, MimeTypes.JSON_HOME]
    return accept_header.best_match(SUPPORTED_TYPES)


class Version(wsgi.Application):

    def __init__(self, version_type, routers=None):
        self.endpoint_url_type = version_type
        self._routers = routers

        super(Version, self).__init__()

    def _get_identity_url(self, context, version):
        """Returns a URL to keystone's own endpoint."""
        url = self.base_url(context, self.endpoint_url_type)
        return '%s/%s/' % (url, version)

    def _get_versions_list(self, context):
        """The list of versions is dependent on the context."""
        versions = {}
        if 'v2.0' in _VERSIONS:
            versions['v2.0'] = {
                'id': 'v2.0',
                'status': 'stable',
                'updated': '2014-04-17T00:00:00Z',
                'links': [
                    {
                        'rel': 'self',
                        'href': self._get_identity_url(context, 'v2.0'),
                    }, {
                        'rel': 'describedby',
                        'type': 'text/html',
                        'href': 'http://docs.openstack.org/'
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
                        'href': self._get_identity_url(context, 'v3'),
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

    def _get_json_home_v3(self):

        def all_resources():
            for router in self._routers:
                for resource in router.v3_resources:
                    yield resource

        return {
            'resources': dict(all_resources())
        }

    def get_version_v3(self, context):
        versions = self._get_versions_list(context)
        if 'v3' in _VERSIONS:
            req_mime_type = v3_mime_type_best_match(context)

            if req_mime_type == MimeTypes.JSON_HOME:
                return wsgi.render_response(
                    body=self._get_json_home_v3(),
                    headers=(('Content-Type', MimeTypes.JSON_HOME),))

            return wsgi.render_response(body={
                'version': versions['v3']
            })
        else:
            raise exception.VersionNotFound(version='v3')
