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

from keystone.common import wsgi
from keystone import catalog
from keystone import exception


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


class Version(wsgi.Application):
    def __init__(self, version_type):
        self.catalog_api = catalog.Manager()
        self.url_key = '%sURL' % version_type

        super(Version, self).__init__()

    def _get_identity_url(self, context):
        catalog_ref = self.catalog_api.get_catalog(context=context,
                                                   user_id=None,
                                                   tenant_id=None)
        for region, region_ref in catalog_ref.iteritems():
            for service, service_ref in region_ref.iteritems():
                if service == 'identity':
                    return service_ref[self.url_key]

        raise exception.NotImplemented()

    def _get_versions_list(self, context):
        """The list of versions is dependent on the context."""
        identity_url = self._get_identity_url(context)
        if not identity_url.endswith('/'):
            identity_url = identity_url + '/'

        versions = {}
        versions['v2.0'] = {
            'id': 'v2.0',
            'status': 'beta',
            'updated': '2011-11-19T00:00:00Z',
            'links': [
                {
                    'rel': 'self',
                    'href': identity_url,
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
                    'type': 'application/vnd.openstack.identity-v2.0'
                            '+json'
                }, {
                    'base': 'application/xml',
                    'type': 'application/vnd.openstack.identity-v2.0'
                            '+xml'
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

    def get_version(self, context):
        versions = self._get_versions_list(context)
        return wsgi.render_response(body={
            'version': versions['v2.0']
        })
