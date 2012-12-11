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

import routes

from keystone import catalog
from keystone.common import logging
from keystone.common import wsgi
from keystone import exception
from keystone import identity
from keystone import policy
from keystone import token


LOG = logging.getLogger(__name__)


class V3Router(wsgi.ComposingRouter):
    def crud_routes(self, mapper, controller, collection_key, key):
        collection_path = '/%(collection_key)s' % {
            'collection_key': collection_key}
        entity_path = '/%(collection_key)s/{%(key)s_id}' % {
            'collection_key': collection_key,
            'key': key}

        mapper.connect(
            collection_path,
            controller=controller,
            action='create_%s' % key,
            conditions=dict(method=['POST']))
        mapper.connect(
            collection_path,
            controller=controller,
            action='list_%s' % collection_key,
            conditions=dict(method=['GET']))
        mapper.connect(
            entity_path,
            controller=controller,
            action='get_%s' % key,
            conditions=dict(method=['GET']))
        mapper.connect(
            entity_path,
            controller=controller,
            action='update_%s' % key,
            conditions=dict(method=['PATCH']))
        mapper.connect(
            entity_path,
            controller=controller,
            action='delete_%s' % key,
            conditions=dict(method=['DELETE']))

    def __init__(self):
        mapper = routes.Mapper()

        apis = dict(
            catalog_api=catalog.Manager(),
            identity_api=identity.Manager(),
            policy_api=policy.Manager(),
            token_api=token.Manager())

        # Catalog

        self.crud_routes(
            mapper,
            catalog.controllers.ServiceV3(**apis),
            'services',
            'service')

        self.crud_routes(
            mapper,
            catalog.controllers.EndpointV3(**apis),
            'endpoints',
            'endpoint')

        # Identity

        self.crud_routes(
            mapper,
            identity.controllers.DomainV3(**apis),
            'domains',
            'domain')

        project_controller = identity.controllers.ProjectV3(**apis)
        self.crud_routes(
            mapper,
            project_controller,
            'projects',
            'project')
        mapper.connect(
            '/users/{user_id}/projects',
            controller=project_controller,
            action='list_user_projects',
            conditions=dict(method=['GET']))

        self.crud_routes(
            mapper,
            identity.controllers.UserV3(**apis),
            'users',
            'user')

        self.crud_routes(
            mapper,
            identity.controllers.CredentialV3(**apis),
            'credentials',
            'credential')

        role_controller = identity.controllers.RoleV3(**apis)
        self.crud_routes(
            mapper,
            role_controller,
            'roles',
            'role')
        mapper.connect(
            '/projects/{project_id}/users/{user_id}/roles/{role_id}',
            controller=role_controller,
            action='create_grant',
            conditions=dict(method=['PUT']))
        mapper.connect(
            '/projects/{project_id}/users/{user_id}/roles/{role_id}',
            controller=role_controller,
            action='check_grant',
            conditions=dict(method=['HEAD']))
        mapper.connect(
            '/projects/{project_id}/users/{user_id}/roles',
            controller=role_controller,
            action='list_grants',
            conditions=dict(method=['GET']))
        mapper.connect(
            '/projects/{project_id}/users/{user_id}/roles/{role_id}',
            controller=role_controller,
            action='revoke_grant',
            conditions=dict(method=['DELETE']))
        mapper.connect(
            '/domains/{domain_id}/users/{user_id}/roles/{role_id}',
            controller=role_controller,
            action='create_grant',
            conditions=dict(method=['PUT']))
        mapper.connect(
            '/domains/{domain_id}/users/{user_id}/roles/{role_id}',
            controller=role_controller,
            action='check_grant',
            conditions=dict(method=['HEAD']))
        mapper.connect(
            '/domains/{domain_id}/users/{user_id}/roles',
            controller=role_controller,
            action='list_grants',
            conditions=dict(method=['GET']))
        mapper.connect(
            '/domains/{domain_id}/users/{user_id}/roles/{role_id}',
            controller=role_controller,
            action='revoke_grant',
            conditions=dict(method=['DELETE']))

        # Policy

        policy_controller = policy.controllers.PolicyV3(**apis)
        self.crud_routes(
            mapper,
            policy_controller,
            'policies',
            'policy')

        # Token

        """
        # v2.0 LEGACY
        mapper.connect('/tokens/{token_id}',
                       controller=auth_controller,
                       action='validate_token',
                       conditions=dict(method=['GET']))
        mapper.connect('/tokens/{token_id}',
                       controller=auth_controller,
                       action='validate_token_head',
                       conditions=dict(method=['HEAD']))
        mapper.connect('/tokens/{token_id}',
                       controller=auth_controller,
                       action='delete_token',
                       conditions=dict(method=['DELETE']))
        mapper.connect('/tokens/{token_id}/endpoints',
                       controller=auth_controller,
                       action='endpoints',
                       conditions=dict(method=['GET']))
        """

        super(V3Router, self).__init__(mapper, [])


class AdminRouter(wsgi.ComposingRouter):
    def __init__(self):
        mapper = routes.Mapper()

        apis = dict(
            catalog_api=catalog.Manager(),
            identity_api=identity.Manager(),
            policy_api=policy.Manager(),
            token_api=token.Manager())

        version_controller = VersionController('admin')
        mapper.connect('/',
                       controller=version_controller,
                       action='get_version')

        # Token Operations
        auth_controller = token.controllers.Auth(**apis)
        mapper.connect('/tokens',
                       controller=auth_controller,
                       action='authenticate',
                       conditions=dict(method=['POST']))
        mapper.connect('/tokens/revoked',
                       controller=auth_controller,
                       action='revocation_list',
                       conditions=dict(method=['GET']))
        mapper.connect('/tokens/{token_id}',
                       controller=auth_controller,
                       action='validate_token',
                       conditions=dict(method=['GET']))
        mapper.connect('/tokens/{token_id}',
                       controller=auth_controller,
                       action='validate_token_head',
                       conditions=dict(method=['HEAD']))
        mapper.connect('/tokens/{token_id}',
                       controller=auth_controller,
                       action='delete_token',
                       conditions=dict(method=['DELETE']))
        mapper.connect('/tokens/{token_id}/endpoints',
                       controller=auth_controller,
                       action='endpoints',
                       conditions=dict(method=['GET']))

        # Certificates used to verify auth tokens
        mapper.connect('/certificates/ca',
                       controller=auth_controller,
                       action='ca_cert',
                       conditions=dict(method=['GET']))

        mapper.connect('/certificates/signing',
                       controller=auth_controller,
                       action='signing_cert',
                       conditions=dict(method=['GET']))

        # Miscellaneous Operations
        extensions_controller = AdminExtensionsController()
        mapper.connect('/extensions',
                       controller=extensions_controller,
                       action='get_extensions_info',
                       conditions=dict(method=['GET']))
        mapper.connect('/extensions/{extension_alias}',
                       controller=extensions_controller,
                       action='get_extension_info',
                       conditions=dict(method=['GET']))
        identity_router = identity.routers.Admin()
        routers = [identity_router]
        super(AdminRouter, self).__init__(mapper, routers)


class PublicRouter(wsgi.ComposingRouter):
    def __init__(self):
        mapper = routes.Mapper()

        apis = dict(
            catalog_api=catalog.Manager(),
            identity_api=identity.Manager(),
            policy_api=policy.Manager(),
            token_api=token.Manager())

        version_controller = VersionController('public')
        mapper.connect('/',
                       controller=version_controller,
                       action='get_version')

        # Token Operations
        auth_controller = token.controllers.Auth(**apis)
        mapper.connect('/tokens',
                       controller=auth_controller,
                       action='authenticate',
                       conditions=dict(method=['POST']))

        mapper.connect('/certificates/ca',
                       controller=auth_controller,
                       action='ca_cert',
                       conditions=dict(method=['GET']))

        mapper.connect('/certificates/signing',
                       controller=auth_controller,
                       action='signing_cert',
                       conditions=dict(method=['GET']))

        # Miscellaneous
        extensions_controller = PublicExtensionsController()
        mapper.connect('/extensions',
                       controller=extensions_controller,
                       action='get_extensions_info',
                       conditions=dict(method=['GET']))
        mapper.connect('/extensions/{extension_alias}',
                       controller=extensions_controller,
                       action='get_extension_info',
                       conditions=dict(method=['GET']))

        identity_router = identity.routers.Public()
        routers = [identity_router]

        super(PublicRouter, self).__init__(mapper, routers)


class PublicVersionRouter(wsgi.ComposingRouter):
    def __init__(self):
        mapper = routes.Mapper()
        version_controller = VersionController('public')
        mapper.connect('/',
                       controller=version_controller,
                       action='get_versions')
        routers = []
        super(PublicVersionRouter, self).__init__(mapper, routers)


class AdminVersionRouter(wsgi.ComposingRouter):
    def __init__(self):
        mapper = routes.Mapper()
        version_controller = VersionController('admin')
        mapper.connect('/',
                       controller=version_controller,
                       action='get_versions')
        routers = []
        super(AdminVersionRouter, self).__init__(mapper, routers)


class VersionController(wsgi.Application):
    def __init__(self, version_type):
        self.catalog_api = catalog.Manager()
        self.url_key = '%sURL' % version_type

        super(VersionController, self).__init__()

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


class NoopController(wsgi.Application):
    def __init__(self):
        super(NoopController, self).__init__()

    def noop(self, context):
        return {}


class ExtensionsController(wsgi.Application):
    """Base extensions controller to be extended by public and admin API's."""

    def __init__(self, extensions=None):
        super(ExtensionsController, self).__init__()

        self.extensions = extensions or {}

    def get_extensions_info(self, context):
        return {'extensions': {'values': self.extensions.values()}}

    def get_extension_info(self, context, extension_alias):
        try:
            return {'extension': self.extensions[extension_alias]}
        except KeyError:
            raise exception.NotFound(target=extension_alias)


class PublicExtensionsController(ExtensionsController):
    pass


class AdminExtensionsController(ExtensionsController):
    def __init__(self, *args, **kwargs):
        super(AdminExtensionsController, self).__init__(*args, **kwargs)

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


@logging.fail_gracefully
def public_app_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    return PublicRouter()


@logging.fail_gracefully
def admin_app_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    return AdminRouter()


@logging.fail_gracefully
def public_version_app_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    return PublicVersionRouter()


@logging.fail_gracefully
def admin_version_app_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    return AdminVersionRouter()


@logging.fail_gracefully
def v3_app_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    return V3Router()
