# Copyright 2012 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import copy
import functools
import random

import mock
from oslo.serialization import jsonutils
from testtools import matchers as tt_matchers

from keystone.common import json_home
from keystone import config
from keystone import controllers
from keystone import tests
from keystone.tests import matchers


CONF = config.CONF

v2_MEDIA_TYPES = [
    {
        "base": "application/json",
        "type": "application/"
                "vnd.openstack.identity-v2.0+json"
    }, {
        "base": "application/xml",
        "type": "application/"
                "vnd.openstack.identity-v2.0+xml"
    }
]

v2_HTML_DESCRIPTION = {
    "rel": "describedby",
    "type": "text/html",
    "href": "http://docs.openstack.org/"
}


v2_EXPECTED_RESPONSE = {
    "id": "v2.0",
    "status": "stable",
    "updated": "2014-04-17T00:00:00Z",
    "links": [
        {
            "rel": "self",
            "href": "",     # Will get filled in after initialization
        },
        v2_HTML_DESCRIPTION
    ],
    "media-types": v2_MEDIA_TYPES
}

v2_VERSION_RESPONSE = {
    "version": v2_EXPECTED_RESPONSE
}

v3_MEDIA_TYPES = [
    {
        "base": "application/json",
        "type": "application/"
                "vnd.openstack.identity-v3+json"
    }, {
        "base": "application/xml",
        "type": "application/"
                "vnd.openstack.identity-v3+xml"
    }
]

v3_EXPECTED_RESPONSE = {
    "id": "v3.0",
    "status": "stable",
    "updated": "2013-03-06T00:00:00Z",
    "links": [
        {
            "rel": "self",
            "href": "",     # Will get filled in after initialization
        }
    ],
    "media-types": v3_MEDIA_TYPES
}

v3_VERSION_RESPONSE = {
    "version": v3_EXPECTED_RESPONSE
}

VERSIONS_RESPONSE = {
    "versions": {
        "values": [
            v3_EXPECTED_RESPONSE,
            v2_EXPECTED_RESPONSE
        ]
    }
}

_build_ec2tokens_relation = functools.partial(
    json_home.build_v3_extension_resource_relation, extension_name='OS-EC2',
    extension_version='1.0')

REVOCATIONS_RELATION = json_home.build_v3_extension_resource_relation(
    'OS-PKI', '1.0', 'revocations')

_build_simple_cert_relation = functools.partial(
    json_home.build_v3_extension_resource_relation,
    extension_name='OS-SIMPLE-CERT', extension_version='1.0')

_build_trust_relation = functools.partial(
    json_home.build_v3_extension_resource_relation, extension_name='OS-TRUST',
    extension_version='1.0')

TRUST_ID_PARAMETER_RELATION = json_home.build_v3_extension_parameter_relation(
    'OS-TRUST', '1.0', 'trust_id')

V3_JSON_HOME_RESOURCES_INHERIT_DISABLED = {
    json_home.build_v3_resource_relation('auth_tokens'): {
        'href': '/auth/tokens'},
    json_home.build_v3_resource_relation('auth_catalog'): {
        'href': '/auth/catalog'},
    json_home.build_v3_resource_relation('auth_projects'): {
        'href': '/auth/projects'},
    json_home.build_v3_resource_relation('auth_domains'): {
        'href': '/auth/domains'},
    json_home.build_v3_resource_relation('credential'): {
        'href-template': '/credentials/{credential_id}',
        'href-vars': {
            'credential_id':
            json_home.build_v3_parameter_relation('credential_id')}},
    json_home.build_v3_resource_relation('credentials'): {
        'href': '/credentials'},
    json_home.build_v3_resource_relation('domain'): {
        'href-template': '/domains/{domain_id}',
        'href-vars': {'domain_id': json_home.Parameters.DOMAIN_ID, }},
    json_home.build_v3_resource_relation('domain_group_role'): {
        'href-template':
        '/domains/{domain_id}/groups/{group_id}/roles/{role_id}',
        'href-vars': {
            'domain_id': json_home.Parameters.DOMAIN_ID,
            'group_id': json_home.Parameters.GROUP_ID,
            'role_id': json_home.Parameters.ROLE_ID, }},
    json_home.build_v3_resource_relation('domain_group_roles'): {
        'href-template': '/domains/{domain_id}/groups/{group_id}/roles',
        'href-vars': {
            'domain_id': json_home.Parameters.DOMAIN_ID,
            'group_id': json_home.Parameters.GROUP_ID}},
    json_home.build_v3_resource_relation('domain_user_role'): {
        'href-template':
        '/domains/{domain_id}/users/{user_id}/roles/{role_id}',
        'href-vars': {
            'domain_id': json_home.Parameters.DOMAIN_ID,
            'role_id': json_home.Parameters.ROLE_ID,
            'user_id': json_home.Parameters.USER_ID, }},
    json_home.build_v3_resource_relation('domain_user_roles'): {
        'href-template': '/domains/{domain_id}/users/{user_id}/roles',
        'href-vars': {
            'domain_id': json_home.Parameters.DOMAIN_ID,
            'user_id': json_home.Parameters.USER_ID, }},
    json_home.build_v3_resource_relation('domains'): {'href': '/domains'},
    json_home.build_v3_resource_relation('endpoint'): {
        'href-template': '/endpoints/{endpoint_id}',
        'href-vars': {
            'endpoint_id':
            json_home.build_v3_parameter_relation('endpoint_id'), }},
    json_home.build_v3_resource_relation('endpoints'): {
        'href': '/endpoints'},
    _build_ec2tokens_relation(resource_name='ec2tokens'): {
        'href': '/ec2tokens'},
    _build_ec2tokens_relation(resource_name='user_credential'): {
        'href-template': '/users/{user_id}/credentials/OS-EC2/{credential_id}',
        'href-vars': {
            'credential_id': json_home.build_v3_extension_parameter_relation(
                'OS-EC2', '1.0', 'credential_id'),
            'user_id': json_home.Parameters.USER_ID, }},
    _build_ec2tokens_relation(resource_name='user_credentials'): {
        'href-template': '/users/{user_id}/credentials/OS-EC2',
        'href-vars': {
            'user_id': json_home.Parameters.USER_ID, }},
    REVOCATIONS_RELATION: {
        'href': '/auth/tokens/OS-PKI/revoked'},
    'http://docs.openstack.org/api/openstack-identity/3/ext/OS-REVOKE/1.0/rel/'
    'events': {
        'href': '/OS-REVOKE/events'},
    _build_simple_cert_relation(resource_name='ca_certificate'): {
        'href': '/OS-SIMPLE-CERT/ca'},
    _build_simple_cert_relation(resource_name='certificates'): {
        'href': '/OS-SIMPLE-CERT/certificates'},
    _build_trust_relation(resource_name='trust'):
    {
        'href-template': '/OS-TRUST/trusts/{trust_id}',
        'href-vars': {'trust_id': TRUST_ID_PARAMETER_RELATION, }},
    _build_trust_relation(resource_name='trust_role'): {
        'href-template': '/OS-TRUST/trusts/{trust_id}/roles/{role_id}',
        'href-vars': {
            'role_id': json_home.Parameters.ROLE_ID,
            'trust_id': TRUST_ID_PARAMETER_RELATION, }},
    _build_trust_relation(resource_name='trust_roles'): {
        'href-template': '/OS-TRUST/trusts/{trust_id}/roles',
        'href-vars': {'trust_id': TRUST_ID_PARAMETER_RELATION, }},
    _build_trust_relation(resource_name='trusts'): {
        'href': '/OS-TRUST/trusts'},
    'http://docs.openstack.org/api/openstack-identity/3/ext/s3tokens/1.0/rel/'
    's3tokens': {
        'href': '/s3tokens'},
    json_home.build_v3_resource_relation('group'): {
        'href-template': '/groups/{group_id}',
        'href-vars': {
            'group_id': json_home.Parameters.GROUP_ID, }},
    json_home.build_v3_resource_relation('group_user'): {
        'href-template': '/groups/{group_id}/users/{user_id}',
        'href-vars': {
            'group_id': json_home.Parameters.GROUP_ID,
            'user_id': json_home.Parameters.USER_ID, }},
    json_home.build_v3_resource_relation('group_users'): {
        'href-template': '/groups/{group_id}/users',
        'href-vars': {'group_id': json_home.Parameters.GROUP_ID, }},
    json_home.build_v3_resource_relation('groups'): {'href': '/groups'},
    json_home.build_v3_resource_relation('policies'): {
        'href': '/policies'},
    json_home.build_v3_resource_relation('policy'): {
        'href-template': '/policies/{policy_id}',
        'href-vars': {
            'policy_id':
            json_home.build_v3_parameter_relation('policy_id'), }},
    json_home.build_v3_resource_relation('project'): {
        'href-template': '/projects/{project_id}',
        'href-vars': {
            'project_id': json_home.Parameters.PROJECT_ID, }},
    json_home.build_v3_resource_relation('project_group_role'): {
        'href-template':
        '/projects/{project_id}/groups/{group_id}/roles/{role_id}',
        'href-vars': {
            'group_id': json_home.Parameters.GROUP_ID,
            'project_id': json_home.Parameters.PROJECT_ID,
            'role_id': json_home.Parameters.ROLE_ID, }},
    json_home.build_v3_resource_relation('project_group_roles'): {
        'href-template': '/projects/{project_id}/groups/{group_id}/roles',
        'href-vars': {
            'group_id': json_home.Parameters.GROUP_ID,
            'project_id': json_home.Parameters.PROJECT_ID, }},
    json_home.build_v3_resource_relation('project_user_role'): {
        'href-template':
        '/projects/{project_id}/users/{user_id}/roles/{role_id}',
        'href-vars': {
            'project_id': json_home.Parameters.PROJECT_ID,
            'role_id': json_home.Parameters.ROLE_ID,
            'user_id': json_home.Parameters.USER_ID, }},
    json_home.build_v3_resource_relation('project_user_roles'): {
        'href-template': '/projects/{project_id}/users/{user_id}/roles',
        'href-vars': {
            'project_id': json_home.Parameters.PROJECT_ID,
            'user_id': json_home.Parameters.USER_ID, }},
    json_home.build_v3_resource_relation('projects'): {
        'href': '/projects'},
    json_home.build_v3_resource_relation('region'): {
        'href-template': '/regions/{region_id}',
        'href-vars': {
            'region_id':
            json_home.build_v3_parameter_relation('region_id'), }},
    json_home.build_v3_resource_relation('regions'): {'href': '/regions'},
    json_home.build_v3_resource_relation('role'): {
        'href-template': '/roles/{role_id}',
        'href-vars': {
            'role_id': json_home.Parameters.ROLE_ID, }},
    json_home.build_v3_resource_relation('role_assignments'): {
        'href': '/role_assignments'},
    json_home.build_v3_resource_relation('roles'): {'href': '/roles'},
    json_home.build_v3_resource_relation('service'): {
        'href-template': '/services/{service_id}',
        'href-vars': {
            'service_id':
            json_home.build_v3_parameter_relation('service_id')}},
    json_home.build_v3_resource_relation('services'): {
        'href': '/services'},
    json_home.build_v3_resource_relation('user'): {
        'href-template': '/users/{user_id}',
        'href-vars': {
            'user_id': json_home.Parameters.USER_ID, }},
    json_home.build_v3_resource_relation('user_change_password'): {
        'href-template': '/users/{user_id}/password',
        'href-vars': {'user_id': json_home.Parameters.USER_ID, }},
    json_home.build_v3_resource_relation('user_groups'): {
        'href-template': '/users/{user_id}/groups',
        'href-vars': {'user_id': json_home.Parameters.USER_ID, }},
    json_home.build_v3_resource_relation('user_projects'): {
        'href-template': '/users/{user_id}/projects',
        'href-vars': {'user_id': json_home.Parameters.USER_ID, }},
    json_home.build_v3_resource_relation('users'): {'href': '/users'},
}


# with os-inherit enabled, there's some more resources.

build_os_inherit_relation = functools.partial(
    json_home.build_v3_extension_resource_relation,
    extension_name='OS-INHERIT', extension_version='1.0')

V3_JSON_HOME_RESOURCES_INHERIT_ENABLED = dict(
    V3_JSON_HOME_RESOURCES_INHERIT_DISABLED)
V3_JSON_HOME_RESOURCES_INHERIT_ENABLED.update(
    (
        (
            build_os_inherit_relation(
                resource_name='domain_user_role_inherited_to_projects'),
            {
                'href-template': '/OS-INHERIT/domains/{domain_id}/users/'
                '{user_id}/roles/{role_id}/inherited_to_projects',
                'href-vars': {
                    'domain_id': json_home.Parameters.DOMAIN_ID,
                    'role_id': json_home.Parameters.ROLE_ID,
                    'user_id': json_home.Parameters.USER_ID,
                },
            }
        ),
        (
            build_os_inherit_relation(
                resource_name='domain_group_role_inherited_to_projects'),
            {
                'href-template': '/OS-INHERIT/domains/{domain_id}/groups/'
                '{group_id}/roles/{role_id}/inherited_to_projects',
                'href-vars': {
                    'domain_id': json_home.Parameters.DOMAIN_ID,
                    'group_id': json_home.Parameters.GROUP_ID,
                    'role_id': json_home.Parameters.ROLE_ID,
                },
            }
        ),
        (
            build_os_inherit_relation(
                resource_name='domain_user_roles_inherited_to_projects'),
            {
                'href-template': '/OS-INHERIT/domains/{domain_id}/users/'
                '{user_id}/roles/inherited_to_projects',
                'href-vars': {
                    'domain_id': json_home.Parameters.DOMAIN_ID,
                    'user_id': json_home.Parameters.USER_ID,
                },
            }
        ),
        (
            build_os_inherit_relation(
                resource_name='domain_group_roles_inherited_to_projects'),
            {
                'href-template': '/OS-INHERIT/domains/{domain_id}/groups/'
                '{group_id}/roles/inherited_to_projects',
                'href-vars': {
                    'domain_id': json_home.Parameters.DOMAIN_ID,
                    'group_id': json_home.Parameters.GROUP_ID,
                },
            }
        ),
        (
            build_os_inherit_relation(
                resource_name='project_user_role_inherited_to_projects'),
            {
                'href-template': '/OS-INHERIT/projects/{project_id}/users/'
                '{user_id}/roles/{role_id}/inherited_to_projects',
                'href-vars': {
                    'project_id': json_home.Parameters.PROJECT_ID,
                    'role_id': json_home.Parameters.ROLE_ID,
                    'user_id': json_home.Parameters.USER_ID,
                },
            }
        ),
        (
            build_os_inherit_relation(
                resource_name='project_group_role_inherited_to_projects'),
            {
                'href-template': '/OS-INHERIT/projects/{project_id}/groups/'
                '{group_id}/roles/{role_id}/inherited_to_projects',
                'href-vars': {
                    'project_id': json_home.Parameters.PROJECT_ID,
                    'group_id': json_home.Parameters.GROUP_ID,
                    'role_id': json_home.Parameters.ROLE_ID,
                },
            }
        ),
    )
)


class VersionTestCase(tests.TestCase):
    def setUp(self):
        super(VersionTestCase, self).setUp()
        self.load_backends()
        self.public_app = self.loadapp('keystone', 'main')
        self.admin_app = self.loadapp('keystone', 'admin')

        self.config_fixture.config(
            public_endpoint='http://localhost:%(public_port)d',
            admin_endpoint='http://localhost:%(admin_port)d')

    def config_overrides(self):
        super(VersionTestCase, self).config_overrides()
        port = random.randint(10000, 30000)
        self.config_fixture.config(public_port=port, admin_port=port)

    def _paste_in_port(self, response, port):
        for link in response['links']:
            if link['rel'] == 'self':
                link['href'] = port

    def test_public_versions(self):
        client = self.client(self.public_app)
        resp = client.get('/')
        self.assertEqual(resp.status_int, 300)
        data = jsonutils.loads(resp.body)
        expected = VERSIONS_RESPONSE
        for version in expected['versions']['values']:
            if version['id'] == 'v3.0':
                self._paste_in_port(
                    version, 'http://localhost:%s/v3/' % CONF.public_port)
            elif version['id'] == 'v2.0':
                self._paste_in_port(
                    version, 'http://localhost:%s/v2.0/' % CONF.public_port)
        self.assertEqual(data, expected)

    def test_admin_versions(self):
        client = self.client(self.admin_app)
        resp = client.get('/')
        self.assertEqual(resp.status_int, 300)
        data = jsonutils.loads(resp.body)
        expected = VERSIONS_RESPONSE
        for version in expected['versions']['values']:
            if version['id'] == 'v3.0':
                self._paste_in_port(
                    version, 'http://localhost:%s/v3/' % CONF.admin_port)
            elif version['id'] == 'v2.0':
                self._paste_in_port(
                    version, 'http://localhost:%s/v2.0/' % CONF.admin_port)
        self.assertEqual(data, expected)

    def test_use_site_url_if_endpoint_unset(self):
        self.config_fixture.config(public_endpoint=None, admin_endpoint=None)

        for app in (self.public_app, self.admin_app):
            client = self.client(app)
            resp = client.get('/')
            self.assertEqual(resp.status_int, 300)
            data = jsonutils.loads(resp.body)
            expected = VERSIONS_RESPONSE
            for version in expected['versions']['values']:
                # localhost happens to be the site url for tests
                if version['id'] == 'v3.0':
                    self._paste_in_port(
                        version, 'http://localhost/v3/')
                elif version['id'] == 'v2.0':
                    self._paste_in_port(
                        version, 'http://localhost/v2.0/')
            self.assertEqual(data, expected)

    def test_public_version_v2(self):
        client = self.client(self.public_app)
        resp = client.get('/v2.0/')
        self.assertEqual(resp.status_int, 200)
        data = jsonutils.loads(resp.body)
        expected = v2_VERSION_RESPONSE
        self._paste_in_port(expected['version'],
                            'http://localhost:%s/v2.0/' % CONF.public_port)
        self.assertEqual(data, expected)

    def test_admin_version_v2(self):
        client = self.client(self.admin_app)
        resp = client.get('/v2.0/')
        self.assertEqual(resp.status_int, 200)
        data = jsonutils.loads(resp.body)
        expected = v2_VERSION_RESPONSE
        self._paste_in_port(expected['version'],
                            'http://localhost:%s/v2.0/' % CONF.admin_port)
        self.assertEqual(data, expected)

    def test_use_site_url_if_endpoint_unset_v2(self):
        self.config_fixture.config(public_endpoint=None, admin_endpoint=None)
        for app in (self.public_app, self.admin_app):
            client = self.client(app)
            resp = client.get('/v2.0/')
            self.assertEqual(resp.status_int, 200)
            data = jsonutils.loads(resp.body)
            expected = v2_VERSION_RESPONSE
            self._paste_in_port(expected['version'], 'http://localhost/v2.0/')
            self.assertEqual(data, expected)

    def test_public_version_v3(self):
        client = self.client(self.public_app)
        resp = client.get('/v3/')
        self.assertEqual(resp.status_int, 200)
        data = jsonutils.loads(resp.body)
        expected = v3_VERSION_RESPONSE
        self._paste_in_port(expected['version'],
                            'http://localhost:%s/v3/' % CONF.public_port)
        self.assertEqual(data, expected)

    def test_admin_version_v3(self):
        client = self.client(self.public_app)
        resp = client.get('/v3/')
        self.assertEqual(resp.status_int, 200)
        data = jsonutils.loads(resp.body)
        expected = v3_VERSION_RESPONSE
        self._paste_in_port(expected['version'],
                            'http://localhost:%s/v3/' % CONF.admin_port)
        self.assertEqual(data, expected)

    def test_use_site_url_if_endpoint_unset_v3(self):
        self.config_fixture.config(public_endpoint=None, admin_endpoint=None)
        for app in (self.public_app, self.admin_app):
            client = self.client(app)
            resp = client.get('/v3/')
            self.assertEqual(resp.status_int, 200)
            data = jsonutils.loads(resp.body)
            expected = v3_VERSION_RESPONSE
            self._paste_in_port(expected['version'], 'http://localhost/v3/')
            self.assertEqual(data, expected)

    @mock.patch.object(controllers, '_VERSIONS', ['v3'])
    def test_v2_disabled(self):
        client = self.client(self.public_app)
        # request to /v2.0 should fail
        resp = client.get('/v2.0/')
        self.assertEqual(resp.status_int, 404)

        # request to /v3 should pass
        resp = client.get('/v3/')
        self.assertEqual(resp.status_int, 200)
        data = jsonutils.loads(resp.body)
        expected = v3_VERSION_RESPONSE
        self._paste_in_port(expected['version'],
                            'http://localhost:%s/v3/' % CONF.public_port)
        self.assertEqual(data, expected)

        # only v3 information should be displayed by requests to /
        v3_only_response = {
            "versions": {
                "values": [
                    v3_EXPECTED_RESPONSE
                ]
            }
        }
        self._paste_in_port(v3_only_response['versions']['values'][0],
                            'http://localhost:%s/v3/' % CONF.public_port)
        resp = client.get('/')
        self.assertEqual(resp.status_int, 300)
        data = jsonutils.loads(resp.body)
        self.assertEqual(data, v3_only_response)

    @mock.patch.object(controllers, '_VERSIONS', ['v2.0'])
    def test_v3_disabled(self):
        client = self.client(self.public_app)
        # request to /v3 should fail
        resp = client.get('/v3/')
        self.assertEqual(resp.status_int, 404)

        # request to /v2.0 should pass
        resp = client.get('/v2.0/')
        self.assertEqual(resp.status_int, 200)
        data = jsonutils.loads(resp.body)
        expected = v2_VERSION_RESPONSE
        self._paste_in_port(expected['version'],
                            'http://localhost:%s/v2.0/' % CONF.public_port)
        self.assertEqual(data, expected)

        # only v2 information should be displayed by requests to /
        v2_only_response = {
            "versions": {
                "values": [
                    v2_EXPECTED_RESPONSE
                ]
            }
        }
        self._paste_in_port(v2_only_response['versions']['values'][0],
                            'http://localhost:%s/v2.0/' % CONF.public_port)
        resp = client.get('/')
        self.assertEqual(resp.status_int, 300)
        data = jsonutils.loads(resp.body)
        self.assertEqual(data, v2_only_response)

    def _test_json_home(self, path, exp_json_home_data):
        client = self.client(self.public_app)
        resp = client.get(path, headers={'Accept': 'application/json-home'})

        self.assertThat(resp.status, tt_matchers.Equals('200 OK'))
        self.assertThat(resp.headers['Content-Type'],
                        tt_matchers.Equals('application/json-home'))

        self.assertThat(jsonutils.loads(resp.body),
                        tt_matchers.Equals(exp_json_home_data))

    def test_json_home_v3(self):
        # If the request is /v3 and the Accept header is application/json-home
        # then the server responds with a JSON Home document.

        exp_json_home_data = {
            'resources': V3_JSON_HOME_RESOURCES_INHERIT_DISABLED}

        self._test_json_home('/v3', exp_json_home_data)

    def test_json_home_root(self):
        # If the request is / and the Accept header is application/json-home
        # then the server responds with a JSON Home document.

        exp_json_home_data = copy.deepcopy({
            'resources': V3_JSON_HOME_RESOURCES_INHERIT_DISABLED})
        json_home.translate_urls(exp_json_home_data, '/v3')

        self._test_json_home('/', exp_json_home_data)

    def test_accept_type_handling(self):
        # Accept headers with multiple types and qvalues are handled.

        def make_request(accept_types=None):
            client = self.client(self.public_app)
            headers = None
            if accept_types:
                headers = {'Accept': accept_types}
            resp = client.get('/v3', headers=headers)
            self.assertThat(resp.status, tt_matchers.Equals('200 OK'))
            return resp.headers['Content-Type']

        JSON = controllers.MimeTypes.JSON
        JSON_HOME = controllers.MimeTypes.JSON_HOME

        JSON_MATCHER = tt_matchers.Equals(JSON)
        JSON_HOME_MATCHER = tt_matchers.Equals(JSON_HOME)

        # Default is JSON.
        self.assertThat(make_request(), JSON_MATCHER)

        # Can request JSON and get JSON.
        self.assertThat(make_request(JSON), JSON_MATCHER)

        # Can request JSONHome and get JSONHome.
        self.assertThat(make_request(JSON_HOME), JSON_HOME_MATCHER)

        # If request JSON, JSON Home get JSON.
        accept_types = '%s, %s' % (JSON, JSON_HOME)
        self.assertThat(make_request(accept_types), JSON_MATCHER)

        # If request JSON Home, JSON get JSON.
        accept_types = '%s, %s' % (JSON_HOME, JSON)
        self.assertThat(make_request(accept_types), JSON_MATCHER)

        # If request JSON Home, JSON;q=0.5 get JSON Home.
        accept_types = '%s, %s;q=0.5' % (JSON_HOME, JSON)
        self.assertThat(make_request(accept_types), JSON_HOME_MATCHER)

        # If request some unknown mime-type, get JSON.
        self.assertThat(make_request(self.getUniqueString()), JSON_MATCHER)


class VersionSingleAppTestCase(tests.TestCase):
    """Tests running with a single application loaded.

    These are important because when Keystone is running in Apache httpd
    there's only one application loaded for each instance.

    """

    def setUp(self):
        super(VersionSingleAppTestCase, self).setUp()
        self.load_backends()

        self.config_fixture.config(
            public_endpoint='http://localhost:%(public_port)d',
            admin_endpoint='http://localhost:%(admin_port)d')

    def config_overrides(self):
        super(VersionSingleAppTestCase, self).config_overrides()
        port = random.randint(10000, 30000)
        self.config_fixture.config(public_port=port, admin_port=port)

    def _paste_in_port(self, response, port):
        for link in response['links']:
            if link['rel'] == 'self':
                link['href'] = port

    def _test_version(self, app_name):
        app = self.loadapp('keystone', app_name)
        client = self.client(app)
        resp = client.get('/')
        self.assertEqual(resp.status_int, 300)
        data = jsonutils.loads(resp.body)
        expected = VERSIONS_RESPONSE
        for version in expected['versions']['values']:
            if version['id'] == 'v3.0':
                self._paste_in_port(
                    version, 'http://localhost:%s/v3/' % CONF.public_port)
            elif version['id'] == 'v2.0':
                self._paste_in_port(
                    version, 'http://localhost:%s/v2.0/' % CONF.public_port)
        self.assertEqual(data, expected)

    def test_public(self):
        self._test_version('main')

    def test_admin(self):
        self._test_version('admin')


class VersionInheritEnabledTestCase(tests.TestCase):
    def setUp(self):
        super(VersionInheritEnabledTestCase, self).setUp()
        self.load_backends()
        self.public_app = self.loadapp('keystone', 'main')
        self.admin_app = self.loadapp('keystone', 'admin')

        self.config_fixture.config(
            public_endpoint='http://localhost:%(public_port)d',
            admin_endpoint='http://localhost:%(admin_port)d')

    def config_overrides(self):
        super(VersionInheritEnabledTestCase, self).config_overrides()
        port = random.randint(10000, 30000)
        self.config_fixture.config(public_port=port, admin_port=port)

        self.config_fixture.config(group='os_inherit', enabled=True)

    def test_json_home_v3(self):
        # If the request is /v3 and the Accept header is application/json-home
        # then the server responds with a JSON Home document.

        client = self.client(self.public_app)
        resp = client.get('/v3/', headers={'Accept': 'application/json-home'})

        self.assertThat(resp.status, tt_matchers.Equals('200 OK'))
        self.assertThat(resp.headers['Content-Type'],
                        tt_matchers.Equals('application/json-home'))

        exp_json_home_data = {
            'resources': V3_JSON_HOME_RESOURCES_INHERIT_ENABLED}

        self.assertThat(jsonutils.loads(resp.body),
                        tt_matchers.Equals(exp_json_home_data))


class XmlVersionTestCase(tests.TestCase):

    REQUEST_HEADERS = {'Accept': 'application/xml'}

    DOC_INTRO = '<?xml version="1.0" encoding="UTF-8"?>'
    XML_NAMESPACE_ATTR = 'xmlns="http://docs.openstack.org/identity/api/v2.0"'
    XML_NAMESPACE_V3 = 'xmlns="http://docs.openstack.org/identity/api/v3"'

    v2_VERSION_DATA = """
<version %(v2_namespace)s status="stable" updated="2014-04-17T00:00:00Z"
         id="v2.0">
  <media-types>
    <media-type base="application/json" type="application/\
vnd.openstack.identity-v2.0+json"/>
    <media-type base="application/xml" type="application/\
vnd.openstack.identity-v2.0+xml"/>
  </media-types>
  <links>
    <link href="http://localhost:%%(port)s/v2.0/" rel="self"/>
    <link href="http://docs.openstack.org/" type="text/html" \
rel="describedby"/>
  </links>
  <link href="http://localhost:%%(port)s/v2.0/" rel="self"/>
  <link href="http://docs.openstack.org/" type="text/html" \
rel="describedby"/>
</version>
"""

    v2_VERSION_RESPONSE = ((DOC_INTRO + v2_VERSION_DATA) %
                           dict(v2_namespace=XML_NAMESPACE_ATTR))

    v3_VERSION_DATA = """
<version %(v3_namespace)s status="stable" updated="2013-03-06T00:00:00Z"
         id="v3.0">
  <media-types>
    <media-type base="application/json" type="application/\
vnd.openstack.identity-v3+json"/>
    <media-type base="application/xml" type="application/\
vnd.openstack.identity-v3+xml"/>
  </media-types>
  <links>
    <link href="http://localhost:%%(port)s/v3/" rel="self"/>
  </links>
</version>
"""

    v3_VERSION_RESPONSE = ((DOC_INTRO + v3_VERSION_DATA) %
                           dict(v3_namespace=XML_NAMESPACE_V3))

    VERSIONS_RESPONSE = ((DOC_INTRO + """
<versions %(namespace)s>
""" +
                          v3_VERSION_DATA +
                          v2_VERSION_DATA + """
</versions>
""") % dict(namespace=XML_NAMESPACE_ATTR, v3_namespace='', v2_namespace=''))

    def setUp(self):
        super(XmlVersionTestCase, self).setUp()
        self.load_backends()
        self.public_app = self.loadapp('keystone', 'main')
        self.admin_app = self.loadapp('keystone', 'admin')

        self.config_fixture.config(
            public_endpoint='http://localhost:%(public_port)d',
            admin_endpoint='http://localhost:%(admin_port)d')

    def config_overrides(self):
        super(XmlVersionTestCase, self).config_overrides()
        port = random.randint(10000, 30000)
        self.config_fixture.config(public_port=port, admin_port=port)

    def test_public_versions(self):
        client = self.client(self.public_app)
        resp = client.get('/', headers=self.REQUEST_HEADERS)
        self.assertEqual(resp.status_int, 300)
        data = resp.body
        expected = self.VERSIONS_RESPONSE % dict(port=CONF.public_port)
        self.assertThat(data, matchers.XMLEquals(expected))

    def test_admin_versions(self):
        client = self.client(self.admin_app)
        resp = client.get('/', headers=self.REQUEST_HEADERS)
        self.assertEqual(resp.status_int, 300)
        data = resp.body
        expected = self.VERSIONS_RESPONSE % dict(port=CONF.admin_port)
        self.assertThat(data, matchers.XMLEquals(expected))

    def test_use_site_url_if_endpoint_unset(self):
        client = self.client(self.public_app)
        resp = client.get('/', headers=self.REQUEST_HEADERS)
        self.assertEqual(resp.status_int, 300)
        data = resp.body
        expected = self.VERSIONS_RESPONSE % dict(port=CONF.public_port)
        self.assertThat(data, matchers.XMLEquals(expected))

    def test_public_version_v2(self):
        client = self.client(self.public_app)
        resp = client.get('/v2.0/', headers=self.REQUEST_HEADERS)
        self.assertEqual(resp.status_int, 200)
        data = resp.body
        expected = self.v2_VERSION_RESPONSE % dict(port=CONF.public_port)
        self.assertThat(data, matchers.XMLEquals(expected))

    def test_admin_version_v2(self):
        client = self.client(self.admin_app)
        resp = client.get('/v2.0/', headers=self.REQUEST_HEADERS)
        self.assertEqual(resp.status_int, 200)
        data = resp.body
        expected = self.v2_VERSION_RESPONSE % dict(port=CONF.admin_port)
        self.assertThat(data, matchers.XMLEquals(expected))

    def test_public_version_v3(self):
        client = self.client(self.public_app)
        resp = client.get('/v3/', headers=self.REQUEST_HEADERS)
        self.assertEqual(resp.status_int, 200)
        data = resp.body
        expected = self.v3_VERSION_RESPONSE % dict(port=CONF.public_port)
        self.assertThat(data, matchers.XMLEquals(expected))

    def test_admin_version_v3(self):
        client = self.client(self.public_app)
        resp = client.get('/v3/', headers=self.REQUEST_HEADERS)
        self.assertEqual(resp.status_int, 200)
        data = resp.body
        expected = self.v3_VERSION_RESPONSE % dict(port=CONF.admin_port)
        self.assertThat(data, matchers.XMLEquals(expected))

    @mock.patch.object(controllers, '_VERSIONS', ['v3'])
    def test_v2_disabled(self):
        client = self.client(self.public_app)

        # request to /v3 should pass
        resp = client.get('/v3/', headers=self.REQUEST_HEADERS)
        self.assertEqual(resp.status_int, 200)
        data = resp.body
        expected = self.v3_VERSION_RESPONSE % dict(port=CONF.public_port)
        self.assertThat(data, matchers.XMLEquals(expected))

        # only v3 information should be displayed by requests to /
        v3_only_response = ((self.DOC_INTRO + '<versions %(namespace)s>' +
                             self.v3_VERSION_DATA + '</versions>') %
                            dict(namespace=self.XML_NAMESPACE_ATTR,
                                 v3_namespace='') %
                            dict(port=CONF.public_port))

        resp = client.get('/', headers=self.REQUEST_HEADERS)
        self.assertEqual(resp.status_int, 300)
        data = resp.body
        self.assertThat(data, matchers.XMLEquals(v3_only_response))

    @mock.patch.object(controllers, '_VERSIONS', ['v2.0'])
    def test_v3_disabled(self):
        client = self.client(self.public_app)

        # request to /v2.0 should pass
        resp = client.get('/v2.0/', headers=self.REQUEST_HEADERS)
        self.assertEqual(resp.status_int, 200)
        data = resp.body
        expected = self.v2_VERSION_RESPONSE % dict(port=CONF.public_port)
        self.assertThat(data, matchers.XMLEquals(expected))

        # only v2 information should be displayed by requests to /
        v2_only_response = ((self.DOC_INTRO + '<versions %(namespace)s>' +
                             self.v2_VERSION_DATA + '</versions>') %
                            dict(namespace=self.XML_NAMESPACE_ATTR,
                                 v2_namespace='') %
                            dict(port=CONF.public_port))

        resp = client.get('/', headers=self.REQUEST_HEADERS)
        self.assertEqual(resp.status_int, 300)
        data = resp.body
        self.assertThat(data, matchers.XMLEquals(v2_only_response))

    @mock.patch.object(controllers, '_VERSIONS', [])
    def test_no_json_home_document_returned_when_v3_disabled(self):
        json_home_document = controllers.request_v3_json_home('some_prefix')
        expected_document = {'resources': {}}
        self.assertEqual(expected_document, json_home_document)

    def test_extension_property_method_returns_none(self):
        extension_obj = controllers.Extensions()
        extensions_property = extension_obj.extensions
        self.assertIsNone(extensions_property)
