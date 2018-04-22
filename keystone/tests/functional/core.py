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

import os

import requests
import testtools

from keystone.tests.common import auth as common_auth


class BaseTestCase(testtools.TestCase, common_auth.AuthTestMixin):

    request_headers = {'content-type': 'application/json'}

    def setUp(self):
        self.ADMIN_URL = os.environ.get('KSTEST_ADMIN_URL',
                                        'http://localhost:5000')
        self.PUBLIC_URL = os.environ.get('KSTEST_PUBLIC_URL',
                                         'http://localhost:5000')
        self.admin = {
            'name': os.environ.get('KSTEST_ADMIN_USERNAME', 'admin'),
            'password': os.environ.get('KSTEST_ADMIN_PASSWORD', ''),
            'domain_id': os.environ.get('KSTEST_ADMIN_DOMAIN_ID', 'default')
        }

        self.user = {
            'name': os.environ.get('KSTEST_USER_USERNAME', 'demo'),
            'password': os.environ.get('KSTEST_USER_PASSWORD', ''),
            'domain_id': os.environ.get('KSTEST_USER_DOMAIN_ID', 'default')
        }

        self.project_id = os.environ.get('KSTEST_PROJECT_ID')
        self.project_name = os.environ.get('KSTEST_PROJECT_NAME')
        self.project_domain_id = os.environ.get('KSTEST_PROJECT_DOMAIN_ID')

        super(BaseTestCase, self).setUp()

    def _http_headers(self, token=None):
        headers = {'content-type': 'application/json'}
        if token:
            headers['X-Auth-Token'] = token
        return headers

    def get_scoped_token_response(self, user):
        """Convenience method so that we can test authenticated requests.

        :param user: A dictionary with user information like 'username',
                     'password', 'domain_id'
        :returns: urllib3.Response object

        """
        body = self.build_authentication_request(
            username=user['name'], user_domain_name=user['domain_id'],
            password=user['password'], project_name=self.project_name,
            project_domain_id=self.project_domain_id)
        return requests.post(self.PUBLIC_URL + '/v3/auth/tokens',
                             headers=self.request_headers,
                             json=body)

    def get_scoped_token(self, user):
        """Convenience method for getting scoped token.

        This method doesn't do any token validation.

        :param user: A dictionary with user information like 'username',
                     'password', 'domain_id'
        :returns: An OpenStack token for further use
        :rtype: str

        """
        r = self.get_scoped_token_response(user)
        return r.headers.get('X-Subject-Token')

    def get_scoped_admin_token(self):
        return self.get_scoped_token(self.admin)

    def get_scoped_user_token(self):
        return self.get_scoped_token(self.user)
