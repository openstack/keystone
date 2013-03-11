import copy
import uuid
import test_v3
import json

from keystone import config
from keystone.common.sql import util as sql_util
from keystone import test

from tests import test_content_types


CONF = config.CONF
DEFAULT_DOMAIN_ID = CONF.identity.default_domain_id


class TrustTestCase(test_v3.RestfulTestCase):
    def setUp(self):
        super(TrustTestCase, self).setUp()
        self.domain = None
        self.password = 'freeipa4all'
        self.auth_url = '/v2.0'
        self.admin_url = '/v2.0'
        self.admin_url_v3 = '/v3'
        self.url_template = "%(auth_url)s/%(resource)s"
        self.headers = {'Content-type': 'application/json'}
        self.trustor = self.create_user()
        self.trustee = self.create_user()
        self.role_1 = self.create_role()
        self.role_2 = self.create_role()
        self.grant_role_to_user(self.trustor['id'],
                                self.role_1['id'],
                                self.get_project()['id'])
        self.grant_role_to_user(self.trustor['id'],
                                self.role_2['id'],
                                self.get_project()['id'])

    def v3_request(self, path, data):
        r = self.request(method='POST',
                         path=path,
                         body=data,
                         headers=self.headers)
        return r

    def get_unscoped_token_response(self, username, password):
        url = self.url_template % {'auth_url': self.admin_url,
                                   'resource': "tokens"}
        data = self.get_unscoped_auth(username=username, password=password)
        r = self.restful_request(method='POST',
                                 port=self._public_port(),
                                 path=url,
                                 body=data,
                                 headers=self.headers)
        if 'access' in r.body:
            return r.body['access']
        raise Exception(r)

    def get_scoped_token_response(self, username, password, project_name):
        url = self.url_template % {'auth_url': self.admin_url,
                                   'resource': "tokens"}
        data = self.get_scoped_auth(username, password, project_name)
        r = self.restful_request(method='POST',
                                 port=self._public_port(),
                                 path=url,
                                 body=data,
                                 headers=self.headers)
        if 'access' in r.body:
            return r.body['access']
        raise Exception(r)

    def get_admin_token_data(self):
        if not hasattr(self, 'admin_token_response'):
            self.admin_token_response = self.get_scoped_token_response(
                'admin', 'freeipa4all', 'demo')
        return self.admin_token_response

    def get_admin_token_id(self):
        return 'ADMIN'

    def make_admin_post_request(self, resource, data):
        return self.make_post_request(resource,
                                      data,
                                      self.get_admin_token_id())

    def make_post_request(self, resource, data, token_id):
        headers = copy.copy(self.headers)
        headers["x-auth-token"] = token_id
        url = self.url_template % {'auth_url': self.admin_url_v3,
                                   'resource': resource}
        r = self.restful_request(method='POST',
                                 path=url,
                                 port=self._admin_port(),
                                 body=data,
                                 headers=headers)
        return r

    def make_v2_post_request(self, resource, data, token_id):
        headers = copy.copy(self.headers)
        headers["x-auth-token"] = token_id
        url = self.url_template % {'auth_url': self.admin_url,
                                   'resource': resource}
        r = self.restful_request(method='POST',
                                 path=url,
                                 port=self._admin_port(),
                                 body=data,
                                 headers=headers)
        return r

    def make_put_request(self, resource, data, token_id):
        headers = copy.copy(self.headers)
        headers["x-auth-token"] = self.get_admin_token_id()
        url = self.url_template % {'auth_url': self.admin_url_v3,
                                   'resource': resource}
        r = self.request(method='PUT',
                         path=url,
                         port=self._admin_port(),
                         body=json.dumps(data),
                         headers=headers)
        return r

    def create_domain(self):
        domain = self.new_domain_ref()
        resource = 'domains'
        data = {'domain': domain}
        r = self.make_admin_post_request(resource, data)
        dom = r.body['domain']
        self.domain = dom

    def create_project(self):
        project = self.new_project_ref(
            domain_id=self.get_domain()['id'])
        data = {'project': project}
        r = self.make_admin_post_request('projects', data)
        self.project = r.body['project']

    def get_domain(self):
        if not self.domain:
            #once authenticate supports domains, use the following function
#            self.create_domain()
            self.domain = {'id': DEFAULT_DOMAIN_ID}
        return self.domain

    def get_project(self):
        if not hasattr(self, 'project'):
            self.create_project()
        return self.project

    def create_user(self):
        user_id = uuid.uuid4().hex
        user = {'user': {'name': uuid.uuid4().hex,
                         'password': self.password,
                         'enabled': True,
                         'domain_id': self.get_domain()['id'],
                         'project_id': self.get_project()['id']}}
        r = self.make_admin_post_request('users', user)
        return r.body['user']

    def create_role(self):
        ref = self.new_role_ref()
        body = {'role': ref}
        r = self.make_admin_post_request('roles', body)
        return r.body['role']

    def grant_role_to_user(self, user_id, role_id, project_id):
        """PUT /projects/{project_id}/users/{user_id}/roles/{role_id}"""
        url_template = 'projects/%(project_id)s/users'\
                       '/%(user_id)s/roles/%(role_id)s'
        url = url_template % {'project_id': project_id,
                              'user_id': user_id,
                              'role_id': role_id}
        r = self.make_put_request(url, '', self.get_admin_token_id())
        return r

    def get_scoped_auth(self, username, password, project_name):
        return {"auth":
                {"passwordCredentials": {"username": username,
                                         "password": password},
                 "projectName": project_name}}

    def get_unscoped_auth(self, username, password):
        return {"auth":
                {"passwordCredentials": {"username": username,
                                         "password": password}}}

    def create_trust(self, impersonation=True):
        trustor_token = self.get_scoped_token_response(
            self.trustor['name'],
            self.password,
            self.get_project()['name'])
        trustee_token = self.get_unscoped_token_response(self.trustee['name'],
                                                         self.password)
        trust_request = {'trust':
                         {'trustor_user_id': self.trustor['id'],
                          'trustee_user_id': self.trustee['id'],
                          'project_id': self.get_project()['id'],
                          'impersonation': impersonation,
                          'description': 'described',
                          'roles': []}}
        trust_response = self.make_post_request('trusts', trust_request,
                                                trustor_token['token']['id'])
        return trust_response, trustee_token

    def test_create_trust(self):
        trust_response, trustee_token = self.create_trust()
        trust_id = trust_response.body['trust']['id']
        self.assertEquals(trust_response.body['trust']['description'],
                          'described')
        auth_data = {"auth": {"token": {'id': trustee_token['token']['id']},
                              "trust_id": trust_id}}
        r = self.make_v2_post_request("tokens",
                                      auth_data,
                                      trustee_token['token']['id'])
        trust_token = r.body
        self.assertIsNotNone(trust_token['access']['token']['id'])
        self.assertEquals(trust_token['access']['trust']['trustee_user_id'],
                          self.trustee['id'])
        self.assertEquals(trust_token['access']['trust']['id'], trust_id)

    def test_delete_trust(self):
        trust_response, trustee_token = self.create_trust()
        url = self.url_template % {'auth_url': self.admin_url_v3,
                                   'resource': "trusts/"}
        url += trust_response.body['trust']['id']
        trustor_token = self.get_scoped_token_response(
            self.trustor['name'],
            self.password,
            self.get_project()['name'])

        headers = copy.copy(self.headers)
        headers["x-auth-token"] = trustor_token['token']['id']
        response = self.request(method='DELETE',
                                path=url,
                                port=self._public_port(),
                                body="",
                                headers=headers)
        self.assertIsNotNone(response)

    def test_list_trusts(self):
        trustor_token = self.get_scoped_token_response(
            self.trustor['name'],
            self.password,
            self.get_project()['name'])

        for i in range(0, 3):
            trust_response, trustee_token = self.create_trust()
        url = self.url_template % {'auth_url': self.admin_url_v3,
                                   'resource': "trusts"}
        headers = copy.copy(self.headers)
        headers["x-auth-token"] = self.get_admin_token_id()
        trust_lists_response = self.restful_request(method='GET',
                                                    path=url,
                                                    port=self._public_port(),
                                                    body="",
                                                    headers=headers)
        trusts = trust_lists_response.body['trusts']
        self.assertEqual(len(trusts), 3)

        trustee_url = url + "?trustee_user_id=" + self.trustee['id']
        headers["x-auth-token"] = trustee_token['token']['id']
        trust_lists_response = self.restful_request(
            method='GET', path=trustee_url, port=self._public_port(),
            body="", headers=headers)
        trusts = trust_lists_response.body['trusts']
        self.assertEqual(len(trusts), 3)

        headers["x-auth-token"] = trustor_token['token']['id']

        trust_lists_response = self.restful_request(
            method='GET', path=trustee_url, port=self._public_port(),
            body="", headers=headers, expected_status=403)

        trustor_url = url + "?trustor_user_id=" + self.trustor['id']
        headers["x-auth-token"] = trustor_token['token']['id']
        trust_lists_response = self.restful_request(
            method='GET',
            path=trustor_url,
            port=self._public_port(),
            body="",
            headers=headers)
        trusts = trust_lists_response.body['trusts']
        self.assertEqual(len(trusts), 3)

        headers["x-auth-token"] = trustee_token['token']['id']
        trust_lists_response = self.restful_request(
            method='GET', path=trustor_url, port=self._public_port(),
            body="", headers=headers, expected_status=403)
