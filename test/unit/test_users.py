import os
import sys
# Need to access identity module
sys.path.append(os.path.abspath(os.path.join(os.path.abspath(__file__),
                                '..', '..', '..', '..', 'keystone')))
import unittest
from webtest import TestApp
import httplib2
import json
from lxml import etree


from test_common import URL, get_token, get_tenant, get_user
from test_common import get_userdisabled, get_auth_token
from test_common import get_exp_auth_token, get_disabled_token
from test_common import delete_token, content_type, get_token_xml
from test_common import get_password, get_email, get_none_token
from test_common import get_non_existing_token, delete_user, delete_user_xml
from test_common import create_user, create_user_xml, handle_user_resp

class user_test(unittest.TestCase):

    def setUp(self):
        self.token = get_token('joeuser', 'secrete', 'token')
        self.tenant = get_tenant()
        self.password = get_password()
        self.email = get_email()
        self.user = get_user()
        self.userdisabled = get_userdisabled()
        self.auth_token = get_auth_token()
        self.exp_auth_token = get_exp_auth_token()
        self.disabled_token = get_disabled_token()
        self.missing_token = get_none_token()
        self.invalid_token = get_non_existing_token()

    def tearDown(self):

        resp, content = delete_user(self.tenant, self.user,
                                    str(self.auth_token))


class create_user_test(user_test):

    def test_a_user_create_json(self):
        resp, content = create_user(self.tenant, self.user,
                                    str(self.auth_token))
        resp_val = int(resp['status'])
        handle_user_resp(self, content, resp_val, content_type(resp))
        self.assertEqual(201, resp_val)

    def test_a_user_create_xml(self):
        resp, content = delete_user_xml(self.tenant, self.user,
                                        str(self.auth_token))
        resp, content = create_user_xml(self.tenant, self.user,
                                        str(self.auth_token))
        resp_val = int(resp['status'])
        handle_user_resp(self, content, resp_val, content_type(resp))

        self.assertEqual(201, resp_val)
        self.assertEqual('application/xml', content_type(resp))

    def test_a_user_create_json_disabled_tenant(self):
        resp, content = create_user('0000', self.user,
                                    str(self.auth_token))
        resp_val = int(resp['status'])
        handle_user_resp(self, content, resp_val, content_type(resp))
        self.assertEqual(403, resp_val)

    def test_a_user_create_json_disabled_tenant_xml(self):
        resp, content = create_user_xml('0000', self.user,
                                        str(self.auth_token))
        resp_val = int(resp['status'])
        handle_user_resp(self, content, resp_val, content_type(resp))
        self.assertEqual(403, resp_val)
        self.assertEqual('application/xml', content_type(resp))

    def test_a_user_again_json(self):
        resp, content = create_user(self.tenant, self.user,
                                    str(self.auth_token))
        resp_val = int(resp['status'])
        handle_user_resp(self, content, resp_val, content_type(resp))
        resp, content = create_user(self.tenant, self.user,
                                    str(self.auth_token))
        self.assertEqual(409, int(resp['status']))

    def test_a_user_again_xml(self):
        resp, content = create_user_xml(self.tenant, self.user,
                                        str(self.auth_token))
        resp, content = create_user_xml(self.tenant, self.user,
                                        str(self.auth_token))
        content = etree.fromstring(content)
        resp_val = int(resp['status'])
        handle_user_resp(self, content, resp_val, content_type(resp))
        self.assertEqual(409, int(resp['status']))
        self.assertEqual('application/xml', content_type(resp))

    def test_a_user_create_expired_token(self):
        resp, content = create_user(self.tenant, self.user,
                                    str(self.exp_auth_token))
        resp_val = int(resp['status'])
        handle_user_resp(self, content, resp_val, content_type(resp))
        self.assertEqual(403, int(resp['status']))

    def test_a_user_create_expired_token_xml(self):
        resp, content = create_user_xml(self.tenant, self.user,
                                        str(self.exp_auth_token))
        resp_val = int(resp['status'])
        handle_user_resp(self, content, resp_val, content_type(resp))
        self.assertEqual(403, int(resp['status']))
        self.assertEqual('application/xml', content_type(resp))

    def test_a_user_create_disabled_token(self):
        resp, content = create_user(self.tenant, self.user,
                                    str(self.disabled_token))
        resp_val = int(resp['status'])
        handle_user_resp(self, content, resp_val, content_type(resp))
        self.assertEqual(403, int(resp['status']))

    def test_a_user_create_disabled_token_xml(self):
        resp, content = create_user_xml(self.tenant, self.user,
                                        str(self.disabled_token))
        resp_val = int(resp['status'])
        handle_user_resp(self, content, resp_val, content_type(resp))
        self.assertEqual(403, int(resp['status']))
        self.assertEqual('application/xml', content_type(resp))

    def test_a_user_create_missing_token(self):
        resp, content = create_user(self.tenant, self.user,
                                    str(self.missing_token))
        resp_val = int(resp['status'])
        handle_user_resp(self, content, resp_val, content_type(resp))
        self.assertEqual(401, int(resp['status']))

    def test_a_user_create_missing_token_xml(self):
        resp, content = create_user_xml(self.tenant, self.user,
                                        str(self.missing_token))
        resp_val = int(resp['status'])
        handle_user_resp(self, content, resp_val, content_type(resp))
        self.assertEqual(401, int(resp['status']))
        self.assertEqual('application/xml', content_type(resp))

    def test_a_user_create_invalid_token(self):
        resp, content = create_user(self.tenant, self.user,
                                    str(self.invalid_token))
        resp_val = int(resp['status'])
        handle_user_resp(self, content, resp_val, content_type(resp))
        self.assertEqual(404, int(resp['status']))

    def test_a_user_create_invalid_token_xml(self):
        resp, content = create_user_xml(self.tenant, self.user,
                                        str(self.invalid_token))
        resp_val = int(resp['status'])
        handle_user_resp(self, content, resp_val, content_type(resp))
        self.assertEqual(404, int(resp['status']))
        self.assertEqual('application/xml', content_type(resp))


class get_user_test(user_test):

    def test_a_user_get_json(self):
        header = httplib2.Http(".cache")
        resp, content = create_user(self.tenant, self.user,
                                    str(self.auth_token))
        url = '%stenants/%s/users/%s' % (URL, self.tenant, self.user)
        resp, content = header.request(url, "GET", body='{}',
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.auth_token})
        resp_val = int(resp['status'])
        handle_user_resp(self, content, resp_val, content_type(resp))
        self.assertEqual(200, resp_val)

    def test_a_user_get_xml(self):
        header = httplib2.Http(".cache")
        resp, content = create_user(self.tenant, self.user,
                                        str(self.auth_token))
        url = '%stenants/%s/users/%s' % (URL, self.tenant, self.user)
        resp, content = header.request(url, "GET", body='{}',
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.auth_token,
                                           "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        handle_user_resp(self, content, resp_val, content_type(resp))
        self.assertEqual(200, resp_val)
        self.assertEqual('application/xml', content_type(resp))

    def test_a_user_get_expired_token(self):
        header = httplib2.Http(".cache")
        resp, content = create_user(self.user, self.tenant,
                                    str(self.auth_token))
        url = '%stenants/%s/users/%s' % (URL, self.tenant, self.user)
        #test for Content-Type = application/json
        resp, content = header.request(url, "GET", body='{}',
                                  headers={"Content-Type": "application/json",
                                        "X-Auth-Token": self.exp_auth_token})
        resp_val = int(resp['status'])
        handle_user_resp(self, content, resp_val, content_type(resp))
        self.assertEqual(403, resp_val)

    def test_a_user_get_expired_token_xml(self):
        header = httplib2.Http(".cache")
        resp, content = create_user(self.user, self.tenant,
                                    str(self.auth_token))
        url = '%stenants/%s/users/%s' % (URL, self.tenant, self.user)
        #test for Content-Type = application/json
        resp, content = header.request(url, "GET", body='',
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.exp_auth_token,
                                           "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        handle_user_resp(self, content, resp_val, content_type(resp))
        self.assertEqual(403, resp_val)
        self.assertEqual('application/xml', content_type(resp))

    def test_a_user_get_disabled_token(self):
        header = httplib2.Http(".cache")
        resp, content = create_user(self.user, self.tenant,
                                    str(self.auth_token))
        url = '%stenants/%s/users/%s' % (URL, self.tenant, self.user)
        #test for Content-Type = application/json
        resp, content = header.request(url, "GET", body='{}',
                                  headers={"Content-Type": "application/json",
                                        "X-Auth-Token": self.disabled_token})
        resp_val = int(resp['status'])
        handle_user_resp(self, content, resp_val, content_type(resp))
        self.assertEqual(403, resp_val)

    def test_a_user_get_disabled_token_xml(self):
        header = httplib2.Http(".cache")
        resp, content = create_user(self.user, self.tenant,
                                    str(self.auth_token))
        url = '%stenants/%s/users/%s' % (URL, self.tenant, self.user)
        #test for Content-Type = application/json
        resp, content = header.request(url, "GET", body='',
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.disabled_token,
                                           "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        handle_user_resp(self, content, resp_val, content_type(resp))
        self.assertEqual(403, resp_val)
        self.assertEqual('application/xml', content_type(resp))

    def test_a_user_get_missing_token(self):
        header = httplib2.Http(".cache")
        resp, content = create_user(self.user, self.tenant,
                                    str(self.auth_token))
        url = '%stenants/%s/users/%s' % (URL, self.tenant, self.user)
        #test for Content-Type = application/json
        resp, content = header.request(url, "GET", body='{}',
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.missing_token})
        resp_val = int(resp['status'])
        handle_user_resp(self, content, resp_val, content_type(resp))
        self.assertEqual(401, resp_val)

    def test_a_user_get_missing_token_xml(self):
        header = httplib2.Http(".cache")
        resp, content = create_user(self.user, self.tenant,
                                    str(self.auth_token))
        url = '%stenants/%s/users/%s' % (URL, self.tenant, self.user)
        #test for Content-Type = application/json
        resp, content = header.request(url, "GET", body='',
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.missing_token,
                                           "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        handle_user_resp(self, content, resp_val, content_type(resp))
        self.assertEqual(401, resp_val)
        self.assertEqual('application/xml', content_type(resp))

    def test_a_user_get_invalid_token(self):
        header = httplib2.Http(".cache")
        resp, content = create_user(self.user, self.tenant,
                                    str(self.auth_token))
        url = '%stenants/%s/users/%s' % (URL, self.tenant, self.user)
        #test for Content-Type = application/json
        resp, content = header.request(url, "GET", body='{}',
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.invalid_token})
        resp_val = int(resp['status'])
        handle_user_resp(self, content, resp_val, content_type(resp))
        self.assertEqual(404, resp_val)

    def test_a_user_get_invalid_token_xml(self):
        header = httplib2.Http(".cache")
        resp, content = create_user(self.user, self.tenant,
                                    str(self.auth_token))
        url = '%stenants/%s/users/%s' % (URL, self.tenant, self.user)
        #test for Content-Type = application/json
        resp, content = header.request(url, "GET", body='',
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.invalid_token,
                                           "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        handle_user_resp(self, content, resp_val, content_type(resp))
        self.assertEqual(404, resp_val)
        self.assertEqual('application/xml', content_type(resp))

    def test_a_user_get_disabled_user(self):
        header = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s' % (URL, self.tenant,
                                         self.userdisabled)
        #test for Content-Type = application/json
        resp, content = header.request(url, "GET", body='{}',
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.auth_token})
        resp_val = int(resp['status'])

        handle_user_resp(self, content, resp_val, content_type(resp))
        self.assertEqual(403, resp_val)

    def test_a_user_get_disabled_user_xml(self):
        header = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s' % (URL, self.tenant, self.userdisabled)

        resp, content = header.request(url, "GET", body='',
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.auth_token,
                                           "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        handle_user_resp(self, content, resp_val, content_type(resp))
        self.assertEqual(403, resp_val)
        self.assertEqual('application/xml', content_type(resp))

    def test_a_user_get_disabled_tenant(self):
        header = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s' % (URL, '0000', self.userdisabled)

        resp, content = header.request(url, "GET", body='{}',
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.auth_token})
        resp_val = int(resp['status'])
        handle_user_resp(self, content, resp_val, content_type(resp))
        self.assertEqual(403, resp_val)

    def test_a_user_get_disabled_tenant_xml(self):
        header = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s' % (URL, '0000', self.userdisabled)
        #test for Content-Type = application/json
        resp, content = header.request(url, "GET", body='',
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.auth_token,
                                           "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        handle_user_resp(self, content, resp_val, content_type(resp))
        self.assertEqual(403, resp_val)
        self.assertEqual('application/xml', content_type(resp))


class delete_user_test(user_test):

    def test_a_user_delete_json(self):
        header = httplib2.Http(".cache")
        resp, content = create_user(self.tenant, self.user,
                                    str(self.auth_token))
        url = '%stenants/%s/users/%s' % (URL, self.tenant, self.user)
        #test for Content-Type = application/json
        resp, content = header.request(url, "DELETE", body='{}',
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.auth_token})
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(204, resp_val)

    def test_a_user_delete_xml(self):
        header = httplib2.Http(".cache")
        resp, content = create_user_xml(self.tenant, self.user,
                                        str(self.auth_token))
        url = '%stenants/%s/users/%s' % (URL, self.tenant, self.user)
        resp, content = header.request(url, "DELETE", body='{}',
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.auth_token,
                                           "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(204, resp_val)

    def test_a_user_delete_expired_token(self):
        header = httplib2.Http(".cache")
        resp, content = create_user(self.user, self.tenant,
                                    str(self.auth_token))
        url = '%stenants/%s/users/%s' % (URL, self.tenant, self.user)
        #test for Content-Type = application/json
        resp, content = header.request(url, "DELETE", body='{}',
                                  headers={"Content-Type": "application/json",
                                         "X-Auth-Token": self.exp_auth_token})
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)

    def test_a_user_delete_expired_token_xml(self):
        header = httplib2.Http(".cache")
        resp, content = create_user(self.user, self.tenant,
                                    str(self.auth_token))
        url = '%stenants/%s/users/%s' % (URL, self.tenant, self.user)
        #test for Content-Type = application/json
        resp, content = header.request(url, "DELETE", body='',
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.exp_auth_token,
                                           "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)
        self.assertEqual('application/xml', content_type(resp))

    def test_a_user_delete_missing_token(self):
        header = httplib2.Http(".cache")
        resp, content = create_user(self.user, self.tenant,
                                    str(self.auth_token))
        url = '%stenants/%s/users/%s' % (URL, self.tenant, self.user)
        #test for Content-Type = application/json
        resp, content = header.request(url, "DELETE", body='{}',
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.missing_token})
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, resp_val)

    def test_a_user_delete_missing_token_xml(self):
        header = httplib2.Http(".cache")
        resp, content = create_user(self.user, self.tenant,
                                    str(self.auth_token))
        url = '%stenants/%s/users/%s' % (URL, self.tenant, self.user)
        #test for Content-Type = application/json
        resp, content = header.request(url, "DELETE", body='',
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.missing_token,
                                           "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, resp_val)
        self.assertEqual('application/xml', content_type(resp))

    def test_a_user_delete_invalid_token(self):
        header = httplib2.Http(".cache")
        resp, content = create_user(self.user, self.tenant,
                                    str(self.auth_token))
        url = '%stenants/%s/users/%s' % (URL, self.tenant, self.user)
        #test for Content-Type = application/json
        resp, content = header.request(url, "DELETE", body='{}',
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.invalid_token})
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, resp_val)

    def test_a_user_delete_invalid_token_xml(self):
        header = httplib2.Http(".cache")
        resp, content = create_user(self.user, self.tenant,
                                    str(self.auth_token))
        url = '%stenants/%s/users/%s' % (URL, self.tenant, self.user)
        #test for Content-Type = application/json
        resp, content = header.request(url, "DELETE", body='',
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.invalid_token,
                                           "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, resp_val)
        self.assertEqual('application/xml', content_type(resp))

    def test_a_user_delete_disabled_tenant(self):
        header = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s' % (URL, '0000', self.userdisabled)
        #test for Content-Type = application/json
        resp, content = header.request(url, "DELETE", body='{}',
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.auth_token})
        resp_val = int(resp['status'])

        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)

    def test_a_user_delete_disabled_tenant_xml(self):
        header = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s' % (URL, '0000', self.userdisabled)
        #test for Content-Type = application/json
        resp, content = header.request(url, "DELETE", body='',
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.auth_token,
                                           "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])

        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)
        self.assertEqual('application/xml', content_type(resp))


class get_users_test(user_test):

    def test_users_get_json(self):
        header = httplib2.Http(".cache")
        url = '%stenants/%s/users' % (URL, self.tenant)
        resp, content = header.request(url, "GET", body='{}',
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.auth_token})
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(200, resp_val)

    def test_users_get_xml(self):
        header = httplib2.Http(".cache")
        url = '%stenants/%s/users' % (URL, self.tenant)
        resp, content = header.request(url, "GET", body='{}',
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.auth_token,
                                           "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(200, resp_val)
        self.assertEqual('application/xml', content_type(resp))

    def test_users_get_expired_token_json(self):
        header = httplib2.Http(".cache")
        url = '%stenants/%s/users' % (URL, self.tenant)
        resp, content = header.request(url, "GET", body='{}',
                                  headers={"Content-Type": "application/json",
                                       "X-Auth-Token": self.exp_auth_token})
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)

    def test_users_get_expired_token_xml(self):
        header = httplib2.Http(".cache")
        url = '%stenants/%s/users' % (URL, self.tenant)
        resp, content = header.request(url, "GET", body='{}',
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.exp_auth_token,
                                           "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)
        self.assertEqual('application/xml', content_type(resp))

    def test_users_get_disabled_token_json(self):
        header = httplib2.Http(".cache")
        url = '%stenants/%s/users' % (URL, self.tenant)
        resp, content = header.request(url, "GET", body='{}',
                                  headers={"Content-Type": "application/json",
                                        "X-Auth-Token": self.disabled_token})
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)

    def test_users_get_disabled_token_xml(self):
        header = httplib2.Http(".cache")
        url = '%stenants/%s/users' % (URL, self.tenant)
        resp, content = header.request(url, "GET", body='{}',
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.disabled_token,
                                           "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)
        self.assertEqual('application/xml', content_type(resp))

    def test_users_get_missing_token_json(self):
        header = httplib2.Http(".cache")
        url = '%stenants/%s/users' % (URL, self.tenant)
        resp, content = header.request(url, "GET", body='{}',
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.missing_token})
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, resp_val)

    def test_users_get_missing_token_xml(self):
        header = httplib2.Http(".cache")
        url = '%stenants/%s/users' % (URL, self.tenant)
        resp, content = header.request(url, "GET", body='{}',
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.missing_token,
                                           "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, resp_val)
        self.assertEqual('application/xml', content_type(resp))

    def test_users_get_invalid_token_json(self):
        header = httplib2.Http(".cache")
        url = '%stenants/%s/users' % (URL, self.tenant)
        resp, content = header.request(url, "GET", body='{}',
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.invalid_token})
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, resp_val)

    def test_users_get_invalid_token_xml(self):
        header = httplib2.Http(".cache")
        url = '%stenants/%s/users' % (URL, self.tenant)
        resp, content = header.request(url, "GET", body='{}',
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.invalid_token,
                                           "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, resp_val)
        self.assertEqual('application/xml', content_type(resp))

    def test_users_get_disabled_tenant_json(self):
        header = httplib2.Http(".cache")
        url = '%stenants/%s/users' % (URL, "0000")
        resp, content = header.request(url, "GET", body='{}',
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.auth_token})
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')

        self.assertEqual(403, resp_val)

    def test_users_get_disabled_tenant_xml(self):
        header = httplib2.Http(".cache")
        url = '%stenants/%s/users' % (URL, "0000")
        resp, content = header.request(url, "GET", body='{}',
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.auth_token,
                                           "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)
        self.assertEqual('application/xml', content_type(resp))


class get_users_group_test(user_test):

    def test_users_group_get_json(self):
        header = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s/groups' % (URL, self.tenant, self.user)
        resp, content = header.request(url, "GET", body='{}',
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.auth_token})
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(200, resp_val)

    def test_users_group_get_xml(self):
        header = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s/groups' % (URL, self.tenant, self.user)
        resp, content = header.request(url, "GET", body='{}',
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.auth_token,
                                           "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(200, resp_val)
        self.assertEqual('application/xml', content_type(resp))

    def test_users_group_get_expired_token_json(self):
        header = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s/groups' % (URL, self.tenant, self.user)
        resp, content = header.request(url, "GET", body='{}',
                                  headers={"Content-Type": "application/json",
                                         "X-Auth-Token": self.exp_auth_token})
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)

    def test_users_group_get_expired_token_xml(self):
        header = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s/groups' % (URL, self.tenant, self.user)
        resp, content = header.request(url, "GET", body='{}',
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.exp_auth_token,
                                           "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)
        self.assertEqual('application/xml', content_type(resp))

    def test_users_group_get_disabled_token_json(self):
        header = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s/groups' % (URL, self.tenant, self.user)
        resp, content = header.request(url, "GET", body='{}',
                                  headers={"Content-Type": "application/json",
                                       "X-Auth-Token": self.disabled_token})
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)

    def test_users_group_get_disabled_token_xml(self):
        header = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s/groups' % (URL, self.tenant, self.user)
        resp, content = header.request(url, "GET", body='{}',
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.disabled_token,
                                           "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)
        self.assertEqual('application/xml', content_type(resp))

    def test_users_group_get_missing_token_json(self):
        header = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s/groups' % (URL, self.tenant, self.user)
        resp, content = header.request(url, "GET", body='{}',
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.missing_token})
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, resp_val)

    def test_users_group_get_missing_token_xml(self):
        header = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s/groups' % (URL, self.tenant, self.user)
        resp, content = header.request(url, "GET", body='{}',
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.missing_token,
                                           "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, resp_val)
        self.assertEqual('application/xml', content_type(resp))

    def test_users_group_get_invalid_token_json(self):
        header = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s/groups' % (URL, self.tenant, self.user)
        resp, content = header.request(url, "GET", body='{}',
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.invalid_token})
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, resp_val)

    def test_users_group_get_invalid_token_xml(self):
        header = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s/groups' % (URL, self.tenant, self.user)
        resp, content = header.request(url, "GET", body='{}',
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.invalid_token,
                                           "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, resp_val)
        self.assertEqual('application/xml', content_type(resp))

    def test_users_group_get_disabled_tenant_json(self):
        header = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s/groups' % (URL, "0000", self.user)
        resp, content = header.request(url, "GET", body='{}',
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.auth_token})
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')

        self.assertEqual(403, resp_val)

    def test_users_group_get_disabled_tenant_xml(self):
        header = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s/groups' % (URL, "0000", self.user)
        resp, content = header.request(url, "GET", body='{}',
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.auth_token,
                                           "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)
        self.assertEqual('application/xml', content_type(resp))


class update_user_test(user_test):

    def test_user_update_json(self):
        header = httplib2.Http(".cache")
        resp, content = create_user(self.tenant, self.user,
                                    str(self.auth_token))

        url = '%stenants/%s/users/%s' % (URL, self.tenant, self.user)

        data = '{"user": { "email": "updatedjoeuser@rackspace.com"}}'
        resp, content = header.request(url, "PUT", body=data,
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.auth_token})
        resp_val = int(resp['status'])

        content = json.loads(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        delete_user(self.tenant, self.user, str(self.auth_token))
        self.assertEqual(200, resp_val)
        self.assertEqual('updatedjoeuser@rackspace.com', \
                        content['user']['email'])

    def test_user_update_xml(self):
        header = httplib2.Http(".cache")
        resp, content = create_user_xml(self.tenant, self.user,
                                        str(self.auth_token))
        url = '%stenants/%s/users/%s' % (URL, self.tenant, self.user)
        data = '<?xml version="1.0" encoding="UTF-8"?> \
                <user xmlns="http://docs.openstack.org/idm/api/v1.0" \
                email="updatedjoeuser@rackspace.com" />'
        resp, content = header.request(url, "PUT", body=data,
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.auth_token,
                                           "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])

        content = etree.fromstring(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        delete_user(self.tenant, self.user, str(self.auth_token))
        self.assertEqual(200, resp_val)
        self.assertEqual('updatedjoeuser@rackspace.com', content.get("email"))
        self.assertEqual('application/xml', content_type(resp))

    def test_user_update_user_disabled_json(self):
        header = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s' % (URL, self.tenant, self.userdisabled)
        data = '{"user": { "email": "updatedjoeuser@rackspace.com"}}'
        resp, content = header.request(url, "PUT", body=data,
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.auth_token})
        resp_val = int(resp['status'])
        content = json.loads(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)

    def test_user_update_user_disabled_xml(self):
        header = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s' % (URL, self.tenant, self.userdisabled)
        data = '<?xml version="1.0" encoding="UTF-8"?> \
                <user xmlns="http://docs.openstack.org/idm/api/v1.0" \
                email="updatedjoeuser@rackspace.com" />'
        resp, content = header.request(url, "PUT", body=data,
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.auth_token,
                                           "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        content = etree.fromstring(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)
        self.assertEqual('application/xml', content_type(resp))

    def test_user_update_email_conflict_json(self):
        header = httplib2.Http(".cache")
        resp, content = create_user_xml(self.tenant, self.user,
                                        str(self.auth_token))
        url = '%stenants/%s/users/%s' % (URL, self.tenant, self.user)
        data = '{"user": { "email": "joe@rackspace.com"}}'
        resp, content = header.request(url, "PUT", body=data,
                                headers={"Content-Type": "application/json",
                                         "X-Auth-Token": self.auth_token})
        resp_val = int(resp['status'])
        content = json.loads(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(409, resp_val)

    def test_user_update_email_conflict_xml(self):
        header = httplib2.Http(".cache")
        resp, content = create_user_xml(self.tenant, self.user,
                                        str(self.auth_token))
        url = '%stenants/%s/users/%s' % (URL, self.tenant, self.user)
        data = '<?xml version="1.0" encoding="UTF-8"?> \
                <user xmlns="http://docs.openstack.org/idm/api/v1.0" \
                email="joe@rackspace.com" />'
        resp, content = header.request(url, "PUT", body=data,
                                headers={"Content-Type": "application/xml",
                                         "X-Auth-Token": self.auth_token,
                                         "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        content = etree.fromstring(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(409, resp_val)
        self.assertEqual('application/xml', content_type(resp))

    def test_user_update_bad_request_json(self):
        header = httplib2.Http(".cache")
        resp, content = create_user(self.tenant, self.user,
                                    str(self.auth_token))
        url = '%stenants/%s/users/%s' % (URL, self.tenant, self.user)
        data = '{"user_bad": { "bad": "updatedjoeuser@rackspace.com"}}'
        resp, content = header.request(url, "PUT", body=data,
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.auth_token})
        resp_val = int(resp['status'])
        content = json.loads(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        delete_user(self.tenant, self.user, str(self.auth_token))
        self.assertEqual(400, resp_val)

    def test_user_update_bad_request_xml(self):
        header = httplib2.Http(".cache")
        resp, content = create_user_xml(self.tenant, self.user,
                                        str(self.auth_token))
        url = '%stenants/%s/users/%s' % (URL, self.tenant, self.user)
        data = '<?xml version="1.0" encoding="UTF-8"?> \
                user xmlns="http://docs.openstack.org/idm/api/v1.0" \
                email="updatedjoeuser@rackspace.com" />'
        resp, content = header.request(url, "PUT", body=data,
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.auth_token,
                                           "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        content = etree.fromstring(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        delete_user(self.tenant, self.user, str(self.auth_token))
        self.assertEqual(400, resp_val)
        self.assertEqual('application/xml', content_type(resp))

    def test_user_update_expired_token_json(self):
        header = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s' % (URL, self.tenant, self.user)
        data = '{"user": { "email": "updatedjoeuser@rackspace.com"}}'
        resp, content = header.request(url, "PUT", body=data,
                                  headers={"Content-Type": "application/json",
                                        "X-Auth-Token": self.exp_auth_token})
        resp_val = int(resp['status'])
        content = json.loads(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)

    def test_user_update_expired_token_xml(self):
        header = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s' % (URL, self.tenant, self.user)
        data = '<?xml version="1.0" encoding="UTF-8"?> \
                <user xmlns="http://docs.openstack.org/idm/api/v1.0" \
                email="updatedjoeuser@rackspace.com" />'
        resp, content = header.request(url, "PUT", body=data,
                                  headers={"Content-Type": "application/xml",
                                         "X-Auth-Token": self.exp_auth_token,
                                         "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        content = etree.fromstring(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)
        self.assertEqual('application/xml', content_type(resp))

    def test_user_update_disabled_token_json(self):
        header = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s' % (URL, self.tenant, self.user)
        data = '{"user": { "email": "updatedjoeuser@rackspace.com"}}'
        resp, content = header.request(url, "PUT", body=data,
                                  headers={"Content-Type": "application/json",
                                        "X-Auth-Token": self.disabled_token})
        resp_val = int(resp['status'])
        content = json.loads(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)

    def test_user_update_disabled_token_xml(self):
        header = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s' % (URL, self.tenant, self.user)
        data = '<?xml version="1.0" encoding="UTF-8"?> \
                <user xmlns="http://docs.openstack.org/idm/api/v1.0" \
                email="updatedjoeuser@rackspace.com" />'
        resp, content = header.request(url, "PUT", body=data,
                                  headers={"Content-Type": "application/xml",
                                         "X-Auth-Token": self.disabled_token,
                                         "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        content = etree.fromstring(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)
        self.assertEqual('application/xml', content_type(resp))

    def test_user_update_invalid_token_json(self):
        header = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s' % (URL, self.tenant, self.user)

        data = '{"user": { "email": "updatedjoeuser@rackspace.com"}}'
        resp, content = header.request(url, "PUT", body=data,
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.invalid_token})
        resp_val = int(resp['status'])

        content = json.loads(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, resp_val)

    def test_user_update_invalid_token_xml(self):
        header = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s' % (URL, self.tenant, self.user)
        data = '<?xml version="1.0" encoding="UTF-8"?> \
                <user xmlns="http://docs.openstack.org/idm/api/v1.0" \
                email="updatedjoeuser@rackspace.com" />'
        resp, content = header.request(url, "PUT", body=data,
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.invalid_token,
                                           "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        content = etree.fromstring(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, resp_val)
        self.assertEqual('application/xml', content_type(resp))

    def test_user_update_missing_token_json(self):
        header = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s' % (URL, self.tenant, self.user)
        data = '{"user": { "email": "updatedjoeuser@rackspace.com"}}'
        resp, content = header.request(url, "PUT", body=data,
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.missing_token})
        resp_val = int(resp['status'])
        content = json.loads(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, resp_val)

    def test_user_update_missing_token_xml(self):
        header = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s' % (URL, self.tenant, self.user)
        data = '<?xml version="1.0" encoding="UTF-8"?> \
                <user xmlns="http://docs.openstack.org/idm/api/v1.0" \
                email="updatedjoeuser@rackspace.com" />'
        resp, content = header.request(url, "PUT", body=data,
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.missing_token,
                                           "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        content = etree.fromstring(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, resp_val)
        self.assertEqual('application/xml', content_type(resp))


class set_password_test(user_test):

    def test_user_password_json(self):
        header = httplib2.Http(".cache")
        resp, content = create_user(self.tenant, self.user,
                                    str(self.auth_token))
        url = '%stenants/%s/users/%s/password' % (URL, self.tenant, self.user)
        data = '{"user": { "password": "p@ssword"}}'
        resp, content = header.request(url, "PUT", body=data,
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.auth_token})
        resp_val = int(resp['status'])
        content = json.loads(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        delete_user(self.tenant, self.user, str(self.auth_token))
        self.assertEqual(200, resp_val)
        self.assertEqual('p@ssword', content['user']['password'])

    def test_user_password_xml(self):
        header = httplib2.Http(".cache")
        resp, content = create_user_xml(self.tenant, self.user,
                                        str(self.auth_token))
        url = '%stenants/%s/users/%s/password' % (URL, self.tenant, self.user)
        data = '<?xml version="1.0" encoding="UTF-8"?> \
                <user xmlns="http://docs.openstack.org/idm/api/v1.0" \
                password="p@ssword" />'
        resp, content = header.request(url, "PUT", body=data,
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.auth_token,
                                           "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        content = etree.fromstring(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        delete_user(self.tenant, self.user, str(self.auth_token))
        self.assertEqual(200, resp_val)
        self.assertEqual('p@ssword', content.get("password"))
        self.assertEqual('application/xml', content_type(resp))

    def test_user_password_user_disabled_json(self):
        header = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s/password' \
                       % (URL, self.tenant, self.userdisabled)
        data = '{"user": { "password": "p@ssword"}}'
        resp, content = header.request(url, "PUT", body=data,
                                headers={"Content-Type": "application/json",
                                    "X-Auth-Token": self.auth_token})
        resp_val = int(resp['status'])
        content = json.loads(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)

    def test_user_password_user_disabled_xml(self):
        header = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s' % (URL, self.tenant, self.userdisabled)
        data = '<?xml version="1.0" encoding="UTF-8"?> \
                <user xmlns="http://docs.openstack.org/idm/api/v1.0" \
                password="p@ssword" />'
        resp, content = header.request(url, "PUT", body=data,
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.auth_token,
                                           "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        content = etree.fromstring(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)
        self.assertEqual('application/xml', content_type(resp))

    def test_user_password_bad_request_json(self):
        header = httplib2.Http(".cache")
        resp, content = create_user(self.tenant, self.user,
                                    str(self.auth_token))
        url = '%stenants/%s/users/%s/password' % (URL, self.tenant, self.user)
        data = '{"user_bad": { "password": "p@ssword"}}'
        resp, content = header.request(url, "PUT", body=data,
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.auth_token})
        resp_val = int(resp['status'])
        content = json.loads(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        delete_user(self.tenant, self.user, str(self.auth_token))
        self.assertEqual(400, resp_val)

    def test_user_password_bad_request_xml(self):
        header = httplib2.Http(".cache")
        resp, content = create_user_xml(self.tenant, self.user,
                                        str(self.auth_token))
        url = '%stenants/%s/users/%s/password' % (URL, self.tenant, self.user)
        data = '<?xml version="1.0" encoding="UTF-8"?> \
                user xmlns="http://docs.openstack.org/idm/api/v1.0" \
                password="p@ssword" />'
        resp, content = header.request(url, "PUT", body=data,
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.auth_token,
                                           "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        content = etree.fromstring(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        delete_user(self.tenant, self.user, str(self.auth_token))
        self.assertEqual(400, resp_val)
        self.assertEqual('application/xml', content_type(resp))

    def test_user_password_expired_token_json(self):
        header = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s/password' % (URL, self.tenant, self.user)
        data = '{"user": { "password": "p@ssword"}}'
        resp, content = header.request(url, "PUT", body=data,
                                  headers={"Content-Type": "application/json",
                                         "X-Auth-Token": self.exp_auth_token})
        resp_val = int(resp['status'])
        content = json.loads(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)

    def test_user_password_expired_token_xml(self):
        header = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s/password' % (URL, self.tenant, self.user)
        data = '<?xml version="1.0" encoding="UTF-8"?> \
                <user xmlns="http://docs.openstack.org/idm/api/v1.0" \
                password="p@ssword" />'
        resp, content = header.request(url, "PUT", body=data,
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.exp_auth_token,
                                           "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        content = etree.fromstring(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)
        self.assertEqual('application/xml', content_type(resp))

    def test_user_password_disabled_token_json(self):
        header = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s/password' % (URL, self.tenant, self.user)
        data = '{"user": { "password": "p@ssword"}}'
        resp, content = header.request(url, "PUT", body=data,
                                  headers={"Content-Type": "application/json",
                                          "X-Auth-Token": self.disabled_token})
        resp_val = int(resp['status'])
        content = json.loads(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)

    def test_user_password_disabled_token_xml(self):
        header = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s/password' % (URL, self.tenant, self.user)
        data = '<?xml version="1.0" encoding="UTF-8"?> \
                <user xmlns="http://docs.openstack.org/idm/api/v1.0" \
                password="p@ssword" />'
        resp, content = header.request(url, "PUT", body=data,
                                headers={"Content-Type": "application/xml",
                                         "X-Auth-Token": self.disabled_token,
                                         "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        content = etree.fromstring(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)
        self.assertEqual('application/xml', content_type(resp))

    def test_user_password_invalid_token_json(self):
        header = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s/password' % (URL, self.tenant, self.user)
        data = '{"user": { "password": "p@ssword"}}'
        resp, content = header.request(url, "PUT", body=data,
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.invalid_token})
        resp_val = int(resp['status'])
        content = json.loads(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, resp_val)

    def test_user_password_invalid_token_xml(self):
        header = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s/password' % (URL, self.tenant, self.user)
        data = '<?xml version="1.0" encoding="UTF-8"?> \
                <user xmlns="http://docs.openstack.org/idm/api/v1.0" \
                password="p@ssword" />'
        resp, content = header.request(url, "PUT", body=data,
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.invalid_token,
                                           "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        content = etree.fromstring(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, resp_val)
        self.assertEqual('application/xml', content_type(resp))

    def test_user_password_missing_token_json(self):
        header = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s/password' % (URL, self.tenant, self.user)
        data = '{"user": { "password": "p@ssword"}}'
        resp, content = header.request(url, "PUT", body=data,
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.missing_token})
        resp_val = int(resp['status'])
        content = json.loads(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, resp_val)

    def test_user_password_missing_token_xml(self):
        header = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s/password' % (URL, self.tenant, self.user)
        data = '<?xml version="1.0" encoding="UTF-8"?> \
                <user xmlns="http://docs.openstack.org/idm/api/v1.0" \
                password="p@ssword" />'
        resp, content = header.request(url, "PUT", body=data,
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.missing_token,
                                           "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        content = etree.fromstring(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, resp_val)
        self.assertEqual('application/xml', content_type(resp))


class set_enabled_test(user_test):

    def test_user_enabled_json(self):
        header = httplib2.Http(".cache")
        resp, content = create_user(self.tenant, self.user,
                                    str(self.auth_token))
        url = '%stenants/%s/users/%s/enabled' % (URL, self.tenant, self.user)
        data = {"user": {"enabled": True}}
        resp, content = header.request(url, "PUT", body=json.dumps(data),
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.auth_token})
        resp_val = int(resp['status'])

        content = json.loads(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        delete_user(self.tenant, self.user, str(self.auth_token))
        self.assertEqual(200, resp_val)
        self.assertEqual(True, content['user']['enabled'])

    def test_user_enabled_xml(self):
        header = httplib2.Http(".cache")
        resp, content = create_user_xml(self.tenant, self.user,
                                        str(self.auth_token))
        url = '%stenants/%s/users/%s/enabled' % (URL, self.tenant, self.user)
        data = '<?xml version="1.0" encoding="UTF-8"?> \
                <user xmlns="http://docs.openstack.org/idm/api/v1.0" \
                enabled="true" />'
        resp, content = header.request(url, "PUT", body=data,
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.auth_token,
                                           "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        content = etree.fromstring(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        delete_user(self.tenant, self.user, str(self.auth_token))
        self.assertEqual(200, resp_val)
        self.assertEqual('true', content.get("enabled"))
        self.assertEqual('application/xml', content_type(resp))

    def test_user_enabled_bad_request_json(self):
        header = httplib2.Http(".cache")
        resp, content = create_user(self.tenant, self.user,
                                    str(self.auth_token))
        url = '%stenants/%s/users/%s/enabled' % (URL, self.tenant, self.user)
        data = '{"user_bad": { "enabled": true}}'
        resp, content = header.request(url, "PUT", body=data,
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.auth_token})
        resp_val = int(resp['status'])
        content = json.loads(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        delete_user(self.tenant, self.user, str(self.auth_token))
        self.assertEqual(400, resp_val)

    def test_user_enabled_bad_request_xml(self):
        header = httplib2.Http(".cache")
        resp, content = create_user_xml(self.tenant, self.user,
                                        str(self.auth_token))
        url = '%stenants/%s/users/%s/enabled' % (URL, self.tenant, self.user)
        data = '<?xml version="1.0" encoding="UTF-8"?> \
                user xmlns="http://docs.openstack.org/idm/api/v1.0" \
                enabled="true" />'
        resp, content = header.request(url, "PUT", body=data,
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.auth_token,
                                           "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        content = etree.fromstring(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        delete_user(self.tenant, self.user, str(self.auth_token))
        self.assertEqual(400, resp_val)
        self.assertEqual('application/xml', content_type(resp))

    def test_user_enabled_expired_token_json(self):
        header = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s/enabled' % (URL, self.tenant, self.user)
        data = '{"user": { "enabled": true}}'
        resp, content = header.request(url, "PUT", body=data,
                                  headers={"Content-Type": "application/json",
                                         "X-Auth-Token": self.exp_auth_token})
        resp_val = int(resp['status'])
        content = json.loads(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)

    def test_user_enabled_expired_token_xml(self):
        header = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s/enabled' % (URL, self.tenant, self.user)
        data = '<?xml version="1.0" encoding="UTF-8"?> \
                <user xmlns="http://docs.openstack.org/idm/api/v1.0" \
                enabled="true" />'
        resp, content = header.request(url, "PUT", body=data,
                                headers={"Content-Type": "application/xml",
                                         "X-Auth-Token": self.exp_auth_token,
                                         "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        content = etree.fromstring(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)
        self.assertEqual('application/xml', content_type(resp))

    def test_user_enabled_disabled_token_json(self):
        header = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s/enabled' % (URL, self.tenant, self.user)
        data = '{"user": { "enabled": true}}'
        resp, content = header.request(url, "PUT", body=data,
                                  headers={"Content-Type": "application/json",
                                         "X-Auth-Token": self.disabled_token})
        resp_val = int(resp['status'])
        content = json.loads(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)

    def test_user_enabled_disabled_token_xml(self):
        header = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s/enabled' % (URL, self.tenant, self.user)
        data = '<?xml version="1.0" encoding="UTF-8"?> \
                <user xmlns="http://docs.openstack.org/idm/api/v1.0" \
                enabled="true" />'
        resp, content = header.request(url, "PUT", body=data,
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.disabled_token,
                                           "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        content = etree.fromstring(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)
        self.assertEqual('application/xml', content_type(resp))

    def test_user_enabled_invalid_token_json(self):
        header = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s/enabled' % (URL, self.tenant, self.user)
        data = '{"user": { "enabled": true}}'
        resp, content = header.request(url, "PUT", body=data,
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.invalid_token})
        resp_val = int(resp['status'])
        content = json.loads(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, resp_val)

    def test_user_enabled_invalid_token_xml(self):
        header = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s/enabled' % (URL, self.tenant, self.user)
        data = '<?xml version="1.0" encoding="UTF-8"?> \
                <user xmlns="http://docs.openstack.org/idm/api/v1.0" \
                enabled="true" />'
        resp, content = header.request(url, "PUT", body=data,
                                headers={"Content-Type": "application/xml",\
                                         "X-Auth-Token": self.invalid_token,
                                         "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        content = etree.fromstring(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, resp_val)
        self.assertEqual('application/xml', content_type(resp))

    def test_user_enabled_missing_token_json(self):
        header = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s/enabled' % (URL, self.tenant, self.user)
        data = '{"user": { "enabled": true}}'
        resp, content = header.request(url, "PUT", body=data,
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.missing_token})
        resp_val = int(resp['status'])
        content = json.loads(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, resp_val)

    def test_user_enabled_missing_token_xml(self):
        header = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s/password' % (URL, self.tenant, self.user)
        data = '<?xml version="1.0" encoding="UTF-8"?> \
                <user xmlns="http://docs.openstack.org/idm/api/v1.0" \
                enabled="true" />'
        resp, content = header.request(url, "PUT", body=data,
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.missing_token,
                                           "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        content = etree.fromstring(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, resp_val)
        self.assertEqual('application/xml', content_type(resp))

if __name__ == '__main__':
    unittest.main()
