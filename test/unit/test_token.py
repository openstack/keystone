import os
import sys
# Need to access identity module
sys.path.append(os.path.abspath(os.path.join(os.path.abspath(__file__),
                                '..', '..', '..', '..', 'keystone')))
import unittest
import httplib2
import test_common as utils


class validate_token(unittest.TestCase):

    def setUp(self):
        self.token = utils.get_token('joeuser', 'secrete', 'token')
        self.tenant = utils.get_tenant()
        self.user = utils.get_user()
        self.userdisabled = utils.get_userdisabled()
        self.auth_token = utils.get_auth_token()
        self.exp_auth_token = utils.get_exp_auth_token()
        self.disabled_token = utils.get_disabled_token()

    def tearDown(self):
        utils.delete_token(self.token, self.auth_token)

    def test_validate_token_true(self):
        header = httplib2.Http(".cache")

        url = '%stoken/%s?belongsTo=%s' % (utils.URL, self.token, self.tenant)
        resp, content = header.request(url, "GET", body='',
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.auth_token})
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(200, int(resp['status']))
        self.assertEqual('application/json', utils.content_type(resp))

    def test_validate_token_true_xml(self):
        header = httplib2.Http(".cache")
        url = '%stoken/%s?belongsTo=%s' % (utils.URL, self.token, self.tenant)
        resp, content = header.request(url, "GET", body='',
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.auth_token,
                                           "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(200, int(resp['status']))
        self.assertEqual('application/xml', utils.content_type(resp))

    def test_validate_token_expired(self):
        header = httplib2.Http(".cache")
        url = '%stoken/%s?belongsTo=%s' % (utils.URL, self.exp_auth_token,
                                           self.tenant)
        resp, content = header.request(url, "GET", body='',
                                  headers={"Content-Type": "application/json",
                                         "X-Auth-Token": self.exp_auth_token})
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(resp['status']))
        self.assertEqual('application/json', utils.content_type(resp))

    def test_validate_token_expired_xml(self):
        header = httplib2.Http(".cache")

        url = '%stoken/%s?belongsTo=%s' % (utils.URL, self.exp_auth_token,
                                           self.tenant)
        resp, content = header.request(url, "GET", body='',
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.exp_auth_token,
                                           "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(resp['status']))
        self.assertEqual('application/xml', utils.content_type(resp))

    def test_validate_token_invalid(self):
        header = httplib2.Http(".cache")
        url = '%stoken/%s?belongsTo=%s' % (utils.URL, 'NonExistingToken',
                                           self.tenant)
        resp, content = header.request(url, "GET", body='',
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.auth_token})

        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, int(resp['status']))
        self.assertEqual('application/json', utils.content_type(resp))

    def test_validate_token_invalid_xml(self):
        header = httplib2.Http(".cache")
        url = '%stoken/%s?belongsTo=%s' % (utils.URL, 'NonExistingToken',
                                           self.tenant)
        resp, content = header.request(url, "GET", body='',
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.auth_token})
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, int(resp['status']))
        self.assertEqual('application/json', utils.content_type(resp))


if __name__ == '__main__':
    unittest.main()
