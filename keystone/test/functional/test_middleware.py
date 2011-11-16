import unittest2 as unittest
from webob import Request, Response

import keystone.common.exception
from keystone.test.functional import common
from keystone.middleware import auth_token


class HeaderApp(object):
    """
    Dummy WSGI app the returns HTTP headers in the body

    This is useful for making sure the headers we want
    aer being passwed down to the downstream WSGI app.
    """
    def __init__(self):
        pass

    def __call__(self, env, start_response):
        self.request = Request.blank('', environ=env)
        body = ''
        for key in env:
            if key.startswith('HTTP_'):
                body += '%s: %s\n' % (key, env[key])
        return Response(status="200 OK",
                        body=body)(env, start_response)


class BlankApp(object):
    """
    Dummy WSGI app - does not do anything
    """
    def __init__(self):
        pass

    def __call__(self, env, start_response):
        self.request = Request.blank('', environ=env)
        return Response(status="200 OK",
                        body={})(env, start_response)


class TestMiddleware(common.FunctionalTestCase):
    """
    Tests for  Keystone WSGI middleware.
    """

    def setUp(self):
        super(TestMiddleware, self).setUp()
        settings = {'delay_auth_decision': '0',
                'auth_host': '127.0.0.1',
                'auth_port': '35357',
                'auth_protocol': 'http',
                'auth_uri': 'http://localhost:35357/',
                'admin_token': '999888777666'}
        cert_file = common.isSsl()
        if cert_file:
            settings['auth_protocol'] = 'https'
            settings['certfile'] = cert_file
            settings['auth_uri'] = 'https://localhost:35357/'
        self.test_middleware = \
            auth_token.filter_factory(settings)(HeaderApp())

        password = common.unique_str()
        self.tenant = self.create_tenant().json['tenant']
        self.user = self.create_user(user_password=password,
            tenant_id=self.tenant['id']).json['user']
        self.user['password'] = password

        self.services = {}
        self.endpoint_templates = {}
        for x in range(0, 5):
            self.services[x] = self.create_service().json['OS-KSADM:service']
            self.endpoint_templates[x] = self.create_endpoint_template(
                name=self.services[x]['name'], \
                type=self.services[x]['type']).\
                json['OS-KSCATALOG:endpointTemplate']
            self.create_endpoint_for_tenant(self.tenant['id'],
                self.endpoint_templates[x]['id'])

        r = self.authenticate(self.user['name'], self.user['password'],
            self.tenant['id'], assert_status=200)
        self.user_token = r.json['access']['token']['id']

    def test_401_without_token(self):
        resp = Request.blank('/').get_response(self.test_middleware)
        self.assertEquals(resp.status_int, 401)
        headers = resp.headers
        self.assertTrue("WWW-Authenticate" in headers)
        if common.isSsl():
            self.assertEquals(headers['WWW-Authenticate'],
                                    "Keystone uri='https://localhost:35357/'")
        else:
            self.assertEquals(headers['WWW-Authenticate'],
                                    "Keystone uri='http://localhost:35357/'")

    def test_401_bad_token(self):
        resp = Request.blank('/',
            headers={'X-Auth-Token': 'MADE_THIS_UP'}) \
            .get_response(self.test_middleware)
        self.assertEquals(resp.status_int, 401)

    def test_200_good_token(self):
        resp = Request.blank('/',
            headers={'X-Auth-Token': self.user_token}) \
            .get_response(self.test_middleware)

        self.assertEquals(resp.status_int, 200)

        headers = resp.body.split('\n')

        header = "HTTP_X_IDENTITY_STATUS: Confirmed"
        self.assertTrue(header in headers)

        header = "HTTP_X_USER_ID: %s" % self.user['id']
        self.assertTrue(header in headers)

        header = "HTTP_X_USER_NAME: %s" % self.user['name']
        self.assertTrue(header in headers)

        header = "HTTP_X_TENANT_ID: %s" % self.tenant['id']
        self.assertTrue(header in headers)

        header = "HTTP_X_TENANT_NAME: %s" % self.tenant['name']
        self.assertTrue(header in headers)

        # These are here for legacy support and should be removed by F
        header = "HTTP_X_TENANT: %s" % self.tenant['id']
        self.assertTrue(header in headers)

        header = "HTTP_X_USER: %s" % self.user['id']
        self.assertTrue(header in headers)


if __name__ == '__main__':
    unittest.main()
