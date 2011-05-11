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
import unittest
from webtest import TestApp
from test_common import *


class tenant_test(unittest.TestCase):

    def setUp(self):
        self.token = get_token('joeuser', 'secrete', 'token')
        self.tenant = get_tenant()
        self.user = get_user()
        self.userdisabled = get_userdisabled()
        self.auth_token = get_auth_token()
        self.exp_auth_token = get_exp_auth_token()
        self.disabled_token = get_disabled_token()

    def tearDown(self):
        resp, content = delete_tenant(self.tenant, self.auth_token)


class create_tenant_test(tenant_test):

    def test_tenant_create(self):
        resp, content = delete_tenant('test_tenant', str(self.auth_token))
        resp, content = create_tenant('test_tenant', str(self.auth_token))
        self.tenant = 'test_tenant'

        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')

        if int(resp['status']) not in (200, 201):

            self.fail('Failed due to %d' % int(resp['status']))

    def test_tenant_create_xml(self):
        resp, content = delete_tenant_xml('test_tenant', str(self.auth_token))
        resp, content = create_tenant_xml('test_tenant', str(self.auth_token))
        self.tenant = 'test_tenant'
        content = etree.fromstring(content)
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')

        if int(resp['status']) not in (200, 201):

            self.fail('Failed due to %d' % int(resp['status']))

    def test_tenant_create_again(self):

        resp, content = create_tenant("test_tenant", str(self.auth_token))
        resp, content = create_tenant("test_tenant", str(self.auth_token))
        if int(resp['status']) == 200:
            self.tenant = content['tenant']['id']
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(409, int(resp['status']))
        if int(resp['status']) == 200:
            self.tenant = content['tenant']['id']

    def test_tenant_create_again_xml(self):

        resp, content = create_tenant_xml("test_tenant", str(self.auth_token))
        resp, content = create_tenant_xml("test_tenant", str(self.auth_token))
        content = etree.fromstring(content)
        if int(resp['status']) == 200:
            self.tenant = content.get("id")

        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(409, int(resp['status']))
        if int(resp['status']) == 200:
            self.tenant = content.get("id")

    def test_tenant_create_forbidden_token(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant("test_tenant", str(self.auth_token))
        if int(resp['status']) == 200:
            self.tenant = content['tenant']['id']

        url = '%stenants' % (URL)
        body = {"tenant": {"id": self.tenant,
                           "description": "A description ...",
                           "enabled": True}}
        resp, content = h.request(url, "POST", body=json.dumps(body),
                                  headers={"Content-Type": "application/json",
                                         "X-Auth-Token": self.token})

        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, int(resp['status']))

    def test_tenant_create_forbidden_token_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant_xml("test_tenant", str(self.auth_token))
        content = etree.fromstring(content)
        if int(resp['status']) == 200:
            self.tenant = content.get('id')

        url = '%stenants' % (URL)
        body = '<?xml version="1.0" encoding="UTF-8"?> \
            <tenant xmlns="http://docs.openstack.org/idm/api/v1.0" \
            enabled="true" id="%s"> \
            <description>A description...</description> \
            </tenant>' % self.tenant
        resp, content = h.request(url, "POST", body=body,
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.token,
                                           "ACCEPT": "application/xml"})

        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, int(resp['status']))

    def test_tenant_create_expired_token(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant("test_tenant", str(self.auth_token))
        if int(resp['status']) == 200:
            self.tenant = content['tenant']['id']

        url = '%stenants' % (URL)
        body = {"tenant": {"id": self.tenant,
                           "description": "A description ...",
                           "enabled": True}}
        resp, content = h.request(url, "POST", body=json.dumps(body),
                                headers={"Content-Type": "application/json",
                                         "X-Auth-Token": self.exp_auth_token})

        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(resp['status']))

    def test_tenant_create_expired_token_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant_xml("test_tenant", str(self.auth_token))
        content = etree.fromstring(content)
        if int(resp['status']) == 200:
            self.tenant = content.get('id')

        url = '%stenants' % (URL)
        body = '<?xml version="1.0" encoding="UTF-8"?> \
            <tenant xmlns="http://docs.openstack.org/idm/api/v1.0" \
            enabled="true" id="%s"> \
            <description>A description...</description> \
            </tenant>' % self.tenant

        resp, content = h.request(url, "POST", body=body,
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.exp_auth_token,
                                           "ACCEPT": "application/xml"})

        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(resp['status']))

    def test_tenant_create_missing_token(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant("test_tenant", str(self.auth_token))
        if int(resp['status']) == 200:
            self.tenant = content['tenant']['id']

        url = '%stenants' % (URL)
        body = {"tenant": {"id": self.tenant,
                           "description": "A description ...",
                           "enabled": True}}
        resp, content = h.request(url, "POST", body=json.dumps(body),
                                headers={"Content-Type": "application/json"})

        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, int(resp['status']))

    def test_tenant_create_missing_token_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant_xml("test_tenant", str(self.auth_token))
        content = etree.fromstring(content)
        if int(resp['status']) == 200:
            self.tenant = content.get('id')

        url = '%stenants' % (URL)

        body = '<?xml version="1.0" encoding="UTF-8"?> \
            <tenant xmlns="http://docs.openstack.org/idm/api/v1.0" \
            enabled="true" id="%s"> \
            <description>A description...</description> \
            </tenant>' % self.tenant
        resp, content = h.request(url, "POST", body=body,
                                  headers={"Content-Type": "application/xml",
                                           "ACCEPT": "application/xml"})

        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, int(resp['status']))

    def test_tenant_create_disabled_token(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant("test_tenant", str(self.auth_token))
        if int(resp['status']) == 200:
            self.tenant = content['tenant']['id']

        url = '%stenants' % (URL)
        body = '{"tenant": { "id": "%s", \
                "description": "A description ...", "enabled"\
                :true  } }' % self.tenant
        resp, content = h.request(url, "POST", body=body,
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": \
                                                   self.disabled_token})

        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(resp['status']))

    def test_tenant_create_disabled_token_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant_xml("test_tenant", str(self.auth_token))
        content = etree.fromstring(content)
        if int(resp['status']) == 200:
            self.tenant = content.get('id')

        url = '%stenants' % (URL)
        body = '<?xml version="1.0" encoding="UTF-8"?> \
            <tenant xmlns="http://docs.openstack.org/idm/api/v1.0" \
            enabled="true" id="%s"> \
            <description>A description...</description> \
            </tenant>' % self.tenant
        resp, content = h.request(url, "POST", body=body,
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.disabled_token,
                                           "ACCEPT": "application/xml"})

        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(resp['status']))

    def test_tenant_create_invalid_token(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant("test_tenant", str(self.auth_token))
        if int(resp['status']) == 200:
            self.tenant = content['tenant']['id']

        url = '%stenants' % (URL)
        body = '{"tenant": { "id": "%s", \
                "description": "A description ...", "enabled"\
                :true  } }' % self.tenant
        resp, content = h.request(url, "POST", body=body,
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": 'nonexsitingtoken'})

        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, int(resp['status']))

    def test_tenant_create_invalid_token_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant_xml("test_tenant", str(self.auth_token))
        content = etree.fromstring(content)
        if int(resp['status']) == 200:
            self.tenant = content.get('id')

        url = '%stenants' % (URL)
        body = '<?xml version="1.0" encoding="UTF-8"?> \
            <tenant xmlns="http://docs.openstack.org/idm/api/v1.0" \
            enabled="true" id="%s"> \
            <description>A description...</description> \
            </tenant>' % self.tenant
        resp, content = h.request(url, "POST", body=body,
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": 'nonexsitingtoken',
                                           "ACCEPT": "application/xml"})

        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, int(resp['status']))


class get_tenants_test(tenant_test):

    def test_get_tenants(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        url = '%stenants' % (URL)
        #test for Content-Type = application/json
        resp, content = h.request(url, "GET", body='{}',
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": \
                                                   self.auth_token})
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(200, int(resp['status']))

    def test_get_tenants_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        url = '%stenants' % (URL)
        #test for Content-Type = application/json
        resp, content = h.request(url, "GET", body='',
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.auth_token,
                                           "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(200, int(resp['status']))

    def test_get_tenants_unauthorized_token(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        url = '%stenants' % (URL)
        #test for Content-Type = application/json
        resp, content = h.request(url, "GET", body='{}',
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.token})
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, int(resp['status']))

    def test_get_tenants_unauthorized_token_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        url = '%stenants' % (URL)
        #test for Content-Type = application/json
        resp, content = h.request(url, "GET", body='',
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.token,
                                           "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, int(resp['status']))

    def test_get_tenants_exp_token(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        url = '%stenants' % (URL)
        #test for Content-Type = application/json
        resp, content = h.request(url, "GET", body='{}',
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": \
                                                   self.exp_auth_token})
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(resp['status']))

    def test_get_tenants_exp_token_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        url = '%stenants' % (URL)
        #test for Content-Type = application/json
        resp, content = h.request(url, "GET", body='',
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.exp_auth_token,
                                           "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(resp['status']))


class get_tenant_test(tenant_test):

    def test_get_tenant(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        url = '%stenants/%s' % (URL, self.tenant)
        #test for Content-Type = application/json
        resp, content = h.request(url, "GET", body='{}',
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.auth_token})
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(200, int(resp['status']))

    def test_get_tenant_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        url = '%stenants/%s' % (URL, self.tenant)
        #test for Content-Type = application/json
        resp, content = h.request(url, "GET", body='',
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.auth_token,
                                           "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(200, int(resp['status']))

    def test_get_tenant_bad(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        url = '%stenants/%s' % (URL, 'tenant_bad')
        #test for Content-Type = application/json
        resp, content = h.request(url, "GET", body='{',
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.auth_token})
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, int(resp['status']))

    def test_get_tenant_bad_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        url = '%stenants/%s' % (URL, 'tenant_bad')
        #test for Content-Type = application/json
        resp, content = h.request(url, "GET", body='{',
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.auth_token,
                                           "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, int(resp['status']))

    def test_get_tenant_not_found(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        url = '%stenants/NonexistingID' % (URL)
        #test for Content-Type = application/json
        resp, content = h.request(url, "GET", body='{}',
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.auth_token})
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, int(resp['status']))

    def test_get_tenant_not_found_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        url = '%stenants/NonexistingID' % (URL)
        #test for Content-Type = application/json
        resp, content = h.request(url, "GET", body='',
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.auth_token,
                                           "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, int(resp['status']))


class update_tenant_test(tenant_test):

    def test_update_tenant(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        url = '%stenants/%s' % (URL, self.tenant)
        data = '{"tenant": { "description": "A NEW description..." ,\
                "enabled":true }}'
        #test for Content-Type = application/json
        resp, content = h.request(url, "PUT", body=data,
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.auth_token})
        body = json.loads(content)
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(200, int(resp['status']))
        self.assertEqual(int(self.tenant), int(body['tenant']['id']))
        self.assertEqual('A NEW description...', body['tenant']['description'])

    def test_update_tenant_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant_xml(self.tenant, str(self.auth_token))
        url = '%stenants/%s' % (URL, self.tenant)
        data = '<?xml version="1.0" encoding="UTF-8"?> \
             <tenant xmlns="http://docs.openstack.org/idm/api/v1.0" \
             enabled="true"> \
             <description>A NEW description...</description> \
             </tenant>'

        #test for Content-Type = application/json
        resp, content = h.request(url, "PUT", body=data,
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.auth_token,
                                           "ACCEPT": "application/xml"})
        body = etree.fromstring(content)
        desc = body.find("{http://docs.openstack.org/idm/api/v1.0}description")
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(200, int(resp['status']))
        self.assertEqual(int(self.tenant), int(body.get('id')))
        self.assertEqual('A NEW description...', desc.text)

    def test_update_tenant_bad(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        url = '%stenants/%s' % (URL, self.tenant)
        data = '{"tenant": { "description_bad": "A NEW description...",\
                "enabled":true  }}'
        #test for Content-Type = application/json

        resp, content = h.request(url, "PUT", body=data,
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.auth_token})
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(400, int(resp['status']))

    def test_update_tenant_bad_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        url = '%stenants/%s' % (URL, self.tenant)
        data = '<?xml version="1.0" encoding="UTF-8"?> \
             <tenant xmlns="http://docs.openstack.org/idm/api/v1.0" \
             enabled="true"> \
             <description_bad>A NEW description...</description> \
             </tenant>'
        #test for Content-Type = application/json
        resp, content = h.request(url, "PUT", body=data,
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.auth_token,
                                           "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(400, int(resp['status']))

    def test_update_tenant_not_found(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        url = '%stenants/NonexistingID' % (URL)
        data = '{"tenant": { "description": "A NEW description...",\
                "enabled":true  }}'
        #test for Content-Type = application/json
        resp, content = h.request(url, "GET", body=data,
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.auth_token})
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, int(resp['status']))

    def test_update_tenant_not_found_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        url = '%stenants/NonexistingID' % (URL)
        data = '<?xml version="1.0" encoding="UTF-8"?> \
             <tenant xmlns="http://docs.openstack.org/idm/api/v1.0" \
             enabled="true"> \
             <description_bad>A NEW description...</description> \
             </tenant>'
        #test for Content-Type = application/json
        resp, content = h.request(url, "GET", body=data,
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.auth_token,
                                           "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, int(resp['status']))


class delete_tenant_test(tenant_test):

    def test_delete_tenant_not_found(self):
        #resp,content=create_tenant("test_tenant_delete", str(self.auth_token))
        resp, content = delete_tenant("test_tenant_delete111",
                                      str(self.auth_token))
        self.assertEqual(404, int(resp['status']))

    def test_delete_tenant_not_found_xml(self):
        #resp,content=create_tenant("test_tenant_delete", str(self.auth_token))
        resp, content = delete_tenant_xml("test_tenant_delete111",
                                          str(self.auth_token))
        self.assertEqual(404, int(resp['status']))

    def test_delete_tenant(self):
        resp, content = create_tenant("test_tenant_delete",
                                      str(self.auth_token))
        resp, content = delete_tenant("test_tenant_delete",
                                      str(self.auth_token))
        self.assertEqual(204, int(resp['status']))

    def test_delete_tenant_xml(self):
        resp, content = create_tenant_xml("test_tenant_delete",
                                          str(self.auth_token))
        resp, content = delete_tenant_xml("test_tenant_delete",
                                          str(self.auth_token))
        self.assertEqual(204, int(resp['status']))

if __name__ == '__main__':
    unittest.main()
