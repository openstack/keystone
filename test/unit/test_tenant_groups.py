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



class tenant_group_test(unittest.TestCase):

    def setUp(self):
        self.token = get_token('joeuser', 'secrete', 'token')
        self.tenant = get_tenant()
        self.user = get_user()
        self.userdisabled = get_userdisabled()
        self.auth_token = get_auth_token()
        self.exp_auth_token = get_exp_auth_token()
        self.disabled_token = get_disabled_token()
        self.tenant_group = 'test_tenant_group_add'

    def tearDown(self):
        resp, content = delete_tenant_group(self.tenant_group,
                                            self.tenant,
                                            self.auth_token)
        resp, content = delete_tenant(self.tenant, self.auth_token)


class create_tenant_group_test(tenant_group_test):

    def test_tenant_group_create(self):

        resp, content = delete_tenant(self.tenant, str(self.auth_token))
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        respG, contentG = delete_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))
        respG, contentG = create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))

        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        if int(respG['status']) not in (200, 201):
            self.fail('Failed due to %d' % int(respG['status']))

    def test_tenant_group_create_xml(self):
        resp, content = delete_tenant_xml(self.tenant, str(self.auth_token))
        resp, content = create_tenant_xml(self.tenant, str(self.auth_token))
        respG, contentG = delete_tenant_group_xml(self.tenant_group,
                                                  self.tenant,
                                                  str(self.auth_token))
        respG, contentG = create_tenant_group_xml(self.tenant_group,
                                                  self.tenant,
                                                  str(self.auth_token))
        self.tenant = self.tenant
        self.tenant_group = self.tenant_group
        content = etree.fromstring(content)
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        if int(respG['status']) not in (200, 201):
            self.fail('Failed due to %d' % int(respG['status']))

    def test_tenant_group_create_again(self):
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        respG, contentG = create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))
        respG, contentG = create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))
        if int(respG['status']) == 200:
            self.tenant = content['tenant']['id']
            self.tenant_group = contentG['group']['id']
        if int(respG['status']) == 500:
            self.fail('IDM fault')
        elif int(respG['status']) == 503:
            self.fail('Service Not Available')
            self.assertEqual(409, int(respG['status']))
        if int(respG['status']) == 200:
            self.tenant = content['tenant']['id']
            self.tenant_group = contentG['group']['id']

    def test_tenant_group_create_again_xml(self):
        resp, content = create_tenant_xml("test_tenant", str(self.auth_token))
        respG, contentG = create_tenant_group_xml(self.tenant_group,
                                                  self.tenant,
                                                  str(self.auth_token))
        respG, contentG = create_tenant_group_xml(self.tenant_group,
                                                  self.tenant,
                                                  str(self.auth_token))
        content = etree.fromstring(content)
        contentG = etree.fromstring(contentG)
        if int(respG['status']) == 200:
            self.tenant = content.get("id")
            self.tenant_group = contentG.get("id")
        if int(respG['status']) == 500:
            self.fail('IDM fault')
        elif int(respG['status']) == 503:
            self.fail('Service Not Available')
            self.assertEqual(409, int(respG['status']))
        if int(respG['status']) == 200:
            self.tenant = content.get("id")
            self.tenant_group = contentG.get("id")

    def test_tenant_group_create_unauthorized_token(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        respG, contentG = create_tenant_group_xml(self.tenant_group,
                                                  self.tenant,
                                                  str(self.auth_token))
        if int(resp['status']) == 200:
            self.tenant = content['tenant']['id']
        if int(respG['status']) == 200:
            self.tenant_group = respG['group']['id']
        url = '%stenant/%s/groups' % (URL, self.tenant)
        body = {"group": {"id": self.tenant_group,
                          "description": "A description ..."}}
        resp, content = h.request(url, "POST", body=json.dumps(body),
                             headers={"Content-Type": "application/json",
                                      "X-Auth-Token": self.token})
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
            self.assertEqual(401, int(resp['status']))

    def test_tenant_group_create_unauthorized_token_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        if int(resp['status']) == 200:
            self.tenant = content['tenant']['id']
        url = '%stenant/%s/groups' % (URL, self.tenant)
        body = '<?xml version="1.0" encoding="UTF-8"?> \
                <group xmlns="http://docs.openstack.org/idm/api/v1.0" \
                id="%s"><description>A description...</description> \
                </group>' % self.tenant_group
        resp, content = h.request(url, "POST", body=body,
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.token,
                                           "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, int(resp['status']))

    def test_tenant_group_create_expired_token(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        if int(resp['status']) == 200:
            self.tenant = content['tenant']['id']
        url = '%stenant/%s/groups' % (URL, self.tenant)
        body = {"group": {"id": self.tenant_group,
                "description": "A description ..."}}
        resp, content = h.request(url, "POST", body=json.dumps(body),
                              headers={"Content-Type": "application/json",
                                       "X-Auth-Token": self.exp_auth_token})
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(resp['status']))

    def test_tenant_group_create_expired_token_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant_xml(self.tenant, str(self.auth_token))
        content = etree.fromstring(content)
        if int(resp['status']) == 200:
            self.tenant = content.get('id')
        url = '%stenant/%s/groups' % (URL, self.tenant)
        body = '<?xml version="1.0" encoding="UTF-8"?> \
                <group xmlns="http://docs.openstack.org/idm/api/v1.0" \
                 id="%s"> \
                <description>A description...</description> \
                </group>' % self.tenant
        resp, content = h.request(url, "POST", body=body,
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.exp_auth_token,
                                           "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(resp['status']))

    def test_tenant_group_create_missing_token(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        if int(resp['status']) == 200:
            self.tenant = content['tenant']['id']
        url = '%stenant/%s/groups' % (URL, self.tenant)
        body = {"group": {"id": self.tenant_group,
                "description": "A description ..."}}
        resp, content = h.request(url, "POST", body=json.dumps(body),
                          headers={"Content-Type": "application/json"})
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, int(resp['status']))


    def test_tenant_group_create_missing_token_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant_xml(self.tenant, str(self.auth_token))
        content = etree.fromstring(content)
        if int(resp['status']) == 200:
            self.tenant = content.get('id')
        url = '%stenant/%s/groups' % (URL, self.tenant)
        body = '<?xml version="1.0" encoding="UTF-8"?> \
                <group xmlns="http://docs.openstack.org/idm/api/v1.0" \
                id="%s"> \
                <description>A description...</description> \
                </group>' % self.tenant_group
        resp, content = h.request(url, "POST", body=body,
                                  headers={"Content-Type": "application/xml",
                                           "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, int(resp['status']))


    def test_tenant_group_create_disabled_token(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        if int(resp['status']) == 200:
            self.tenant = content['tenant']['id']

        url = '%stenant/%s/groups' % (URL, self.tenant)
        body = '{"group": { "id": "%s", \
            "description": "A description ..." } }' % self.tenant_group
        resp, content = h.request(url, "POST", body=body,
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.disabled_token})

        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(resp['status']))

    def test_tenant_group_create_disabled_token_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant_xml(self.tenant, str(self.auth_token))
        content = etree.fromstring(content)
        if int(resp['status']) == 200:
            self.tenant = content.get('id')

        url = '%stenant/%s/groups' % (URL, self.tenant)
        body = '<?xml version="1.0" encoding="UTF-8"?> \
        <group xmlns="http://docs.openstack.org/idm/api/v1.0" \
        id="%s"> \
        <description>A description...</description> \
        </group>' % self.tenant_group
        resp, content = h.request(url, "POST", body=body,
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.disabled_token,
                                           "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(resp['status']))

    def test_tenant_group_create_invalid_token(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        if int(resp['status']) == 200:
            self.tenant = content['tenant']['id']

        url = '%stenant/%s/groups' % (URL, self.tenant)
        body = '{"group": { "id": "%s", \
            "description": "A description ..." } }' % self.tenant
        resp, content = h.request(url, "POST", body=body,
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": 'nonexsitingtoken'})

        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, int(resp['status']))

    def test_tenant_group_create_invalid_token_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant_xml(self.tenant, str(self.auth_token))
        content = etree.fromstring(content)
        if int(resp['status']) == 200:
            self.tenant = content.get('id')

        url = '%stenant/%s/groups' % (URL, self.tenant)
        body = '<?xml version="1.0" encoding="UTF-8"?> \
                 <group xmlns="http://docs.openstack.org/idm/api/v1.0" \
                 id="%s"> \
                <description>A description...</description> \
                </group>' % self.tenant_group
        resp, content = h.request(url, "POST", body=body,
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": 'nonexsitingtoken',
                                           "ACCEPT": "application/xml"})

        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, int(resp['status']))


class get_tenant_groups_test(tenant_group_test):

    def test_get_tenant_groups(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))

        respG, contentG = create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))

        url = '%stenant/%s/groups' % (URL, self.tenant)

        resp, content = h.request(url, "GET", body='{}',
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.auth_token})
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(200, int(resp['status']))

    def test_get_tenant_groups_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))

        respG, contentG = create_tenant_group_xml(self.tenant_group,
                                                  self.tenant,
                                                  str(self.auth_token))
        url = '%stenant/%s/groups' % (URL, self.tenant)
        resp, content = h.request(url, "GET", body='',
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.auth_token,
                                           "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(200, int(resp['status']))

    def test_get_tenant_groups_unauthorized_token(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))

        respG, contentG = create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))
        url = '%stenant/%s/groups' % (URL, self.tenant)
        #test for Content-Type = application/json
        resp, content = h.request(url, "GET", body='{}',
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.token})
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, int(resp['status']))

    def test_get_tenant_groups_unauthorized_token_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        respG, contentG = create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))
        url = '%stenant/%s/groups' % (URL, self.tenant)
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

    def test_get_tenant_groups_exp_token(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        respG, contentG = create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))
        url = '%stenant/%s/groups' % (URL, self.tenant)
        #test for Content-Type = application/json
        resp, content = h.request(url, "GET", body='{}',
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.exp_auth_token})
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(resp['status']))

    def test_get_tenant_groups_exp_token_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        respG, contentG = create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))
        url = '%stenant/%s/groups' % (URL, self.tenant)
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


class get_tenant_group_test(tenant_group_test):

    def test_get_tenant_group(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        respG, contentG = create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))
        url = '%stenant/%s/groups/%s' % (URL, self.tenant, self.tenant_group)
        #test for Content-Type = application/json
        resp, content = h.request(url, "GET", body='{}',
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.auth_token})
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(200, int(resp['status']))

    def test_get_tenant_group_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        respG, contentG = create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))
        url = '%stenant/%s/groups/%s' % (URL, self.tenant, self.tenant_group)
        #test for Content-Type = application/xml
        resp, content = h.request(url, "GET", body='',
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.auth_token,
                                           "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(200, int(resp['status']))

    def test_get_tenant_group_bad(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        respG, contentG = create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))
        url = '%stenant/%s/groups/%s' % (URL, 'tenant_bad', self.tenant_group)

        #test for Content-Type = application/json
        resp, content = h.request(url, "GET", body='{',
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.auth_token})
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, int(resp['status']))

    def test_get_tenant_group_bad_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        respG, contentG = create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))
        url = '%stenant/%s/groups/%s' % (URL, 'tenant_bad', self.tenant_group)
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

    def test_get_tenant_group_not_found(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        respG, contentG = create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))
        url = '%stenant/%s/groups/%s' % (URL, self.tenant, 'nonexistinggroup')
        #test for Content-Type = application/json
        resp, content = h.request(url, "GET", body='{}',
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.auth_token})
        if int(resp['status']) == 500:
              self.fail('IDM fault')
        elif int(resp['status']) == 503:
              self.fail('Service Not Available')
        self.assertEqual(404, int(resp['status']))

    def test_get_tenant_group_not_found_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        respG, contentG = create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))
        url = '%stenant/%s/groups/%s' % (URL, self.tenant, 'nonexistinggroup')

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


class update_tenant_group_test(tenant_group_test):

    def test_update_tenant_group(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        resp, content = delete_tenant_group(self.tenant_group,
                                            self.tenant,
                                            str(self.auth_token))
        respG, contentG = create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))
        url = '%stenant/%s/groups/%s' % (URL, self.tenant, self.tenant_group)

        data = '{"group": { "id":"%s","description": "A NEW description..." ,\
                "tenantId":"%s" }}' % (self.tenant_group, self.tenant)
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
        self.assertEqual(self.tenant_group, body['group']['id'])
        self.assertEqual('A NEW description...', body['group']['description'])

    def test_update_tenant_group_xml(self):
        h = httplib2.Http(".cache")
        resp, content = delete_tenant(self.tenant, str(self.auth_token))

        resp, content = create_tenant(self.tenant, str(self.auth_token))

        resp, content = delete_tenant_group(self.tenant_group,
                                            self.tenant,
                                            str(self.auth_token))

        respG, contentG = create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))

        url = '%stenant/%s/groups/%s' % (URL, self.tenant , self.tenant_group)

        data = '<group xmlns="http://docs.openstack.org/idm/api/v1.0" \
             tenantId="%s" id="%s"> \
             <description>A NEW description...</description> \
             </group>' % (self.tenant, self.tenant_group)

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
        self.assertEqual(str(self.tenant_group), str(body.get('id')))
        self.assertEqual('A NEW description...', desc.text)

    def test_update_tenant_group_bad(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        resp, content = delete_tenant_group(self.tenant_group,
                                            self.tenant,
                                            str(self.auth_token))
        respG, contentG = create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))
        url = '%stenant/%s/groups/%s' % (URL, self.tenant, self.tenant_group)
        data = '{"group": { "description_bad": "A NEW description...",\
            "id":"%s","tenantId":"%s"  }}' % (self.tenant_group, self.tenant)
        #test for Content-Type = application/json

        resp, content = h.request(url, "PUT", body=data,
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.auth_token})
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(400, int(resp['status']))

    def test_update_tenant_group_bad_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        resp, content = delete_tenant_group(self.tenant_group,
                                            self.tenant,
                                            str(self.auth_token))
        respG, contentG = create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))
        url = '%stenant/%s/groups/%s' % (URL, self.tenant, self.tenant_group)
        data = '<?xml version="1.0" encoding="UTF-8"?> \
             <group xmlns="http://docs.openstack.org/idm/api/v1.0" \
             tenantId="%s" id="%s"> \
             <description_bad>A NEW description...</description> \
             </group>' % (self.tenant, self.tenant_group)
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

    def test_update_tenant_group_not_found(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        resp, content = delete_tenant_group(self.tenant_group,
                                            self.tenant,
                                            str(self.auth_token))
        respG, contentG = create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))
        url = '%stenant/%s/groups/NonexistingID' % (URL, self.tenant)

        data = '{"group": { "description": "A NEW description...",\
            "id":"NonexistingID", "tenantId"="test_tenant"  }}'
        #test for Content-Type = application/json
        resp, content = h.request(url, "GET", body=data,
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.auth_token})
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, int(resp['status']))

    def test_update_tenant_group_not_found_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        url = '%stenant/%s/groups/NonexistingID' % (URL, self.tenant)
        data = '<?xml version="1.0" encoding="UTF-8"?> \
             <group xmlns="http://docs.openstack.org/idm/api/v1.0" \
             id="NonexistingID", "tenant_id"="test_tenant"> \
             <description_bad>A NEW description...</description> \
             </group>'
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


class delete_tenant_group_test(tenant_group_test):

    def test_delete_tenant_group_not_found(self):
        #resp,content=create_tenant("test_tenant_delete", str(self.auth_token))
        resp, content = delete_tenant_group("test_tenant_delete111",
                                            self.tenant,
                                            str(self.auth_token))
        self.assertEqual(404, int(resp['status']))

    def test_delete_tenant_group_not_found_xml(self):
        #resp,content=create_tenant("test_tenant_delete", str(self.auth_token))
        resp, content = delete_tenant_group_xml("test_tenant_delete111",
                                                self.tenant,
                                                str(self.auth_token))
        self.assertEqual(404, int(resp['status']))

    def test_delete_tenant_group(self):
        resp, content = create_tenant("test_tenant_delete",
                                      str(self.auth_token))
        respG, contentG = create_tenant_group('test_tenant_group_delete',
                                              "test_tenant_delete",
                                              str(self.auth_token))
        respG, contentG = delete_tenant_group('test_tenant_group_delete',
                                              "test_tenant_delete",
                                              str(self.auth_token))
        resp, content = delete_tenant("test_tenant_delete",
                                      str(self.auth_token))
        self.assertEqual(204, int(respG['status']))

    def test_delete_tenant_group_xml(self):
        resp, content = create_tenant("test_tenant_delete",
                                      str(self.auth_token))
        respG, contentG = create_tenant_group('test_tenant_group_delete',
                                              "test_tenant_delete",
                                              str(self.auth_token))
        respG, contentG = delete_tenant_group('test_tenant_group_delete',
                                              "test_tenant_delete",
                                              str(self.auth_token))
        resp, content = delete_tenant_xml("test_tenant_delete",
                                          str(self.auth_token))
        self.assertEqual(204, int(respG['status']))


class add_user_tenant_group_test(tenant_group_test):

    def setUp(self):
        self.token = get_token('joeuser', 'secrete', 'token')
        self.tenant = 'test_tenant'
        self.user = get_user()
        self.userdisabled = get_userdisabled()
        self.auth_token = get_auth_token()
        self.exp_auth_token = get_exp_auth_token()
        self.disabled_token = get_disabled_token()
        self.tenant_group = 'test_tenant_group_add'

    def tearDown(self):
        respG, contentG = delete_user_tenant_group(self.tenant,
                                                   self.tenant_group,
                                                   self.user,
                                                   str(self.auth_token))

        respG, contentG = delete_user(self.tenant, self.user,
                                      str(self.auth_token))
        resp, content = delete_tenant_group(self.tenant_group,
                                            self.tenant,
                                            self.auth_token)
        resp, content = delete_tenant(self.tenant, self.auth_token)


    def test_add_user_tenant_group(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))

        respG, contentG = create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))

        respG, contentG = create_user(self.tenant, self.user,
                                      str(self.auth_token))
        respG, contentG = add_user_tenant_group(self.tenant, self.tenant_group,
                                                self.user, str(self.auth_token)
                                                )

        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        if int(respG['status']) not in (200, 201):
            self.fail('Failed due to %d' % int(respG['status']))


    def test_add_user_tenant_group_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        respG, contentG = create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))
        respG, contentG = create_user(self.tenant, self.user,
                                      str(self.auth_token))
        respG, contentG = add_user_tenant_group_xml(self.tenant,
                                                    self.tenant_group,
                                                    self.user,
                                                    str(self.auth_token))

        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        if int(respG['status']) not in (200, 201):
            self.fail('Failed due to %d' % int(respG['status']))


    def test_add_user_tenant_group_conflict(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        respG, contentG = create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))
        respG, contentG = create_user(self.tenant, self.user,
                                      str(self.auth_token))
        respG, contentG = add_user_tenant_group(self.tenant, self.tenant_group,
                                                self.user, str(self.auth_token)
                                                )
        respG, contentG = add_user_tenant_group(self.tenant, self.tenant_group,
                                                self.user, str(self.auth_token)
                                                )

        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(409, int(respG['status']))

    def test_add_user_tenant_group_conflict_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        respG, contentG = create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))
        respG, contentG = create_user(self.tenant, self.user,
                                      str(self.auth_token))
        respG, contentG = add_user_tenant_group_xml(self.tenant, self.tenant_group,
                                                self.user, str(self.auth_token)
                                                )
        respG, contentG = add_user_tenant_group_xml(self.tenant, self.tenant_group,
                                                self.user, str(self.auth_token)
                                                )

        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(409, int(respG['status']))

    def test_add_user_tenant_group_unauthorized(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        respG, contentG = create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))
        respG, contentG = create_user(self.tenant, self.user,
                                      str(self.auth_token))

        respG, contentG = add_user_tenant_group(self.tenant, self.tenant_group,
                                                self.user, self.token)

        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, int(respG['status']))

    def test_add_user_tenant_group_unauthorized_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        respG, contentG = create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))
        respG, contentG = create_user(self.tenant, self.user,
                                      str(self.auth_token))

        respG, contentG = add_user_tenant_group_xml(self.tenant, self.tenant_group,
                                                self.user, self.token)

        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, int(respG['status']))

    def test_add_user_tenant_group_forbidden(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        respG, contentG = create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))
        respG, contentG = create_user(self.tenant, self.user,
                                      str(self.auth_token))

        respG, contentG = add_user_tenant_group(self.tenant, self.tenant_group,
                                                self.user, self.disabled_token)

        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(respG['status']))

    def test_add_user_tenant_group_forbidden_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        respG, contentG = create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))
        respG, contentG = create_user(self.tenant, self.user,
                                      str(self.auth_token))

        respG, contentG = add_user_tenant_group_xml(self.tenant, self.tenant_group,
                                                self.user, self.disabled_token)

        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(respG['status']))


class get_users_tenant_group_test(tenant_group_test):

    def setUp(self):
        self.token = get_token('joeuser', 'secrete', 'token')
        self.tenant = 'test_tenant'
        self.user = get_user()
        self.userdisabled = get_userdisabled()
        self.auth_token = get_auth_token()
        self.exp_auth_token = get_exp_auth_token()
        self.disabled_token = get_disabled_token()
        self.tenant_group = 'test_tenant_group_add'

    def tearDown(self):
        respG, contentG = delete_user_tenant_group(self.tenant,
                                                   self.tenant_group,
                                                   self.user,
                                                   str(self.auth_token))

        respG, contentG = delete_user(self.tenant, self.user,
                                      str(self.auth_token))
        resp, content = delete_tenant_group(self.tenant_group,
                                            self.tenant,
                                            self.auth_token)
        resp, content = delete_tenant(self.tenant, self.auth_token)

    def test_get_users_tenant_group(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        respG, contentG = create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))

        respG, contentG = create_user(self.tenant, self.user,
                                      str(self.auth_token))
        respG, contentG = add_user_tenant_group(self.tenant, self.tenant_group,
                                                self.user, str(self.auth_token)
                                                )
        respG, contentG = get_user_tenant_group(self.tenant, self.tenant_group,
                                                str(self.auth_token)
                                                )

        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(200, int(respG['status']))


    def test_get_users_tenant_group_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        respG, contentG = create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))
        respG, contentG = create_user(self.tenant, self.user,
                                      str(self.auth_token))
        respG, contentG = add_user_tenant_group_xml(self.tenant,
                                                    self.tenant_group,
                                                    self.user,
                                                    str(self.auth_token))
        respG, contentG = get_user_tenant_group_xml(self.tenant,
                                                    self.tenant_group,
                                                    str(self.auth_token)
                                                )
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(200, int(respG['status']))


    def test_get_users_tenant_group_unauthorized(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        respG, contentG = create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))
        respG, contentG = create_user(self.tenant, self.user,
                                      str(self.auth_token))

        respG, contentG = add_user_tenant_group(self.tenant, self.tenant_group,
                                                self.user, self.auth_token)

        respG, contentG = get_user_tenant_group(self.tenant, self.tenant_group,
                                                str(self.token)
                                                )

        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, int(respG['status']))

    def test_get_users_tenant_group_unauthorized_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        respG, contentG = create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))
        respG, contentG = create_user(self.tenant, self.user,
                                      str(self.auth_token))

        respG, contentG = add_user_tenant_group(self.tenant, self.tenant_group,
                                                self.user, self.auth_token)
        respG, contentG = get_user_tenant_group_xml(self.tenant,
                                                    self.tenant_group,
                                                    str(self.token)
                                                )

        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, int(respG['status']))

    def test_get_users_tenant_group_forbidden(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        respG, contentG = create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))
        respG, contentG = create_user(self.tenant, self.user,
                                      str(self.auth_token))

        respG, contentG = add_user_tenant_group(self.tenant, self.tenant_group,
                                                self.user, self.auth_token)
        respG, contentG = get_user_tenant_group(self.tenant,
                                                self.tenant_group,
                                                str(self.disabled_token)
                                                )

        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(respG['status']))

    def test_get_users_tenant_group_forbidden_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        respG, contentG = create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))
        respG, contentG = create_user(self.tenant, self.user,
                                      str(self.auth_token))

        respG, contentG = add_user_tenant_group(self.tenant, self.tenant_group,
                                                self.user, self.auth_token)
        respG, contentG = get_user_tenant_group_xml(self.tenant,
                                                    self.tenant_group,
                                                    str(self.disabled_token)
                                                )
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(respG['status']))

    def test_get_users_tenant_group_expired(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        respG, contentG = create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))
        respG, contentG = create_user(self.tenant, self.user,
                                      str(self.auth_token))

        respG, contentG = add_user_tenant_group(self.tenant, self.tenant_group,
                                                self.user, self.auth_token)
        respG, contentG = get_user_tenant_group(self.tenant, self.tenant_group,
                                                str(self.exp_auth_token)
                                                )

        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(respG['status']))

    def test_get_users_tenant_group_expired_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        respG, contentG = create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))
        respG, contentG = create_user(self.tenant, self.user,
                                      str(self.auth_token))

        respG, contentG = add_user_tenant_group(self.tenant, self.tenant_group,
                                                self.user, self.auth_token)
        respG, contentG = get_user_tenant_group_xml(self.tenant,
                                                    self.tenant_group,
                                                    str(self.exp_auth_token)
                                                )
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(respG['status']))

class delete_users_tenant_group_test(tenant_group_test):

    def test_delete_user_tenant_group(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        respG, contentG = create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))
        respG, contentG = create_user(self.tenant, self.user,
                                      str(self.auth_token))
        respG, contentG = add_user_tenant_group(self.tenant, self.tenant_group,
                                                self.user, str(self.auth_token)
                                                )
        respG, contentG = delete_user_tenant_group(self.tenant,
                                                   self.tenant_group,
                                                   self.user,
                                                   str(self.auth_token)
                                                )

        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(204, int(respG['status']))


    def test_delete_user_tenant_group_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        respG, contentG = create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))
        respG, contentG = create_user(self.tenant, self.user,
                                      str(self.auth_token))
        respG, contentG = add_user_tenant_group_xml(self.tenant,
                                                    self.tenant_group,
                                                    self.user,
                                                    str(self.auth_token))
        respG, contentG = delete_user_tenant_group_xml(self.tenant,
                                                    self.tenant_group,
                                                    self.user,
                                                    str(self.auth_token))

        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(204, int(respG['status']))

    def test_delete_user_tenant_group_notfound(self):
        h = httplib2.Http(".cache")

        respG, contentG = delete_user_tenant_group(self.tenant,
                                                   self.tenant_group,
                                                   'NonExistinguser',
                                                   str(self.auth_token)
                                                )

        if int(respG['status']) == 500:
            self.fail('IDM fault')
        elif int(respG['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, int(respG['status']))

    def test_delete_user_tenant_group_notfound_xml(self):
        h = httplib2.Http(".cache")

        respG, contentG = delete_user_tenant_group_xml(self.tenant,
                                                   self.tenant_group,
                                                   'NonExistinguser',
                                                   str(self.auth_token)
                                                )

        if int(respG['status']) == 500:
            self.fail('IDM fault')
        elif int(respG['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, int(respG['status']))

def run():
    unittest.main()
    
if __name__ == '__main__':
    unittest.main()
