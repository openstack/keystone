# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright (c) 2010-2011 OpenStack, LLC.
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


import httplib2
import json
from lxml import etree
import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.abspath(__file__),
                                '..', '..', '..', '..', 'keystone')))
import unittest

import test_common as util


class TenantGroupTest(unittest.TestCase):

    def setUp(self):
        self.tenant = util.get_another_tenant()
        self.user = util.get_user()
        self.userdisabled = util.get_userdisabled()
        self.auth_token = util.get_auth_token()
        self.exp_auth_token = util.get_exp_auth_token()
        self.disabled_token = util.get_disabled_token()
        self.tenant_group = 'test_tenant_group_new'
        util.create_tenant(self.tenant, str(self.auth_token))
        util.create_user(self.tenant, self.user, self.auth_token)
        util.add_user_json(self.tenant, self.user, self.auth_token)
        self.token = util.get_token(self.user, 'secrete', self.tenant,
                                     'token')

    def tearDown(self):
        resp = util.delete_user(self.tenant, self.user,
                                      str(self.auth_token))

        resp, content = util.delete_tenant_group(self.tenant_group,
                                            self.tenant,
                                            self.auth_token)
        resp = util.delete_tenant(self.tenant, self.auth_token)


class CreateTenantGroupTest(TenantGroupTest):

    def test_tenant_group_create(self):
        util.delete_user(self.tenant, self.user,
                                      str(self.auth_token))
        resp = util.delete_tenant(self.tenant, str(self.auth_token))
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        util.create_tenant(self.tenant, str(self.auth_token))
        resp, content = util.delete_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))
        resp, content = util.create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))

        if int(resp['status']) not in (200, 201):
            self.fail('Failed due to %d' % int(resp['status']))

    def test_tenant_group_create_xml(self):
        util.delete_user(self.tenant, self.user,
                                      str(self.auth_token))
        resp = util.delete_tenant_xml(self.tenant,
                                               str(self.auth_token))
        resp, content = util.create_tenant_xml(self.tenant,
                                               str(self.auth_token))
        resp, content = util.delete_tenant_group_xml(self.tenant_group,
                                                  self.tenant,
                                                  str(self.auth_token))
        resp, content = util.create_tenant_group_xml(self.tenant_group,
                                                  self.tenant,
                                                  str(self.auth_token))

        content = etree.fromstring(content)
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        if int(resp['status']) not in (200, 201):
            self.fail('Failed due to %d' % int(resp['status']))

    def test_tenant_group_create_again(self):
        resp, content = util.create_tenant(self.tenant,
                                           str(self.auth_token))
        resp, content = util.create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))
        resp, content = util.create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))
        if int(resp['status']) == 200:
            self.tenant = content['tenant']['id']
            self.tenant_group = content['group']['id']
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
            self.assertEqual(409, int(resp['status']))

    def test_tenant_group_create_again_xml(self):
        resp, content = util.create_tenant_xml("test_tenant",
                                               str(self.auth_token))
        resp, content = util.create_tenant_group_xml(self.tenant_group,
                                                  self.tenant,
                                                  str(self.auth_token))
        resp_new, content_new = util.create_tenant_group_xml(self.tenant_group,
                                                  self.tenant,
                                                  str(self.auth_token))
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
            self.assertEqual(409, int(resp['status']))

    def test_tenant_group_create_unauthorized_token(self):
        header = httplib2.Http(".cache")
        resp, content = util.create_tenant(self.tenant, str(self.auth_token))
        if int(resp['status']) == 200:
            self.tenant = content['tenant']['id']
        resp, content = util.create_tenant_group_xml(self.tenant_group,
                                                  self.tenant,
                                                  str(self.auth_token))

        if int(resp['status']) == 200:
            self.tenant_group = resp['group']['id']
        url = '%stenants/%s/groups' % (util.URL, self.tenant)
        body = {"group": {"id": self.tenant_group,
                          "description": "A description ..."}}
        resp, content = header.request(url, "POST", body=json.dumps(body),
                             headers={"Content-Type": "application/json",
                                      "X-Auth-Token": self.token})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
            self.assertEqual(401, int(resp['status']))

    def test_tenant_group_create_unauthorized_token_xml(self):
        header = httplib2.Http(".cache")
        resp, content = util.create_tenant(self.tenant, str(self.auth_token))
        if int(resp['status']) == 200:
            self.tenant = content['tenant']['id']
        url = '%stenants/%s/groups' % (util.URL, self.tenant)
        body = '<?xml version="1.0" encoding="UTF-8"?> \
                <group xmlns="http://docs.openstack.org/identity/api/v2.0" \
                id="%s"><description>A description...</description> \
                </group>' % self.tenant_group
        resp, content = header.request(url, "POST", body=body,
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.token,
                                           "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, int(resp['status']))

    def test_tenant_group_create_expired_token(self):
        header = httplib2.Http(".cache")
        resp, content = util.create_tenant(self.tenant, str(self.auth_token))
        if int(resp['status']) == 200:
            self.tenant = content['tenant']['id']
        url = '%stenants/%s/groups' % (util.URL, self.tenant)
        body = {"group": {"id": self.tenant_group,
                "description": "A description ..."}}
        resp, content = header.request(url, "POST", body=json.dumps(body),
                              headers={"Content-Type": "application/json",
                                       "X-Auth-Token": self.exp_auth_token})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(resp['status']))

    def test_tenant_group_create_expired_token_xml(self):
        header = httplib2.Http(".cache")
        resp, content = util.create_tenant_xml(self.tenant,
                                               str(self.auth_token))
        content = etree.fromstring(content)
        if int(resp['status']) == 200:
            self.tenant = content.get('id')
        url = '%stenants/%s/groups' % (util.URL, self.tenant)
        body = '<?xml version="1.0" encoding="UTF-8"?> \
                <group xmlns="http://docs.openstack.org/identity/api/v2.0" \
                 id="%s"> \
                <description>A description...</description> \
                </group>' % self.tenant
        resp, content = header.request(url, "POST", body=body,
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.exp_auth_token,
                                           "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(resp['status']))

    def test_tenant_group_create_missing_token(self):
        header = httplib2.Http(".cache")
        resp, content = util.create_tenant(self.tenant, str(self.auth_token))
        if int(resp['status']) == 200:
            self.tenant = content['tenant']['id']
        url = '%stenants/%s/groups' % (util.URL, self.tenant)
        body = {"group": {"id": self.tenant_group,
                "description": "A description ..."}}
        resp, content = header.request(url, "POST", body=json.dumps(body),
                          headers={"Content-Type": "application/json"})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, int(resp['status']))

    def test_tenant_group_create_missing_token_xml(self):
        header = httplib2.Http(".cache")
        resp, content = util.create_tenant_xml(self.tenant,
                                               str(self.auth_token))
        content = etree.fromstring(content)
        if int(resp['status']) == 200:
            self.tenant = content.get('id')
        url = '%stenants/%s/groups' % (util.URL, self.tenant)
        body = '<?xml version="1.0" encoding="UTF-8"?> \
                <group xmlns="http://docs.openstack.org/identity/api/v2.0" \
                id="%s"> \
                <description>A description...</description> \
                </group>' % self.tenant_group
        resp, content = header.request(url, "POST", body=body,
                                  headers={"Content-Type": "application/xml",
                                           "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, int(resp['status']))

    def test_tenant_group_create_disabled_token(self):
        header = httplib2.Http(".cache")
        resp, content = util.create_tenant(self.tenant, str(self.auth_token))
        if int(resp['status']) == 200:
            self.tenant = content['tenant']['id']

        url = '%stenants/%s/groups' % (util.URL, self.tenant)
        body = '{"group": { "id": "%s", \
            "description": "A description ..." } }' % self.tenant_group
        resp, content = header.request(url, "POST", body=body,
                                  headers={"Content-Type": "application/json",
                                          "X-Auth-Token": self.disabled_token})

        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(resp['status']))

    def test_tenant_group_create_disabled_token_xml(self):
        header = httplib2.Http(".cache")
        resp, content = util.create_tenant_xml(self.tenant,
                str(self.auth_token))
        content = etree.fromstring(content)
        if int(resp['status']) == 200:
            self.tenant = content.get('id')

        url = '%stenants/%s/groups' % (util.URL, self.tenant)
        body = '<?xml version="1.0" encoding="UTF-8"?> \
        <group xmlns="http://docs.openstack.org/identity/api/v2.0" \
        id="%s"> \
        <description>A description...</description> \
        </group>' % self.tenant_group
        resp, content = header.request(url, "POST", body=body,
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.disabled_token,
                                           "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(resp['status']))

    def test_tenant_group_create_invalid_token(self):
        header = httplib2.Http(".cache")
        resp, content = util.create_tenant(self.tenant, str(self.auth_token))
        if int(resp['status']) == 200:
            self.tenant = content['tenant']['id']

        url = '%stenants/%s/groups' % (util.URL, self.tenant)
        body = '{"group": { "id": "%s", \
            "description": "A description ..." } }' % self.tenant
        resp, content = header.request(url, "POST", body=body,
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": 'nonexsitingtoken'})

        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, int(resp['status']))

    def test_tenant_group_create_invalid_token_xml(self):
        header = httplib2.Http(".cache")
        resp, content = util.create_tenant_xml(self.tenant,
                                               str(self.auth_token))
        content = etree.fromstring(content)
        if int(resp['status']) == 200:
            self.tenant = content.get('id')

        url = '%stenants/%s/groups' % (util.URL, self.tenant)
        body = '<?xml version="1.0" encoding="UTF-8"?> \
                 <group xmlns="http://docs.openstack.org/identity/api/v2.0" \
                 id="%s"> \
                <description>A description...</description> \
                </group>' % self.tenant_group
        resp, content = header.request(url, "POST", body=body,
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": 'nonexsitingtoken',
                                           "ACCEPT": "application/xml"})

        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, int(resp['status']))


class GetTenantGroupsTest(TenantGroupTest):

    def test_get_tenant_groups(self):
        header = httplib2.Http(".cache")
        resp, content = util.create_tenant(self.tenant, str(self.auth_token))

        resp, content = util.create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))

        url = '%stenants/%s/groups' % (util.URL, self.tenant)

        resp, content = header.request(url, "GET", body='{}',
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.auth_token})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(200, int(resp['status']))

    def test_get_tenant_groups_xml(self):
        header = httplib2.Http(".cache")
        resp, content = util.create_tenant(self.tenant, str(self.auth_token))

        resp, content = util.create_tenant_group_xml(self.tenant_group,
                                                  self.tenant,
                                                  str(self.auth_token))
        url = '%stenants/%s/groups' % (util.URL, self.tenant)
        resp, content = header.request(url, "GET", body='',
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.auth_token,
                                           "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(200, int(resp['status']))

    def test_get_tenant_groups_unauthorized_token(self):
        header = httplib2.Http(".cache")
        resp, content = util.create_tenant(self.tenant, str(self.auth_token))

        resp, content = util.create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))
        url = '%stenants/%s/groups' % (util.URL, self.tenant)
        #test for Content-Type = application/json
        resp, content = header.request(url, "GET", body='{}',
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.token})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, int(resp['status']))

    def test_get_tenant_groups_unauthorized_token_xml(self):
        header = httplib2.Http(".cache")
        resp, content = util.create_tenant(self.tenant, str(self.auth_token))
        resp, content = util.create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))
        url = '%stenants/%s/groups' % (util.URL, self.tenant)
        #test for Content-Type = application/json
        resp, content = header.request(url, "GET", body='',
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.token,
                                           "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, int(resp['status']))

    def test_get_tenant_groups_exp_token(self):
        header = httplib2.Http(".cache")
        resp, content = util.create_tenant(self.tenant, str(self.auth_token))
        resp, content = util.create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))
        url = '%stenants/%s/groups' % (util.URL, self.tenant)
        #test for Content-Type = application/json
        resp, content = header.request(url, "GET", body='{}',
                                  headers={"Content-Type": "application/json",
                                          "X-Auth-Token": self.exp_auth_token})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(resp['status']))

    def test_get_tenant_groups_exp_token_xml(self):
        header = httplib2.Http(".cache")
        resp, content = util.create_tenant(self.tenant, str(self.auth_token))
        resp, content = util.create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))
        url = '%stenants/%s/groups' % (util.URL, self.tenant)
        #test for Content-Type = application/json
        resp, content = header.request(url, "GET", body='',
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.exp_auth_token,
                                           "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(resp['status']))


class GetTenantGroupTest(TenantGroupTest):

    def test_get_tenant_group(self):
        header = httplib2.Http(".cache")
        resp, content = util.create_tenant(self.tenant, str(self.auth_token))
        resp, content = util.create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))
        url = '%stenants/%s/groups/%s' % (util.URL, self.tenant,
                                         self.tenant_group)
        #test for Content-Type = application/json
        resp, content = header.request(url, "GET", body='{}',
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.auth_token})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(200, int(resp['status']))

    def test_get_tenant_group_xml(self):
        header = httplib2.Http(".cache")
        resp, content = util.create_tenant(self.tenant, str(self.auth_token))
        resp, content = util.create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))
        url = '%stenants/%s/groups/%s' % (util.URL, self.tenant,
                                         self.tenant_group)
        #test for Content-Type = application/xml
        resp, content = header.request(url, "GET", body='',
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.auth_token,
                                           "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(200, int(resp['status']))

    def test_get_tenant_group_bad(self):
        header = httplib2.Http(".cache")
        resp, content = util.create_tenant(self.tenant, str(self.auth_token))
        resp, content = util.create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))
        url = '%stenants/%s/groups/%s' % (util.URL, 'tenant_bad',
                                         self.tenant_group)

        #test for Content-Type = application/json
        resp, content = header.request(url, "GET", body='{',
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.auth_token})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, int(resp['status']))

    def test_get_tenant_group_bad_xml(self):
        header = httplib2.Http(".cache")
        resp, content = util.create_tenant(self.tenant, str(self.auth_token))
        resp, content = util.create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))
        url = '%stenants/%s/groups/%s' % (util.URL, 'tenant_bad',
                                         self.tenant_group)
        #test for Content-Type = application/json
        resp, content = header.request(url, "GET", body='{',
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.auth_token,
                                           "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, int(resp['status']))

    def test_get_tenant_group_not_found(self):
        header = httplib2.Http(".cache")
        resp, content = util.create_tenant(self.tenant, str(self.auth_token))
        resp, content = util.create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))
        url = '%stenants/%s/groups/%s' % (util.URL, self.tenant,
                                         'nonexistinggroup')
        #test for Content-Type = application/json
        resp, content = header.request(url, "GET", body='{}',
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.auth_token})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, int(resp['status']))

    def test_get_tenant_group_not_found_xml(self):
        header = httplib2.Http(".cache")
        resp, content = util.create_tenant(self.tenant, str(self.auth_token))
        resp, content = util.create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))
        url = '%stenants/%s/groups/%s' % (util.URL, self.tenant,
                                         'nonexistinggroup')

        #test for Content-Type = application/json
        resp, content = header.request(url, "GET", body='',
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.auth_token,
                                           "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, int(resp['status']))


class UpdateTenantGroupTest(TenantGroupTest):

    def test_update_tenant_group(self):
        header = httplib2.Http(".cache")
        resp, content = util.create_tenant(self.tenant, str(self.auth_token))
        resp, content = util.delete_tenant_group(self.tenant_group,
                                            self.tenant,
                                            str(self.auth_token))
        resp, content = util.create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))
        url = '%stenants/%s/groups/%s' % (util.URL, self.tenant,
                                         self.tenant_group)

        data = '{"group": { "id":"%s","description": "A NEW description..." ,\
                "tenantId":"%s" }}' % (self.tenant_group, self.tenant)
        #test for Content-Type = application/json

        resp, content = header.request(url, "PUT", body=data,
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.auth_token})

        body = json.loads(content)
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(200, int(resp['status']))
        self.assertEqual(self.tenant_group, body['group']['id'])
        self.assertEqual('A NEW description...', body['group']['description'])

    def test_update_tenant_group_xml(self):
        header = httplib2.Http(".cache")
        resp = util.delete_tenant(self.tenant, str(self.auth_token))

        resp, content = util.create_tenant(self.tenant, str(self.auth_token))

        resp, content = util.delete_tenant_group(self.tenant_group,
                                            self.tenant,
                                            str(self.auth_token))

        resp, content = util.create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))

        url = '%stenants/%s/groups/%s' % (util.URL, self.tenant,
                                         self.tenant_group)

        data = '<group xmlns="http://docs.openstack.org/identity/api/v2.0" \
             tenantId="%s" id="%s"> \
             <description>A NEW description...</description> \
             </group>' % (self.tenant, self.tenant_group)

        #test for Content-Type = application/json
        resp, content = header.request(url, "PUT", body=data,
                                headers={"Content-Type": "application/xml",
                                         "X-Auth-Token": self.auth_token,
                                         "ACCEPT": "application/xml"})

        body = etree.fromstring(content)
        desc = body.find("{http://docs.openstack.org/identity/api/v2.0}description")

        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')

        self.assertEqual(200, int(resp['status']))
        self.assertEqual(str(self.tenant_group), str(body.get('id')))
        self.assertEqual('A NEW description...', desc.text)

    def test_update_tenant_group_bad(self):
        header = httplib2.Http(".cache")
        resp, content = util.create_tenant(self.tenant, str(self.auth_token))
        resp, content = util.delete_tenant_group(self.tenant_group,
                                            self.tenant,
                                            str(self.auth_token))
        resp, content = util.create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))
        url = '%stenants/%s/groups/%s' % (util.URL, self.tenant,
                                         self.tenant_group)
        data = '{"group": { "description_bad": "A NEW description...",\
            "id":"%s","tenantId":"%s"  }}' % (self.tenant_group, self.tenant)
        #test for Content-Type = application/json

        resp, content = header.request(url, "PUT", body=data,
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.auth_token})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(400, int(resp['status']))

    def test_update_tenant_group_bad_xml(self):
        header = httplib2.Http(".cache")
        resp, content = util.create_tenant(self.tenant, str(self.auth_token))
        resp, content = util.delete_tenant_group(self.tenant_group,
                                            self.tenant,
                                            str(self.auth_token))
        resp, content = util.create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))
        url = '%stenants/%s/groups/%s' % (util.URL, self.tenant,
                                         self.tenant_group)
        data = '<?xml version="1.0" encoding="UTF-8"?> \
             <group xmlns="http://docs.openstack.org/identity/api/v2.0" \
             tenantId="%s" id="%s"> \
             <description_bad>A NEW description...</description> \
             </group>' % (self.tenant, self.tenant_group)
        #test for Content-Type = application/json
        resp, content = header.request(url, "PUT", body=data,
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.auth_token,
                                           "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(400, int(resp['status']))

    def test_update_tenant_group_not_found(self):
        header = httplib2.Http(".cache")
        resp, content = util.create_tenant(self.tenant, str(self.auth_token))
        resp, content = util.delete_tenant_group(self.tenant_group,
                                            self.tenant,
                                            str(self.auth_token))
        resp, content = util.create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))
        url = '%stenants/%s/groups/NonexistingID' % (util.URL, self.tenant)

        data = '{"group": { "description": "A NEW description...",\
            "id":"NonexistingID", "tenantId"="test_tenant"  }}'
        #test for Content-Type = application/json
        resp, content = header.request(url, "GET", body=data,
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.auth_token})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, int(resp['status']))

    def test_update_tenant_group_not_found_xml(self):
        header = httplib2.Http(".cache")
        resp, content = util.create_tenant(self.tenant, str(self.auth_token))
        url = '%stenants/%s/groups/NonexistingID' % (util.URL, self.tenant)
        data = '<?xml version="1.0" encoding="UTF-8"?> \
             <group xmlns="http://docs.openstack.org/identity/api/v2.0" \
             id="NonexistingID", "tenant_id"="test_tenant"> \
             <description_bad>A NEW description...</description> \
             </group>'
        #test for Content-Type = application/json
        resp, content = header.request(url, "GET", body=data,
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.auth_token,
                                           "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, int(resp['status']))


class DeleteTenantGroupTest(TenantGroupTest):

    def test_delete_tenant_group_not_found(self):
        resp, content = util.delete_tenant_group("test_tenant_delete111",
                                            self.tenant,
                                            str(self.auth_token))
        self.assertEqual(404, int(resp['status']))

    def test_delete_tenant_group_not_found_xml(self):
        resp, content = util.delete_tenant_group_xml("test_tenant_delete111",
                                                self.tenant,
                                                str(self.auth_token))
        self.assertEqual(404, int(resp['status']))

    def test_delete_tenant_group(self):
        resp, content = util.create_tenant("test_tenant_delete",
                                      str(self.auth_token))
        resp, content = util.create_tenant_group(self.tenant_group,
                                              'test_tenant_delete',
                                              str(self.auth_token))
        resp, content = util.delete_tenant_group(self.tenant_group,
                                                 'test_tenant_delete',
                                              str(self.auth_token))
        self.assertEqual(204, int(resp['status']))
        resp = util.delete_tenant("test_tenant_delete",
                                      str(self.auth_token))
        self.assertEqual(204, int(resp['status']))


class AddUserTenantGroupTest(TenantGroupTest):

    def setUp(self):
        self.tenant = 'test_tenant'
        self.user = util.get_user()
        self.userdisabled = util.get_userdisabled()
        self.auth_token = util.get_auth_token()
        self.exp_auth_token = util.get_exp_auth_token()
        self.disabled_token = util.get_disabled_token()
        self.tenant_group = 'test_tenant_group_add'
        util.create_tenant(self.tenant, str(self.auth_token))
        util.create_user(self.tenant, self.user, self.auth_token)
        util.add_user_json(self.tenant, self.user, self.auth_token)
        self.token = util.get_token(self.user, 'secrete', self.tenant,
                                     'token')

    def tearDown(self):
        resp, content = util.delete_user_tenant_group(self.tenant,
                                                   self.tenant_group,
                                                   self.user,
                                                   str(self.auth_token))

        resp = util.delete_user(self.tenant, self.user,
                                      str(self.auth_token))
        resp, content = util.delete_tenant_group(self.tenant_group,
                                            self.tenant,
                                            self.auth_token)
        resp = util.delete_tenant(self.tenant, self.auth_token)

    def test_add_user_tenant_group(self):
        resp, content = util.create_tenant(self.tenant, str(self.auth_token))

        resp, content = util.create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))

        resp, content = util.create_user(self.tenant, self.user,
                                      str(self.auth_token))
        resp, content = util.add_user_tenant_group(self.tenant,
                                                   self.tenant_group,
                                                   self.user,
                                                   str(self.auth_token))

        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        if int(resp['status']) not in (200, 201):
            self.fail('Failed due to %d' % int(resp['status']))

    def test_add_user_tenant_group_xml(self):
        resp, content = util.create_tenant(self.tenant, str(self.auth_token))
        resp, content = util.create_tenant_group(self.tenant_group,
                                                 self.tenant,
                                                 str(self.auth_token))
        resp, content = util.create_user(self.tenant, self.user,
                                      str(self.auth_token))
        resp, content = util.add_user_tenant_group_xml(self.tenant,
                                                    self.tenant_group,
                                                    self.user,
                                                    str(self.auth_token))

        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        if int(resp['status']) not in (200, 201):
            self.fail('Failed due to %d' % int(resp['status']))

    def test_add_user_tenant_group_conflict(self):
        resp, content = util.create_tenant(self.tenant, str(self.auth_token))
        resp, content = util.create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))
        resp, content = util.create_user(self.tenant, self.user,
                                      str(self.auth_token))
        resp, content = util.add_user_tenant_group(self.tenant,
                                                   self.tenant_group,
                                                   self.user,
                                                   str(self.auth_token))
        resp, content = util.add_user_tenant_group(self.tenant,
                                                   self.tenant_group,
                                                   self.user,
                                                   str(self.auth_token))
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(409, int(resp['status']))

    def test_add_user_tenant_group_conflict_xml(self):
        resp, content = util.create_tenant(self.tenant, str(self.auth_token))
        resp, content = util.create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))
        resp, content = util.create_user(self.tenant, self.user,
                                      str(self.auth_token))
        resp, content = util.add_user_tenant_group_xml(self.tenant,
                                                self.tenant_group,
                                              self.user, str(self.auth_token))
        resp, content = util.add_user_tenant_group_xml(self.tenant,
                                                self.tenant_group,
                                                self.user,
                                                str(self.auth_token))

        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(409, int(resp['status']))

    def test_add_user_tenant_group_unauthorized(self):
        resp, content = util.create_tenant(self.tenant, str(self.auth_token))
        resp, content = util.create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))
        resp, content = util.create_user(self.tenant, self.user,
                                      str(self.auth_token))

        resp, content = util.add_user_tenant_group(self.tenant,
                                                   self.tenant_group,
                                                   self.user, self.token)

        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, int(resp['status']))

    def test_add_user_tenant_group_unauthorized_xml(self):
        resp, content = util.create_tenant(self.tenant, str(self.auth_token))
        resp, content = util.create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))
        resp, content = util.create_user(self.tenant, self.user,
                                         str(self.auth_token))

        resp, content = util.add_user_tenant_group_xml(self.tenant,
                                                    self.tenant_group,
                                                    self.user, self.token)

        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, int(resp['status']))

    def test_add_user_tenant_group_forbidden(self):
        resp, content = util.create_tenant(self.tenant, str(self.auth_token))
        resp, content = util.create_tenant_group(self.tenant_group,
                                                 self.tenant,
                                                 str(self.auth_token))
        resp, content = util.create_user(self.tenant, self.user,
                                      str(self.auth_token))

        resp, content = util.add_user_tenant_group(self.tenant,
                                                   self.tenant_group,
                                                   self.user,
                                                   self.disabled_token)

        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(resp['status']))

    def test_add_user_tenant_group_forbidden_xml(self):
        resp, content = util.create_tenant(self.tenant, str(self.auth_token))
        resp, content = util.create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))
        resp, content = util.create_user(self.tenant, self.user,
                                      str(self.auth_token))

        resp, content = util.add_user_tenant_group_xml(self.tenant,
                                                    self.tenant_group,
                                                    self.user,
                                                    self.disabled_token)

        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(resp['status']))


class GetUsersTenantGroupTest(TenantGroupTest):

    def setUp(self):
        self.tenant = 'test_tenant'
        self.user = util.get_user()
        self.userdisabled = util.get_userdisabled()
        self.auth_token = util.get_auth_token()
        self.exp_auth_token = util.get_exp_auth_token()
        self.disabled_token = util.get_disabled_token()
        self.tenant_group = 'test_tenant_group_add'
        util.create_tenant(self.tenant, str(self.auth_token))
        util.create_user(self.tenant, self.user, self.auth_token)
        util.add_user_json(self.tenant, self.user, self.auth_token)
        self.token = util.get_token(self.user, 'secrete', self.tenant,
                                     'token')

    def tearDown(self):
        resp, content = util.delete_user_tenant_group(self.tenant,
                                                   self.tenant_group,
                                                   self.user,
                                                   str(self.auth_token))

        resp = util.delete_user(self.tenant, self.user,
                                      str(self.auth_token))
        resp, content = util.delete_tenant_group(self.tenant_group,
                                            self.tenant,
                                            self.auth_token)
        util.delete_tenant(self.tenant, self.auth_token)

    def test_get_users_tenant_group(self):
        resp, content = util.create_tenant(self.tenant, str(self.auth_token))
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        resp, content = util.create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))

        util.create_user(self.tenant, self.user,
                                      str(self.auth_token))
        util.add_user_tenant_group(self.tenant,
                                                   self.tenant_group,
                                                   self.user,
                                                   str(self.auth_token))
        resp, content = util.get_user_tenant_group(self.tenant,
                                                   self.tenant_group,
                                                   str(self.auth_token))

        self.assertEqual(200, int(resp['status']))

    def test_get_users_tenant_group_xml(self):
        resp, content = util.create_tenant(self.tenant, str(self.auth_token))
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        util.create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))
        util.create_user(self.tenant, self.user,
                                      str(self.auth_token))
        util.add_user_tenant_group_xml(self.tenant,
                                                    self.tenant_group,
                                                    self.user,
                                                    str(self.auth_token))
        resp, content = util.get_user_tenant_group_xml(self.tenant,
                                                    self.tenant_group,
                                                    str(self.auth_token))

        self.assertEqual(200, int(resp['status']))

    def test_get_users_tenant_group_unauthorized(self):
        resp, content = util.create_tenant(self.tenant, str(self.auth_token))
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        util.create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))
        util.create_user(self.tenant, self.user,
                                      str(self.auth_token))

        util.add_user_tenant_group(self.tenant,
                                                self.tenant_group,
                                                self.user,
                                                self.auth_token)

        resp, content = util.get_user_tenant_group(self.tenant,
                                                   self.tenant_group,
                                                   str(self.token))
        self.assertEqual(401, int(resp['status']))

    def test_get_users_tenant_group_unauthorized_xml(self):
        resp, content = util.create_tenant(self.tenant, str(self.auth_token))
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')

        util.create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))
        util.create_user(self.tenant, self.user,
                                      str(self.auth_token))

        util.add_user_tenant_group(self.tenant,
                                                   self.tenant_group,
                                                   self.user, self.auth_token)
        resp, content = util.get_user_tenant_group_xml(self.tenant,
                                                    self.tenant_group,
                                                    str(self.token))
        self.assertEqual(401, int(resp['status']))

    def test_get_users_tenant_group_forbidden(self):
        resp, content = util.create_tenant(self.tenant, str(self.auth_token))
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        util.create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))
        util.create_user(self.tenant, self.user,
                                      str(self.auth_token))

        util.add_user_tenant_group(self.tenant,
                                                   self.tenant_group,
                                                   self.user, self.auth_token)
        resp, content = util.get_user_tenant_group(self.tenant,
                                                self.tenant_group,
                                                str(self.disabled_token))

        self.assertEqual(403, int(resp['status']))

    def test_get_users_tenant_group_forbidden_xml(self):
        resp, content = util.create_tenant(self.tenant, str(self.auth_token))
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        util.create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))
        util.create_user(self.tenant, self.user,
                                      str(self.auth_token))

        util.add_user_tenant_group(self.tenant,
                                                   self.tenant_group,
                                                   self.user, self.auth_token)
        resp, content = util.get_user_tenant_group_xml(self.tenant,
                                                    self.tenant_group,
                                                    str(self.disabled_token))

        self.assertEqual(403, int(resp['status']))

    def test_get_users_tenant_group_expired(self):
        resp, content = util.create_tenant(self.tenant, str(self.auth_token))
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        util.create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))
        util.create_user(self.tenant, self.user,
                                      str(self.auth_token))

        util.add_user_tenant_group(self.tenant,
                                                   self.tenant_group,
                                                   self.user, self.auth_token)
        resp, content = util.get_user_tenant_group(self.tenant,
                                                   self.tenant_group,
                                                   str(self.exp_auth_token))
        self.assertEqual(403, int(resp['status']))

    def test_get_users_tenant_group_expired_xml(self):
        resp, content = util.create_tenant(self.tenant, str(self.auth_token))
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        util.create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))
        util.create_user(self.tenant, self.user,
                                      str(self.auth_token))

        util.add_user_tenant_group(self.tenant,
                                                   self.tenant_group,
                                                self.user, self.auth_token)
        resp, content = util.get_user_tenant_group_xml(self.tenant,
                                                    self.tenant_group,
                                                    str(self.exp_auth_token))

        self.assertEqual(403, int(resp['status']))


class DeleteUsersTenantGroupTest(TenantGroupTest):

    def test_delete_user_tenant_group(self):
        resp, content = util.create_tenant(self.tenant, str(self.auth_token))
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        util.create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))
        util.create_user(self.tenant, self.user,
                                      str(self.auth_token))
        util.add_user_tenant_group(self.tenant,
                                                self.tenant_group,
                                                self.user,
                                                str(self.auth_token))
        resp, content = util.delete_user_tenant_group(self.tenant,
                                                   self.tenant_group,
                                                   self.user,
                                                   str(self.auth_token))

        self.assertEqual(204, int(resp['status']))

    def test_delete_user_tenant_group_xml(self):
        resp, content = util.create_tenant(self.tenant, str(self.auth_token))
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        util.create_tenant_group(self.tenant_group,
                                              self.tenant,
                                              str(self.auth_token))
        util.create_user(self.tenant, self.user,
                                      str(self.auth_token))
        util.add_user_tenant_group_xml(self.tenant,
                                                    self.tenant_group,
                                                    self.user,
                                                    str(self.auth_token))
        resp, content = util.delete_user_tenant_group_xml(self.tenant,
                                                    self.tenant_group,
                                                    self.user,
                                                    str(self.auth_token))

        self.assertEqual(204, int(resp['status']))

    def test_delete_user_tenant_group_notfound(self):
        resp, content = util.delete_user_tenant_group(self.tenant,
                                                   self.tenant_group,
                                                   'NonExistinguser',
                                                   str(self.auth_token))
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, int(resp['status']))

    def test_delete_user_tenant_group_notfound_xml(self):
        resp, content = util.delete_user_tenant_group_xml(self.tenant,
                                                   self.tenant_group,
                                                   'NonExistinguser',
                                                   str(self.auth_token))
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, int(resp['status']))

if __name__ == '__main__':
    unittest.main()
