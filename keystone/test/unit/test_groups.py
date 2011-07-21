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
                                '..', '..', '..', '..', '..', 'keystone')))
import unittest

import test_common as utils


##
## Global Group Tests
##


class GlobalGroupTest(unittest.TestCase):

    def setUp(self):
        self.globaltenant = utils.get_global_tenant()
        self.user = utils.get_user()
        self.userdisabled = utils.get_userdisabled()
        self.auth_token = utils.get_auth_token()
        self.exp_auth_token = utils.get_exp_auth_token()
        self.disabled_token = utils.get_disabled_token()
        self.global_group = 'test_global_group_add'
        utils.create_tenant(self.globaltenant, str(self.auth_token))
        utils.create_user(self.globaltenant, self.user, self.auth_token)
        utils.add_user_json(self.auth_token)
        self.token = utils.get_token(self.user, 'secrete', self.globaltenant,
                                     'token')

    def tearDown(self):
        utils.delete_user(self.user, str(self.auth_token))
        utils.delete_global_group(self.global_group, self.auth_token)
        utils.delete_tenant(self.globaltenant, self.auth_token)


class CreateGlobalGroupTest(GlobalGroupTest):

    def test_global_group_create(self):
        utils.delete_global_group(self.global_group, str(self.auth_token))
        resp_new, _content_new = utils.create_global_group(self.global_group,
                                              str(self.auth_token))

        if int(resp_new['status']) == 500:
            self.fail('Identity fault')
        elif int(resp_new['status']) == 503:
            self.fail('Service Not Available')
        if int(resp_new['status']) not in (200, 201):
            self.fail('Failed due to %d' % int(resp_new['status']))

    def test_global_group_create_xml(self):
        utils.delete_global_group_xml(self.global_group, str(self.auth_token))
        resp_new, _content_new = utils.create_global_group_xml(\
                                                  self.global_group,
                                                  str(self.auth_token))

        if int(resp_new['status']) == 500:
            self.fail('Identity fault')
        elif int(resp_new['status']) == 503:
            self.fail('Service Not Available')

        if int(resp_new['status']) not in (200, 201):
            self.fail('Failed due to %d' % int(resp_new['status']))

    def test_global_group_create_again(self):
        utils.create_global_group(self.global_group, str(self.auth_token))
        resp_new, _content_new = utils.create_global_group(self.global_group,
                                              str(self.auth_token))
        if int(resp_new['status']) == 500:
            self.fail('Identity fault')
        elif int(resp_new['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(409, int(resp_new['status']))

    def test_global_group_create_again_xml(self):
        utils.create_global_group_xml(self.global_group, str(self.auth_token))
        resp_new, content_new = utils.create_global_group_xml(\
                                                self.global_group,
                                                str(self.auth_token))
        content_new = etree.fromstring(content_new)
        if int(resp_new['status']) == 500:
            self.fail('Identity fault')
        elif int(resp_new['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(409, int(resp_new['status']))

    def test_global_group_create_unauthorized_token(self):
        _header = httplib2.Http(".cache")
        resp, _content = utils.create_global_group(\
                                                    self.global_group,
                                                    str(self.token))
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, int(resp['status']))

    def test_global_group_create_unauthorized_token_xml(self):
        _header = httplib2.Http(".cache")
        resp, _content = utils.create_global_group_xml(\
                                                    self.global_group,
                                                    str(self.token))
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, int(resp['status']))

    def test_global_group_create_expired_token(self):
        header = httplib2.Http(".cache")
        url = '%sgroups' % (utils.URL_V2)
        body = {"group": {"id": self.global_group,
                          "description": "A description ..."}}
        resp, _content = header.request(url, "POST", body=json.dumps(body),
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": \
                                                   self.exp_auth_token})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(resp['status']))

    def test_global_group_create_expired_token_xml(self):
        header = httplib2.Http(".cache")
        url = '%sgroups' % (utils.URL_V2)
        body = '<?xml version="1.0" encoding="UTF-8"?> \
                <group xmlns="http://docs.openstack.org/identity/api/v2.0" \
                id="%s"><description>A description...</description> \
                </group>' % self.globaltenant
        resp, _content = header.request(url, "POST", body=body,
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.exp_auth_token,
                                           "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(resp['status']))

    def test_global_group_create_missing_token(self):
        header = httplib2.Http(".cache")
        url = '%sgroups' % (utils.URL_V2)
        body = {"group": {"id": self.global_group,
                          "description": "A description ..."}}
        resp, _content = header.request(url, "POST", body=json.dumps(body),
                                  headers={"Content-Type": "application/json"})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, int(resp['status']))

    def test_global_group_create_missing_token_xml(self):
        header = httplib2.Http(".cache")
        url = '%sgroups' % (utils.URL_V2)
        body = '<?xml version="1.0" encoding="UTF-8"?> \
                <group xmlns="http://docs.openstack.org/identity/api/v2.0" \
                id="%s"><description>A description...</description> \
                </group>' % self.global_group
        resp, _content = header.request(url, "POST", body=body,
                                  headers={"Content-Type": "application/xml",
                                           "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, int(resp['status']))

    def test_global_group_create_disabled_token(self):
        header = httplib2.Http(".cache")
        url = '%sgroups' % (utils.URL_V2)
        body = '{"group": { "id": "%s", \
                "description": "A description ..." } }' % self.global_group
        resp, _content = header.request(url, "POST", body=body,
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": \
                                                   self.disabled_token})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(resp['status']))

    def test_global_group_create_disabled_token_xml(self):
        header = httplib2.Http(".cache")
        url = '%sgroups' % (utils.URL_V2)
        body = '<?xml version="1.0" encoding="UTF-8"?> \
                <group xmlns="http://docs.openstack.org/identity/api/v2.0" \
                id="%s"><description>A description...</description> \
                </group>' % self.global_group
        resp, _content = header.request(url, "POST", body=body,
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.disabled_token,
                                           "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(resp['status']))

    def test_global_group_create_invalid_token(self):
        header = httplib2.Http(".cache")
        url = '%sgroups' % (utils.URL_V2)
        body = '{"group": { "id": "%s", \
                "description": "A description ..." } }' % self.globaltenant
        resp, _content = header.request(url, "POST", body=body,
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": 'nonexsitingtoken'})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, int(resp['status']))

    def test_global_group_create_invalid_token_xml(self):
        header = httplib2.Http(".cache")
        url = '%sgroups' % (utils.URL_V2)
        body = '<?xml version="1.0" encoding="UTF-8"?> \
                <group xmlns="http://docs.openstack.org/identity/api/v2.0" \
                id="%s"><description>A description...</description> \
                </group>' % self.global_group
        resp, _content = header.request(url, "POST", body=body,
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": 'nonexsitingtoken',
                                           "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, int(resp['status']))


class GetGlobalGroupsTest(GlobalGroupTest):

    def test_get_global_groups(self):
        header = httplib2.Http(".cache")
        utils.delete_global_group(self.global_group, str(self.auth_token))
        _resp_new, _content_new = utils.create_global_group(self.global_group,
                                              str(self.auth_token))

        url = '%sgroups' % (utils.URL_V2)
        resp, _content = header.request(url, "GET", body='{}',
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.auth_token})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(200, int(resp['status']))

    def test_get_global_groups_xml(self):
        header = httplib2.Http(".cache")
        utils.create_global_group_xml(self.global_group, str(self.auth_token))
        url = '%sgroups' % (utils.URL_V2)
        resp, _content = header.request(url, "GET", body='',
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.auth_token,
                                           "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(200, int(resp['status']))

    def test_get_global_groups_unauthorized_token(self):
        header = httplib2.Http(".cache")
        _resp_new, _content_new = utils.create_global_group(self.global_group,
                                              str(self.auth_token))
        url = '%sgroups' % (utils.URL_V2)
        #test for Content-Type = application/json
        resp, _content = header.request(url, "GET", body='{}',
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.token})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, int(resp['status']))

    def test_get_global_groups_unauthorized_token_xml(self):
        header = httplib2.Http(".cache")
        _resp_new, _content_new = utils.create_global_group_xml(\
                                                    self.global_group,
                                                    str(self.auth_token))
        url = '%sgroups' % (utils.URL_V2)
        #test for Content-Type = application/json
        resp, _content = header.request(url, "GET", body='',
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.token,
                                           "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, int(resp['status']))

    def test_get_global_groups_exp_token(self):
        header = httplib2.Http(".cache")
        _resp_new, _content_new = utils.create_global_group(self.global_group,
                                              str(self.auth_token))
        url = '%sgroups' % (utils.URL_V2)
        #test for Content-Type = application/json
        resp, _content = header.request(url, "GET", body='{}',
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": \
                                                   self.exp_auth_token})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(resp['status']))

    def test_get_global_groups_exp_token_xml(self):
        header = httplib2.Http(".cache")
        _resp_new, _content_new = utils.create_global_group_xml(\
                                                    self.global_group,
                                                    str(self.auth_token))
        url = '%sgroups' % (utils.URL_V2)
        #test for Content-Type = application/json
        resp, _content = header.request(url, "GET", body='',
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.exp_auth_token,
                                           "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(resp['status']))


class GetGlobalGroupTest(GlobalGroupTest):

    def test_get_global_group(self):
        header = httplib2.Http(".cache")
        _resp_new, _content_new = utils.create_global_group(self.global_group,
                                              str(self.auth_token))
        url = '%sgroups/%s' % (utils.URL_V2, self.global_group)
        #test for Content-Type = application/json
        resp, _content = header.request(url, "GET", body='{}',
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.auth_token})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(200, int(resp['status']))

    def test_get_global_group_xml(self):
        header = httplib2.Http(".cache")
        _resp_new, _content_new = utils.create_global_group_xml(\
                                                    self.global_group,
                                                    str(self.auth_token))
        url = '%sgroups/%s' % (utils.URL_V2, self.global_group)
        #test for Content-Type = application/json
        resp, _content = header.request(url, "GET", body='',
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.auth_token,
                                           "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(200, int(resp['status']))

    def test_get_global_group_bad(self):
        header = httplib2.Http(".cache")
        _resp_new, _content_new = utils.create_global_group(self.global_group,
                                              str(self.auth_token))
        url = '%sgroups/%s' % (utils.URL_V2, 'global_group_bad')
        #test for Content-Type = application/json
        resp, _content = header.request(url, "GET", body='',
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.auth_token})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, int(resp['status']))

    def test_get_global_group_bad_xml(self):
        header = httplib2.Http(".cache")
        _resp_new, _content_new = utils.create_global_group_xml(\
                                                    self.global_group,
                                                    str(self.auth_token))
        url = '%sgroups/%s' % (utils.URL_V2, 'global_group_bad')
        #test for Content-Type = application/json
        resp, _content = header.request(url, "GET", body='',
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.auth_token,
                                           "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, int(resp['status']))


class UpdateGlobalGroupsTest(GlobalGroupTest):

    def test_update_global_group(self):
        header = httplib2.Http(".cache")
        _resp_new, _content_new = utils.create_global_group(self.global_group,
                                              str(self.auth_token))
        url = '%sgroups/%s' % (utils.URL_V2, self.global_group)
        resp, content = header.request(url, "PUT", body='{"group":{\
                "id" : "%s","description" :\
                "A New description of the group..."}}' % self.global_group,
                headers={"Content-Type": "application/json",
                         "X-Auth-Token": self.auth_token})
        body = json.loads(content)
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(200, int(resp['status']))
        self.assertEqual(self.global_group, body['group']['id'])
        self.assertEqual('A New description of the group...',
                         str(body['group']['description']))

    def test_update_global_group_xml(self):
        header = httplib2.Http(".cache")
        _resp_new, _content_new = utils.create_global_group(self.global_group,
                                                  str(self.auth_token))

        url = '%sgroups/%s' % (utils.URL_V2, self.global_group)
        data = u'<?xml version="1.0" encoding="UTF-8"?> \
                <group xmlns="http://docs.openstack.org/identity/api/v2.0" \
                id="%s"><description>A NEW description...</description> \
                </group>' % (self.global_group)
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
        self.assertEqual(str(self.global_group), str(body.get('id')))
        self.assertEqual('A NEW description...', desc.text)

    def test_update_global_group_bad(self):
        header = httplib2.Http(".cache")
        _resp_new, _content_new = utils.create_global_group(self.global_group,
                                              str(self.auth_token))
        url = '%sgroups/%s' % (utils.URL_V2, self.global_group)
        data = '{"group": { "description_bad": "A NEW description...", \
                "id":"%s"  }}'\
                % (self.global_group)
        #test for Content-Type = application/json
        resp, _content = header.request(url, "PUT", body=data,
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.auth_token})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(400, int(resp['status']))

    def test_update_global_group_bad_xml(self):
        header = httplib2.Http(".cache")
        utils.create_global_group_xml(self.global_group, str(self.auth_token))
        url = '%sgroups/%s' % (utils.URL_V2, self.global_group)
        data = '<?xml version="1.0" encoding="UTF-8"?> \
                <group xmlns="http://docs.openstack.org/identity/api/v2.0" \
                id="%s"><description_bad>A NEW description...</description> \
                </group>' % (self.global_group)
        #test for Content-Type = application/json
        resp, _content = header.request(url, "PUT", body=data,
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.auth_token,
                                           "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')

        self.assertEqual(400, int(resp['status']))

    def test_update_global_group_not_found(self):
        header = httplib2.Http(".cache")
        utils.create_global_group(self.global_group, str(self.auth_token))
        url = '%sgroups/NonexistingID' % (utils.URL_V2)
        data = '{"group": { "description": "A NEW description...", \
                "id":"NonexistingID"}}'
        #test for Content-Type = application/json
        resp, _content = header.request(url, "GET", body=data,
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.auth_token})
        self.assertEqual(404, int(resp['status']))

    def test_update_global_group_not_found_xml(self):
        header = httplib2.Http(".cache")
        utils.create_tenant_xml(self.globaltenant, str(self.auth_token))
        url = '%sgroups/NonexistingID' % (utils.URL_V2)
        data = '<?xml version="1.0" encoding="UTF-8"?> \
                <group xmlns="http://docs.openstack.org/identity/api/v2.0" \
                id="NonexistingID"> \
                <description_bad>A NEW description...</description> \
                </group>'
        #test for Content-Type = application/json
        resp, _content = header.request(url, "GET", body=data,
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.auth_token,
                                           "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, int(resp['status']))


class DeleteGlobalGroupTest(GlobalGroupTest):

    def test_delete_global_group_not_found(self):
        resp, _content = utils.delete_global_group("test_global_group_1",
                                            str(self.auth_token))
        self.assertEqual(404, int(resp['status']))

    def test_delete_global_group_not_found_xml(self):
        resp, _content = utils.delete_global_group_xml("test_global_group_1",
                                                str(self.auth_token))
        self.assertEqual(404, int(resp['status']))

    def test_delete_global_group(self):
        utils.create_tenant(self.globaltenant, str(self.auth_token))
        utils.create_tenant_group('test_global_group_delete',
                                  self.globaltenant, str(self.auth_token))
        resp_new, _content_new = utils.delete_global_group(\
                                  'test_global_group_delete',
                                  str(self.auth_token))
        _resp = utils.delete_tenant(self.globaltenant, str(self.auth_token))
        self.assertEqual(204, int(resp_new['status']))

    def test_delete_global_group_xml(self):

        utils.create_tenant_xml(self.globaltenant, str(self.auth_token))

        utils.create_tenant_group_xml('test_global_group_delete',
                                      self.globaltenant, str(self.auth_token))

        resp_new, _content_new = utils.delete_global_group_xml(\
                                                  'test_global_group_delete',
                                                  str(self.auth_token))
        utils.delete_tenant_xml(self.globaltenant, str(self.auth_token))

        self.assertEqual(204, int(resp_new['status']))


class AddUserGlobalGroupTest(unittest.TestCase):

    def setUp(self):
        self.tenant = utils.get_global_tenant()
        self.auth_token = utils.get_auth_token()
        self.user = utils.get_user()
        self.userdisabled = utils.get_userdisabled()
        self.exp_auth_token = utils.get_exp_auth_token()
        self.disabled_token = utils.get_disabled_token()
        self.global_group = 'test_global_group'
        utils.create_tenant(self.tenant, str(self.auth_token))
        utils.create_user(self.tenant, self.user, self.auth_token)
        utils.add_user_json(self.auth_token)
        self.token = utils.get_token(self.user, 'secrete', self.tenant,
                                     'token')
        
    def tearDown(self):
        utils.delete_user_global_group(self.global_group, self.user,
                                       str(self.auth_token))

        utils.delete_user(self.user, str(self.auth_token))
        utils.delete_user(self.user, self.auth_token)
        utils.delete_global_group(self.global_group, self.auth_token)

    def test_add_user_global_group(self):
        resp, _content = utils.create_global_group(self.global_group,
                                              str(self.auth_token))
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        resp_new, _content_new = utils.add_user_global_group(self.global_group,
                                                self.user,
                                                str(self.auth_token))

        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        if int(resp_new['status']) not in (200, 201):
            self.fail('Failed due to %d' % int(resp_new['status']))

    def test_add_user_global_group_xml(self):
        resp, _content = utils.create_global_group(self.global_group,
                                              str(self.auth_token))
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        resp_new, _content_new = utils.add_user_global_group_xml(\
                                                self.global_group,
                                                self.user,
                                                str(self.auth_token))

        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        if int(resp_new['status']) not in (200, 201):
            self.fail('Failed due to %d' % int(resp_new['status']))

    def test_add_user_global_group_conflict(self):
        resp, _content = utils.create_global_group(self.global_group,
                                              str(self.auth_token))
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        utils.add_user_global_group(self.global_group, self.user,
                                    str(self.auth_token))
        resp_new, _content_new = utils.add_user_global_group(self.global_group,
                                                self.user,
                                                str(self.auth_token))

        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(409, int(resp_new['status']))

    def test_add_user_global_group_conflict_xml(self):
        resp, _content = utils.create_global_group(self.global_group,
                                              str(self.auth_token))
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        utils.add_user_global_group_xml(self.global_group, self.user,
                                        str(self.auth_token))
        resp_new, _content_new = utils.add_user_global_group_xml(\
                                                self.global_group,
                                                self.user,
                                                str(self.auth_token))

        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(409, int(resp_new['status']))

    def test_add_user_global_group_unauthorized(self):
        resp, _content = utils.create_global_group(self.global_group,
                                              str(self.auth_token))

        utils.create_user(self.tenant, self.user, str(self.auth_token))

        resp_new, _content_new = utils.add_user_global_group(self.global_group,
                                                self.user,
                                                str(self.token))
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, int(resp_new['status']))

    def test_add_user_global_group_unauthorized_xml(self):
        resp, _content = utils.create_global_group(self.global_group,
                                              str(self.auth_token))
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        resp_new, _content_new = utils.add_user_global_group_xml(\
                                                    self.global_group,
                                                    self.user,
                                                    str(self.token))

        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, int(resp_new['status']))

    def test_add_user_global_group_forbidden(self):
        resp, _content = utils.create_global_group(self.global_group,
                                              str(self.auth_token))
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        resp_new, _content_new = utils.add_user_global_group(\
                                                self.global_group,
                                                self.user,
                                                str(self.disabled_token))

        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(resp_new['status']))

    def test_add_user_global_group_forbidden_xml(self):
        resp, _content = utils.create_global_group(self.global_group,
                                              str(self.auth_token))
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        resp_new, _content_new = utils.add_user_global_group_xml(\
                                                self.global_group,
                                                self.user,
                                                str(self.disabled_token))
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(resp_new['status']))


class GetUsersTenantGroupTest(unittest.TestCase):

    def setUp(self):
        self.tenant = utils.get_global_tenant()
        self.user = utils.get_user()
        self.userdisabled = utils.get_userdisabled()
        self.auth_token = utils.get_auth_token()
        self.exp_auth_token = utils.get_exp_auth_token()
        self.disabled_token = utils.get_disabled_token()
        self.global_group = 'test_global_group'
        utils.create_tenant(self.tenant, str(self.auth_token))
        utils.create_user(self.tenant, self.user, self.auth_token)
        utils.add_user_json(self.auth_token)
        self.token = utils.get_token(self.user, 'secrete', self.tenant,
                                     'token')

    def tearDown(self):
        utils.delete_user_global_group(self.global_group, self.user,
                                       str(self.auth_token))
        utils.delete_user(self.user, str(self.auth_token))
        utils.delete_global_group(self.global_group, self.auth_token)

    def test_get_users_global_group(self):
        resp, _content = utils.create_global_group(self.global_group,
                                              str(self.auth_token))
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        utils.add_user_global_group(self.global_group, self.user,
                                    str(self.auth_token))
        resp_new, _content_new = utils.get_user_global_group(
                                                self.global_group,
                                                str(self.auth_token))

        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(200, int(resp_new['status']))

    def test_get_users_global_group_xml(self):
        resp, _content = utils.create_global_group(self.global_group,
                                              str(self.auth_token))
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        utils.add_user_global_group_xml(self.global_group, self.user,
                                        str(self.auth_token))
        resp_new, _content_new = utils.get_user_global_group_xml(\
                                                self.global_group,
                                                str(self.auth_token))
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(200, int(resp_new['status']))

    def test_get_users_global_group_unauthorized(self):
        resp, _content = utils.create_global_group(self.global_group,
                                              str(self.auth_token))
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        utils.add_user_global_group(self.global_group, self.user,
                                    str(self.auth_token))

        resp_new, _content_new = utils.get_user_global_group(\
                                                self.global_group,
                                                str(self.token))

        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, int(resp_new['status']))

    def test_get_users_global_group_unauthorized_xml(self):
        resp, _content = utils.create_global_group(self.global_group,
                                              str(self.auth_token))
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        utils.add_user_global_group(self.global_group, self.user,
                                    str(self.auth_token))
        resp_new, _content_new = utils.get_user_global_group_xml(\
                                                self.global_group,
                                                str(self.token))

        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, int(resp_new['status']))

    def test_get_users_global_group_forbidden(self):
        resp, _content = utils.create_global_group(self.global_group,
                                              str(self.auth_token))
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        utils.add_user_global_group(self.global_group, self.user,
                                    str(self.auth_token))
        resp_new, _content_new = utils.get_user_global_group(\
                                                self.global_group,
                                                str(self.disabled_token))

        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(resp_new['status']))

    def test_get_users_global_group_forbidden_xml(self):
        resp, _content = utils.create_global_group(self.global_group,
                                              str(self.auth_token))
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        utils.add_user_global_group(self.global_group, self.user,
                                    str(self.auth_token))
        resp_new, _content_new = utils.get_user_global_group_xml(\
                                                self.global_group,
                                                str(self.disabled_token))
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(resp_new['status']))

    def test_get_users_global_group_expired(self):
        resp, _content = utils.create_global_group(self.global_group,
                                              str(self.auth_token))
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        utils.add_user_global_group(self.global_group, self.user,
                                    str(self.auth_token))
        resp_new, _content_new = utils.get_user_global_group(\
                                                self.global_group,
                                                str(self.exp_auth_token))

        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(resp_new['status']))

    def test_get_users_global_group_expired_xml(self):
        resp, _content = utils.create_global_group(self.global_group,
                                              str(self.auth_token))
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        utils.add_user_global_group(self.global_group, self.user,
                                    str(self.auth_token))
        resp_new, _content_new = utils.get_user_global_group_xml(\
                                                self.global_group,
                                                str(self.exp_auth_token))
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(resp_new['status']))


class DeleteUsersGlobalGroupTest(unittest.TestCase):

    def setUp(self):
        self.tenant = utils.get_global_tenant()
        self.user = utils.get_user()
        self.userdisabled = utils.get_userdisabled()
        self.auth_token = utils.get_auth_token()
        self.exp_auth_token = utils.get_exp_auth_token()
        self.disabled_token = utils.get_disabled_token()
        self.global_group = 'test_global_group'
        utils.create_tenant(self.tenant, str(self.auth_token))
        utils.create_user(self.tenant, self.user, self.auth_token)
        utils.add_user_json(self.auth_token)
        self.token = utils.get_token(self.user, 'secrete', self.tenant,
                                     'token')

    def tearDown(self):
        utils.delete_user_global_group(self.global_group, self.user,
                                       str(self.auth_token))

        utils.delete_user(self.user, str(self.auth_token))
        utils.delete_global_group(self.global_group, self.auth_token)

    def test_delete_user_global_group(self):
        resp, _content = utils.create_global_group(self.global_group,
                                              str(self.auth_token))
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        utils.add_user_global_group(self.global_group, self.user,
                                    str(self.auth_token))

        resp_new, _content_new = utils.delete_user_global_group(\
                                                    self.global_group,
                                                   self.user,
                                                   str(self.auth_token))

        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(204, int(resp_new['status']))

    def test_delete_user_global_group_xml(self):
        resp, _content = utils.create_global_group(self.global_group,
                                              str(self.auth_token))
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        utils.add_user_global_group(self.global_group, self.user,
                                    str(self.auth_token))
        resp_new, _content_new = utils.delete_user_global_group_xml(\
                                                    self.global_group,
                                                   self.user,
                                                   str(self.auth_token))
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(204, int(resp_new['status']))

    def test_delete_user_global_group_notfound(self):
        resp, _content = utils.create_global_group(self.global_group,
                                              str(self.auth_token))
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        utils.add_user_global_group(self.global_group, self.user,
                                    str(self.disabled_token))
        utils.delete_user_global_group(self.global_group, self.user,
                                       str(self.auth_token))
        resp_new, _content_new = utils.delete_user_global_group(
                                                self.global_group,
                                                self.user,
                                                str(self.auth_token))
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, int(resp_new['status']))

    def test_delete_user_global_group_notfound_xml(self):
        resp, _content = utils.create_global_group(self.global_group,
                                              str(self.auth_token))
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        utils.add_user_global_group(self.global_group, self.user,
                                    str(self.disabled_token))
        utils.delete_user_global_group(self.global_group, self.user,
                                       str(self.auth_token))
        resp_new, _content_new = utils.delete_user_global_group_xml(\
                                        self.global_group, self.user,
                                           str(self.auth_token))
        self.assertEqual(404, int(resp_new['status']))

if __name__ == '__main__':
    unittest.main()
