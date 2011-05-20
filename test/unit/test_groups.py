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

import test_common as utils

##
## Global Group Tests
##


class global_group_test(unittest.TestCase):

    def setUp(self):
        self.token = utils.get_token('joeuser', 'secrete', 'token')
        self.globaltenant = utils.get_global_tenant()
        self.user = utils.get_user()
        self.userdisabled = utils.get_userdisabled()
        self.auth_token = utils.get_auth_token()
        self.exp_auth_token = utils.get_exp_auth_token()
        self.disabled_token = utils.get_disabled_token()
        self.global_group = 'test_global_group_add'

    def tearDown(self):
        resp, content = utils.delete_global_group(self.global_group,
                                            self.auth_token)
        resp, content = utils.delete_tenant(self.globaltenant, self.auth_token)


class create_global_group_test(global_group_test):

    def test_global_group_create(self):
        respG, contentG = utils.delete_global_group(self.global_group,
                                              str(self.auth_token))
        respG, contentG = utils.create_global_group(self.global_group,
                                              str(self.auth_token))

        if int(respG['status']) == 500:
            self.fail('Identity Fault')
        elif int(respG['status']) == 503:
            self.fail('Service Not Available')
        if int(respG['status']) not in (200, 201):
            self.fail('Failed due to %d' % int(respG['status']))

    def test_global_group_create_xml(self):
        respG, contentG = utils.delete_global_group_xml(self.global_group,
                                                  str(self.auth_token))
        respG, contentG = utils.create_global_group_xml(self.global_group,
                                                  str(self.auth_token))

        if int(respG['status']) == 500:
            self.fail('Identity Fault')
        elif int(respG['status']) == 503:
            self.fail('Service Not Available')

        if int(respG['status']) not in (200, 201):
            self.fail('Failed due to %d' % int(respG['status']))

    def test_global_group_create_again(self):
        respG, contentG = utils.create_global_group(self.global_group,
                                              str(self.auth_token))
        respG, contentG = utils.create_global_group(self.global_group,
                                              str(self.auth_token))
        if int(respG['status']) == 500:
            self.fail('Identity Fault')
        elif int(respG['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(409, int(respG['status']))

    def test_global_group_create_again_xml(self):
        respG, contentG = utils.create_global_group_xml(self.global_group,
                                                  str(self.auth_token))
        respG, contentG = utils.create_global_group_xml(self.global_group,
                                                  str(self.auth_token))
        contentG = etree.fromstring(contentG)
        if int(respG['status']) == 500:
            self.fail('Identity Fault')
        elif int(respG['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(409, int(respG['status']))

    def test_global_group_create_unauthorized_token(self):
        h = httplib2.Http(".cache")
        respG, contentG = utils.create_global_group_xml(self.global_group,
                                                  str(self.auth_token))
        url = '%sgroups' % (utils.URL)
        body = {"group": {"id": self.global_group,
                          "description": "A description ..."}}
        resp, content = h.request(url, "POST", body=json.dumps(body),
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.token})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, int(resp['status']))

    def test_global_group_create_unauthorized_token_xml(self):
        h = httplib2.Http(".cache")
        url = '%sgroups' % (utils.URL)
        body = '<?xml version="1.0" encoding="UTF-8"?> \
                <group xmlns="http://docs.openstack.org/identity/api/v2.0" \
                id="%s"> \
                <description>A description...</description> \
                </group>' % self.global_group
        resp, content = h.request(url, "POST", body=body,
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.token,
                                           "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, int(resp['status']))

    def test_global_group_create_expired_token(self):
        h = httplib2.Http(".cache")
        url = '%sgroups' % (utils.URL)
        body = {"group": {"id": self.global_group,
                          "description": "A description ..."}}
        resp, content = h.request(url, "POST", body=json.dumps(body),
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": \
                                                   self.exp_auth_token})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(resp['status']))

    def test_global_group_create_expired_token_xml(self):
        h = httplib2.Http(".cache")
        url = '%sgroups' % (utils.URL)
        body = '<?xml version="1.0" encoding="UTF-8"?> \
                <group xmlns="http://docs.openstack.org/identity/api/v2.0" \
                id="%s"><description>A description...</description> \
                </group>' % self.globaltenant
        resp, content = h.request(url, "POST", body=body,
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.exp_auth_token,
                                           "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(resp['status']))

    def test_global_group_create_missing_token(self):
        h = httplib2.Http(".cache")
        url = '%sgroups' % (utils.URL)
        body = {"group": {"id": self.global_group,
                          "description": "A description ..."}}
        resp, content = h.request(url, "POST", body=json.dumps(body),
                                  headers={"Content-Type": "application/json"})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, int(resp['status']))

    def test_global_group_create_missing_token_xml(self):
        h = httplib2.Http(".cache")
        url = '%sgroups' % (utils.URL)
        body = '<?xml version="1.0" encoding="UTF-8"?> \
                <group xmlns="http://docs.openstack.org/identity/api/v2.0" \
                id="%s"><description>A description...</description> \
                </group>' % self.global_group
        resp, content = h.request(url, "POST", body=body,
                                  headers={"Content-Type": "application/xml",
                                           "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, int(resp['status']))

    def test_global_group_create_disabled_token(self):
        h = httplib2.Http(".cache")
        url = '%sgroups' % (utils.URL)
        body = '{"group": { "id": "%s", \
                "description": "A description ..." } }' % self.global_group
        resp, content = h.request(url, "POST", body=body,
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": \
                                                   self.disabled_token})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(resp['status']))

    def test_global_group_create_disabled_token_xml(self):
        h = httplib2.Http(".cache")
        url = '%sgroups' % (utils.URL)
        body = '<?xml version="1.0" encoding="UTF-8"?> \
                <group xmlns="http://docs.openstack.org/identity/api/v2.0" \
                id="%s"><description>A description...</description> \
                </group>' % self.global_group
        resp, content = h.request(url, "POST", body=body,
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.disabled_token,
                                           "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(resp['status']))

    def test_global_group_create_invalid_token(self):
        h = httplib2.Http(".cache")
        url = '%sgroups' % (utils.URL)
        body = '{"group": { "id": "%s", \
                "description": "A description ..." } }' % self.globaltenant
        resp, content = h.request(url, "POST", body=body,
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": 'nonexsitingtoken'})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, int(resp['status']))

    def test_global_group_create_invalid_token_xml(self):
        h = httplib2.Http(".cache")
        url = '%sgroups' % (utils.URL)
        body = '<?xml version="1.0" encoding="UTF-8"?> \
                <group xmlns="http://docs.openstack.org/identity/api/v2.0" \
                id="%s"><description>A description...</description> \
                </group>' % self.global_group
        resp, content = h.request(url, "POST", body=body,
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": 'nonexsitingtoken',
                                           "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, int(resp['status']))


class get_global_groups_test(global_group_test):

    def test_get_global_groups(self):
        h = httplib2.Http(".cache")
        respG, contentG = utils.delete_global_group(self.global_group,
                                              str(self.auth_token))
        respG, contentG = utils.create_global_group(self.global_group,
                                              str(self.auth_token))

        url = '%sgroups' % (utils.URL)
        resp, content = h.request(url, "GET", body='{}',
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.auth_token})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(200, int(resp['status']))

    def test_get_global_groups_xml(self):
        h = httplib2.Http(".cache")
        respG, contentG = utils.create_global_group_xml(self.global_group,
                                                  str(self.auth_token))
        url = '%sgroups' % (utils.URL)
        resp, content = h.request(url, "GET", body='',
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.auth_token,
                                           "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(200, int(resp['status']))

    def test_get_global_groups_unauthorized_token(self):
        h = httplib2.Http(".cache")
        respG, contentG = utils.create_global_group(self.global_group,
                                              str(self.auth_token))
        url = '%sgroups' % (utils.URL)
        #test for Content-Type = application/json
        resp, content = h.request(url, "GET", body='{}',
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.token})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, int(resp['status']))

    def test_get_global_groups_unauthorized_token_xml(self):
        h = httplib2.Http(".cache")
        respG, contentG = utils.create_global_group_xml(self.global_group,
                                                  str(self.auth_token))
        url = '%sgroups' % (utils.URL)
        #test for Content-Type = application/json
        resp, content = h.request(url, "GET", body='',
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.token,
                                           "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, int(resp['status']))

    def test_get_global_groups_exp_token(self):
        h = httplib2.Http(".cache")
        respG, contentG = utils.create_global_group(self.global_group,
                                              str(self.auth_token))
        url = '%sgroups' % (utils.URL)
        #test for Content-Type = application/json
        resp, content = h.request(url, "GET", body='{}',
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": \
                                                   self.exp_auth_token})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(resp['status']))

    def test_get_global_groups_exp_token_xml(self):
        h = httplib2.Http(".cache")
        respG, contentG = utils.create_global_group_xml(self.global_group,
                                                  str(self.auth_token))
        url = '%sgroups' % (utils.URL)
        #test for Content-Type = application/json
        resp, content = h.request(url, "GET", body='',
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.exp_auth_token,
                                           "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(resp['status']))


class get_global_group_test(global_group_test):

    def test_get_global_group(self):
        h = httplib2.Http(".cache")
        respG, contentG = utils.create_global_group(self.global_group,
                                              str(self.auth_token))
        url = '%sgroups/%s' % (utils.URL, self.global_group)
        #test for Content-Type = application/json
        resp, content = h.request(url, "GET", body='{}',
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.auth_token})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(200, int(resp['status']))

    def test_get_global_group_xml(self):
        h = httplib2.Http(".cache")
        respG, contentG = utils.create_global_group_xml(self.global_group,
                                                  str(self.auth_token))
        url = '%sgroups/%s' % (utils.URL, self.global_group)
        #test for Content-Type = application/json
        resp, content = h.request(url, "GET", body='',
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.auth_token,
                                           "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(200, int(resp['status']))

    def test_get_global_group_bad(self):
        h = httplib2.Http(".cache")
        respG, contentG = utils.create_global_group(self.global_group,
                                              str(self.auth_token))
        url = '%sgroups/%s' % (utils.URL, 'global_group_bad')
        #test for Content-Type = application/json
        resp, content = h.request(url, "GET", body='',
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.auth_token})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, int(resp['status']))

    def test_get_global_group_bad_xml(self):
        h = httplib2.Http(".cache")
        respG, contentG = utils.create_global_group_xml(self.global_group,
                                                  str(self.auth_token))
        url = '%sgroups/%s' % (utils.URL, 'global_group_bad')
        #test for Content-Type = application/json
        resp, content = h.request(url, "GET", body='',
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.auth_token,
                                           "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, int(resp['status']))


class update_global_groups_test(global_group_test):

    def test_update_global_group(self):
        h = httplib2.Http(".cache")
        respG, contentG = utils.create_global_group(self.global_group,
                                              str(self.auth_token))
        url = '%sgroups/%s' % (utils.URL, self.global_group)
        resp, content = h.request(url, "PUT", body='{"group":{\
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
        h = httplib2.Http(".cache")
        respG, contentG = utils.create_global_group(self.global_group,
                                                  str(self.auth_token))

        url = '%sgroups/%s' % (utils.URL, self.global_group)
        data = u'<?xml version="1.0" encoding="UTF-8"?> \
                <group xmlns="http://docs.openstack.org/identity/api/v2.0" \
                id="%s"><description>A NEW description...</description> \
                </group>' % (self.global_group)
        #test for Content-Type = application/json
        resp, content = h.request(url, "PUT", body=data,
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
        h = httplib2.Http(".cache")
        respG, contentG = utils.create_global_group(self.global_group,
                                              str(self.auth_token))
        url = '%sgroups/%s' % (utils.URL, self.global_group)
        data = '{"group": { "description_bad": "A NEW description...", \
                "id":"%s"  }}'\
                % (self.global_group)
        #test for Content-Type = application/json
        resp, content = h.request(url, "PUT", body=data,
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.auth_token})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(400, int(resp['status']))

    def test_update_global_group_bad_xml(self):
        h = httplib2.Http(".cache")
        respG, contentG = utils.create_global_group_xml(self.global_group,
                                                  str(self.auth_token))
        url = '%sgroups/%s' % (utils.URL, self.global_group)
        data = '<?xml version="1.0" encoding="UTF-8"?> \
                <group xmlns="http://docs.openstack.org/identity/api/v2.0" \
                id="%s"><description_bad>A NEW description...</description> \
                </group>' % (self.global_group)
        #test for Content-Type = application/json
        resp, content = h.request(url, "PUT", body=data,
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.auth_token,
                                           "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')

        self.assertEqual(400, int(resp['status']))

    def test_update_global_group_not_found(self):
        h = httplib2.Http(".cache")
        respG, contentG = utils.create_global_group(self.global_group,
                                              str(self.auth_token))
        url = '%sgroups/NonexistingID' % (utils.URL)
        data = '{"group": { "description": "A NEW description...", \
                "id":"NonexistingID"}}'
        #test for Content-Type = application/json
        resp, content = h.request(url, "GET", body=data,
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.auth_token})
        self.assertEqual(404, int(resp['status']))

    def test_update_global_group_not_found_xml(self):
        h = httplib2.Http(".cache")
        resp, content = utils.create_tenant_xml(self.globaltenant,
                                          str(self.auth_token))
        url = '%sgroups/NonexistingID' % (utils.URL)
        data = '<?xml version="1.0" encoding="UTF-8"?> \
                <group xmlns="http://docs.openstack.org/identity/api/v2.0" \
                id="NonexistingID"> \
                <description_bad>A NEW description...</description> \
                </group>'
        #test for Content-Type = application/json
        resp, content = h.request(url, "GET", body=data,
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.auth_token,
                                           "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, int(resp['status']))


class delete_global_group_test(global_group_test):

    def test_delete_global_group_not_found(self):
        resp, content = utils.delete_global_group("test_global_group_1",
                                            str(self.auth_token))
        self.assertEqual(404, int(resp['status']))

    def test_delete_global_group_not_found_xml(self):
        resp, content = utils.delete_global_group_xml("test_global_group_1",
                                                str(self.auth_token))
        self.assertEqual(404, int(resp['status']))

    def test_delete_global_group(self):
        resp, content = utils.create_tenant(self.globaltenant,
                                            str(self.auth_token))
        respG, contentG = utils.create_tenant_group('test_global_group_delete',
                                              self.globaltenant,
                                              str(self.auth_token))
        respG, contentG = utils.delete_global_group('test_global_group_delete',
                                              str(self.auth_token))
        resp, content = utils.delete_tenant(self.globaltenant,
                                      str(self.auth_token))
        self.assertEqual(204, int(respG['status']))

    def test_delete_global_group_xml(self):
        resp, content = utils.create_tenant_xml(self.globaltenant,
                                                str(self.auth_token))
        respG, contentG = utils.create_tenant_group_xml(\
                                                  'test_global_group_delete',
                                                  self.globaltenant,
                                                  str(self.auth_token))
        respG, contentG = utils.delete_global_group_xml(\
                                                  'test_global_group_delete',
                                                  str(self.auth_token))
        resp, content = utils.delete_tenant_xml(self.globaltenant,
                                          str(self.auth_token))
        self.assertEqual(204, int(resp['status']))


class add_user_global_group_test(unittest.TestCase):

    def setUp(self):
        self.token = utils.get_token('joeuser', 'secrete', 'token')
        self.tenant = utils.get_global_tenant()
        self.user = utils.get_user()
        self.userdisabled = utils.get_userdisabled()
        self.auth_token = utils.get_auth_token()
        self.exp_auth_token = utils.get_exp_auth_token()
        self.disabled_token = utils.get_disabled_token()
        self.global_group = 'test_global_group'

    def tearDown(self):
        respG, contentG = utils.delete_user_global_group(self.global_group,
                                                   self.user,
                                                   str(self.auth_token))

        respG, contentG = utils.delete_user(self.tenant, self.user,
                                      str(self.auth_token))
        resp, content = utils.delete_global_group(self.global_group,
                                            self.auth_token)

    def test_add_user_global_group(self):
        h = httplib2.Http(".cache")
        resp, content = utils.create_global_group(self.global_group,
                                              str(self.auth_token))
        respG, contentG = utils.create_user(self.tenant, self.user,
                                      str(self.auth_token))
        respG, contentG = utils.add_user_global_group(self.global_group,
                                                self.user,
                                                str(self.auth_token))

        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        if int(respG['status']) not in (200, 201):
            self.fail('Failed due to %d' % int(respG['status']))

    def test_add_user_global_group_xml(self):
        h = httplib2.Http(".cache")
        resp, content = utils.create_global_group(self.global_group,
                                              str(self.auth_token))
        respG, contentG = utils.create_user(self.tenant, self.user,
                                      str(self.auth_token))
        respG, contentG = utils.add_user_global_group_xml(self.global_group,
                                                self.user,
                                                str(self.auth_token))

        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        if int(respG['status']) not in (200, 201):
            self.fail('Failed due to %d' % int(respG['status']))

    def test_add_user_global_group_conflict(self):
        h = httplib2.Http(".cache")
        resp, content = utils.create_global_group(self.global_group,
                                              str(self.auth_token))
        respG, contentG = utils.create_user(self.tenant, self.user,
                                      str(self.auth_token))
        respG, contentG = utils.add_user_global_group(self.global_group,
                                                self.user,
                                                str(self.auth_token))
        respG, contentG = utils.add_user_global_group(self.global_group,
                                                self.user,
                                                str(self.auth_token))

        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(409, int(respG['status']))

    def test_add_user_global_group_conflict_xml(self):
        h = httplib2.Http(".cache")
        resp, content = utils.create_global_group(self.global_group,
                                              str(self.auth_token))
        respG, contentG = utils.create_user(self.tenant, self.user,
                                      str(self.auth_token))
        respG, contentG = utils.add_user_global_group_xml(self.global_group,
                                                self.user,
                                                str(self.auth_token))
        respG, contentG = utils.add_user_global_group_xml(self.global_group,
                                                self.user,
                                                str(self.auth_token))

        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(409, int(respG['status']))

    def test_add_user_global_group_unauthorized(self):
        h = httplib2.Http(".cache")
        resp, content = utils.create_global_group(self.global_group,
                                              str(self.auth_token))
        respG, contentG = utils.create_user(self.tenant, self.user,
                                      str(self.auth_token))
        respG, contentG = utils.add_user_global_group(self.global_group,
                                                self.user,
                                                str(self.token))

        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, int(respG['status']))

    def test_add_user_global_group_unauthorized_xml(self):
        h = httplib2.Http(".cache")
        resp, content = utils.create_global_group(self.global_group,
                                              str(self.auth_token))
        respG, contentG = utils.create_user(self.tenant, self.user,
                                      str(self.auth_token))
        respG, contentG = utils.add_user_global_group_xml(self.global_group,
                                                    self.user,
                                                    str(self.token))

        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, int(respG['status']))

    def test_add_user_global_group_forbidden(self):
        h = httplib2.Http(".cache")
        resp, content = utils.create_global_group(self.global_group,
                                              str(self.auth_token))
        respG, contentG = utils.create_user(self.tenant, self.user,
                                      str(self.auth_token))
        respG, contentG = utils.add_user_global_group(self.global_group,
                                                self.user,
                                                str(self.disabled_token))

        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(respG['status']))

    def test_add_user_global_group_forbidden_xml(self):
        h = httplib2.Http(".cache")
        resp, content = utils.create_global_group(self.global_group,
                                              str(self.auth_token))
        respG, contentG = utils.create_user(self.tenant, self.user,
                                      str(self.auth_token))
        respG, contentG = utils.add_user_global_group_xml(self.global_group,
                                                self.user,
                                                str(self.disabled_token))
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(respG['status']))


class get_users_tenant_group_test(unittest.TestCase):

    def setUp(self):
        self.token = utils.get_token('joeuser', 'secrete', 'token')
        self.tenant = utils.get_global_tenant()
        self.user = utils.get_user()
        self.userdisabled = utils.get_userdisabled()
        self.auth_token = utils.get_auth_token()
        self.exp_auth_token = utils.get_exp_auth_token()
        self.disabled_token = utils.get_disabled_token()
        self.global_group = 'test_global_group'

    def tearDown(self):
        respG, contentG = utils.delete_user_global_group(self.global_group,
                                                   self.user,
                                                   str(self.auth_token))

        respG, contentG = utils.delete_user(self.tenant, self.user,
                                      str(self.auth_token))
        resp, content = utils.delete_global_group(self.global_group,
                                            self.auth_token)

    def test_get_users_global_group(self):
        h = httplib2.Http(".cache")
        resp, content = utils.create_global_group(self.global_group,
                                              str(self.auth_token))
        respG, contentG = utils.create_user(self.tenant, self.user,
                                      str(self.auth_token))
        respG, contentG = utils.add_user_global_group(self.global_group,
                                                self.user,
                                                str(self.auth_token))
        respG, contentG = utils.get_user_global_group(self.global_group,
                                                str(self.auth_token))

        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(200, int(respG['status']))

    def test_get_users_global_group_xml(self):
        h = httplib2.Http(".cache")
        resp, content = utils.create_global_group(self.global_group,
                                              str(self.auth_token))
        respG, contentG = utils.create_user(self.tenant, self.user,
                                      str(self.auth_token))
        respG, contentG = utils.add_user_global_group_xml(self.global_group,
                                                self.user,
                                                str(self.auth_token))
        respG, contentG = utils.get_user_global_group_xml(self.global_group,
                                                str(self.auth_token))
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(200, int(respG['status']))

    def test_get_users_global_group_unauthorized(self):
        h = httplib2.Http(".cache")
        resp, content = utils.create_global_group(self.global_group,
                                              str(self.auth_token))
        respG, contentG = utils.create_user(self.tenant, self.user,
                                      str(self.auth_token))
        respG, contentG = utils.add_user_global_group(self.global_group,
                                                self.user,
                                                str(self.auth_token))

        respG, contentG = utils.get_user_global_group(self.global_group,
                                                str(self.token))

        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, int(respG['status']))

    def test_get_users_global_group_unauthorized_xml(self):
        h = httplib2.Http(".cache")
        resp, content = utils.create_global_group(self.global_group,
                                              str(self.auth_token))
        respG, contentG = utils.create_user(self.tenant, self.user,
                                      str(self.auth_token))
        respG, contentG = utils.add_user_global_group(self.global_group,
                                                self.user,
                                                str(self.auth_token))
        respG, contentG = utils.get_user_global_group_xml(self.global_group,
                                                str(self.token))

        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, int(respG['status']))

    def test_get_users_global_group_forbidden(self):
        h = httplib2.Http(".cache")
        resp, content = utils.create_global_group(self.global_group,
                                              str(self.auth_token))
        respG, contentG = utils.create_user(self.tenant, self.user,
                                      str(self.auth_token))
        respG, contentG = utils.add_user_global_group(self.global_group,
                                                self.user,
                                                str(self.auth_token))
        respG, contentG = utils.get_user_global_group(self.global_group,
                                                str(self.disabled_token))

        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(respG['status']))

    def test_get_users_global_group_forbidden_xml(self):
        h = httplib2.Http(".cache")
        resp, content = utils.create_global_group(self.global_group,
                                              str(self.auth_token))
        respG, contentG = utils.create_user(self.tenant, self.user,
                                      str(self.auth_token))
        respG, contentG = utils.add_user_global_group(self.global_group,
                                                self.user,
                                                str(self.auth_token))
        respG, contentG = utils.get_user_global_group_xml(self.global_group,
                                                str(self.disabled_token))
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(respG['status']))

    def test_get_users_global_group_expired(self):
        h = httplib2.Http(".cache")
        resp, content = utils.create_global_group(self.global_group,
                                              str(self.auth_token))
        respG, contentG = utils.create_user(self.tenant, self.user,
                                      str(self.auth_token))
        respG, contentG = utils.add_user_global_group(self.global_group,
                                                self.user,
                                                str(self.auth_token))
        respG, contentG = utils.get_user_global_group(self.global_group,
                                                str(self.exp_auth_token))

        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(respG['status']))

    def test_get_users_global_group_expired_xml(self):
        h = httplib2.Http(".cache")
        resp, content = utils.create_global_group(self.global_group,
                                              str(self.auth_token))
        respG, contentG = utils.create_user(self.tenant, self.user,
                                      str(self.auth_token))
        respG, contentG = utils.add_user_global_group(self.global_group,
                                                self.user,
                                                str(self.auth_token))
        respG, contentG = utils.get_user_global_group_xml(self.global_group,
                                                str(self.exp_auth_token))
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(respG['status']))


class delete_users_global_group_test(unittest.TestCase):

    def setUp(self):
        self.token = utils.get_token('joeuser', 'secrete', 'token')
        self.tenant = utils.get_global_tenant()
        self.user = utils.get_user()
        self.userdisabled = utils.get_userdisabled()
        self.auth_token = utils.get_auth_token()
        self.exp_auth_token = utils.get_exp_auth_token()
        self.disabled_token = utils.get_disabled_token()
        self.global_group = 'test_global_group'

    def tearDown(self):
        respG, contentG = utils.delete_user_global_group(self.global_group,
                                                   self.user,
                                                   str(self.auth_token))

        respG, contentG = utils.delete_user(self.tenant, self.user,
                                      str(self.auth_token))
        resp, content = utils.delete_global_group(self.global_group,
                                            self.auth_token)

    def test_delete_user_global_group(self):
        h = httplib2.Http(".cache")
        resp, content = utils.create_global_group(self.global_group,
                                              str(self.auth_token))
        respG, contentG = utils.create_user(self.tenant, self.user,
                                      str(self.auth_token))
        respG, contentG = utils.add_user_global_group(self.global_group,
                                                self.user,
                                                str(self.auth_token))

        respG, contentG = utils.delete_user_global_group(self.global_group,
                                                   self.user,
                                                   str(self.auth_token))

        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(204, int(respG['status']))

    def test_delete_user_global_group_xml(self):
        h = httplib2.Http(".cache")
        resp, content = utils.create_global_group(self.global_group,
                                              str(self.auth_token))
        respG, contentG = utils.create_user(self.tenant, self.user,
                                      str(self.auth_token))
        respG, contentG = utils.add_user_global_group(self.global_group,
                                                self.user,
                                                str(self.auth_token))
        respG, contentG = utils.delete_user_global_group_xml(self.global_group,
                                                   self.user,
                                                   str(self.auth_token))
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(204, int(respG['status']))

    def test_delete_user_global_group_notfound(self):
        h = httplib2.Http(".cache")
        resp, content = utils.create_global_group(self.global_group,
                                              str(self.auth_token))
        respG, contentG = utils.create_user(self.tenant, self.user,
                                      str(self.auth_token))
        respG, contentG = utils.add_user_global_group(self.global_group,
                                                self.user,
                                                str(self.disabled_token))
        respG, contentG = utils.delete_user_global_group(self.global_group,
                                                   self.user,
                                                   str(self.auth_token))
        respG, contentG = utils.delete_user_global_group(self.global_group,
                                                   self.user,
                                                   str(self.auth_token))
        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, int(respG['status']))

    def test_delete_user_global_group_notfound_xml(self):
        h = httplib2.Http(".cache")
        resp, content = utils.create_global_group(self.global_group,
                                              str(self.auth_token))
        respG, contentG = utils.create_user(self.tenant, self.user,
                                      str(self.auth_token))
        respG, contentG = utils.add_user_global_group(self.global_group,
                                                self.user,
                                                str(self.disabled_token))
        respG, contentG = utils.delete_user_global_group(self.global_group,
                                                   self.user,
                                                   str(self.auth_token))
        respG, contentG = utils.delete_user_global_group_xml(self.global_group,
                                                   self.user,
                                                   str(self.auth_token))

        if int(resp['status']) == 500:
            self.fail('Identity Fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, int(respG['status']))

if __name__ == '__main__':
    unittest.main()
