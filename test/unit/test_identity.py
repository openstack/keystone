import os
import sys
# Need to access identity module
sys.path.append(os.path.abspath(os.path.join(os.path.abspath(__file__),
                                '..', '..', '..', '..', 'keystone')))
#from keystone import auth_server
import unittest
from webtest import TestApp
import httplib2
import json
from lxml import etree
import unittest
from webtest import TestApp

URL = 'http://localhost:8080/v1.0/'


def get_token(user, pswd, kind=''):
        h = httplib2.Http(".cache")
        url = '%stoken' % URL
        body = {"passwordCredentials": {"username": user,
                                        "password": pswd}}
        resp, content = h.request(url, "POST", body=json.dumps(body),
                                  headers={"Content-Type": "application/json"})
        content = json.loads(content)

        token = str(content['auth']['token']['id'])
        if kind == 'token':
            return token
        else:
            return (resp, content)


def delete_token(token, auth_token):
    h = httplib2.Http(".cache")
    url = '%stoken/%s' % (URL, token)
    resp, content = h.request(url, "DELETE", body='', \
                            headers={"Content-Type": "application/json", \
                                     "X-Auth-Token": auth_token})
    return (resp, content)


def create_tenant(tenantid, auth_token):
    h = httplib2.Http(".cache")

    url = '%stenants' % (URL)
    body = {"tenant": {"id": tenantid,
                       "description": "A description ...",
                       "enabled": True}}
    resp, content = h.request(url, "POST", body=json.dumps(body),
                              headers={"Content-Type": "application/json",
                                       "X-Auth-Token": auth_token})
    return (resp, content)


def create_tenant_group(groupid, tenantid, auth_token):
    h = httplib2.Http(".cache")

    url = '%stenant/%s/groups' % (URL,tenantid)
    body = {"group": {"id": groupid,
                       "description": "A description ..."
                         }}
    resp, content = h.request(url, "POST", body=json.dumps(body),
                              headers={"Content-Type": "application/json",
                                       "X-Auth-Token": auth_token})
    return (resp, content)


def delete_tenant(tenantid, auth_token):
    h = httplib2.Http(".cache")
    url = '%stenants/%s' % (URL, tenantid)
    resp, content = h.request(url, "DELETE", body='{}',\
                            headers={"Content-Type": "application/json",\
                                     "X-Auth-Token": auth_token})
    return (resp, content)


def delete_tenant_group(groupid, tenantid, auth_token):
    h = httplib2.Http(".cache")
    url = '%stenant/%s/groups/%s' % (URL, tenantid, groupid)
    resp, content = h.request(url, "DELETE", body='{}',\
                            headers={"Content-Type": "application/json",\
                                     "X-Auth-Token": auth_token})
    return (resp, content)


def create_global_group(auth_token):
    h = httplib2.Http(".cache")

    url = '%s/groups' % (URL)
    body = {"group": {"id": 'Admin',
                       "description": "A description ..."
                         }}
    resp, content = h.request(url, "POST", body=json.dumps(body),
                              headers={"Content-Type": "application/json",
                                       "X-Auth-Token": auth_token})
    return (resp, content)


def delete_global_group(groupid, auth_token):
    h = httplib2.Http(".cache")
    url = '%s/groups/%s' % (URL, groupid)
    resp, content = h.request(url, "DELETE", body='{}',\
                            headers={"Content-Type": "application/json",\
                                     "X-Auth-Token": auth_token})
    return (resp, content)


def get_token_xml(user, pswd, type=''):
        h = httplib2.Http(".cache")
        url = '%stoken' % URL
        body = '<?xml version="1.0" encoding="UTF-8"?> \
                <passwordCredentials \
                xmlns="http://docs.openstack.org/idm/api/v1.0" \
                password="%s" username="%s" \
                tenantId="77654"/> ' % (pswd, user)
        resp, content = h.request(url, "POST", body=body,\
                                headers={"Content-Type": "application/xml",
                                         "ACCEPT": "application/xml"})
        dom = etree.fromstring(content)
        root = dom.find("{http://docs.openstack.org/idm/api/v1.0}token")
        token_root = root.attrib
        token = str(token_root['id'])
        if type == 'token':
            return token
        else:
            return (resp, content)


def delete_token_xml(token, auth_token):
    h = httplib2.Http(".cache")
    url = '%stoken/%s' % (URL, token)
    resp, content = h.request(url, "DELETE", body='',\
                            headers={"Content-Type": "application/xml", \
                                     "X-Auth-Token": auth_token,
                                     "ACCEPT": "application/xml"})
    return (resp, content)


def create_tenant_xml(tenantid, auth_token):
    h = httplib2.Http(".cache")
    url = '%stenants' % (URL)
    body = '<?xml version="1.0" encoding="UTF-8"?> \
            <tenant xmlns="http://docs.openstack.org/idm/api/v1.0" \
            enabled="true" id="%s"> \
            <description>A description...</description> \
            </tenant>' % tenantid
    resp, content = h.request(url, "POST", body=body,\
                              headers={"Content-Type": "application/xml",\
                              "X-Auth-Token": auth_token,
                              "ACCEPT": "application/xml"})
    return (resp, content)


def create_tenant_group_xml(groupid, tenantid, auth_token):
    h = httplib2.Http(".cache")
    url = '%stenant/%s/groups' % (URL,tenantid)
    body = '<?xml version="1.0" encoding="UTF-8"?> \
            <group xmlns="http://docs.openstack.org/idm/api/v1.0" \
             id="%s"> \
            <description>A description...</description> \
            </group>' % groupid
    resp, content = h.request(url, "POST", body=body,\
                              headers={"Content-Type": "application/xml",\
                              "X-Auth-Token": auth_token,
                              "ACCEPT": "application/xml"})
    return (resp, content)


def delete_tenant_xml(tenantid, auth_token):
    h = httplib2.Http(".cache")
    url = '%stenants/%s' % (URL, tenantid)
    resp, content = h.request(url, "DELETE", body='',\
                            headers={"Content-Type": "application/xml",\
                                     "X-Auth-Token": auth_token,
                                     "ACCEPT": "application/xml"})
    return (resp, content)


def delete_tenant_group_xml(groupid, tenantid, auth_token):
    h = httplib2.Http(".cache")
    url = '%stenant/%s/groups/%s' % (URL, tenantid, groupid)
    resp, content = h.request(url, "DELETE", body='',\
                            headers={"Content-Type": "application/xml",\
                                     "X-Auth-Token": auth_token,
                                     "ACCEPT": "application/xml"})
    return (resp, content)


def create_global_group_xml(auth_token):
    h = httplib2.Http(".cache")
    url = '%s/groups' % (URL)
    body = '<?xml version="1.0" encoding="UTF-8"?> \
            <group xmlns="http://docs.openstack.org/idm/api/v1.0" \
             id="Admin"> \
            <description>A description...</description> \
            </group>'
    resp, content = h.request(url, "POST", body=body,\
                              headers={"Content-Type": "application/xml",\
                              "X-Auth-Token": auth_token,
                              "ACCEPT": "application/xml"})
    return (resp, content)

def create_user_json(tenantid, userid, auth_token):
    h = httplib2.Http(".cache")
    url = '%stenants/%s/users' % (URL, tenantid)
    body = {"user": {"password": "secrete",
                       "id": userid,
                       "tenantId": tenantid,
                       "email": "%s@rackspace.com" % userid,
                       "enabled": True}}
    resp, content = h.request(url, "POST", body=json.dumps(body),
                              headers={"Content-Type": "application/json",
                                       "X-Auth-Token": auth_token})
    return (resp, content)


def delete_user_json(tenant, userid, auth_token):
    h = httplib2.Http(".cache")
    url = '%stenants/%s/users/%s' % (URL, tenant, userid)
    print url
    resp, content = h.request(url, "DELETE", body='{}', \
            headers={"Content-Type": "application/json", \
            "X-Auth-Token": auth_token})
    return (resp, content)

def create_user_xml(tenantid, userid, auth_token):
    h = httplib2.Http(".cache")
    url = '%stenants/%s/users' % (URL, tenantid)
    body = '<?xml version="1.0" encoding="UTF-8"?> \
            <user xmlns="http://docs.openstack.org/idm/api/v1.0" \
            email="joetest@rackspace.com" \
            tenantId="%s" id="%s" \
            enabled="true" password="secrete"/>'\
             % (tenantid, userid)
    resp, content = h.request(url, "POST", body=body, \
            headers={"Content-Type": "application/xml",\
            "X-Auth-Token": auth_token, \
            "ACCEPT": "application/xml"})
    return (resp, content)


def delete_user_xml(tenantid, userid, auth_token):
    h = httplib2.Http(".cache")
    url = '%stenants/%s/users/%s' % (URL, tenantid, userid)
    resp, content = h.request(url, "DELETE", body='',\
                            headers={"Content-Type": "application/xml",\
                                     "X-Auth-Token": auth_token,
                                     "ACCEPT": "application/xml"})
    return (resp, content)


def delete_global_group_xml(groupid, auth_token):
    h = httplib2.Http(".cache")
    url = '%s/groups/%s' % (URL, groupid)
    resp, content = h.request(url, "DELETE", body='',\
                            headers={"Content-Type": "application/xml",\
                                     "X-Auth-Token": auth_token,
                                     "ACCEPT": "application/xml"})
    return (resp, content)

def get_userid():
    return 'test_user11'


def get_password():
    return 'secrete'


def get_email():
    return 'joetest@rackspace.com'

def get_tenant():
    return '1234'


def get_user():
    return '1234'


def get_userdisabled():
    return 'disabled'

def get_auth_token():
    return '999888777666'


def get_exp_auth_token():
    return '000999'

def get_none_token():
    return ''

def get_non_existing_token():
    return 'invalid_token'

def get_disabled_token():
    return '999888777'

def handle_user_resp(self,content, respvalue,resptype):
    if respvalue == 200:
        if resptype == 'application/json':
            content = json.loads(content)
            self.tenant = content['user']['tenantId']
            self.userid = content['user']['id']
        if resptype == 'application/xml':
            content=etree.fromstring(content)
            self.tenant=content.get("tenantId")
            self.id=content.get("id")


    if respvalue == 500:
        self.fail('IDM fault')
    elif respvalue == 503:
        self.fail('Service Not Available')

def content_type(resp):
    return resp['content-type'].split(';')[0]

class identity_test(unittest.TestCase):

    #Given _a_ to make inherited test cases in an order.
    #here to call below method will call as last test case

    def test_a_get_version_json(self):
        h = httplib2.Http(".cache")
        url = URL
        resp, content = h.request(url, "GET", body="",
                                   headers={"Content-Type": "application/json"})

        self.assertEqual(200, int(resp['status']))
        self.assertEqual('application/json', content_type(resp))

    def test_a_get_version_xml(self):
        h = httplib2.Http(".cache")
        url = URL
        resp, content = h.request(url, "GET", body="",
                                headers={"Content-Type": "application/xml",
                                         "ACCEPT": "application/xml"})

        self.assertEqual(200, int(resp['status']))
        self.assertEqual('application/xml', content_type(resp))


class authorize_test(identity_test):

    def setUp(self):
        self.token = get_token('joeuser', 'secrete', 'token')
        self.tenant = get_tenant()
        self.user = get_user()
        self.userdisabled = get_userdisabled()
        self.auth_token = get_auth_token()
        self.exp_auth_token = get_exp_auth_token()
        self.disabled_token = get_disabled_token()



    def tearDown(self):
        delete_token(self.token, self.auth_token)

    def test_a_authorize(self):
        resp, content = get_token('joeuser', 'secrete')

        self.assertEqual(200, int(resp['status']))
        self.assertEqual('application/json', content_type(resp))

    def test_a_authorize_xml(self):
        resp, content = get_token_xml('joeuser', 'secrete')
        self.assertEqual(200, int(resp['status']))
        self.assertEqual('application/xml', content_type(resp))

    def test_a_authorize_user_disaabled(self):
        h = httplib2.Http(".cache")
        url = '%stoken' % URL
        body = {"passwordCredentials": {"username": "disabled",
                                        "password": "self.tenant_group='test_tenant_group'secrete"}}
        resp, content = h.request(url, "POST", body=json.dumps(body),
                                headers={"Content-Type": "application/json"})
        content = json.loads(content)
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(resp['status']))

    def test_a_authorize_user_disaabled_xml(self):
        h = httplib2.Http(".cache")
        url = '%stoken' % URL

        body = '<?xml version="1.0" encoding="UTF-8"?> \
                <passwordCredentials \
                xmlns="http://docs.openstack.org/idm/api/v1.0" \
                password="secrete" username="disabled" \
                />'
        resp, content = h.request(url, "POST", body=body,\
                                  headers={"Content-Type": "application/xml",
                                           "ACCEPT": "application/xml"})
        content = etree.fromstring(content)
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(resp['status']))

    def test_a_authorize_user_wrong(self):
        h = httplib2.Http(".cache")
        url = '%stoken' % URL
        body = {"passwordCredentials": {"username-w": "disabled",
                                        "password": "secrete"}}
        resp, content = h.request(url, "POST", body=json.dumps(body),
                                headers={"Content-Type": "application/json"})
        content = json.loads(content)
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(400, int(resp['status']))

    def test_a_authorize_user_wrong_xml(self):
        h = httplib2.Http(".cache")
        url = '%stoken' % URL
        body = '<?xml version="1.0" encoding="UTF-8"?> \
                <passwordCredentials \
                xmlns="http://docs.openstack.org/idm/api/v1.0" \
                password="secrete" username-w="disabled" \
                />'
        resp, content = h.request(url, "POST", body=body,\
                                 headers={"Content-Type": "application/xml",
                                         "ACCEPT": "application/xml"})
        content = etree.fromstring(content)
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(400, int(resp['status']))


class validate_token(authorize_test):

    def test_validate_token_true(self):
        h = httplib2.Http(".cache")

        url = '%stoken/%s?belongsTo=%s' % (URL, self.token, self.tenant)
        resp, content = h.request(url, "GET", body='',\
                                headers={"Content-Type": "application/json", \
                                         "X-Auth-Token": self.auth_token})
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(200, int(resp['status']))
        self.assertEqual('application/json', content_type(resp))

    def test_validate_token_true_xml(self):
        h = httplib2.Http(".cache")
        url = '%stoken/%s?belongsTo=%s' % (URL, self.token, self.tenant)
        resp, content = h.request(url, "GET", body='',\
                                headers={"Content-Type": "application/xml", \
                                         "X-Auth-Token": self.auth_token,
                                         "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(200, int(resp['status']))
        self.assertEqual('application/xml', content_type(resp))

    def test_validate_token_expired(self):
        h = httplib2.Http(".cache")
        url = '%stoken/%s?belongsTo=%s' % (URL, self.exp_auth_token, \
                                            self.tenant)
        resp, content = h.request(url, "GET", body='',\
                                headers={"Content-Type": "application/json", \
                                         "X-Auth-Token": self.exp_auth_token})
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, int(resp['status']))
        self.assertEqual('application/json', content_type(resp))

    def test_validate_token_expired_xml(self):
        h = httplib2.Http(".cache")

        url = '%stoken/%s?belongsTo=%s' % (URL, self.exp_auth_token, \
                                            self.tenant)
        resp, content = h.request(url, "GET", body='',\
                                headers={"Content-Type": "application/xml", \
                                         "X-Auth-Token": self.exp_auth_token,
                                         "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, int(resp['status']))
        self.assertEqual('application/xml', content_type(resp))

    def test_validate_token_invalid(self):
        h = httplib2.Http(".cache")
        url = '%stoken/%s?belongsTo=%s' % (URL, 'NonExistingToken', \
                                            self.tenant)
        resp, content = h.request(url, "GET", body='',\
                                headers={"Content-Type": "application/json", \
                                         "X-Auth-Token": self.auth_token})

        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, int(resp['status']))
        self.assertEqual('application/json', content_type(resp))

    def test_validate_token_invalid_xml(self):
        h = httplib2.Http(".cache")
        url = '%stoken/%s?belongsTo=%s' % (URL, 'NonExistingToken', \
                                            self.tenant)
        resp, content = h.request(url, "GET", body='',\
                                headers={"Content-Type": "application/json", \
                                         "X-Auth-Token": self.auth_token})
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, int(resp['status']))
        self.assertEqual('application/json', content_type(resp))


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
""" "passwordCredentials" : {"username" : "joeuser","password": "secrete","tenantId": "1234"}
"""

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
        self.assertEqual(403, int(resp['status']))

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
        resp, content = h.request(url, "POST", body=body,\
                                headers={"Content-Type": "application/xml",\
                                         "X-Auth-Token": self.token,
                                         "ACCEPT": "application/xml"})

        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(resp['status']))

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
        self.assertEqual(401, int(resp['status']))

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

        resp, content = h.request(url, "POST", body=body,\
                                headers={"Content-Type": "application/xml",\
                                         "X-Auth-Token": self.exp_auth_token,
                                         "ACCEPT": "application/xml"})

        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, int(resp['status']))

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
        resp, content = h.request(url, "POST", body=body,\
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
        resp, content = h.request(url, "POST", body=body,\
                                headers={"Content-Type": "application/json",\
                                         "X-Auth-Token": self.disabled_token})

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
        resp, content = h.request(url, "POST", body=body,\
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
        resp, content = h.request(url, "POST", body=body,\
                                headers={"Content-Type": "application/json",\
                                         "X-Auth-Token": 'nonexsitingtoken'})

        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, int(resp['status']))

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
        resp, content = h.request(url, "POST", body=body,\
                                headers={"Content-Type": "application/xml",\
                                         "X-Auth-Token": 'nonexsitingtoken',
                                         "ACCEPT": "application/xml"})

        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, int(resp['status']))


class get_tenants_test(tenant_test):

    def test_get_tenants(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        url = '%stenants' % (URL)
        #test for Content-Type = application/json
        resp, content = h.request(url, "GET", body='{}',\
                                headers={"Content-Type": "application/json",\
                                         "X-Auth-Token": self.auth_token})
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
        resp, content = h.request(url, "GET", body='',\
                                headers={"Content-Type": "application/xml",\
                                         "X-Auth-Token": self.auth_token,
                                         "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(200, int(resp['status']))

    def test_get_tenants_forbidden_token(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        url = '%stenants' % (URL)
        #test for Content-Type = application/json
        resp, content = h.request(url, "GET", body='{}',\
                                headers={"Content-Type": "application/json",\
                                         "X-Auth-Token": self.token})
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(resp['status']))

    def test_get_tenants_forbidden_token_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        url = '%stenants' % (URL)
        #test for Content-Type = application/json
        resp, content = h.request(url, "GET", body='',\
                                headers={"Content-Type": "application/xml",\
                                         "X-Auth-Token": self.token,
                                         "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(resp['status']))

    def test_get_tenants_exp_token(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        url = '%stenants' % (URL)
        #test for Content-Type = application/json
        resp, content = h.request(url, "GET", body='{}',\
                                headers={"Content-Type": "application/json",\
                                         "X-Auth-Token": self.exp_auth_token})
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, int(resp['status']))

    def test_get_tenants_exp_token_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        url = '%stenants' % (URL)
        #test for Content-Type = application/json
        resp, content = h.request(url, "GET", body='',\
                                headers={"Content-Type": "application/xml",\
                                         "X-Auth-Token": self.exp_auth_token,
                                         "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, int(resp['status']))


class get_tenant_test(tenant_test):

    def test_get_tenant(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        url = '%stenants/%s' % (URL, self.tenant)
        #test for Content-Type = application/json
        resp, content = h.request(url, "GET", body='{}',\
                                headers={"Content-Type": "application/json",\
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
        resp, content = h.request(url, "GET", body='',\
                                headers={"Content-Type": "application/xml",\
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
        resp, content = h.request(url, "GET", body='{',\
                                headers={"Content-Type": "application/json",\
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
        resp, content = h.request(url, "GET", body='{',\
                                headers={"Content-Type": "application/xml",\
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
        resp, content = h.request(url, "GET", body='{}',\
                                headers={"Content-Type": "application/json",\
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
        resp, content = h.request(url, "GET", body='',\
                                headers={"Content-Type": "application/xml",\
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
        resp, content = h.request(url, "PUT", body=data,\
                                headers={"Content-Type": "application/json",\
                                         "X-Auth-Token": self.auth_token})
        body = json.loads(content)
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(200, int(resp['status']))
        self.assertEqual(int(self.tenant), int(body['tenant']['id']))
        self.assertEqual('A NEW description...', \
                         body['tenant']['description'])

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
        resp, content = h.request(url, "PUT", body=data,\
                                headers={"Content-Type": "application/xml",\
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
        self.assertEqual('A NEW description...', \
                         desc.text)

    def test_update_tenant_bad(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        url = '%stenants/%s' % (URL, self.tenant)
        data = '{"tenant": { "description_bad": "A NEW description...",\
                "enabled":true  }}'
        #test for Content-Type = application/json

        resp, content = h.request(url, "PUT", body=data,\
                                headers={"Content-Type": "application/json",\
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
        resp, content = h.request(url, "PUT", body=data,\
                                headers={"Content-Type": "application/xml",\
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
        resp, content = h.request(url, "GET", body=data,\
                                headers={"Content-Type": "application/json",\
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
        resp, content = h.request(url, "GET", body=data,\
                                headers={"Content-Type": "application/xml",\
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
        resp, content = delete_tenant("test_tenant_delete111", \
                                        str(self.auth_token))
        self.assertEqual(404, int(resp['status']))

    def test_delete_tenant_not_found_xml(self):
        #resp,content=create_tenant("test_tenant_delete", str(self.auth_token))
        resp, content = delete_tenant_xml("test_tenant_delete111", \
                                            str(self.auth_token))
        self.assertEqual(404, int(resp['status']))

    def test_delete_tenant(self):
        resp, content = create_tenant("test_tenant_delete", \
                                    str(self.auth_token))
        resp, content = delete_tenant("test_tenant_delete", \
                                        str(self.auth_token))
        self.assertEqual(204, int(resp['status']))

    def test_delete_tenant_xml(self):
        resp, content = create_tenant_xml("test_tenant_delete", \
                                          str(self.auth_token))
        resp, content = delete_tenant_xml("test_tenant_delete", \
                                            str(self.auth_token))
        self.assertEqual(204, int(resp['status']))




class tenant_group_test(unittest.TestCase):

    def setUp(self):
        self.token = get_token('joeuser', 'secrete', 'token')
        self.tenant = get_tenant()
        self.user = get_user()
        self.userdisabled = get_userdisabled()
        self.auth_token = get_auth_token()
        self.exp_auth_token = get_exp_auth_token()
        self.disabled_token = get_disabled_token()
        self.tenant_group = 'test_tenant_group'

    def tearDown(self):
        resp, content = delete_tenant_group('test_tenant_group', \
                                    self.tenant, self.auth_token)
        resp, content = delete_tenant(self.tenant, self.auth_token)


class create_tenant_group_test(tenant_group_test):

    def test_tenant_group_create(self):
        resp, content = delete_tenant('test_tenant', str(self.auth_token))
        resp, content = create_tenant('test_tenant', str(self.auth_token))

        respG, contentG = delete_tenant_group('test_tenant_group', \
                     'test_tenant', str(self.auth_token))
        respG, contentG = create_tenant_group('test_tenant_group', \
                                    'test_tenant', str(self.auth_token))

        self.tenant = 'test_tenant'
        self.tenant_group = 'test_tenant_group'

        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')

        if int(respG['status']) not in (200, 201):
            self.fail('Failed due to %d' % int(respG['status']))

    def test_tenant_group_create_xml(self):
        resp, content = delete_tenant_xml('test_tenant', str(self.auth_token))
        resp, content = create_tenant_xml('test_tenant', str(self.auth_token))
        respG, contentG = delete_tenant_group_xml('test_tenant_group', \
                        "test_tenant", str(self.auth_token))
        respG, contentG = create_tenant_group_xml('test_tenant_group', \
                        "test_tenant", str(self.auth_token))

        self.tenant = 'test_tenant'
        self.tenant_group = 'test_tenant_group'
        content = etree.fromstring(content)
        if int(resp['status']) == 500:
                  self.fail('IDM fault')
        elif int(resp['status']) == 503:
                  self.fail('Service Not Available')

        if int(respG['status']) not in (200, 201):

                  self.fail('Failed due to %d' % int(respG['status']))

    def test_tenant_group_create_again(self):

        resp, content = create_tenant("test_tenant", str(self.auth_token))

        respG, contentG = create_tenant_group('test_tenant_group', \
                        "test_tenant", str(self.auth_token))
        respG, contentG = create_tenant_group('test_tenant_group', \
                        "test_tenant", str(self.auth_token))

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

        respG, contentG = create_tenant_group_xml('test_tenant_group', \
                        "test_tenant", str(self.auth_token))
        respG, contentG = create_tenant_group_xml('test_tenant_group', \
                        "test_tenant", str(self.auth_token))

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

    def test_tenant_group_create_forbidden_token(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant("test_tenant", str(self.auth_token))
        respG, contentG = create_tenant_group_xml('test_tenant_group', \
                        "test_tenant", str(self.auth_token))
        if int(resp['status']) == 200:
            self.tenant = content['tenant']['id']

        if int(respG['status']) == 200:
            self.tenant_group = respG['group']['id']

        url = '%stenant/%s/groups' % (URL, self.tenant)
        body = {"group": {"id": self.tenant_group,
                   "description": "A description ..."
                   }}
        resp, content = h.request(url, "POST", body=json.dumps(body),
                      headers={"Content-Type": "application/json",
                         "X-Auth-Token": self.token})

        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
            self.assertEqual(403, int(resp['status']))

    def test_tenant_group_create_forbidden_token_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant("test_tenant", str(self.auth_token))
        if int(resp['status']) == 200:
            self.tenant = content['tenant']['id']

        url = '%stenant/%s/groups' % (URL, self.tenant)
        body = '<?xml version="1.0" encoding="UTF-8"?> \
        <group xmlns="http://docs.openstack.org/idm/api/v1.0" \
         id="%s"> \
        <description>A description...</description> \
        </group>' % self.tenant_group
        resp, content = h.request(url, "POST", body=body,\
                    headers={"Content-Type": "application/xml", \
                         "X-Auth-Token": self.token,
                         "ACCEPT": "application/xml"})

        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')

        self.assertEqual(403, int(resp['status']))

    def test_tenant_group_create_expired_token(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant("test_tenant", str(self.auth_token))
        if int(resp['status']) == 200:
            self.tenant = content['tenant']['id']

        url = '%stenant/%s/groups' % (URL, self.tenant)
        body = {"group": {"id": self.tenant_group,
                   "description": "A description ..."
                   }}
        resp, content = h.request(url, "POST", body=json.dumps(body),
                    headers={"Content-Type": "application/json",
                         "X-Auth-Token": self.exp_auth_token})

        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, int(resp['status']))

    def test_tenant_group_create_expired_token_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant_xml("test_tenant", str(self.auth_token))
        content = etree.fromstring(content)
        if int(resp['status']) == 200:
            self.tenant = content.get('id')

        url = '%stenant/%s/groups' % (URL, self.tenant)
        body = '<?xml version="1.0" encoding="UTF-8"?> \
        <group xmlns="http://docs.openstack.org/idm/api/v1.0" \
         id="%s"> \
        <description>A description...</description> \
        </group>' % self.tenant

        resp, content = h.request(url, "POST", body=body,\
                    headers={"Content-Type": "application/xml", \
                         "X-Auth-Token": self.exp_auth_token,
                         "ACCEPT": "application/xml"})

        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, int(resp['status']))

    def test_tenant_group_create_missing_token(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant("test_tenant", str(self.auth_token))
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
        resp, content = create_tenant_xml("test_tenant", str(self.auth_token))
        content = etree.fromstring(content)
        if int(resp['status']) == 200:
            self.tenant = content.get('id')

        url = '%stenant/%s/groups' % (URL, self.tenant)

        body = '<?xml version="1.0" encoding="UTF-8"?> \
        <group xmlns="http://docs.openstack.org/idm/api/v1.0" \
        id="%s"> \
        <description>A description...</description> \
        </group>' % self.tenant_group
        resp, content = h.request(url, "POST", body=body,\
                    headers={"Content-Type": "application/xml",
                         "ACCEPT": "application/xml"})

        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, int(resp['status']))

    def test_tenant_group_create_disabled_token(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant("test_tenant", str(self.auth_token))
        if int(resp['status']) == 200:
            self.tenant = content['tenant']['id']

        url = '%stenant/%s/groups' % (URL, self.tenant)
        body = '{"group": { "id": "%s", \
            "description": "A description ..." } }' % self.tenant_group
        resp, content = h.request(url, "POST", body=body,\
                    headers={"Content-Type": "application/json",\
                         "X-Auth-Token": self.disabled_token})

        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(resp['status']))

    def test_tenant_group_create_disabled_token_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant_xml("test_tenant", str(self.auth_token))
        content = etree.fromstring(content)
        if int(resp['status']) == 200:
            self.tenant = content.get('id')

        url = '%stenant/%s/groups' % (URL, self.tenant)
        body = '<?xml version="1.0" encoding="UTF-8"?> \
        <group xmlns="http://docs.openstack.org/idm/api/v1.0" \
        id="%s"> \
        <description>A description...</description> \
        </group>' % self.tenant_group
        resp, content = h.request(url, "POST", body=body,\
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
        resp, content = create_tenant("test_tenant", str(self.auth_token))
        if int(resp['status']) == 200:
            self.tenant = content['tenant']['id']

        url = '%stenant/%s/groups' % (URL, self.tenant)
        body = '{"group": { "id": "%s", \
            "description": "A description ..." } }' % self.tenant
        resp, content = h.request(url, "POST", body=body,\
                    headers={"Content-Type": "application/json",\
                         "X-Auth-Token": 'nonexsitingtoken'})

        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, int(resp['status']))

    def test_tenant_group_create_invalid_token_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant_xml("test_tenant", str(self.auth_token))
        content = etree.fromstring(content)
        if int(resp['status']) == 200:
            self.tenant = content.get('id')

        url = '%stenant/%s/groups' % (URL, self.tenant)
        body = '<?xml version="1.0" encoding="UTF-8"?> \
        <group xmlns="http://docs.openstack.org/idm/api/v1.0" \
         id="%s"> \
        <description>A description...</description> \
        </group>' % self.tenant_group
        resp, content = h.request(url, "POST", body=body,\
                    headers={"Content-Type": "application/xml",\
                         "X-Auth-Token": 'nonexsitingtoken',
                         "ACCEPT": "application/xml"})

        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, int(resp['status']))


class get_tenant_groups_test(tenant_group_test):

    def test_get_tenant_groups(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))

        respG, contentG = create_tenant_group(self.tenant_group,\
                        self.tenant, str(self.auth_token))

        url = '%stenant/%s/groups' % (URL,self.tenant)

        resp, content = h.request(url, "GET", body='{}',\
                    headers={"Content-Type": "application/json",\
                         "X-Auth-Token": self.auth_token})
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(200, int(resp['status']))

    def test_get_tenant_groups_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))

        respG, contentG = create_tenant_group_xml(self.tenant_group,\
                        self.tenant, str(self.auth_token))

        url = '%stenant/%s/groups' % (URL,self.tenant)

        resp, content = h.request(url, "GET", body='',\
                    headers={"Content-Type": "application/xml",\
                         "X-Auth-Token": self.auth_token,
                         "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(200, int(resp['status']))

    def test_get_tenant_groups_forbidden_token(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))

        respG, contentG = create_tenant_group(self.tenant_group,\
                        self.tenant, str(self.auth_token))
        url = '%stenant/%s/groups' % (URL,self.tenant)
        #test for Content-Type = application/json
        resp, content = h.request(url, "GET", body='{}',\
                    headers={"Content-Type": "application/json",\
                         "X-Auth-Token": self.token})
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(resp['status']))

    def test_get_tenant_groups_forbidden_token_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        respG, contentG = create_tenant_group(self.tenant_group,\
                        self.tenant, str(self.auth_token))
        url = '%stenant/%s/groups' % (URL,self.tenant)
        #test for Content-Type = application/json
        resp, content = h.request(url, "GET", body='',\
                    headers={"Content-Type": "application/xml",\
                         "X-Auth-Token": self.token,
                         "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(resp['status']))

    def test_get_tenant_groups_exp_token(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        respG, contentG = create_tenant_group(self.tenant_group,\
                        self.tenant, str(self.auth_token))
        url = '%stenant/%s/groups' % (URL,self.tenant)
        #test for Content-Type = application/json
        resp, content = h.request(url, "GET", body='{}',\
                    headers={"Content-Type": "application/json",\
                         "X-Auth-Token": self.exp_auth_token})
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, int(resp['status']))

    def test_get_tenant_groups_exp_token_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        respG, contentG = create_tenant_group(self.tenant_group,\
                        self.tenant, str(self.auth_token))
        url = '%stenant/%s/groups' % (URL,self.tenant)
        #test for Content-Type = application/json
        resp, content = h.request(url, "GET", body='',\
                    headers={"Content-Type": "application/xml",\
                         "X-Auth-Token": self.exp_auth_token,
                         "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, int(resp['status']))


class get_tenant_group_test(tenant_group_test):

    def test_get_tenant_group(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        respG, contentG = create_tenant_group(self.tenant_group,\
                        self.tenant, str(self.auth_token))
        url = '%stenant/%s/groups/%s' % (URL,self.tenant,self.tenant_group)
        #test for Content-Type = application/json
        resp, content = h.request(url, "GET", body='{}',\
                    headers={"Content-Type": "application/json",\
                         "X-Auth-Token": self.auth_token})
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(200, int(resp['status']))

    def test_get_tenant_group_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        respG, contentG = create_tenant_group_xml(self.tenant_group,\
                        self.tenant, str(self.auth_token))
        url = '%stenant/%s/groups/%s' % (URL,self.tenant,self.tenant_group)
        #test for Content-Type = application/json
        resp, content = h.request(url, "GET", body='',\
                    headers={"Content-Type": "application/xml",\
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
        respG, contentG = create_tenant_group(self.tenant_group,\
                        self.tenant, str(self.auth_token))
        url = '%stenant/%s/groups/%s' % (URL,'tenant_bad',self.tenant_group)

        #test for Content-Type = application/json
        resp, content = h.request(url, "GET", body='{',\
                    headers={"Content-Type": "application/json",\
                         "X-Auth-Token": self.auth_token})
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, int(resp['status']))

    def test_get_tenant_group_bad_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        respG, contentG = create_tenant_group(self.tenant_group,\
                        self.tenant, str(self.auth_token))
        url = '%stenant/%s/groups/%s' % (URL,'tenant_bad',self.tenant_group)
        #test for Content-Type = application/json
        resp, content = h.request(url, "GET", body='{',\
                    headers={"Content-Type": "application/xml",\
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
        respG, contentG = create_tenant_group(self.tenant_group,\
                        self.tenant, str(self.auth_token))
        url = '%stenant/%s/groups/%s' % (URL,self.tenant,'nonexistinggroup')
        #test for Content-Type = application/json
        resp, content = h.request(url, "GET", body='{}',\
                    headers={"Content-Type": "application/json",\
                         "X-Auth-Token": self.auth_token})
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, int(resp['status']))

    def test_get_tenant_group_not_found_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        respG, contentG = create_tenant_group(self.tenant_group,\
                        self.tenant, str(self.auth_token))
        url = '%stenant/%s/groups/%s' % (URL,self.tenant,'nonexistinggroup')

        #test for Content-Type = application/json
        resp, content = h.request(url, "GET", body='',\
                    headers={"Content-Type": "application/xml",\
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
        respG, contentG = create_tenant_group(self.tenant_group,\
                        self.tenant, str(self.auth_token))
        url = '%stenant/%s/groups/%s' % (URL,self.tenant,self.tenant_group)

        data = '{"group": { "id":"%s","description": "A NEW description..." ,\
            "tenantId":"%s" }}' % (self.tenant_group,self.tenant)
        #test for Content-Type = application/json
        resp, content = h.request(url, "PUT", body=data,\
                    headers={"Content-Type": "application/json",\
                         "X-Auth-Token": self.auth_token})
        body = json.loads(content)
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(200, int(resp['status']))
        self.assertEqual(self.tenant_group, body['group']['id'])
        self.assertEqual('A NEW description...', \
                 body['group']['description'])

    def test_update_tenant_group_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant_xml(self.tenant, str(self.auth_token))
        respG, contentG = create_tenant_group(self.tenant_group,\
                        self.tenant, str(self.auth_token))
        url = '%stenant/%s/groups/%s' % (URL, self.tenant ,self.tenant_group)
        data = '<?xml version="1.0" encoding="UTF-8"?> \
         <group xmlns="http://docs.openstack.org/idm/api/v1.0" \
         tenantId="%s" id="%s"> \
         <description>A NEW description...</description> \
         </group>' % (self.tenant, self.tenant_group)

        #test for Content-Type = application/json
        resp, content = h.request(url, "PUT", body=data,\
                    headers={"Content-Type": "application/xml",\
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
        self.assertEqual('A NEW description...', \
                 desc.text)

    def test_update_tenant_group_bad(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        respG, contentG = create_tenant_group(self.tenant_group,\
                        self.tenant, str(self.auth_token))
        url = '%stenant/%s/groups/%s' % (URL,self.tenant,self.tenant_group)
        data = '{"group": { "description_bad": "A NEW description...",\
            "id":"%s","tenantId":"%s"  }}' % (self.tenant_group,self.tenant)
        #test for Content-Type = application/json

        resp, content = h.request(url, "PUT", body=data,\
                    headers={"Content-Type": "application/json",\
                         "X-Auth-Token": self.auth_token})
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(400, int(resp['status']))

    def test_update_tenant_group_bad_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant(self.tenant, str(self.auth_token))
        respG, contentG = create_tenant_group(self.tenant_group,\
                        self.tenant, str(self.auth_token))
        url = '%stenant/%s/groups/%s' % (URL,self.tenant,self.tenant_group)
        data = '<?xml version="1.0" encoding="UTF-8"?> \
         <group xmlns="http://docs.openstack.org/idm/api/v1.0" \
         tenantId="%s" id="%s"> \
         <description_bad>A NEW description...</description> \
         </group>' % (self.tenant, self.tenant_group)
        #test for Content-Type = application/json
        resp, content = h.request(url, "PUT", body=data,\
                    headers={"Content-Type": "application/xml",\
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
        respG, contentG = create_tenant_group(self.tenant_group,\
                        self.tenant, str(self.auth_token))
        url = '%stenant/%s/groups/NonexistingID' % (URL, self.tenant)

        data = '{"group": { "description": "A NEW description...",\
            "id":"NonexistingID", "tenantId"="test_tenant"  }}'
        #test for Content-Type = application/json
        resp, content = h.request(url, "GET", body=data,\
                    headers={"Content-Type": "application/json",\
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
        resp, content = h.request(url, "GET", body=data,\
                    headers={"Content-Type": "application/xml",\
                         "X-Auth-Token": self.auth_token,
                         "ACCEPT": "application/xml"})
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, int(resp['status']))


class delete_tenant_group_test(tenant_test):

    def test_delete_tenant_group_not_found(self):
        #resp,content=create_tenant("test_tenant_delete", str(self.auth_token))
        resp, content = delete_tenant_group("test_tenant_delete111", \
                        "test_tenant", str(self.auth_token))
        self.assertEqual(404, int(resp['status']))

    def test_delete_tenant_group_not_found_xml(self):
        #resp,content=create_tenant("test_tenant_delete", str(self.auth_token))
        resp, content = delete_tenant_group_xml("test_tenant_delete111", \
                        "test_tenant", str(self.auth_token))
        self.assertEqual(404, int(resp['status']))

    def test_delete_tenant_group(self):
        resp, content = create_tenant("test_tenant_delete", \
                    str(self.auth_token))
        respG, contentG = create_tenant_group('test_tenant_group_delete', \
                        "test_tenant_delete", str(self.auth_token))
        respG, contentG = delete_tenant_group('test_tenant_group_delete', \
                        "test_tenant_delete", str(self.auth_token))
        resp, content = delete_tenant("test_tenant_delete", \
                        str(self.auth_token))
        self.assertEqual(204, int(respG['status']))

    def test_delete_tenant_group_xml(self):
        resp, content = create_tenant_xml("test_tenant_delete", \
                          str(self.auth_token))
        respG, contentG = create_tenant_group_xml('test_tenant_group_delete', \
                        "test_tenant_delete", str(self.auth_token))
        respG, contentG = delete_tenant_group_xml('test_tenant_group_delete', \
                        "test_tenant_delete", str(self.auth_token))
        resp, content = delete_tenant_xml("test_tenant_delete", \
                        str(self.auth_token))
        self.assertEqual(204, int(respG['status']))

class user_test(unittest.TestCase):

    def setUp(self):
        self.token = get_token('joeuser', 'secrete', 'token')
        self.tenant = get_tenant()
        self.userid = get_userid()
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
        
        resp, content = delete_user_json(self.tenant,\
                self.userid, str(self.auth_token))
       
        #resp, content = delete_user_xml(self.tenant,\
                #self.userid, str(self.auth_token))

class create_user_test(user_test):

    def test_a_user_create_json(self):
        resp, content = create_user_json('1234', 'test_user11',\
                str(self.auth_token))
        resp_val = int(resp['status'])
        handle_user_resp(self,content, resp_val,content_type(resp))
        self.assertEqual(201,resp_val)

    def test_a_user_create_xml(self):
        resp, content = delete_user_xml('1234', 'test_user11', \
                str(self.auth_token))
        resp, content = create_user_xml('1234', 'test_user11', \
                str(self.auth_token))
        resp_val = int(resp['status'])
        handle_user_resp(self,content, resp_val,content_type(resp))
        print 'here'
        print resp
        print content
        self.assertEqual(201,resp_val)
        self.assertEqual('application/xml', content_type(resp))
    
    def test_a_user_create_json_disabled_tenant(self):
        resp, content = create_user_json('0000', 'test_user11',\
                str(self.auth_token))
        resp_val = int(resp['status'])
        handle_user_resp(self,content, resp_val,content_type(resp))
        self.assertEqual(403,resp_val)
    
    def test_a_user_create_json_disabled_tenant_xml(self):
        resp, content = create_user_xml('0000', 'test_user11',\
                str(self.auth_token))
        resp_val = int(resp['status'])
        handle_user_resp(self,content, resp_val,content_type(resp))
        self.assertEqual(403,resp_val)
        self.assertEqual('application/xml', content_type(resp))

    def test_a_user_again_json(self):
        resp, content = create_user_json("1234", "test_user11", \
                str(self.auth_token))
        resp_val = int(resp['status'])
        handle_user_resp(self,content, resp_val,content_type(resp))
        resp, content = create_user_json("1234", "test_user11", \
                str(self.auth_token))
        self.assertEqual(409, int(resp['status']))

    def test_a_user_again_xml(self):
        resp, content = create_user_xml("1234", "test_user11", \
                str(self.auth_token))
        resp, content = create_user_xml("1234", "test_user11", \
                str(self.auth_token))
        content = etree.fromstring(content)
        resp_val = int(resp['status'])
        handle_user_resp(self,content, resp_val,content_type(resp))
        self.assertEqual(409, int(resp['status']))
        self.assertEqual('application/xml', content_type(resp))

    def test_a_user_create_expired_token(self):
        resp, content = create_user_json('1234', 'test_user11', \
                str(self.exp_auth_token))
        resp_val = int(resp['status'])
        handle_user_resp(self, content,resp_val,content_type(resp))
        self.assertEqual(401, int(resp['status']))

    def test_a_user_create_expired_token_xml(self):
        resp, content = create_user_xml('1234', 'test_user11', \
                str(self.exp_auth_token))
        resp_val = int(resp['status'])
        handle_user_resp(self, content,resp_val,content_type(resp))
        self.assertEqual(401, int(resp['status']))
        self.assertEqual('application/xml', content_type(resp))

    def test_a_user_create_disabled_token(self):
        resp, content = create_user_json('1234', 'test_user11', \
                str(self.disabled_token))
        resp_val = int(resp['status'])
        handle_user_resp(self, content, resp_val,content_type(resp))
        self.assertEqual(403, int(resp['status']))

    def test_a_user_create_disabled_token_xml(self):
        resp, content = create_user_xml('1234', 'test_user11', \
                str(self.disabled_token))
        resp_val = int(resp['status'])
        handle_user_resp(self, content, resp_val,content_type(resp))
        self.assertEqual(403, int(resp['status']))
        self.assertEqual('application/xml', content_type(resp))

    def test_a_user_create_missing_token(self):
        resp, content = create_user_json('1234', 'test_user11', \
                str(self.missing_token))
        resp_val = int(resp['status'])
        handle_user_resp(self, content, resp_val,content_type(resp))
        self.assertEqual(401, int(resp['status']))

    def test_a_user_create_missing_token_xml(self):
        resp, content = create_user_xml('1234', 'test_user11', \
                str(self.missing_token))
        resp_val = int(resp['status'])
        handle_user_resp(self, content, resp_val,content_type(resp))
        self.assertEqual(401, int(resp['status']))
        self.assertEqual('application/xml', content_type(resp))

    def test_a_user_create_invalid_token(self):
        resp, content = create_user_json('1234', 'test_user11', \
                str(self.invalid_token))
        resp_val = int(resp['status'])
        handle_user_resp(self,  content,resp_val,content_type(resp))
        self.assertEqual(401, int(resp['status']))

    def test_a_user_create_invalid_token_xml(self):
        resp, content = create_user_xml('1234', 'test_user11', \
                str(self.invalid_token))
        resp_val = int(resp['status'])
        handle_user_resp(self,  content,resp_val,content_type(resp))
        self.assertEqual(401, int(resp['status']))
        self.assertEqual('application/xml', content_type(resp))


class get_user_test(user_test):

    def test_a_user_get_json(self):
        h = httplib2.Http(".cache")
        resp, content = create_user_json(self.user,self.tenant,str(self.auth_token))
        url = '%stenants/%s/users/%s' % (URL,self.tenant,self.user)
        #test for Content-Type = application/json
        resp, content = h.request(url, "GET", body='{}',\
                                headers={"Content-Type": "application/json",\
                                         "X-Auth-Token": self.auth_token})
        resp_val = int(resp['status'])
        handle_user_resp(self,content, resp_val,content_type(resp))
        self.assertEqual(200,resp_val)

    def test_a_user_get_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_user_xml(self.user,self.tenant,str(self.auth_token))
        url = '%stenants/%s/users/%s' % (URL,self.tenant,self.user)
        resp, content = h.request(url, "GET", body='{}',\
                                headers={"Content-Type": "application/xml",\
                                         "X-Auth-Token": self.auth_token,
                                         "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        handle_user_resp(self,content, resp_val,content_type(resp))
        self.assertEqual(200,resp_val)
        self.assertEqual('application/xml', content_type(resp))
    
    def test_a_user_get_expired_token(self):
        h = httplib2.Http(".cache")
        resp, content = create_user_json(self.user,self.tenant,str(self.auth_token))
        url = '%stenants/%s/users/%s' % (URL,self.tenant,self.user)
        #test for Content-Type = application/json
        resp, content = h.request(url, "GET", body='{}',\
                                headers={"Content-Type": "application/json",\
                                         "X-Auth-Token": self.exp_auth_token})
        resp_val = int(resp['status'])
        handle_user_resp(self,content, resp_val,content_type(resp))
        self.assertEqual(401,resp_val)
    
    def test_a_user_get_expired_token_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_user_json(self.user,self.tenant,str(self.auth_token))
        url = '%stenants/%s/users/%s' % (URL,self.tenant,self.user)
        #test for Content-Type = application/json
        resp, content = h.request(url, "GET", body='',\
                                headers={"Content-Type": "application/xml",\
                                         "X-Auth-Token": self.exp_auth_token,
                                         "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        handle_user_resp(self,content, resp_val,content_type(resp))
        self.assertEqual(401,resp_val)
        self.assertEqual('application/xml', content_type(resp))
    
    def test_a_user_get_disabled_token(self):
        h = httplib2.Http(".cache")
        resp, content = create_user_json(self.user,self.tenant,str(self.auth_token))
        url = '%stenants/%s/users/%s' % (URL,self.tenant,self.user)
        #test for Content-Type = application/json
        resp, content = h.request(url, "GET", body='{}',\
                                headers={"Content-Type": "application/json",\
                                         "X-Auth-Token": self.disabled_token})
        resp_val = int(resp['status'])
        handle_user_resp(self,content, resp_val,content_type(resp))
        self.assertEqual(403,resp_val)
    
    def test_a_user_get_disabled_token_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_user_json(self.user,self.tenant,str(self.auth_token))
        url = '%stenants/%s/users/%s' % (URL,self.tenant,self.user)
        #test for Content-Type = application/json
        resp, content = h.request(url, "GET", body='',\
                                headers={"Content-Type": "application/xml",\
                                         "X-Auth-Token": self.disabled_token,
                                         "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        handle_user_resp(self,content, resp_val,content_type(resp))
        self.assertEqual(403,resp_val)
        self.assertEqual('application/xml', content_type(resp))
        
    def test_a_user_get_missing_token(self):
        h = httplib2.Http(".cache")
        resp, content = create_user_json(self.user,self.tenant,str(self.auth_token))
        url = '%stenants/%s/users/%s' % (URL,self.tenant,self.user)
        #test for Content-Type = application/json
        resp, content = h.request(url, "GET", body='{}',\
                                headers={"Content-Type": "application/json",\
                                         "X-Auth-Token": self.missing_token})
        resp_val = int(resp['status'])
        handle_user_resp(self,content, resp_val,content_type(resp))
        self.assertEqual(401,resp_val)
    
    def test_a_user_get_missing_token_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_user_json(self.user,self.tenant,str(self.auth_token))
        url = '%stenants/%s/users/%s' % (URL,self.tenant,self.user)
        #test for Content-Type = application/json
        resp, content = h.request(url, "GET", body='',\
                                headers={"Content-Type": "application/xml",\
                                         "X-Auth-Token": self.missing_token,
                                         "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        handle_user_resp(self,content, resp_val,content_type(resp))
        self.assertEqual(401,resp_val)
        self.assertEqual('application/xml', content_type(resp))
    
    def test_a_user_get_invalid_token(self):
        h = httplib2.Http(".cache")
        resp, content = create_user_json(self.user,self.tenant,str(self.auth_token))
        url = '%stenants/%s/users/%s' % (URL,self.tenant,self.user)
        #test for Content-Type = application/json
        resp, content = h.request(url, "GET", body='{}',\
                                headers={"Content-Type": "application/json",\
                                         "X-Auth-Token": self.invalid_token})
        resp_val = int(resp['status'])
        handle_user_resp(self,content, resp_val,content_type(resp))
        self.assertEqual(401,resp_val)
    
    def test_a_user_get_invalid_token_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_user_json(self.user,self.tenant,str(self.auth_token))
        url = '%stenants/%s/users/%s' % (URL,self.tenant,self.user)
        #test for Content-Type = application/json
        resp, content = h.request(url, "GET", body='',\
                                headers={"Content-Type": "application/xml",\
                                         "X-Auth-Token": self.invalid_token,
                                         "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        handle_user_resp(self,content, resp_val,content_type(resp))
        self.assertEqual(401,resp_val)
        self.assertEqual('application/xml', content_type(resp))
        
    def test_a_user_get_disabled_user(self):
        h = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s' % (URL,self.tenant,self.userdisabled)
        #test for Content-Type = application/json
        resp, content = h.request(url, "GET", body='{}',\
                                headers={"Content-Type": "application/json",\
                                         "X-Auth-Token": self.auth_token})
        resp_val = int(resp['status'])
        print resp,content
        handle_user_resp(self,content, resp_val,content_type(resp))
        self.assertEqual(403,resp_val)
    
    def test_a_user_get_disabled_user_xml(self):
        h = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s' % (URL,self.tenant,self.userdisabled)
        #test for Content-Type = application/json
        resp, content = h.request(url, "GET", body='',\
                                headers={"Content-Type": "application/xml",\
                                         "X-Auth-Token": self.auth_token,
                                         "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        handle_user_resp(self,content, resp_val,content_type(resp))
        self.assertEqual(403,resp_val)
        self.assertEqual('application/xml', content_type(resp))
    
    def test_a_user_get_disabled_tenant(self):
        h = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s' % (URL,'0000',self.userdisabled)
        #test for Content-Type = application/json
        resp, content = h.request(url, "GET", body='{}',\
                                headers={"Content-Type": "application/json",\
                                         "X-Auth-Token": self.auth_token})
        resp_val = int(resp['status'])
        handle_user_resp(self,content, resp_val,content_type(resp))
        self.assertEqual(403,resp_val)
    
    def test_a_user_get_disabled_tenant_xml(self):
        h = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s' % (URL,'0000',self.userdisabled)
        #test for Content-Type = application/json
        resp, content = h.request(url, "GET", body='',\
                                headers={"Content-Type": "application/xml",\
                                         "X-Auth-Token": self.auth_token,
                                         "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        handle_user_resp(self,content, resp_val,content_type(resp))
        self.assertEqual(403,resp_val)
        self.assertEqual('application/xml', content_type(resp))


class delete_user_test(user_test):

    def test_a_user_delete_json(self):
        h = httplib2.Http(".cache")
        resp, content = create_user_json(self.user,self.tenant,str(self.auth_token))
        url = '%stenants/%s/users/%s' % (URL,self.tenant,self.user)
        #test for Content-Type = application/json
        resp, content = h.request(url, "DELETE", body='{}',\
                                headers={"Content-Type": "application/json",\
                                         "X-Auth-Token": self.auth_token})
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(204,resp_val)

    def test_a_user_delete_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_user_xml(self.user,self.tenant,str(self.auth_token))
        url = '%stenants/%s/users/%s' % (URL,self.tenant,self.user)
        resp, content = h.request(url, "DELETE", body='{}',\
                                headers={"Content-Type": "application/xml",\
                                         "X-Auth-Token": self.auth_token,
                                         "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(204,resp_val)
    
    def test_a_user_delete_expired_token(self):
        h = httplib2.Http(".cache")
        resp, content = create_user_json(self.user,self.tenant,str(self.auth_token))
        url = '%stenants/%s/users/%s' % (URL,self.tenant,self.user)
        #test for Content-Type = application/json
        resp, content = h.request(url, "DELETE", body='{}',\
                                headers={"Content-Type": "application/json",\
                                         "X-Auth-Token": self.exp_auth_token})
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(401,resp_val)
    
    def test_a_user_delete_expired_token_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_user_json(self.user,self.tenant,str(self.auth_token))
        url = '%stenants/%s/users/%s' % (URL,self.tenant,self.user)
        #test for Content-Type = application/json
        resp, content = h.request(url, "DELETE", body='',\
                                headers={"Content-Type": "application/xml",\
                                         "X-Auth-Token": self.exp_auth_token,
                                         "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(401,resp_val)
        self.assertEqual('application/xml', content_type(resp))
        
    def test_a_user_delete_missing_token(self):
        h = httplib2.Http(".cache")
        resp, content = create_user_json(self.user,self.tenant,str(self.auth_token))
        url = '%stenants/%s/users/%s' % (URL,self.tenant,self.user)
        #test for Content-Type = application/json
        resp, content = h.request(url, "DELETE", body='{}',\
                                headers={"Content-Type": "application/json",\
                                         "X-Auth-Token": self.missing_token})
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(401,resp_val)
    
    def test_a_user_delete_missing_token_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_user_json(self.user,self.tenant,str(self.auth_token))
        url = '%stenants/%s/users/%s' % (URL,self.tenant,self.user)
        #test for Content-Type = application/json
        resp, content = h.request(url, "DELETE", body='',\
                                headers={"Content-Type": "application/xml",\
                                         "X-Auth-Token": self.missing_token,
                                         "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(401,resp_val)
        self.assertEqual('application/xml', content_type(resp))
    
    def test_a_user_delete_invalid_token(self):
        h = httplib2.Http(".cache")
        resp, content = create_user_json(self.user,self.tenant,str(self.auth_token))
        url = '%stenants/%s/users/%s' % (URL,self.tenant,self.user)
        #test for Content-Type = application/json
        resp, content = h.request(url, "DELETE", body='{}',\
                                headers={"Content-Type": "application/json",\
                                         "X-Auth-Token": self.invalid_token})
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(401,resp_val)
    
    def test_a_user_delete_invalid_token_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_user_json(self.user,self.tenant,str(self.auth_token))
        url = '%stenants/%s/users/%s' % (URL,self.tenant,self.user)
        #test for Content-Type = application/json
        resp, content = h.request(url, "DELETE", body='',\
                                headers={"Content-Type": "application/xml",\
                                         "X-Auth-Token": self.invalid_token,
                                         "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(401,resp_val)
        self.assertEqual('application/xml', content_type(resp))

    def test_a_user_delete_disabled_tenant(self):
        h = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s' % (URL,'0000',self.userdisabled)
        #test for Content-Type = application/json
        resp, content = h.request(url, "DELETE", body='{}',\
                                headers={"Content-Type": "application/json",\
                                         "X-Auth-Token": self.auth_token})
        resp_val = int(resp['status'])
        print resp,content
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403,resp_val)
    
    def test_a_user_delete_disabled_tenant_xml(self):
        h = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s' % (URL,'0000',self.userdisabled)
        #test for Content-Type = application/json
        resp, content = h.request(url, "DELETE", body='',\
                                headers={"Content-Type": "application/xml",\
                                         "X-Auth-Token": self.auth_token,
                                         "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        print resp,content
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403,resp_val)
        self.assertEqual('application/xml', content_type(resp))

class get_users_test(user_test):

    def test_users_get_json(self):
        h = httplib2.Http(".cache")
        url = '%stenants/%s/users' % (URL,self.tenant)
        resp, content = h.request(url, "GET", body='{}',\
                                headers={"Content-Type": "application/json",\
                                         "X-Auth-Token": self.auth_token})
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(200,resp_val)

    def test_users_get_xml(self):
        h = httplib2.Http(".cache")
        url = '%stenants/%s/users' % (URL,self.tenant)
        resp, content = h.request(url, "GET", body='{}',\
                                headers={"Content-Type": "application/xml",\
                                         "X-Auth-Token": self.auth_token,
                                         "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(200,resp_val)
        self.assertEqual('application/xml', content_type(resp))
    
    def test_users_get_expired_token_json(self):
        h = httplib2.Http(".cache")
        url = '%stenants/%s/users' % (URL,self.tenant)
        resp, content = h.request(url, "GET", body='{}',\
                                headers={"Content-Type": "application/json",\
                                         "X-Auth-Token": self.exp_auth_token})
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(401,resp_val)
    
    def test_users_get_expired_token_xml(self):
        h = httplib2.Http(".cache")
        url = '%stenants/%s/users' % (URL,self.tenant)
        resp, content = h.request(url, "GET", body='{}',\
                                headers={"Content-Type": "application/xml",\
                                         "X-Auth-Token": self.exp_auth_token,
                                         "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(401,resp_val)
        self.assertEqual('application/xml', content_type(resp))
    
    def test_users_get_disabled_token_json(self):
        h = httplib2.Http(".cache")
        url = '%stenants/%s/users' % (URL,self.tenant)
        resp, content = h.request(url, "GET", body='{}',\
                                headers={"Content-Type": "application/json",\
                                         "X-Auth-Token": self.disabled_token})
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403,resp_val)
    
    def test_users_get_disabled_token_xml(self):
        h = httplib2.Http(".cache")
        url = '%stenants/%s/users' % (URL,self.tenant)
        resp, content = h.request(url, "GET", body='{}',\
                                headers={"Content-Type": "application/xml",\
                                         "X-Auth-Token": self.disabled_token,
                                         "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403,resp_val)
        self.assertEqual('application/xml', content_type(resp))
        
    def test_users_get_missing_token_json(self):
        h = httplib2.Http(".cache")
        url = '%stenants/%s/users' % (URL,self.tenant)
        resp, content = h.request(url, "GET", body='{}',\
                                headers={"Content-Type": "application/json",\
                                         "X-Auth-Token": self.missing_token})
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(401,resp_val)
    
    def test_users_get_missing_token_xml(self):
        h = httplib2.Http(".cache")
        url = '%stenants/%s/users' % (URL,self.tenant)
        resp, content = h.request(url, "GET", body='{}',\
                                headers={"Content-Type": "application/xml",\
                                         "X-Auth-Token": self.missing_token,
                                         "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(401,resp_val)
        self.assertEqual('application/xml', content_type(resp))
    
    def test_users_get_invalid_token_json(self):
        h = httplib2.Http(".cache")
        url = '%stenants/%s/users' % (URL,self.tenant)
        resp, content = h.request(url, "GET", body='{}',\
                                headers={"Content-Type": "application/json",\
                                         "X-Auth-Token": self.invalid_token})
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(401,resp_val)
    
    def test_users_get_invalid_token_xml(self):
        h = httplib2.Http(".cache")
        url = '%stenants/%s/users' % (URL,self.tenant)
        resp, content = h.request(url, "GET", body='{}',\
                                headers={"Content-Type": "application/xml",\
                                         "X-Auth-Token": self.invalid_token,
                                         "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(401,resp_val)
        self.assertEqual('application/xml', content_type(resp))
    
    def test_users_get_disabled_tenant_json(self):
        h = httplib2.Http(".cache")
        url = '%stenants/%s/users' % (URL,"0000")
        resp, content = h.request(url, "GET", body='{}',\
                                headers={"Content-Type": "application/json",\
                                         "X-Auth-Token": self.auth_token})
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        print resp,content
        self.assertEqual(403,resp_val)
    
    def test_users_get_disabled_tenant_xml(self):
        h = httplib2.Http(".cache")
        url = '%stenants/%s/users' % (URL,"0000")
        resp, content = h.request(url, "GET", body='{}',\
                                headers={"Content-Type": "application/xml",\
                                         "X-Auth-Token": self.auth_token,
                                         "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403,resp_val)
        self.assertEqual('application/xml', content_type(resp))
        
class get_users_group_test(user_test):

    def test_users_get_json(self):
        h = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s/groups' % (URL,self.tenant,self.user)
        resp, content = h.request(url, "GET", body='{}',\
                                headers={"Content-Type": "application/json",\
                                         "X-Auth-Token": self.auth_token})
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(200,resp_val)

    def test_users_get_xml(self):
        h = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s/groups' % (URL,self.tenant,self.user)
        resp, content = h.request(url, "GET", body='{}',\
                                headers={"Content-Type": "application/xml",\
                                         "X-Auth-Token": self.auth_token,
                                         "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(200,resp_val)
        self.assertEqual('application/xml', content_type(resp))
    
    def test_users_get_expired_token_json(self):
        h = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s/groups' % (URL,self.tenant,self.user)
        resp, content = h.request(url, "GET", body='{}',\
                                headers={"Content-Type": "application/json",\
                                         "X-Auth-Token": self.exp_auth_token})
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(401,resp_val)
    
    def test_users_get_expired_token_xml(self):
        h = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s/groups' % (URL,self.tenant,self.user)
        resp, content = h.request(url, "GET", body='{}',\
                                headers={"Content-Type": "application/xml",\
                                         "X-Auth-Token": self.exp_auth_token,
                                         "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(401,resp_val)
        self.assertEqual('application/xml', content_type(resp))
    
    def test_users_get_disabled_token_json(self):
        h = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s/groups' % (URL,self.tenant,self.user)
        resp, content = h.request(url, "GET", body='{}',\
                                headers={"Content-Type": "application/json",\
                                         "X-Auth-Token": self.disabled_token})
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403,resp_val)
    
    def test_users_get_disabled_token_xml(self):
        h = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s/groups' % (URL,self.tenant,self.user)
        resp, content = h.request(url, "GET", body='{}',\
                                headers={"Content-Type": "application/xml",\
                                         "X-Auth-Token": self.disabled_token,
                                         "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403,resp_val)
        self.assertEqual('application/xml', content_type(resp))
        
    def test_users_get_missing_token_json(self):
        h = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s/groups' % (URL,self.tenant,self.user)
        resp, content = h.request(url, "GET", body='{}',\
                                headers={"Content-Type": "application/json",\
                                         "X-Auth-Token": self.missing_token})
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(401,resp_val)
    
    def test_users_get_missing_token_xml(self):
        h = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s/groups' % (URL,self.tenant,self.user)
        resp, content = h.request(url, "GET", body='{}',\
                                headers={"Content-Type": "application/xml",\
                                         "X-Auth-Token": self.missing_token,
                                         "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(401,resp_val)
        self.assertEqual('application/xml', content_type(resp))
    
    def test_users_get_invalid_token_json(self):
        h = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s/groups' % (URL,self.tenant,self.user)
        resp, content = h.request(url, "GET", body='{}',\
                                headers={"Content-Type": "application/json",\
                                         "X-Auth-Token": self.invalid_token})
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(401,resp_val)
    
    def test_users_get_invalid_token_xml(self):
        h = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s/groups' % (URL,self.tenant,self.user)
        resp, content = h.request(url, "GET", body='{}',\
                                headers={"Content-Type": "application/xml",\
                                         "X-Auth-Token": self.invalid_token,
                                         "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(401,resp_val)
        self.assertEqual('application/xml', content_type(resp))
    
    def test_users_get_disabled_tenant_json(self):
        h = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s/groups' % (URL,"0000",self.user)
        resp, content = h.request(url, "GET", body='{}',\
                                headers={"Content-Type": "application/json",\
                                         "X-Auth-Token": self.auth_token})
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        print resp,content
        self.assertEqual(403,resp_val)
    
    def test_users_get_disabled_tenant_xml(self):
        h = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s/groups' % (URL,"0000",self.user)
        resp, content = h.request(url, "GET", body='{}',\
                                headers={"Content-Type": "application/xml",\
                                         "X-Auth-Token": self.auth_token,
                                         "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403,resp_val)
        self.assertEqual('application/xml', content_type(resp))
        



class update_user_test(user_test):

    def test_user_update_json(self):
        h = httplib2.Http(".cache")
        resp, content = create_user_json(self.tenant,self.user , \
                str(self.auth_token))
        print resp,content
        url = '%stenants/%s/users/%s' % (URL,self.tenant,self.user)
        print url
        data = '{"user": { "email": "updatedjoeuser@rackspace.com"}}'
        resp, content = h.request(url, "PUT", body=data,
                                headers={"Content-Type": "application/json",\
                                         "X-Auth-Token": self.auth_token})
        resp_val = int(resp['status'])
        print resp,content
        content=json.loads(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        delete_user_json(self.tenant,self.user , \
                str(self.auth_token))
        self.assertEqual(200,resp_val)
        self.assertEqual('updatedjoeuser@rackspace.com',content['user']['email'])

    def test_user_update_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_user_xml(self.tenant,self.user , \
                str(self.auth_token))
        print resp,content
        url = '%stenants/%s/users/%s' % (URL,self.tenant,self.user)
        print url
        data = '<?xml version="1.0" encoding="UTF-8"?> \
                <user xmlns="http://docs.openstack.org/idm/api/v1.0" \
                email="updatedjoeuser@rackspace.com" />'
        resp, content = h.request(url, "PUT", body=data,
                                headers={"Content-Type": "application/xml",\
                                         "X-Auth-Token": self.auth_token,
                                         "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        print resp,content
        content=etree.fromstring(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        delete_user_json(self.tenant,self.user , \
                str(self.auth_token))
        self.assertEqual(200,resp_val)
        self.assertEqual('updatedjoeuser@rackspace.com',content.get("email"))
        self.assertEqual('application/xml', content_type(resp))
    
    def test_user_update_user_disabled_json(self):
        h = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s' % (URL,self.tenant,self.userdisabled)
        print url
        data = '{"user": { "email": "updatedjoeuser@rackspace.com"}}'
        resp, content = h.request(url, "PUT", body=data,
                                headers={"Content-Type": "application/json",\
                                         "X-Auth-Token": self.auth_token})
        resp_val = int(resp['status'])
        print resp,content
        content=json.loads(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403,resp_val)
    
    def test_user_update_user_disabled_xml(self):
        h = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s' % (URL,self.tenant,self.userdisabled)
        data = '<?xml version="1.0" encoding="UTF-8"?> \
                <user xmlns="http://docs.openstack.org/idm/api/v1.0" \
                email="updatedjoeuser@rackspace.com" />'
        resp, content = h.request(url, "PUT", body=data,
                                headers={"Content-Type": "application/xml",\
                                         "X-Auth-Token": self.auth_token,
                                         "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        print resp,content
        content=etree.fromstring(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403,resp_val)
        self.assertEqual('application/xml', content_type(resp))
        
    def test_user_update_email_conflict_json(self):
        h = httplib2.Http(".cache")
        resp, content = create_user_xml(self.tenant,self.user , \
                str(self.auth_token))
        url = '%stenants/%s/users/%s' % (URL,self.tenant,self.user)
        print url
        data = '{"user": { "email": "joe@rackspace.com"}}'
        resp, content = h.request(url, "PUT", body=data,
                                headers={"Content-Type": "application/json",\
                                         "X-Auth-Token": self.auth_token})
        resp_val = int(resp['status'])
        print resp,content
        content=json.loads(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(409,resp_val)
    
    def test_user_update_email_conflict_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_user_xml(self.tenant,self.user , \
                str(self.auth_token))
        url = '%stenants/%s/users/%s' % (URL,self.tenant,self.user)
        data = '<?xml version="1.0" encoding="UTF-8"?> \
                <user xmlns="http://docs.openstack.org/idm/api/v1.0" \
                email="joe@rackspace.com" />'
        resp, content = h.request(url, "PUT", body=data,
                                headers={"Content-Type": "application/xml",\
                                         "X-Auth-Token": self.auth_token,
                                         "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        print resp,content
        content=etree.fromstring(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(409,resp_val)
        self.assertEqual('application/xml', content_type(resp))
     
    def test_user_update_bad_request_json(self):
        h = httplib2.Http(".cache")
        resp, content = create_user_json(self.tenant,self.user , \
                str(self.auth_token))
        print resp,content
        url = '%stenants/%s/users/%s' % (URL,self.tenant,self.user)
        print url
        data = '{"user_bad": { "bad": "updatedjoeuser@rackspace.com"}}'
        resp, content = h.request(url, "PUT", body=data,
                                headers={"Content-Type": "application/json",\
                                         "X-Auth-Token": self.auth_token})
        resp_val = int(resp['status'])
        print resp,content
        content=json.loads(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        delete_user_json(self.tenant,self.user , \
                str(self.auth_token))
        self.assertEqual(400,resp_val)

    def test_user_update_bad_request_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_user_xml(self.tenant,self.user , \
                str(self.auth_token))
        print resp,content
        url = '%stenants/%s/users/%s' % (URL,self.tenant,self.user)
        print url
        data = '<?xml version="1.0" encoding="UTF-8"?> \
                user xmlns="http://docs.openstack.org/idm/api/v1.0" \
                email="updatedjoeuser@rackspace.com" />'
        resp, content = h.request(url, "PUT", body=data,
                                headers={"Content-Type": "application/xml",\
                                         "X-Auth-Token": self.auth_token,
                                         "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        print resp,content
        content=etree.fromstring(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        delete_user_json(self.tenant,self.user , \
                str(self.auth_token))
        self.assertEqual(400,resp_val)
        self.assertEqual('application/xml', content_type(resp))
    
    
    def test_user_update_expired_token_json(self):
        h = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s' % (URL,self.tenant,self.user)
        print url
        data = '{"user": { "email": "updatedjoeuser@rackspace.com"}}'
        resp, content = h.request(url, "PUT", body=data,
                                headers={"Content-Type": "application/json",\
                                         "X-Auth-Token": self.exp_auth_token})
        resp_val = int(resp['status'])
        print resp,content
        content=json.loads(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(401,resp_val)
    
    def test_user_update_expired_token_xml(self):
        h = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s' % (URL,self.tenant,self.user)
        data = '<?xml version="1.0" encoding="UTF-8"?> \
                <user xmlns="http://docs.openstack.org/idm/api/v1.0" \
                email="updatedjoeuser@rackspace.com" />'
        resp, content = h.request(url, "PUT", body=data,
                                headers={"Content-Type": "application/xml",\
                                         "X-Auth-Token": self.exp_auth_token,
                                         "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        print resp,content
        content=etree.fromstring(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(401,resp_val)
        self.assertEqual('application/xml', content_type(resp))
    
    def test_user_update_disabled_token_json(self):
        h = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s' % (URL,self.tenant,self.user)
        print url
        data = '{"user": { "email": "updatedjoeuser@rackspace.com"}}'
        resp, content = h.request(url, "PUT", body=data,
                                headers={"Content-Type": "application/json",\
                                         "X-Auth-Token": self.disabled_token})
        resp_val = int(resp['status'])
        print resp,content
        content=json.loads(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403,resp_val)
    
    def test_user_update_disabled_token_xml(self):
        h = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s' % (URL,self.tenant,self.user)
        data = '<?xml version="1.0" encoding="UTF-8"?> \
                <user xmlns="http://docs.openstack.org/idm/api/v1.0" \
                email="updatedjoeuser@rackspace.com" />'
        resp, content = h.request(url, "PUT", body=data,
                                headers={"Content-Type": "application/xml",\
                                         "X-Auth-Token": self.disabled_token,
                                         "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        print resp,content
        content=etree.fromstring(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403,resp_val)
        self.assertEqual('application/xml', content_type(resp))
    
    def test_user_update_invalid_token_json(self):
        h = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s' % (URL,self.tenant,self.user)
        print url
        data = '{"user": { "email": "updatedjoeuser@rackspace.com"}}'
        resp, content = h.request(url, "PUT", body=data,
                                headers={"Content-Type": "application/json",\
                                         "X-Auth-Token": self.invalid_token})
        resp_val = int(resp['status'])
        print resp,content
        content=json.loads(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(401,resp_val)
    
    def test_user_update_invalid_token_xml(self):
        h = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s' % (URL,self.tenant,self.user)
        data = '<?xml version="1.0" encoding="UTF-8"?> \
                <user xmlns="http://docs.openstack.org/idm/api/v1.0" \
                email="updatedjoeuser@rackspace.com" />'
        resp, content = h.request(url, "PUT", body=data,
                                headers={"Content-Type": "application/xml",\
                                         "X-Auth-Token": self.invalid_token,
                                         "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        print resp,content
        content=etree.fromstring(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(401,resp_val)
        self.assertEqual('application/xml', content_type(resp))
    
    def test_user_update_missing_token_json(self):
        h = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s' % (URL,self.tenant,self.user)
        print url
        data = '{"user": { "email": "updatedjoeuser@rackspace.com"}}'
        resp, content = h.request(url, "PUT", body=data,
                                headers={"Content-Type": "application/json",\
                                         "X-Auth-Token": self.missing_token})
        resp_val = int(resp['status'])
        print resp,content
        content=json.loads(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(401,resp_val)
    
    def test_user_update_missing_token_xml(self):
        h = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s' % (URL,self.tenant,self.user)
        data = '<?xml version="1.0" encoding="UTF-8"?> \
                <user xmlns="http://docs.openstack.org/idm/api/v1.0" \
                email="updatedjoeuser@rackspace.com" />'
        resp, content = h.request(url, "PUT", body=data,
                                headers={"Content-Type": "application/xml",\
                                         "X-Auth-Token": self.missing_token,
                                         "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        print resp,content
        content=etree.fromstring(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(401,resp_val)
        self.assertEqual('application/xml', content_type(resp))
        

class set_password_test(user_test):

    def test_user_password_json(self):
        h = httplib2.Http(".cache")
        resp, content = create_user_json(self.tenant,self.user , \
                str(self.auth_token))
        print resp,content
        url = '%stenants/%s/users/%s/password' % (URL,self.tenant,self.user)
        print url
        data = '{"user": { "password": "p@ssword"}}'
        resp, content = h.request(url, "PUT", body=data,
                                headers={"Content-Type": "application/json",\
                                         "X-Auth-Token": self.auth_token})
        resp_val = int(resp['status'])
        print resp,content
        content=json.loads(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        delete_user_json(self.tenant,self.user , \
                str(self.auth_token))
        self.assertEqual(200,resp_val)
        self.assertEqual('p@ssword',content['user']['password'])

    def test_user_password_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_user_xml(self.tenant,self.user , \
                str(self.auth_token))
        print resp,content
        url = '%stenants/%s/users/%s/password' % (URL,self.tenant,self.user)
        print url
        data = '<?xml version="1.0" encoding="UTF-8"?> \
                <user xmlns="http://docs.openstack.org/idm/api/v1.0" \
                password="p@ssword" />'
        resp, content = h.request(url, "PUT", body=data,
                                headers={"Content-Type": "application/xml",\
                                         "X-Auth-Token": self.auth_token,
                                         "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        print resp,content
        content=etree.fromstring(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        delete_user_json(self.tenant,self.user , \
                str(self.auth_token))
        self.assertEqual(200,resp_val)
        self.assertEqual('p@ssword',content.get("password"))
        self.assertEqual('application/xml', content_type(resp))
    
    def test_user_password_user_disabled_json(self):
        h = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s/password' % (URL,self.tenant,self.userdisabled)
        print url
        data = '{"user": { "password": "p@ssword"}}'
        resp, content = h.request(url, "PUT", body=data,
                                headers={"Content-Type": "application/json",\
                                         "X-Auth-Token": self.auth_token})
        resp_val = int(resp['status'])
        print resp,content
        content=json.loads(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403,resp_val)
    
    def test_user_password_user_disabled_xml(self):
        h = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s' % (URL,self.tenant,self.userdisabled)
        data = '<?xml version="1.0" encoding="UTF-8"?> \
                <user xmlns="http://docs.openstack.org/idm/api/v1.0" \
                password="p@ssword" />'
        resp, content = h.request(url, "PUT", body=data,
                                headers={"Content-Type": "application/xml",\
                                         "X-Auth-Token": self.auth_token,
                                         "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        print resp,content
        content=etree.fromstring(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403,resp_val)
        self.assertEqual('application/xml', content_type(resp))
        
    def test_user_password_bad_request_json(self):
        h = httplib2.Http(".cache")
        resp, content = create_user_json(self.tenant,self.user , \
                str(self.auth_token))
        print resp,content
        url = '%stenants/%s/users/%s/password' % (URL,self.tenant,self.user)
        print url
        data = '{"user_bad": { "password": "p@ssword"}}'
        resp, content = h.request(url, "PUT", body=data,
                                headers={"Content-Type": "application/json",\
                                         "X-Auth-Token": self.auth_token})
        resp_val = int(resp['status'])
        print resp,content
        content=json.loads(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        delete_user_json(self.tenant,self.user , \
                str(self.auth_token))
        self.assertEqual(400,resp_val)

    def test_user_password_bad_request_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_user_xml(self.tenant,self.user , \
                str(self.auth_token))
        print resp,content
        url = '%stenants/%s/users/%s/password' % (URL,self.tenant,self.user)
        print url
        data = '<?xml version="1.0" encoding="UTF-8"?> \
                user xmlns="http://docs.openstack.org/idm/api/v1.0" \
                password="p@ssword" />'
        resp, content = h.request(url, "PUT", body=data,
                                headers={"Content-Type": "application/xml",\
                                         "X-Auth-Token": self.auth_token,
                                         "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        print resp,content
        content=etree.fromstring(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        delete_user_json(self.tenant,self.user , \
                str(self.auth_token))
        self.assertEqual(400,resp_val)
        self.assertEqual('application/xml', content_type(resp))
    
    
    def test_user_password_expired_token_json(self):
        h = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s/password' % (URL,self.tenant,self.user)
        print url
        data = '{"user": { "password": "p@ssword"}}'
        resp, content = h.request(url, "PUT", body=data,
                                headers={"Content-Type": "application/json",\
                                         "X-Auth-Token": self.exp_auth_token})
        resp_val = int(resp['status'])
        print resp,content
        content=json.loads(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(401,resp_val)
    
    def test_user_password_expired_token_xml(self):
        h = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s/password' % (URL,self.tenant,self.user)
        data = '<?xml version="1.0" encoding="UTF-8"?> \
                <user xmlns="http://docs.openstack.org/idm/api/v1.0" \
                password="p@ssword" />'
        resp, content = h.request(url, "PUT", body=data,
                                headers={"Content-Type": "application/xml",\
                                         "X-Auth-Token": self.exp_auth_token,
                                         "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        print resp,content
        content=etree.fromstring(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(401,resp_val)
        self.assertEqual('application/xml', content_type(resp))
    
    def test_user_password_disabled_token_json(self):
        h = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s/password' % (URL,self.tenant,self.user)
        print url
        data = '{"user": { "password": "p@ssword"}}'
        resp, content = h.request(url, "PUT", body=data,
                                headers={"Content-Type": "application/json",\
                                         "X-Auth-Token": self.disabled_token})
        resp_val = int(resp['status'])
        print resp,content
        content=json.loads(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403,resp_val)
    
    def test_user_password_disabled_token_xml(self):
        h = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s/password' % (URL,self.tenant,self.user)
        data = '<?xml version="1.0" encoding="UTF-8"?> \
                <user xmlns="http://docs.openstack.org/idm/api/v1.0" \
                password="p@ssword" />'
        resp, content = h.request(url, "PUT", body=data,
                                headers={"Content-Type": "application/xml",\
                                         "X-Auth-Token": self.disabled_token,
                                         "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        print resp,content
        content=etree.fromstring(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403,resp_val)
        self.assertEqual('application/xml', content_type(resp))
    
    def test_user_password_invalid_token_json(self):
        h = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s/password' % (URL,self.tenant,self.user)
        print url
        data = '{"user": { "password": "p@ssword"}}'
        resp, content = h.request(url, "PUT", body=data,
                                headers={"Content-Type": "application/json",\
                                         "X-Auth-Token": self.invalid_token})
        resp_val = int(resp['status'])
        print resp,content
        content=json.loads(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(401,resp_val)
    
    def test_user_password_invalid_token_xml(self):
        h = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s/password' % (URL,self.tenant,self.user)
        data = '<?xml version="1.0" encoding="UTF-8"?> \
                <user xmlns="http://docs.openstack.org/idm/api/v1.0" \
                password="p@ssword" />'
        resp, content = h.request(url, "PUT", body=data,
                                headers={"Content-Type": "application/xml",\
                                         "X-Auth-Token": self.invalid_token,
                                         "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        print resp,content
        content=etree.fromstring(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(401,resp_val)
        self.assertEqual('application/xml', content_type(resp))
    
    def test_user_password_missing_token_json(self):
        h = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s/password' % (URL,self.tenant,self.user)
        print url
        data = '{"user": { "password": "p@ssword"}}'
        resp, content = h.request(url, "PUT", body=data,
                                headers={"Content-Type": "application/json",\
                                         "X-Auth-Token": self.missing_token})
        resp_val = int(resp['status'])
        print resp,content
        content=json.loads(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(401,resp_val)
    
    def test_user_password_missing_token_xml(self):
        h = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s/password' % (URL,self.tenant,self.user)
        data = '<?xml version="1.0" encoding="UTF-8"?> \
                <user xmlns="http://docs.openstack.org/idm/api/v1.0" \
                password="p@ssword" />'
        resp, content = h.request(url, "PUT", body=data,
                                headers={"Content-Type": "application/xml",\
                                         "X-Auth-Token": self.missing_token,
                                         "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        print resp,content
        content=etree.fromstring(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(401,resp_val)
        self.assertEqual('application/xml', content_type(resp))
        
        
class set_enabled_test(user_test):

    def test_user_enabled_json(self):
        h = httplib2.Http(".cache")
        resp, content = create_user_json(self.tenant,self.user , \
                str(self.auth_token))
        print resp,content
        url = '%stenants/%s/users/%s/enabled' % (URL,self.tenant,self.user)
        print url
        data = '{"user": { "enabled": true}}'
        resp, content = h.request(url, "PUT", body=data,
                                headers={"Content-Type": "application/json",\
                                         "X-Auth-Token": self.auth_token})
        resp_val = int(resp['status'])
        print resp,content
        content=json.loads(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        delete_user_json(self.tenant,self.user , \
                str(self.auth_token))
        self.assertEqual(200,resp_val)
        self.assertEqual(True,content['user']['enabled'])

    def test_user_enabled_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_user_xml(self.tenant,self.user , \
                str(self.auth_token))
        print resp,content
        url = '%stenants/%s/users/%s/enabled' % (URL,self.tenant,self.user)
        print url
        data = '<?xml version="1.0" encoding="UTF-8"?> \
                <user xmlns="http://docs.openstack.org/idm/api/v1.0" \
                enabled="true" />'
        resp, content = h.request(url, "PUT", body=data,
                                headers={"Content-Type": "application/xml",\
                                         "X-Auth-Token": self.auth_token,
                                         "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        print resp,content
        content=etree.fromstring(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        delete_user_json(self.tenant,self.user , \
                str(self.auth_token))
        self.assertEqual(200,resp_val)
        self.assertEqual('true',content.get("enabled"))
        self.assertEqual('application/xml', content_type(resp))
                
    def test_user_enabled_bad_request_json(self):
        h = httplib2.Http(".cache")
        resp, content = create_user_json(self.tenant,self.user , \
                str(self.auth_token))
        print resp,content
        url = '%stenants/%s/users/%s/enabled' % (URL,self.tenant,self.user)
        print url
        data = '{"user_bad": { "enabled": true}}'
        resp, content = h.request(url, "PUT", body=data,
                                headers={"Content-Type": "application/json",\
                                         "X-Auth-Token": self.auth_token})
        resp_val = int(resp['status'])
        print resp,content
        content=json.loads(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        delete_user_json(self.tenant,self.user , \
                str(self.auth_token))
        self.assertEqual(400,resp_val)

    def test_user_enabled_bad_request_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_user_xml(self.tenant,self.user , \
                str(self.auth_token))
        print resp,content
        url = '%stenants/%s/users/%s/enabled' % (URL,self.tenant,self.user)
        print url
        data = '<?xml version="1.0" encoding="UTF-8"?> \
                user xmlns="http://docs.openstack.org/idm/api/v1.0" \
                enabled="true" />'
        resp, content = h.request(url, "PUT", body=data,
                                headers={"Content-Type": "application/xml",\
                                         "X-Auth-Token": self.auth_token,
                                         "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        print resp,content
        content=etree.fromstring(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        delete_user_json(self.tenant,self.user , \
                str(self.auth_token))
        self.assertEqual(400,resp_val)
        self.assertEqual('application/xml', content_type(resp))
    
    
    def test_user_enabled_expired_token_json(self):
        h = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s/enabled' % (URL,self.tenant,self.user)
        print url
        data = '{"user": { "enabled": true}}'
        resp, content = h.request(url, "PUT", body=data,
                                headers={"Content-Type": "application/json",\
                                         "X-Auth-Token": self.exp_auth_token})
        resp_val = int(resp['status'])
        print resp,content
        content=json.loads(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(401,resp_val)
    
    def test_user_enabled_expired_token_xml(self):
        h = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s/enabled' % (URL,self.tenant,self.user)
        data = '<?xml version="1.0" encoding="UTF-8"?> \
                <user xmlns="http://docs.openstack.org/idm/api/v1.0" \
                enabled="true" />'
        resp, content = h.request(url, "PUT", body=data,
                                headers={"Content-Type": "application/xml",\
                                         "X-Auth-Token": self.exp_auth_token,
                                         "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        print resp,content
        content=etree.fromstring(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(401,resp_val)
        self.assertEqual('application/xml', content_type(resp))
    
    def test_user_enabled_disabled_token_json(self):
        h = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s/enabled' % (URL,self.tenant,self.user)
        print url
        data = '{"user": { "enabled": true}}'
        resp, content = h.request(url, "PUT", body=data,
                                headers={"Content-Type": "application/json",\
                                         "X-Auth-Token": self.disabled_token})
        resp_val = int(resp['status'])
        print resp,content
        content=json.loads(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403,resp_val)
    
    def test_user_enabled_disabled_token_xml(self):
        h = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s/enabled' % (URL,self.tenant,self.user)
        data = '<?xml version="1.0" encoding="UTF-8"?> \
                <user xmlns="http://docs.openstack.org/idm/api/v1.0" \
                enabled="true" />'
        resp, content = h.request(url, "PUT", body=data,
                                headers={"Content-Type": "application/xml",\
                                         "X-Auth-Token": self.disabled_token,
                                         "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        print resp,content
        content=etree.fromstring(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403,resp_val)
        self.assertEqual('application/xml', content_type(resp))
    
    def test_user_enabled_invalid_token_json(self):
        h = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s/enabled' % (URL,self.tenant,self.user)
        print url
        data = '{"user": { "enabled": true}}'
        resp, content = h.request(url, "PUT", body=data,
                                headers={"Content-Type": "application/json",\
                                         "X-Auth-Token": self.invalid_token})
        resp_val = int(resp['status'])
        print resp,content
        content=json.loads(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(401,resp_val)
    
    def test_user_enabled_invalid_token_xml(self):
        h = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s/enabled' % (URL,self.tenant,self.user)
        data = '<?xml version="1.0" encoding="UTF-8"?> \
                <user xmlns="http://docs.openstack.org/idm/api/v1.0" \
                enabled="true" />'
        resp, content = h.request(url, "PUT", body=data,
                                headers={"Content-Type": "application/xml",\
                                         "X-Auth-Token": self.invalid_token,
                                         "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        print resp,content
        content=etree.fromstring(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(401,resp_val)
        self.assertEqual('application/xml', content_type(resp))
    
    def test_user_enabled_missing_token_json(self):
        h = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s/enabled' % (URL,self.tenant,self.user)
        print url
        data = '{"user": { "enabled": true}}'
        resp, content = h.request(url, "PUT", body=data,
                                headers={"Content-Type": "application/json",\
                                         "X-Auth-Token": self.missing_token})
        resp_val = int(resp['status'])
        print resp,content
        content=json.loads(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(401,resp_val)
    
    def test_user_enabled_missing_token_xml(self):
        h = httplib2.Http(".cache")
        url = '%stenants/%s/users/%s/password' % (URL,self.tenant,self.user)
        data = '<?xml version="1.0" encoding="UTF-8"?> \
                <user xmlns="http://docs.openstack.org/idm/api/v1.0" \
                enabled="true" />'
        resp, content = h.request(url, "PUT", body=data,
                                headers={"Content-Type": "application/xml",\
                                         "X-Auth-Token": self.missing_token,
                                         "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        print resp,content
        content=etree.fromstring(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(401,resp_val)
        self.assertEqual('application/xml', content_type(resp))
    
    

    


#class get_user_test(user_test):

class global_group_test(unittest.TestCase):

    def setUp(self):
        self.token = get_token('joeuser', 'secrete', 'token')
        self.tenant = get_tenant()
        self.user = get_user()
        self.userdisabled = get_userdisabled()
        self.auth_token = get_auth_token()
        self.exp_auth_token = get_exp_auth_token()
        self.disabled_token = get_disabled_token()
        self.tenant_group = 'test_tenant_group'

    def tearDown(self):
        resp, content = delete_tenant_group('test_tenant_group', \
                                    self.tenant, self.auth_token)
        resp, content = delete_tenant(self.tenant, self.auth_token)



class create_global_group_test(global_group_test):

    def test_global_group_create(self):

        respG, contentG = delete_global_group('test_tenant_group', \
                        str(self.auth_token))
        respG, contentG = create_global_group(str(self.auth_token))
        self.group = 'test_tenant_group'

        if int(respG['status']) == 500:
            self.fail('IDM fault')
        elif int(respG['status']) == 503:
            self.fail('Service Not Available')
        if int(respG['status']) not in (200, 201):
            self.fail('Failed due to %d' % int(respG['status']))


    def test_global_group_create_again(self):

        respG, contentG = create_global_group('test_tenant_group', \
                         str(self.auth_token))
        respG, contentG = create_global_group('test_tenant_group', \
                        "test_tenant", str(self.auth_token))

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

class create_tenant_group_test(tenant_group_test):

    def test_tenant_group_create_forbidden_token(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant("test_tenant", str(self.auth_token))
        respG, contentG = create_tenant_group_xml('test_tenant_group', \
                        "test_tenant", str(self.auth_token))
        if int(resp['status']) == 200:
            self.tenant = content['tenant']['id']

        if int(respG['status']) == 200:
            self.tenant_group = respG['group']['id']

        url = '%stenant/%s/groups' % (URL, self.tenant)
        body = {"group": {"id": self.tenant_group,
                   "description": "A description ..."
                   }}
        resp, content = h.request(url, "POST", body=json.dumps(body),
                      headers={"Content-Type": "application/json",
                         "X-Auth-Token": self.token})

        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(resp['status']))


    def test_tenant_group_create_expired_token(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant("test_tenant", str(self.auth_token))
        if int(resp['status']) == 200:
            self.tenant = content['tenant']['id']

        url = '%stenant/%s/groups' % (URL, self.tenant)
        body = {"group": {"id": self.tenant_group,
                   "description": "A description ..."
                   }}
        resp, content = h.request(url, "POST", body=json.dumps(body),
                    headers={"Content-Type": "application/json",
                         "X-Auth-Token": self.exp_auth_token})
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, int(resp['status']))

    def test_tenant_group_create_missing_token(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant("test_tenant", str(self.auth_token))
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

    def test_tenant_group_create_disabled_token(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant("test_tenant", str(self.auth_token))
        if int(resp['status']) == 200:
            self.tenant = content['tenant']['id']

        url = '%stenant/%s/groups' % (URL, self.tenant)
        body = '{"group": { "id": "%s", \
            "description": "A description ..." } }' % self.tenant_group
        resp, content = h.request(url, "POST", body=body,\
                    headers={"Content-Type": "application/json",\
                         "X-Auth-Token": self.disabled_token})

        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(resp['status']))

    def test_tenant_group_create_invalid_token(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant("test_tenant", str(self.auth_token))
        if int(resp['status']) == 200:
            self.tenant = content['tenant']['id']

        url = '%stenant/%s/groups' % (URL, self.tenant)
        body = '{"group": { "id": "%s", \
            "description": "A description ..." } }' % self.tenant
        resp, content = h.request(url, "POST", body=body,\
                    headers={"Content-Type": "application/json",\
                         "X-Auth-Token": 'nonexsitingtoken'})

        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, int(resp['status']))



    def test_tenant_group_create_xml(self):
        resp, content = delete_tenant_xml('test_tenant', str(self.auth_token))
        resp, content = create_tenant_xml('test_tenant', str(self.auth_token))
        respG, contentG = delete_tenant_group_xml('test_tenant_group', \
                        "test_tenant", str(self.auth_token))
        respG, contentG = create_tenant_group_xml('test_tenant_group', \
                        "test_tenant", str(self.auth_token))

        print contentG
        self.tenant = 'test_tenant'
        self.tenant_group = 'test_tenant_group'
        content = etree.fromstring(content)
        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')

        if int(respG['status']) not in (200, 201):
            self.fail('Failed due to %d' % int(respG['status']))

    def test_tenant_group_create_again_xml(self):

        resp, content = create_tenant_xml("test_tenant", str(self.auth_token))

        respG, contentG = create_tenant_group_xml('test_tenant_group', \
                        "test_tenant", str(self.auth_token))
        respG, contentG = create_tenant_group_xml('test_tenant_group', \
                        "test_tenant", str(self.auth_token))

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

    def test_tenant_group_create_forbidden_token_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant("test_tenant", str(self.auth_token))
        if int(resp['status']) == 200:
            self.tenant = content['tenant']['id']

        url = '%stenant/%s/groups' % (URL, self.tenant)
        body = '<?xml version="1.0" encoding="UTF-8"?> \
        <group xmlns="http://docs.openstack.org/idm/api/v1.0" \
         id="%s"> \
        <description>A description...</description> \
        </group>' % self.tenant_group
        resp, content = h.request(url, "POST", body=body,\
                    headers={"Content-Type": "application/xml", \
                         "X-Auth-Token": self.token,
                         "ACCEPT": "application/xml"})

        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')

        self.assertEqual(403, int(resp['status']))

    def test_tenant_group_create_expired_token_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant_xml("test_tenant", str(self.auth_token))
        content = etree.fromstring(content)
        if int(resp['status']) == 200:
            self.tenant = content.get('id')

        url = '%stenant/%s/groups' % (URL, self.tenant)
        body = '<?xml version="1.0" encoding="UTF-8"?> \
        <group xmlns="http://docs.openstack.org/idm/api/v1.0" \
         id="%s"> \
        <description>A description...</description> \
        </group>' % self.tenant

        resp, content = h.request(url, "POST", body=body,\
                    headers={"Content-Type": "application/xml", \
                         "X-Auth-Token": self.exp_auth_token,
                         "ACCEPT": "application/xml"})

        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, int(resp['status']))

    def test_tenant_group_create_missing_token_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant_xml("test_tenant", str(self.auth_token))
        content = etree.fromstring(content)
        if int(resp['status']) == 200:
            self.tenant = content.get('id')

        url = '%stenant/%s/groups' % (URL, self.tenant)

        body = '<?xml version="1.0" encoding="UTF-8"?> \
        <group xmlns="http://docs.openstack.org/idm/api/v1.0" \
        id="%s"> \
        <description>A description...</description> \
        </group>' % self.tenant_group
        resp, content = h.request(url, "POST", body=body,\
                    headers={"Content-Type": "application/xml",
                         "ACCEPT": "application/xml"})

        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, int(resp['status']))

    def test_tenant_group_create_disabled_token_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant_xml("test_tenant", str(self.auth_token))
        content = etree.fromstring(content)
        if int(resp['status']) == 200:
            self.tenant = content.get('id')

        url = '%stenant/%s/groups' % (URL, self.tenant)
        body = '<?xml version="1.0" encoding="UTF-8"?> \
        <group xmlns="http://docs.openstack.org/idm/api/v1.0" \
        id="%s"> \
        <description>A description...</description> \
        </group>' % self.tenant_group
        resp, content = h.request(url, "POST", body=body,\
                    headers={"Content-Type": "application/xml",
                         "X-Auth-Token": self.disabled_token,
                         "ACCEPT": "application/xml"})

        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, int(resp['status']))

    def test_tenant_group_create_invalid_token_xml(self):
        h = httplib2.Http(".cache")
        resp, content = create_tenant_xml("test_tenant", str(self.auth_token))
        content = etree.fromstring(content)
        if int(resp['status']) == 200:
            self.tenant = content.get('id')

        url = '%stenant/%s/groups' % (URL, self.tenant)
        body = '<?xml version="1.0" encoding="UTF-8"?> \
        <group xmlns="http://docs.openstack.org/idm/api/v1.0" \
         id="%s"> \
        <description>A description...</description> \
        </group>' % self.tenant_group
        resp, content = h.request(url, "POST", body=body,\
                    headers={"Content-Type": "application/xml",\
                         "X-Auth-Token": 'nonexsitingtoken',
                         "ACCEPT": "application/xml"})

        if int(resp['status']) == 500:
            self.fail('IDM fault')
        elif int(resp['status']) == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, int(resp['status']))

if __name__ == '__main__':
    unittest.main()
