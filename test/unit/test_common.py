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
    resp, content = h.request(url, "DELETE", body='',
                              headers={"Content-Type": "application/json",
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

    url = '%stenant/%s/groups' % (URL, tenantid)
    body = {"group": {"id": groupid,
                       "description": "A description ..."}}
    resp, content = h.request(url, "POST", body=json.dumps(body),
                              headers={"Content-Type": "application/json",
                                       "X-Auth-Token": auth_token})
    return (resp, content)


def delete_tenant(tenantid, auth_token):
    h = httplib2.Http(".cache")
    url = '%stenants/%s' % (URL, tenantid)
    resp, content = h.request(url, "DELETE", body='{}',
                              headers={"Content-Type": "application/json",
                                       "X-Auth-Token": auth_token})
    return (resp, content)


def delete_tenant_group(groupid, tenantid, auth_token):
    h = httplib2.Http(".cache")
    url = '%stenant/%s/groups/%s' % (URL, tenantid, groupid)
    resp, content = h.request(url, "DELETE", body='{}',
                              headers={"Content-Type": "application/json",
                                       "X-Auth-Token": auth_token})
    return (resp, content)


def create_global_group(groupid, auth_token):
    h = httplib2.Http(".cache")

    url = '%sgroups' % (URL)
    body = {"group": {"id": groupid,
                      "description": "A description ..."}}
    resp, content = h.request(url, "POST", body=json.dumps(body),
                              headers={"Content-Type": "application/json",
                                       "X-Auth-Token": auth_token})
    return (resp, content)


def create_global_group_xml(groupid, auth_token):
    h = httplib2.Http(".cache")
    url = '%sgroups' % (URL)
    body = '<?xml version="1.0" encoding="UTF-8"?>\
            <group xmlns="http://docs.openstack.org/idm/api/v1.0" \
            id="%s"><description>A Description of the group</description>\
                    </group>' % groupid
    resp, content = h.request(url, "POST", body=body,
                              headers={"Content-Type": "application/xml",
                                       "X-Auth-Token": auth_token,
                                       "ACCEPT": "application/xml"})
    return (resp, content)


def delete_global_group(groupid, auth_token):
    h = httplib2.Http(".cache")
    url = '%sgroups/%s' % (URL, groupid)
    resp, content = h.request(url, "DELETE", body='{}',
                              headers={"Content-Type": "application/json",
                                       "X-Auth-Token": auth_token})
    return (resp, content)


def delete_global_group_xml(groupid, auth_token):
    h = httplib2.Http(".cache")
    url = '%sgroups/%s' % (URL, groupid)
    resp, content = h.request(url, "DELETE", body='',
                              headers={"Content-Type": "application/xml",
                                       "X-Auth-Token": auth_token,
                                       "ACCEPT": "application/xml"})
    return (resp, content)


def get_token_xml(user, pswd, type=''):
        h = httplib2.Http(".cache")
        url = '%stoken' % URL
        body = '<?xml version="1.0" encoding="UTF-8"?> \
                <passwordCredentials \
                xmlns="http://docs.openstack.org/idm/api/v1.0" \
                password="%s" username="%s" \
                tenantId="77654"/> ' % (pswd, user)
        resp, content = h.request(url, "POST", body=body,
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
    resp, content = h.request(url, "DELETE", body='',
                              headers={"Content-Type": "application/xml",
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
    resp, content = h.request(url, "POST", body=body,
                              headers={"Content-Type": "application/xml",
                                       "X-Auth-Token": auth_token,
                                       "ACCEPT": "application/xml"})
    return (resp, content)


def create_tenant_group_xml(groupid, tenantid, auth_token):
    h = httplib2.Http(".cache")
    url = '%stenant/%s/groups' % (URL, tenantid)
    body = '<?xml version="1.0" encoding="UTF-8"?> \
            <group xmlns="http://docs.openstack.org/idm/api/v1.0" \
             id="%s"> \
            <description>A description...</description> \
            </group>' % groupid
    resp, content = h.request(url, "POST", body=body,
                              headers={"Content-Type": "application/xml",
                                       "X-Auth-Token": auth_token,
                                       "ACCEPT": "application/xml"})
    return (resp, content)


def delete_tenant_xml(tenantid, auth_token):
    h = httplib2.Http(".cache")
    url = '%stenants/%s' % (URL, tenantid)
    resp, content = h.request(url, "DELETE", body='',
                              headers={"Content-Type": "application/xml",
                                       "X-Auth-Token": auth_token,
                                       "ACCEPT": "application/xml"})
    return (resp, content)


def delete_tenant_group_xml(groupid, tenantid, auth_token):
    h = httplib2.Http(".cache")
    url = '%stenant/%s/groups/%s' % (URL, tenantid, groupid)
    resp, content = h.request(url, "DELETE", body='',
                              headers={"Content-Type": "application/xml",
                                       "X-Auth-Token": auth_token,
                                       "ACCEPT": "application/xml"})
    return (resp, content)


def create_user(tenantid, userid, auth_token):
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


def create_user_xml(tenantid, userid, auth_token):
    h = httplib2.Http(".cache")
    url = '%stenants/%s/users' % (URL, tenantid)
    body = '<?xml version="1.0" encoding="UTF-8"?> \
            <user xmlns="http://docs.openstack.org/idm/api/v1.0" \
            email="joetest@rackspace.com" \
            tenantId="%s" id="%s" \
            enabled="true" password="secrete"/>' % (tenantid, userid)
    resp, content = h.request(url, "POST", body=body,
                              headers={"Content-Type": "application/xml",
                                       "X-Auth-Token": auth_token,
                                       "ACCEPT": "application/xml"})
    return (resp, content)


def delete_user(tenant, userid, auth_token):
    h = httplib2.Http(".cache")
    url = '%stenants/%s/users/%s' % (URL, tenant, userid)

    resp, content = h.request(url, "DELETE", body='{}',
                              headers={"Content-Type": "application/json",
                                       "X-Auth-Token": auth_token})
    return resp


def delete_user_xml(tenantid, userid, auth_token):
    h = httplib2.Http(".cache")
    url = '%stenants/%s/users/%s' % (URL, tenantid, userid)
    resp, content = h.request(url, "DELETE", body='',
                              headers={"Content-Type": "application/xml",
                                       "X-Auth-Token": auth_token,
                                       "ACCEPT": "application/xml"})
    return resp


def user_update_json(tenant_id, user_id, auth_token, email=None):
    h = httplib2.Http(".cache")
    url = '%stenants/%s/users/%s' % (URL, tenant_id, user_id)
    if email is None:
        new_email = "updatedjoeuser@rackspace.com"
    else:
        new_email = email
    data = '{"user": { "email": "%s"}}' % (new_email)
    resp, content = h.request(url, "PUT", body=data,
                              headers={"Content-Type": "application/json",
                                       "X-Auth-Token": auth_token})
    return (resp, content)


def user_update_xml(tenant_id, user_id, auth_token, email=None):
    h = httplib2.Http(".cache")
    url = '%stenants/%s/users/%s' % (URL, tenant_id, user_id)
    if email is None:
        new_email = "updatedjoeuser@rackspace.com"
    else:
        new_email = email
    data = '<?xml version="1.0" encoding="UTF-8"?> \
            <user xmlns="http://docs.openstack.org/idm/api/v1.0" \
            email="%s" />' % (new_email)
    resp, content = h.request(url, "PUT", body=data,
                              headers={"Content-Type": "application/xml",
                                       "X-Auth-Token": auth_token,
                                       "ACCEPT": "application/xml"})
    return (resp, content)


def user_get_json(tenant_id, user_id, auth_token):
    h = httplib2.Http(".cache")
    url = '%stenants/%s/users/%s' % (URL, tenant_id, user_id)
    #test for Content-Type = application/json
    resp, content = h.request(url, "GET", body='{}',
                              headers={"Content-Type": "application/json",
                                       "X-Auth-Token": auth_token})
    return (resp, content)


def user_password_json(tenant_id, user_id, auth_token):
    h = httplib2.Http(".cache")
    url = '%stenants/%s/users/%s/password' % (URL, tenant_id, user_id)
    data = '{"user": { "password": "p@ssword"}}'
    resp, content = h.request(url, "PUT", body=data,
                              headers={"Content-Type": "application/json",
                                       "X-Auth-Token": auth_token})
    return (resp, content)


def user_password_xml(tenant_id, user_id, auth_token):
    h = httplib2.Http(".cache")
    url = '%stenants/%s/users/%s/password' % (URL, tenant_id, user_id)
    data = '<?xml version="1.0" encoding="UTF-8"?> \
            <user xmlns="http://docs.openstack.org/idm/api/v1.0" \
            password="p@ssword" />'
    resp, content = h.request(url, "PUT", body=data,
                              headers={"Content-Type": "application/xml",
                                       "X-Auth-Token": auth_token,
                                       "ACCEPT": "application/xml"})
    return (resp, content)


def user_enabled_json(tenant_id, user_id, auth_token):
    h = httplib2.Http(".cache")
    url = '%stenants/%s/users/%s/enabled' % (URL, tenant_id, user_id)
    data = {"user": {"enabled": True}}
    resp, content = h.request(url, "PUT", body=json.dumps(data),
                              headers={"Content-Type": "application/json",
                                       "X-Auth-Token": auth_token})
    return (resp, content)


def user_enabled_xml(tenant_id, user_id, auth_token):
    h = httplib2.Http(".cache")
    url = '%stenants/%s/users/%s/enabled' % (URL, tenant_id, user_id)
    data = '<?xml version="1.0" encoding="UTF-8"?> \
            <user xmlns="http://docs.openstack.org/idm/api/v1.0" \
            enabled="true" />'
    resp, content = h.request(url, "PUT", body=data,
                              headers={"Content-Type": "application/xml",
                                       "X-Auth-Token": auth_token,
                                       "ACCEPT": "application/xml"})
    return (resp, content)


def user_get_xml(tenant_id, user_id, auth_token):
    h = httplib2.Http(".cache")
    url = '%stenants/%s/users/%s' % (URL, tenant_id, user_id)
    resp, content = h.request(url, "GET", body='{}',
                              headers={"Content-Type": "application/xml",
                                       "X-Auth-Token": auth_token,
                                       "ACCEPT": "application/xml"})
    return (resp, content)


def users_get_json(tenant_id, auth_token):
    h = httplib2.Http(".cache")
    url = '%stenants/%s/users' % (URL, tenant_id)
    resp, content = h.request(url, "GET", body='{}',
                              headers={"Content-Type": "application/json",
                                       "X-Auth-Token": auth_token})
    return (resp, content)


def users_get_xml(tenant_id, auth_token):
    h = httplib2.Http(".cache")
    url = '%stenants/%s/users' % (URL, tenant_id)
    resp, content = h.request(url, "GET", body='{}',
                              headers={"Content-Type": "application/xml",
                                       "X-Auth-Token": auth_token,
                                       "ACCEPT": "application/xml"})
    return (resp, content)


def users_group_get_json(tenant_id, user_id, auth_token):
    h = httplib2.Http(".cache")
    url = '%stenants/%s/users/%s/groups' % (URL, tenant_id, user_id)
    resp, content = h.request(url, "GET", body='{}',
                              headers={"Content-Type": "application/json",
                                       "X-Auth-Token": auth_token})
    return (resp, content)


def users_group_get_xml(tenant_id, user_id, auth_token):
    h = httplib2.Http(".cache")
    url = '%stenants/%s/users/%s/groups' % (URL, tenant_id, user_id)
    resp, content = h.request(url, "GET", body='{}',
                              headers={"Content-Type": "application/xml",
                                       "X-Auth-Token": auth_token,
                                       "ACCEPT": "application/xml"})
    return (resp, content)


def add_user_tenant_group(tenantid, groupid, userid, auth_token):
    h = httplib2.Http(".cache")
    url = '%stenants/%s/groups/%s/users/%s' % (URL, tenantid, groupid, userid)

    resp, content = h.request(url, "PUT", body='',
                              headers={"Content-Type": "application/json",
                                       "X-Auth-Token": auth_token})
    return (resp, content)


def add_user_tenant_group_xml(tenantid, groupid, userid, auth_token):
    h = httplib2.Http(".cache")
    url = '%stenants/%s/groups/%s/users/%s' % (URL, tenantid, groupid, userid)

    resp, content = h.request(url, "PUT", body='',
                              headers={"Content-Type": "application/xml",
                                       "X-Auth-Token": auth_token,
                                       "ACCEPT": "application/xml"})
    return (resp, content)


def delete_user_tenant_group(tenantid, groupid, userid, auth_token):
    h = httplib2.Http(".cache")
    url = '%stenants/%s/groups/%s/users/%s' % (URL, tenantid, groupid, userid)

    resp, content = h.request(url, "DELETE", body='',
                              headers={"Content-Type": "application/json",
                                       "X-Auth-Token": auth_token})
    return (resp, content)


def delete_user_tenant_group_xml(tenantid, groupid, userid, auth_token):
    h = httplib2.Http(".cache")
    url = '%stenants/%s/groups/%s/users/%s' % (URL, tenantid, groupid, userid)

    resp, content = h.request(url, "DELETE", body='',
                              headers={"Content-Type": "application/xml",
                                       "X-Auth-Token": auth_token,
                                       "ACCEPT": "application/xml"})
    return (resp, content)


def get_user_tenant_group(tenantid, groupid, auth_token):
    h = httplib2.Http(".cache")
    url = '%stenants/%s/groups/%s/users' % (URL, tenantid, groupid)

    resp, content = h.request(url, "GET", body='',
                              headers={"Content-Type": "application/json",
                                       "X-Auth-Token": auth_token})
    return (resp, content)


def get_user_tenant_group_xml(tenantid, groupid, auth_token):
    h = httplib2.Http(".cache")
    url = '%stenants/%s/groups/%s/users' % (URL, tenantid, groupid)

    resp, content = h.request(url, "GET", body='',
                              headers={"Content-Type": "application/xml",
                                       "X-Auth-Token": auth_token,
                                       "ACCEPT": "application/xml"})
    return (resp, content)


def add_user_global_group(groupid, userid, auth_token):
    h = httplib2.Http(".cache")
    url = '%sgroups/%s/users/%s' % (URL, groupid, userid)

    resp, content = h.request(url, "PUT", body='',
                              headers={"Content-Type": "application/json",
                                       "X-Auth-Token": auth_token})
    return (resp, content)


def add_user_global_group_xml(groupid, userid, auth_token):
    h = httplib2.Http(".cache")
    url = '%sgroups/%s/users/%s' % (URL, groupid, userid)

    resp, content = h.request(url, "PUT", body='',
                              headers={"Content-Type": "application/xml",
                                       "X-Auth-Token": auth_token,
                                       "ACCEPT": "application/xml"})
    return (resp, content)


def delete_user_global_group(groupid, userid, auth_token):
    h = httplib2.Http(".cache")
    url = '%sgroups/%s/users/%s' % (URL, groupid, userid)

    resp, content = h.request(url, "DELETE", body='',
                              headers={"Content-Type": "application/json",
                                       "X-Auth-Token": auth_token})
    return (resp, content)


def delete_user_global_group_xml(groupid, userid, auth_token):
    h = httplib2.Http(".cache")
    url = '%sgroups/%s/users/%s' % (URL, groupid, userid)

    resp, content = h.request(url, "DELETE", body='',
                              headers={"Content-Type": "application/xml",
                                       "X-Auth-Token": auth_token,
                                       "ACCEPT": "application/xml"})
    return (resp, content)


def get_user_global_group(groupid, auth_token):
    h = httplib2.Http(".cache")
    url = '%sgroups/%s/users' % (URL, groupid)

    resp, content = h.request(url, "GET", body='',
                              headers={"Content-Type": "application/json",
                                       "X-Auth-Token": auth_token})

    return (resp, content)


def get_userid():
    return 'test_user11'


def get_password():
    return 'secrete'


def get_email():
    return 'joetest@rackspace.com'


def get_user_global_group_xml(groupid, auth_token):
    h = httplib2.Http(".cache")
    url = '%sgroups/%s/users' % (URL, groupid)

    resp, content = h.request(url, "GET", body='',
                              headers={"Content-Type": "application/xml",
                                       "X-Auth-Token": auth_token,
                                       "ACCEPT": "application/xml"})
    return (resp, content)


def get_tenant():
    return '1234'


def get_user():
    return 'test_user'


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


def content_type(resp):
    return resp['content-type'].split(';')[0]


def get_global_tenant():
    return 'GlobalTenant'


def handle_user_resp(self, content, respvalue, resptype):
    if respvalue == 200:
        if resptype == 'application/json':
            content = json.loads(content)
            self.tenant = content['user']['tenantId']
            self.userid = content['user']['id']
        if resptype == 'application/xml':
            content = etree.fromstring(content)
            self.tenant = content.get("tenantId")
            self.id = content.get("id")
    if respvalue == 500:
        self.fail('IDM fault')
    elif respvalue == 503:
        self.fail('Service Not Available')


def content_type(resp):
    return resp['content-type'].split(';')[0]
