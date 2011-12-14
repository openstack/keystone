#!/usr/bin/env python
# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
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

"""
D5 API Compatibility Module

This WSGI component adds support for the D5 API contract. That contract was
an unofficial contract that made it into live deployments in the wild, so
this middleware is an attempt to support production deployemnts of that
code and allow them to interoperate with Keystone trunk while gradually moving
to updated Keystone code.

The middleware transforms responses in this way:
- POST /tokens that come in D5 format (not wrapped in "auth":{}) will receive
  a D5 formatted response (wrapped in "auth":{} instead of "access":{})
- GET /tokens/{id} will respond with both an "auth" and an "access" wrapper
  (since we can't tell if the caller is expecting a D5 or Diablo final
  response)

Notes:
- GET /tokens will not repond in D5 syntax in XML (because only one root
  can exist in XML and I chose not to break Diablo)
- This relies on the URL normalizer (middlewre/url.py) to set
  KEYSTONE_API_VERSION. Without that set to '2.0', this middleware does
  nothing
"""

import copy
import json
from lxml import etree
import os
import sys

from webob.exc import Request

POSSIBLE_TOPDIR = os.path.normpath(os.path.join(os.path.abspath(sys.argv[0]),
                                   os.pardir,
                                   os.pardir,
                                   os.pardir))
if os.path.exists(os.path.join(POSSIBLE_TOPDIR, 'keystone', '__init__.py')):
    sys.path.insert(0, POSSIBLE_TOPDIR)

from keystone.logic.types import fault
import keystone.utils as utils

PROTOCOL_NAME = "D5 API Compatibility"


class D5AuthBase(object):
    """ Handles validating json and XML syntax of auth requests """

    def __init__(self, tenant_id=None, tenant_name=None):
        self.tenant_id = tenant_id
        self.tenant_name = tenant_name

    @staticmethod
    def _validate_auth(obj, *valid_keys):
        root = obj.keys()[0]

        for key in root:
            if not key in valid_keys:
                raise fault.BadRequestFault('Invalid attribute(s): %s' % key)

        if root.get('tenantId') and root.get('tenantName'):
            raise fault.BadRequestFault(
                'Expecting either Tenant ID or Tenant Name, but not both')

        return root

    @staticmethod
    def _validate_key(obj, key, required_keys, optional_keys):
        if not key in obj:
            raise fault.BadRequestFault('Expecting %s' % key)

        ret = obj[key]

        for skey in ret:
            if not skey in required_keys and not skey in optional_keys:
                raise fault.BadRequestFault('Invalid attribute(s): %s' % skey)

        for required_key in required_keys:
            if not ret.get(required_key):
                raise fault.BadRequestFault('Expecting %s:%s' %
                                            (key, required_key))
        return ret


class D5AuthWithPasswordCredentials(D5AuthBase):
    def __init__(self, username, password, tenant_id=None, tenant_name=None):
        super(D5AuthWithPasswordCredentials, self).__init__(tenant_id,
                                                          tenant_name)
        self.username = username
        self.password = password

    @staticmethod
    def from_xml(xml_str):
        try:
            dom = etree.Element("root")
            dom.append(etree.fromstring(xml_str))
            password_credentials = \
                dom.find("{http://docs.openstack.org/identity/api/v2.0}"
                "passwordCredentials")
            if password_credentials is None:
                raise fault.BadRequestFault("Expecting passwordCredentials")
            tenant_id = password_credentials.get("tenantId")
            tenant_name = password_credentials.get("tenantName")
            username = password_credentials.get("username")
            utils.check_empty_string(username, "Expecting a username")
            password = password_credentials.get("password")
            utils.check_empty_string(password, "Expecting a password")

            if tenant_id and tenant_name:
                raise fault.BadRequestFault(
                    "Expecting either Tenant ID or Tenant Name, but not both")

            return D5AuthWithPasswordCredentials(username, password,
                                                  tenant_id, tenant_name)
        except etree.LxmlError as e:
            raise fault.BadRequestFault("Cannot parse passwordCredentials",
                                        str(e))

    @staticmethod
    def from_json(json_str):
        try:
            obj = json.loads(json_str)

            cred = D5AuthBase._validate_key(obj, 'passwordCredentials',
                                    required_keys=['username', 'password'],
                                    optional_keys=['tenantId', 'tenantName'])

            return D5AuthWithPasswordCredentials(cred['username'],
                                               cred['password'],
                                               cred.get('tenantId'),
                                               cred.get('tenantName'))
        except (ValueError, TypeError) as e:
            raise fault.BadRequestFault("Cannot parse passwordCredentials",
                                        str(e))

    def to_json(self):
        """ Format the response in Diablo/Stable contract format """
        data = {"auth": {"passwordCredentials": {
            "username": self.username,
            "password": self.password}}}
        if self.tenant_id:
            data["auth"]["tenantId"] = self.tenant_id
        else:
            if self.tenant_name:
                data["auth"]["tenant_name"] = self.tenant_name
        return json.dumps(data)

    def to_xml(self):
        """ Format the response in Diablo/Stable contract format """
        dom = etree.Element("auth",
            xmlns="http://docs.openstack.org/identity/api/v2.0")

        password_credentials = etree.Element("passwordCredentials",
            username=self.username,
            password=self.password)

        if self.tenant_id:
            dom.set("tenantId", self.tenant_id)
        else:
            if self.tenant_name:
                dom.set("tenant_name", self.tenant_name)

        dom.append(password_credentials)

        return etree.tostring(dom)


class D5toDiabloAuthData(object):
    """Authentation Information returned upon successful login.

        This class handles rendering to JSON and XML. It renders
        the token, the user data, the roles, and the service catalog.
    """
    xml = None
    json = None

    def __init__(self, init_json=None, init_xml=None):
        if init_json:
            self.json = init_json
        if init_xml is not None:
            self.xml = init_xml

    @staticmethod
    def from_xml(xml_str):
        """ Verify Diablo syntax and return class initialized with data"""
        try:
            dom = etree.Element("root")
            dom.append(etree.fromstring(xml_str))
            root = \
                dom.find("{http://docs.openstack.org/identity/api/v2.0}"
                "access")
            if root is None:
                raise fault.BadRequestFault("Expecting access")
            return D5toDiabloAuthData(init_xml=root)
        except etree.LxmlError as e:
            raise fault.BadRequestFault("Cannot parse Diablo response",
                                        str(e))

    @staticmethod
    def from_json(json_str):
        """ Verify Diablo syntax and return class initialized with data"""
        try:
            obj = json.loads(json_str)
            auth = obj["access"]
            return D5toDiabloAuthData(init_json=auth)
        except (ValueError, TypeError) as e:
            raise fault.BadRequestFault("Cannot parse auth response",
                                        str(e))

    def to_xml(self):
        """ Convert to D5 syntax from Diablo"""
        if self.xml is None:
            if self.json is None:
                raise NotImplementedError
            else:
                raise fault.IdentityFault("%s not initialized with data" % \
                                          self.__class__.__str__)
        dom = etree.Element("auth",
            xmlns="http://docs.openstack.org/identity/api/v2.0")
        for element in self.xml:
            dom.append(element)
        return etree.tostring(dom)

    def to_json(self):
        """ Convert to D5 syntax from Diablo"""
        if self.json is None:
            if self.xml is None:
                raise NotImplementedError
            else:
                raise fault.IdentityFault("%s not initialized with data" % \
                                          self.__class__.__str__)
        d5_data = {"auth": {}}
        for key, value in self.json.iteritems():
            d5_data["auth"][key] = value

        return json.dumps(d5_data)


class D5ValidateData(object):
    """Authentation Information returned upon successful token validation."""
    xml = None
    json = None

    def __init__(self, init_json=None, init_xml=None):
        if init_json:
            self.json = init_json
        if init_xml is not None:
            self.xml = init_xml

    @staticmethod
    def from_xml(xml_str):
        """ Verify Diablo syntax and return class initialized with data"""
        try:
            dom = etree.Element("root")
            dom.append(etree.fromstring(xml_str))
            root = \
                dom.find("{http://docs.openstack.org/identity/api/v2.0}"
                "access")
            if root is None:
                raise fault.BadRequestFault("Expecting access")
            return D5ValidateData(init_xml=root)
        except etree.LxmlError as e:
            raise fault.BadRequestFault("Cannot parse Diablo response",
                                        str(e))

    @staticmethod
    def from_json(json_str):
        """ Verify Diablo syntax and return class initialized with data"""
        try:
            obj = json.loads(json_str)
            return D5ValidateData(init_json=obj)
        except (ValueError, TypeError) as e:
            raise fault.BadRequestFault("Cannot parse auth response",
                                        str(e))

    def to_xml(self):
        """ Returns only Diablo syntax (can only have one root in XML)

        This middleware is designed to provide D5 compatibility but NOT
        at the expense of breaking the Diablo contract."""
        if self.xml is None:
            if self.json is None:
                raise NotImplementedError
            else:
                raise fault.IdentityFault("%s not initialized with data" % \
                                          self.__class__.__str__)
        return etree.tostring(self.xml)

    def to_json(self):
        """ Returns both Diablo and D5 syntax ("access" and "auth")"""
        if self.json is None:
            if self.xml is None:
                raise NotImplementedError
            else:
                raise fault.IdentityFault("%s not initialized with data" % \
                                          self.__class__.__str__)
        d5_data = self.json.copy()
        auth = {}
        for key, value in self.json["access"].iteritems():
            auth[key] = copy.copy(value)
        if "user" in auth:
            # D5 returns 'username' only
            user = auth["user"]
            user["username"] = user["name"]
            del user["name"]
            del user["id"]

            # D5 has 'tenantId' under token
            token = auth["token"]
            if 'tenant' in token:
                tenant = token["tenant"]
                token["tenantId"] = tenant["id"]

            if "roles" in auth["user"]:
                auth["user"]["roleRefs"] = []
                rolerefs = auth["user"]["roleRefs"]
                for role in auth["user"]["roles"]:
                    ref = {}
                    ref["id"] = role["id"]
                    ref["roleId"] = role["name"]
                    if "tenantId" in role:
                        ref["tenantId"] = role["tenantId"]
                    rolerefs.append(ref)
                del auth["user"]["roles"]
        d5_data["auth"] = auth

        return json.dumps(d5_data)


class D5AuthProtocol(object):
    """D5 Cmpatibility Middleware that transforms client calls and responses"""

    def __init__(self, app, conf):
        """ Common initialization code """
        print "Starting the %s component" % PROTOCOL_NAME
        self.conf = conf
        self.app = app

    def __call__(self, env, start_response):
        """ Handle incoming request. Transform. And send downstream. """
        request = Request(env)
        if 'KEYSTONE_API_VERSION' in env and \
                                    env['KEYSTONE_API_VERSION'] == '2.0':
            if request.path.startswith("/tokens"):
                is_d5_request = False
                if request.method == "POST":
                    try:
                        auth_with_credentials = \
                            utils.get_normalized_request_content(
                            D5AuthWithPasswordCredentials, request)
                        # Convert request body to Diablo syntax
                        if request.content_type == "application/xml":
                            request.body = auth_with_credentials.to_xml()
                        else:
                            request.body = auth_with_credentials.to_json()
                        is_d5_request = True
                    except:
                        pass

                    if is_d5_request:
                        response = request.get_response(self.app)
                        #Handle failures.
                        if not str(response.status).startswith('20'):
                            return response(env, start_response)
                        auth_data = utils.get_normalized_request_content(
                            D5toDiabloAuthData, response)
                        resp = utils.send_result(response.status_int, request,
                                                 auth_data)
                        return resp(env, start_response)
                    else:
                        # Pass through
                        return self.app(env, start_response)

                elif request.method == "GET":
                    if request.path.endswith("/endpoints"):
                        # Pass through
                        return self.app(env, start_response)
                    else:
                        response = request.get_response(self.app)
                        #Handle failures.
                        if not str(response.status).startswith('20'):
                            return response(env, start_response)
                        validate_data = utils.get_normalized_request_content(
                            D5ValidateData, response)
                        resp = utils.send_result(response.status_int, request,
                                                 validate_data)
                        return resp(env, start_response)

        # All other calls pass to downstream WSGI component
        return self.app(env, start_response)


def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def auth_filter(wsgiapp):
        """Closure to return"""
        return D5AuthProtocol(wsgiapp, conf)
    return auth_filter
