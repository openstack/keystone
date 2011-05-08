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


"""
Service that stores identities and issues and manages tokens

HEADERS
-------
HTTP_ is a standard http header
HTTP_X is an extended http header

> Coming in from initial call
HTTP_X_AUTH_TOKEN   : the client token being passed in
HTTP_X_STORAGE_TOKEN: the client token being passed in (legacy Rackspace use)
                      to support cloud files
> Used for communication between components
www-authenticate    : only used if this component is being used remotely
HTTP_AUTHORIZATION  : basic auth password used to validate the connection

> What we add to the request for use by the OpenStack service
HTTP_X_AUTHORIZATION: the client identity being passed in

"""
import functools
import logging
import os
import sys
import httplib
import json

import routes
from webob import Response
from webob import Request
from webob.exc import (HTTPNotFound,
                       HTTPConflict,
                       HTTPBadRequest)

POSSIBLE_TOPDIR = os.path.normpath(os.path.join(os.path.abspath(sys.argv[0]),
                                   os.pardir,os.pardir,
                                   os.pardir))
if os.path.exists(os.path.join(POSSIBLE_TOPDIR, 'keystone', '__init__.py')):
    sys.path.insert(0, POSSIBLE_TOPDIR)



from queryext import exthandler
from keystone.common import wsgi
import keystone.logic.service as serv
import keystone.logic.types.tenant as tenants
import keystone.logic.types.auth as auth
import keystone.logic.types.fault as fault
import keystone.logic.types.user as users

VERSION_STATUS = "ALPHA"
VERSION_DATE = "2011-04-23T00:00:00Z"

service = serv.IDMService()


def is_xml_response(req):
    if not "Accept" in req.headers:
        return False
    return req.content_type == "application/xml"


def get_auth_token(req):
    auth_token = None
    if "X-Auth-Token" in req.headers:
        auth_token = req.headers["X-Auth-Token"]
    return auth_token


def get_normalized_request_content(model, req):
    """initialize a model from json/xml contents of request body"""

    if  req.content_type == "application/xml":
        ret = model.from_xml(req.body)
    elif req.content_type == "application/json":
        ret = model.from_json(req.body)
    else:
        raise fault.IDMFault("I don't understand the content type ", code=415)
    return ret


def send_result(code, req, result):
    content = None
    resp = Response()
    resp.headers['Content-Type'] = None
    if result:
        if is_xml_response(req):
            content = result.to_xml()
            resp.headers['Content_Type'] = "application/xml"
        else:
            content = result.to_json()
            resp.headers['Content-Type'] = "application/json"
    resp.status = code
    if code > 399:
        #return bottle.abort(code, content)
        return
    return content

class MiscController(wsgi.Controller):

    def __init__(self, options):
        self.options = options

    def get_version_info(self, req):
        if is_xml_response(req):
            resp_file = os.path.join(POSSIBLE_TOPDIR,
                                     "keystone/content/version.xml.tpl")
        else:
            resp_file = os.path.join(POSSIBLE_TOPDIR,
                                 "keystone/content/version.json.tpl")

        hostname = req.environ.get("SERVER_NAME")
        port = req.environ.get("SERVER_PORT")
        #try:
        tmplfile=open(resp_file);
        tmplstring=tmplfile.read()

        send_result(200,req, tmplstring.format(HOST=hostname, PORT=port,
                           VERSION_STATUS=VERSION_STATUS,
                           VERSION_DATE=VERSION_DATE))


class AuthController(wsgi.Controller):

    def __init__(self, options):
        self.options = options

    def authenticate(self, req):
        creds = get_normalized_request_content(auth.PasswordCredentials, req)
        return send_result(200, req, service.authenticate(creds))

    def validate_token(self, req, token_id):
        belongs_to = None
        if "belongsTo" in req.GET:
            belongs_to = req.GET["belongsTo"]
        rval = service.validate_token(get_auth_token(req), token_id, belongs_to)
        return send_result(200, req, rval)

    def delete_token(self, req, token_id):
        return send_result(204, req, service.revoke_token(get_auth_token(req), token_id))


class TenantController(wsgi.Controller):

    def __init__(self, options):
        self.options = options

    def create_tenant(self, req):
        tenant = get_normalized_request_content(tenants.Tenant, req)
        return send_result(201, req,
                       service.create_tenant(get_auth_token(req), tenant))

    def get_tenants(self, req):
        marker = None
        if "marker" in req.GET:
            marker = req.GET["marker"]

        if "limit" in req.GET:
            limit = req.GET["limit"]
        else:
            limit = 10

        url = '%s://%s:%s%s' % (req.environ['wsgi.url_scheme'],
                            req.environ.get("SERVER_NAME"),
                            req.environ.get("SERVER_PORT"),
                            req.environ['PATH_INFO'])

        tenants = service.get_tenants(get_auth_token(req), marker, limit, url)
        return send_result(200, req, tenants)

    def get_tenant(self, req, tenant_id):
        tenant = service.get_tenant(get_auth_token(req), tenant_id)
        return send_result(200, req, tenant)

    def update_tenant(self, req, tenant_id):
        tenant = get_normalized_request_content(tenants.Tenant, req)
        rval = service.update_tenant(get_auth_token(req), tenant_id, tenant)
        return send_result(200, req, rval)

    def delete_tenant(self, req, tenant_id):
        rval = service.delete_tenant(get_auth_token(req), tenant_id)
        return send_result(204, req, rval)



    # Tenant Group Methods

    def create_tenant_group(self, req, tenant_id):
        group = get_normalized_request_content(tenants.Group, req)
        return send_result(201, req,
                       service.create_tenant_group(get_auth_token(req), \
                                                   tenant_id, group))

    def get_tenant_groups(self, req, tenant_id):
        marker = None
        if "marker" in req.GET:
            marker = req.GET["marker"]

        if "limit" in req.GET:
            limit = req.GET["limit"]
        else:
            limit = 10

        url = '%s://%s:%s%s' % (req.environ['wsgi.url_scheme'],
                             req.environ.get("SERVER_NAME"),
                             req.environ.get("SERVER_PORT"),
                             req.environ['PATH_INFO'])

        groups = service.get_tenant_groups(get_auth_token(req),
                                        tenant_id, marker, limit, url)
        return send_result(200, req, groups)

    def get_tenant_group(self, req, tenant_id,  group_id):
        tenant = service.get_tenant_group(get_auth_token(req), tenant_id,
                group_id)
        return send_result(200, req,  tenant)


    def update_tenant_group(self, req, tenant_id, group_id):
        group = get_normalized_request_content(tenants.Group, req)
        rval = service.update_tenant_group(get_auth_token(req),\
                                        tenant_id, group_id, group)
        return send_result(200, req, rval)

    def delete_tenant_group(self, req, tenant_id, group_id):
        rval = service.delete_tenant_group(get_auth_token(req), tenant_id,
                group_id)
        return send_result(204, req, rval)

    def add_user_tenant_group(self, req, tenant_id, group_id, user_id):
        # TBD
        # IDMDevguide clarification needed on this property
        return None

    def delete_user_tenant_group(self, req, tenant_id, group_id, user_id):
        # TBD
        # IDMDevguide clarification needed on this property
        return None
    def get_user_tenant_group(self, req, tenant_id, group_id, user_id):
        # TBD
        # IDMDevguide clarification needed on this property
        return None

class UserController(wsgi.Controller):

    def __init__(self, options):
        self.options = options

    def create_user(self, req, tenant_id):
        user = get_normalized_request_content(users.User, req)
        return send_result(201, req,
                       service.create_user(get_auth_token(req), tenant_id, user))

    def get_tenant_users(self, req, tenant_id):
        marker = None
        if "marker" in req.GET:
            marker = req.GET["marker"]
        if "limit" in req.GET:
            limit = req.GET["limit"]
        else:
            limit = 10
        url = '%s://%s:%s%s' % (req.environ['wsgi.url_scheme'],
                                                        req.environ.get("SERVER_NAME"),
                                                        req.environ.get("SERVER_PORT"),
                                                        req.environ['PATH_INFO'])
        users = service.get_tenant_users(get_auth_token(req), tenant_id, marker, limit, url)
        return send_result(200, req, users)

    def get_user_groups(self, req, tenant_id, user_id):
        marker = None
        if "marker" in req.GET:
            marker = req.GET["marker"]

        if "limit" in req.GET:
            limit = req.GET["limit"]
        else:
            limit = 10

        url = '%s://%s:%s%s' % (req.environ['wsgi.url_scheme'],\
                             req.environ.get("SERVER_NAME"),\
                             req.environ.get("SERVER_PORT"),\
                             req.environ['PATH_INFO'])

        groups = service.get_user_groups(get_auth_token(),\
                                        tenant_id,user_id, marker, limit,url)
        return send_result(200, groups)

    def get_user(self, req, tenant_id, user_id):
        user = service.get_user(get_auth_token(req), tenant_id, user_id)
        return send_result(200, req, user)

    def update_user(self, req, user_id, tenant_id):
        user = get_normalized_request_content(users.User_Update, req)
        rval = service.update_user(get_auth_token(req), user_id, user, tenant_id)
        return send_result(200, req, rval)

    def delete_user(self, req, user_id, tenant_id):
        rval = service.delete_user(get_auth_token(req), user_id, tenant_id)
        return send_result(204, req, rval)

    def set_user_password(self, req, user_id, tenant_id):
        user = get_normalized_request_content(users.User_Update, req)
        rval = service.set_user_password(get_auth_token(req), user_id, user, tenant_id)
        return send_result(204, req, rval)

    def set_user_enabled(self, req, user_id,tenant_id):
        rval = service.enable_disable_user(get_auth_token(req), user_id, tenant_id)
        return send_result(204, req, rval)


class Auth_API(wsgi.Router):
    """WSGI entry point for all Keystone Auth API requests."""

    def __init__(self, options):
        self.options = options
        mapper = routes.Mapper()

        # Token Operations
        auth_controller = AuthController(options)
        mapper.connect("/v1.0/token", controller=auth_controller, action="authenticate")
        mapper.connect("/v1.0/token/{token_id}", controller=auth_controller,
                        action="validate_token", conditions=dict(method=["GET"]))
        mapper.connect("/v1.0/token/{token_id}", controller=auth_controller,
                        action="delete_token", conditions=dict(method=["DELETE"]))

        # Tenant Operations
        tenant_controller = TenantController(options)
        mapper.connect("/v1.0/tenants", controller=tenant_controller,
                action="create_tenant", conditions=dict(method=["POST"]))
        mapper.connect("/v1.0/tenants", controller=tenant_controller,
                action="get_tenants", conditions=dict(method=["GET"]))
        mapper.connect("/v1.0/tenants/{tenant_id}", controller=tenant_controller,
                action="get_tenant", conditions=dict(method=["GET"]))
        mapper.connect("/v1.0/tenants/{tenant_id}", controller=tenant_controller,
                action="update_tenant", conditions=dict(method=["PUT"]))
        mapper.connect("/v1.0/tenants/{tenant_id}", controller=tenant_controller,
                action="delete_tenant", conditions=dict(method=["DELETE"]))

        # Tenant Group Operations

        mapper.connect("/v1.0/tenants/{tenant_id}/groups", controller=tenant_controller,
                action="create_tenant_group", conditions=dict(method=["POST"]))
        mapper.connect("/v1.0/tenants/{tenant_id}/groups", controller=tenant_controller,
                action="get_tenant_groups", conditions=dict(method=["GET"]))
        mapper.connect("/v1.0/tenants/{tenant_id}/groups/{group_id}", controller=tenant_controller,
                action="get_tenant_group", conditions=dict(method=["GET"]))
        mapper.connect("/v1.0/tenants/{tenant_id}/groups/{group_id}", controller=tenant_controller,
                action="update_tenant_group", conditions=dict(method=["PUT"]))
        mapper.connect("/v1.0/tenants/{tenant_id}/groups/{group_id}", controller=tenant_controller,
                action="delete_tenant_group", conditions=dict(method=["DELETE"]))

        # User Operations
        user_controller = UserController(options)
        mapper.connect("/v1.0/tenants/{tenant_id}/users", controller=user_controller,
                action="create_user", conditions=dict(method=["POST"]))
        mapper.connect("/v1.0/tenants/{tenant_id}/users", controller=user_controller,
                action="get_tenant_users", conditions=dict(method=["GET"]))
        mapper.connect("/v1.0/tenants/{tenant_id}/users/{user_id}", controller=user_controller,
                action="get_user", conditions=dict(method=["GET"]))
        mapper.connect("/v1.0/tenants/{tenant_id}/users/{user_id}", controller=user_controller,
                action="update_user", conditions=dict(method=["PUT"]))
        mapper.connect("/v1.0/tenants/{tenant_id}/users/{user_id}", controller=user_controller,
                action="delete_user", conditions=dict(method=["DELETE"]))


        # Miscellaneous Operations
        misc_controller = MiscController(options)
        mapper.connect("/v1.0/", controller=misc_controller, 
                       action="get_version_info",conditions=dict(method=["GET"]))
        mapper.connect("/v1.0", controller=misc_controller, 
                       action="get_version_info",conditions=dict(method=["GET"]))


        super(Auth_API, self).__init__(mapper)

def app_factory(global_conf, **local_conf):
    """paste.deploy app factory for creating Glance API server apps"""
    try:
        conf = global_conf.copy()
        conf.update(local_conf)
    except Exception as err:
        print err
    return Auth_API(conf)
