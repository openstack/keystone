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
                                   os.pardir,
                                   os.pardir))
if os.path.exists(os.path.join(POSSIBLE_TOPDIR, 'keystone', '__init__.py')):
    sys.path.insert(0, POSSIBLE_TOPDIR)

from queryext import exthandler
from keystone.common import wsgi
import keystone.logic.service as serv
import keystone.logic.types.auth as auth


service = serv.IDMService()

def is_xml_response():
    if not "Accept" in request.header:
        return False
    return request.header["Accept"] == "application/xml"


def get_normalized_request_content(model, req):
    """initialize a model from json/xml contents of request body"""

    if  req.content_type == "application/xml":
        ret = model.from_xml(req.body)
    elif req.content_type == "application/json":
        ret = model.from_json(req.body)
    else:
        raise fault.IDMFault("I don't understand the content type ", code=415)
    return ret


def send_result(code, result):
    content = None
    response.content_type = None
    if result:
        if is_xml_response():
            content = result.to_xml()
            response.content_type = "application/xml"
        else:
            content = result.to_json()
            response.content_type = "application/json"
    response.status = code
    if code > 399:
       #return bottle.abort(code, content)
       return;
    return content


class Controller(wsgi.Controller):

    def __init__(self, options):
        self.options = options

    def authenticate(self, req):
        creds = get_normalized_request_content(auth.PasswordCredentials, req)
        return send_result(200, service.authenticate(creds))


class Auth_API(wsgi.Router):
    """WSGI entry point for all Keystone Auth API requests."""

    def __init__(self, options):
        self.options = options
        mapper = routes.Mapper()
        controller = Controller(options)
        mapper.connect("/v1.0/token", controller=controller, action="authenticate")
        super(Auth_API, self).__init__(mapper)


def app_factory(global_conf, **local_conf):
    """paste.deploy app factory for creating Glance API server apps"""
    try:
        conf = global_conf.copy()
        conf.update(local_conf)
    except Exception as err:
        print err
    return Auth_API(conf)
