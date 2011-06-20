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


import functools
import httplib
import json
import logging
import os
import routes
import sys
import hashlib
from webob import Response
from webob import Request
from webob import descriptors
from webob.exc import (HTTPNotFound,
                       HTTPConflict,
                       HTTPBadRequest)

POSSIBLE_TOPDIR = os.path.normpath(os.path.join(os.path.abspath(sys.argv[0]),
                                   os.pardir,
                                   os.pardir))
if os.path.exists(os.path.join(POSSIBLE_TOPDIR, 'keystone', '__init__.py')):
    sys.path.insert(0, POSSIBLE_TOPDIR)

from queryext import exthandler
import keystone.logic.types.fault as fault

def is_xml_response(req):
    if not "Accept" in req.headers:
        return False
    return req.content_type == "application/xml"


def get_app_root():
    return os.path.abspath(os.path.dirname(__file__))


def get_auth_token(req):
    auth_token = None
    if "X-Auth-Token" in req.headers:
        auth_token = req.headers["X-Auth-Token"]
    return auth_token


def get_auth_user(req):
    auth_user = None
    if "X-Auth-User" in req.headers:
        auth_user = req.headers["X-Auth-User"]
    return auth_user


def get_auth_key(req):
    auth_key = None
    if "X-Auth-Key" in req.headers:
        auth_key = req.headers["X-Auth-Key"]
    return auth_key


def wrap_error(func):

    @functools.wraps(func)
    def check_error(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as err:
            if isinstance(err, fault.IdentityFault):
                return send_error(err.code, kwargs['req'], err)
            else:
                logging.exception(err)
                return send_error(500, kwargs['req'],
                                fault.IdentityFault("Unhandled error",
                                                    str(err)))
    return check_error


def get_normalized_request_content(model, req):
    """Initialize a model from json/xml contents of request body"""

    if  req.content_type == "application/xml":
        ret = model.from_xml(req.body)
    elif req.content_type == "application/json":
        ret = model.from_json(req.body)
    else:
        raise fault.IdentityFault("I don't understand the content type ",
                                  code=415)
    return ret


def send_error(code, req, result):
    content = None
    resp = Response()

    resp.headers['content-type'] = None
    resp.status = code

    if result:

        if is_xml_response(req):

            content = result.to_xml()
            resp.headers['content-type'] = "application/xml"
        else:

            content = result.to_json()
            resp.headers['content-type'] = "application/json"

        resp.content_type_params = {'charset': 'UTF-8'}
        resp.unicode_body = content.decode('UTF-8')

    return resp


def send_result(code, req, result):
    content = None
    resp = Response()
    resp.headers['content-type'] = None
    resp.status = code
    if code > 399:
        return resp

    if result:

        if is_xml_response(req):
            content = result.to_xml()
            resp.headers['content-type'] = "application/xml"
        else:
            content = result.to_json()
            resp.headers['content-type'] = "application/json"

        resp.content_type_params = {'charset': 'UTF-8'}
        resp.unicode_body = content.decode('UTF-8')

    return resp


def send_legacy_result(code, headers):
    resp = Response()
    if 'content-type' not in headers:
        headers['content-type'] = "text/plain"

    resp.headers = headers
    resp.status = code
    if code > 399:
        return resp

    resp.content_type_params = {'charset': 'UTF-8'}

    return resp

#Currently using sha1 to hash.Need to figure if there is an openstack standard.Not using salt val as of now.
def get_hashed_password(password):
    if password != None and len(password) > 0:
        return hashlib.sha1(password).hexdigest()
    else:
        return None