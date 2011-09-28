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


import os
import sys
import logging
import functools
from webob import Response
import keystone.logic.types.fault as fault


def is_xml_response(req):
    """Returns True when the request wants an XML response, False otherwise"""
    return "Accept" in req.headers and "application/xml" in req.accept


def is_json_response(req):
    """Returns True when the request wants a JSON response, False otherwise"""
    return "Accept" in req.headers and "application/json" in req.accept


def get_app_root():
    return os.path.abspath(os.path.dirname(__file__))


def get_auth_token(req):
    """Returns the auth token from request headers"""
    return req.headers.get("X-Auth-Token")


def get_auth_user(req):
    """Returns the auth user from request headers"""
    return req.headers.get("X-Auth-User")


def get_auth_key(req):
    """Returns the auth key from request headers"""
    return req.headers.get("X-Auth-Key")


def wrap_error(func):

    @functools.wraps(func)
    def check_error(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as err:
            if isinstance(err, fault.IdentityFault):
                return send_error(err.code, kwargs['req'], err)
            elif isinstance(err, fault.ItemNotFoundFault):
                return send_error(err.code, kwargs['req'], err)
            else:
                logging.exception(err)
                return send_error(500, kwargs['req'],
                                fault.IdentityFault("Unhandled error",
                                                    str(err)))
    return check_error


def get_normalized_request_content(model, req):
    """Initialize a model from json/xml contents of request body"""

    if req.content_type == "application/xml":
        return model.from_xml(req.body)
    elif req.content_type == "application/json":
        return model.from_json(req.body)
    else:
        raise fault.IdentityFault("I don't understand the content type",
                                  code=415)


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


def send_result(code, req, result=None):
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


def import_module(module_name, class_name=None):
    '''Import a class given a full module.class name or seperate
    module and options. If no class_name is given, it is assumed to
    be the last part of the module_name string.'''
    if class_name is None:
        try:
            __import__(module_name)
            return sys.modules[module_name]
        except ImportError as exc:
            module_name, _separator, class_name = module_name.rpartition('.')
            if not exc.args[0].startswith('No module named %s' % class_name):
                raise
    try:
        __import__(module_name)
        return getattr(sys.modules[module_name], class_name)
    except (ImportError, ValueError, AttributeError), exception:
        raise ImportError(_('Class %s.%s cannot be found (%s)') %
            (module_name, class_name, exception))
