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

# pylint: disable=W1201

import functools
import json
import logging
from lxml import etree
import os
import sys
import tempfile
from webob import Response

from keystone import config
import keystone.logic.types.fault as fault

logger = logging.getLogger(__name__)  # pylint: disable=C0103

CONF = config.CONF


def is_xml_response(req):
    """Returns True when the request wants an XML response, False otherwise"""
    return "Accept" in req.headers and "application/xml" in req.accept


def is_json_response(req):
    """Returns True when the request wants a JSON response, False otherwise"""
    return "Accept" in req.headers and "application/json" in req.accept


def is_atom_response(req):
    """Returns True when the request wants an ATOM response, False otherwise"""
    return "Accept" in req.headers and "application/atom+xml" in req.accept


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

    # pylint: disable=W0703
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
        logging.debug("Unsupported content-type passed: %s" % req.content_type)
        raise fault.IdentityFault("I don't understand the content type",
                                  code=415)


# pylint: disable=R0912
def detect_credential_type(req):
    """Return the credential type name by detecting them in json/xml body"""

    if req.content_type == "application/xml":
        dom = etree.Element("root")
        dom.append(etree.fromstring(req.body))
        root = dom.find("{http://docs.openstack.org/identity/api/v2.0}"
                        "auth")
        if root is None:
            # Try legacy without wrapper
            creds = dom.find("*")
            if creds:
                logger.warning("Received old syntax credentials not wrapped in"
                               "'auth'")
        else:
            creds = root.find("*")

        if creds is None:
            raise fault.BadRequestFault("Request is missing credentials")

        name = creds.tag
        if "}" in name:
            #trim away namespace if it is there
            name = name[name.rfind("}") + 1:]

        return name
    elif req.content_type == "application/json":
        obj = json.loads(req.body)
        if len(obj) == 0:
            raise fault.BadRequestFault("Expecting 'auth'")
        tag = obj.keys()[0]
        if tag == "auth":
            if len(obj[tag]) == 0:
                raise fault.BadRequestFault("Expecting Credentials")
            for key, value in obj[tag].iteritems():  # pylint: disable=W0612
                if key not in ['tenantId', 'tenantName']:
                    return key
            raise fault.BadRequestFault("Credentials missing from request")
        else:
            credentials_type = tag
        return credentials_type
    else:
        logging.debug("Unsupported content-type passed: %s" % req.content_type)
        raise fault.IdentityFault("I don't understand the content type",
                                  code=415)


def send_error(code, req, result):
    content = None

    resp = Response()
    resp.headers['content-type'] = None
    resp.headers['Vary'] = 'X-Auth-Token'
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
    resp.headers['Vary'] = 'X-Auth-Token'
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
    resp.headers['Vary'] = 'X-Auth-Token'

    headers['Vary'] = 'X-Auth-Token'

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
            if module_name not in sys.modules:
                __import__(module_name)
            return sys.modules[module_name]
        except ImportError as exc:
            logging.exception(exc)
            module_name, _separator, class_name = module_name.rpartition('.')
            if not exc.args[0].startswith('No module named %s' % class_name):
                raise
    try:
        if module_name not in sys.modules:
            __import__(module_name)
        return getattr(sys.modules[module_name], class_name)
    except (ImportError, ValueError, AttributeError), exception:
        logging.exception(exception)
        raise ImportError(_('Class %s.%s cannot be found (%s)') %
            (module_name, class_name, exception))


def check_empty_string(value, message):
    """
    Checks whether a string is empty and raises
    fault for empty string.
    """
    if is_empty_string(value):
        raise fault.BadRequestFault(message)


def is_empty_string(value):
    """
    Checks whether string is empty.
    """
    if value is None:
        return True
    if not isinstance(value, basestring):
        return False
    if len(value.strip()) == 0:
        return True
    return False


def write_temp_file(txt):
    """
    Writes the supplied text to a temporary file and returns the file path.

    When the file is no longer needed, it is up to the calling program to
    delete it.
    """
    fd, tmpname = tempfile.mkstemp()
    os.close(fd)
    with file(tmpname, "w") as fconf:
        fconf.write(txt)
    return tmpname


def opt_to_conf(options, create_temp=False):
    """
    Takes a dict of options and either returns a string that represents the
    equivalent CONF configuration file (when create_temp is False), or writes
    the temp file and returns the name of that temp file. NOTE: it is up to
    the calling program to delete the temp file when it is no longer needed.
    """
    def parse_opt(options, section=None):
        out = []
        subsections = []
        if section is None:
            section = "DEFAULT"
        # Create the section header
        out.append("[%s]" % section)
        for key, val in options.iteritems():
            if isinstance(val, dict):
                # This is a subsection; parse recursively.
                subsections.append(parse_opt(val, section=key))
            else:
                out.append("%s = %s" % (key.replace("-", "_"), val))

        # Add the subsections
        for subsection in subsections:
            out.append("")
            out.append(subsection)
        return "\n".join(out)

    txt = parse_opt(options)
    if create_temp:
        return write_temp_file(txt)
    else:
        return txt


def set_configuration(options):
    """ Given a dict of options, populates the config.CONF module to match."""
    _config_file = opt_to_conf(options, create_temp=True)
    CONF(config_files=[_config_file])
    os.remove(_config_file)
