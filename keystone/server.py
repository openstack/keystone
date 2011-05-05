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
# Not yet PEP8


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
import eventlet
from eventlet import wsgi

import bottle
from bottle import request
from bottle import response
from queryext import exthandler

# If ../keystone/__init__.py exists, add ../ to Python search path, so that
# it will override what happens to be installed in /usr/(local/)lib/python...
POSSIBLE_TOPDIR = os.path.normpath(os.path.join(os.path.abspath(sys.argv[0]),
                                   os.pardir,
                                   os.pardir))
if os.path.exists(os.path.join(POSSIBLE_TOPDIR, 'keystone', '__init__.py')):
    sys.path.insert(0, POSSIBLE_TOPDIR)
print POSSIBLE_TOPDIR

import keystone.logic.service as serv
import keystone.logic.types.auth as auth
import keystone.logic.types.tenant as tenants
import keystone.logic.types.fault as fault

VERSION_STATUS = "ALPHA"
VERSION_DATE = "2011-04-23T00:00:00Z"

bottle.debug(True)

service = serv.IDMService()

##
## Override error pages
##


@bottle.error(400)
@bottle.error(401)
@bottle.error(403)
@bottle.error(404)
@bottle.error(409)
@bottle.error(415)
@bottle.error(500)
@bottle.error(503)
def error_handler(err):
    return err.output


def is_xml_response():
    if not "Accept" in request.header:
        return False
    return request.header["Accept"] == "application/xml"


def get_app_root():
    return os.path.abspath(os.path.dirname(__file__))


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
        return bottle.abort(code, content)
    return content


def get_normalized_request_content(model):
    """initialize a model from json/xml contents of request body"""

    ctype = request.environ.get("CONTENT_TYPE")
    if ctype == "application/xml":
        ret = model.from_xml(request.body.read())
    elif ctype == "application/json":
        ret = model.from_json(request.body.read())
    else:
        raise fault.IDMFault("I don't understand the content type ", code=415)
    return ret


def get_auth_token():
    auth_token = None
    if "X-Auth-Token" in request.header:
        auth_token = request.header["X-Auth-Token"]
    return auth_token


def wrap_error(func):
    @functools.wraps(func)
    def check_error(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as err:
            if isinstance(err, fault.IDMFault):
                send_result(err.code, err)
            else:
                logging.exception(err)
                send_result(500, fault.IDMFault("Unhandled error", str(err)))
    return check_error


@bottle.route('/v1.0', method='GET')
@bottle.route('/v1.0/', method='GET')
@wrap_error
def get_version_info():
    if is_xml_response():
        resp_file = os.path.join(POSSIBLE_TOPDIR, "keystone/content/version.xml.tpl")
        response.content_type = "application/xml"
    else:
        resp_file = os.path.join(POSSIBLE_TOPDIR, "keystone/content/version.json.tpl")
        response.content_type = "application/json"
    hostname = request.environ.get("SERVER_NAME")
    port = request.environ.get("SERVER_PORT")
    return bottle.template(resp_file, HOST=hostname, PORT=port,
                           VERSION_STATUS=VERSION_STATUS,
                           VERSION_DATE=VERSION_DATE)

##
## Version links:
##


@bottle.route('/v1.0/idmdevguide.pdf', method='GET')
@wrap_error
def get_pdf_contract():
    return bottle.static_file("content/idmdevguide.pdf",
                              root=get_app_root(),
                              mimetype="application/pdf")


@bottle.route('/v1.0/identity.wadl', method='GET')
@wrap_error
def get_wadl_contract():
    return bottle.static_file("identity.wadl",
                              root=get_app_root(),
                              mimetype="application/vnd.sun.wadl+xml")


@bottle.route('/v1.0/xsd/:xsd', method='GET')
@wrap_error
def get_xsd_contract(xsd):
    return bottle.static_file("/xsd/" + xsd,
                              root=get_app_root(),
                              mimetype="application/xml")


@bottle.route('/v1.0/xsd/atom/:xsd', method='GET')
@wrap_error
def get_xsd_atom_contract(xsd):
    return bottle.static_file("/xsd/atom/" + xsd,
                              root=get_app_root(),
                              mimetype="application/xml")

##
##  Token Operations
##


@bottle.route('/v1.0/token', method='POST')
@wrap_error
def authenticate():
    creds = get_normalized_request_content(auth.PasswordCredentials)
    return send_result(200, service.authenticate(creds))


@bottle.route('/v1.0/token/:token_id', method='GET')
@wrap_error
def validate_token(token_id):
    belongs_to = None
    if "belongsTo" in request.GET:
        belongs_to = request.GET["belongsTo"]
    rval = service.validate_token(get_auth_token(), token_id, belongs_to)
    return send_result(200, rval)


@bottle.route('/v1.0/token/:token_id', method='DELETE')
@wrap_error
def delete_token(token_id):
    return send_result(204,
                       service.revoke_token(get_auth_token(), token_id))

##
##  Tenant Operations
##


@bottle.route('/v1.0/tenants', method='POST')
@wrap_error
def create_tenant():
    tenant = get_normalized_request_content(tenants.Tenant)
    return send_result(201,
                       service.create_tenant(get_auth_token(), tenant))

#
# Tenants Pagination Script Added
@bottle.route('/v1.0/tenants', method='GET')
@wrap_error
def get_tenants():
    marker = None
    if "marker" in request.GET:
        marker = request.GET["marker"]

    if "limit" in request.GET:
        limit = request.GET["limit"]
    else:
        limit=10

    url = '%s://%s:%s%s' % (request.environ['wsgi.url_scheme'],\
                         request.environ.get("SERVER_NAME"),\
                         request.environ.get("SERVER_PORT"),\
                         request.environ['PATH_INFO'])

    tenants = service.get_tenants(get_auth_token(), marker, limit,url)
    return send_result(200, tenants)

@bottle.route('/v1.0/tenants/:tenant_id', method='GET')
@wrap_error
def get_tenant(tenant_id):
    tenant = service.get_tenant(get_auth_token(), tenant_id)
    return send_result(200, tenant)


@bottle.route('/v1.0/tenants/:tenant_id', method='PUT')
@wrap_error
def update_tenant(tenant_id):
    tenant = get_normalized_request_content(tenants.Tenant)
    rval = service.update_tenant(get_auth_token(), tenant_id, tenant)
    return send_result(200, rval)


@bottle.route('/v1.0/tenants/:tenant_id', method='DELETE')
@wrap_error
def delete_tenant(tenant_id):
    rval = service.delete_tenant(get_auth_token(), tenant_id)
    return send_result(204, rval)



##
##    Tenant Groups
##

@bottle.route('/v1.0/tenant/:tenantId/groups', method='POST')
@wrap_error
def create_tenant_group(tenantId):
    group = get_normalized_request_content(tenants.Group)
    return send_result(201,
                       service.create_tenant_group(get_auth_token(), \
                                                   tenantId, group))

@bottle.route('/v1.0/tenant/:tenantId/groups', method='GET')
@wrap_error
def get_tenant_groups(tenantId):
    marker = None
    if "marker" in request.GET:
        marker = request.GET["marker"]

    if "limit" in request.GET:
        limit = request.GET["limit"]
    else:
        limit=10

    url = '%s://%s:%s%s' % (request.environ['wsgi.url_scheme'],\
                         request.environ.get("SERVER_NAME"),\
                         request.environ.get("SERVER_PORT"),\
                         request.environ['PATH_INFO'])

    groups = service.get_tenant_groups(get_auth_token(),\
                                        tenantId, marker, limit,url)
    return send_result(200, groups)


@bottle.route('/v1.0/tenant/:tenantId/groups/:groupId', method='GET')
@wrap_error
def get_tenant_group(tenantId,groupId):
    tenant = service.get_tenant_group(get_auth_token(), tenantId, groupId)
    return send_result(200, tenant)


@bottle.route('/v1.0/tenant/:tenantId/groups/:groupId', method='PUT')
@wrap_error
def update_tenant_group(tenantId, groupId):
    group = get_normalized_request_content(tenants.Group)
    rval = service.update_tenant_group(get_auth_token(),\
                                        tenantId, groupId, group)
    return send_result(200, rval)


@bottle.route('/v1.0/tenant/:tenantId/groups/:groupId', method='DELETE')
@wrap_error
def delete_tenant_group(tenantId, groupId):
    rval = service.delete_tenant_group(get_auth_token(), tenantId, groupId)
    return send_result(204, rval)


@bottle.route('/v1.0/tenants/:tenantId/groups/:groupId/users', method='GET')
@wrap_error
def get_users_tenant_group(tenantId, groupId):
    marker = None
    if "marker" in request.GET:
        marker = request.GET["marker"]

    if "limit" in request.GET:
        limit = request.GET["limit"]
    else:
        limit=10

    url = '%s://%s:%s%s' % (request.environ['wsgi.url_scheme'],\
                         request.environ.get("SERVER_NAME"),\
                         request.environ.get("SERVER_PORT"),\
                         request.environ['PATH_INFO'])

    users = service.get_users_tenant_group(get_auth_token(),\
                                        tenantId, groupId, marker, limit,url)
    return send_result(200, users)


##
##  Extensions
##

@bottle.route('/v1.0/extensions', method='GET')
@wrap_error
def get_extensions():
    if is_xml_response():
        resp_file = "content/extensions.xml"
        mimetype = "application/xml"
    else:
        resp_file = "content/extensions.json"
        mimetype = "application/json"
    return bottle.static_file(resp_file,
                              root=get_app_root(),
                              mimetype=mimetype)


@bottle.route('/v1.0/extensions/:ext_alias', method='GET')
@wrap_error
def get_extension(ext_alias):
    #
    # Todo: Define some extensions :-)
    #
    raise fault.ItemNotFoundFault("The extension is not found")

def start_server(port=8080):
    app = exthandler.UrlExtensionFilter(bottle.default_app(), None)
    wsgi.server(eventlet.listen(('', port)), app)

if __name__ == "__main__":
    start_server()


