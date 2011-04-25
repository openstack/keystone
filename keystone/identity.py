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


import bottle
from bottle import request
from bottle import response
import os
import sys

# If ../keystone/__init__.py exists, add ../ to Python search path, so that
# it will override what happens to be installed in /usr/(local/)lib/python...
POSSIBLE_TOPDIR = os.path.normpath(os.path.join(os.path.abspath(sys.argv[0]),
                                   os.pardir,
                                   os.pardir))
if os.path.exists(os.path.join(POSSIBLE_TOPDIR, 'keystone', '__init__.py')):
    sys.path.insert(0, POSSIBLE_TOPDIR)

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


def get_request(ctx):
    ctype = request.environ.get("CONTENT_TYPE")
    if ctype == "application/xml":
        ret = ctx.from_xml(request.body.read())
    elif ctype == "application/json":
        ret = ctx.from_json(request.body.read())
    else:
        raise fault.IDMFault("I don't understand the content type ", code=415)
    return ret


def get_auth_token():
    auth_token = None
    if "X-Auth-Token" in request.header:
        auth_token = request.header["X-Auth-Token"]
    return auth_token


def send_error(error):
    if isinstance(error, fault.IDMFault):
        send_result(error.code, error)
    else:
        send_result(500, fault.IDMFault("Unhandled error", str(error)))


@bottle.route('/v1.0', method='GET')
@bottle.route('/v1.0/', method='GET')
def get_version_info():
    try:
        if is_xml_response():
            resp_file = "content/version.xml"
            response.content_type = "application/xml"
        else:
            resp_file = "content/version.json"
            response.content_type = "application/json"
        hostname = request.environ.get("SERVER_NAME")
        port = request.environ.get("SERVER_PORT")
        return bottle.template(resp_file, HOST=hostname, PORT=port,
                               VERSION_STATUS=VERSION_STATUS,
                               VERSION_DATE=VERSION_DATE)
    except Exception as e:
        return send_error(e)

##
## Version links:
##


@bottle.route('/v1.0/idmdevguide.pdf', method='GET')
def get_pdf_contract():
    try:
        return bottle.static_file("content/idmdevguide.pdf",
                                  root=get_app_root(),
                                  mimetype="application/pdf")
    except Exception as e:
        return send_error(e)


@bottle.route('/v1.0/identity.wadl', method='GET')
def get_wadl_contract():
    try:
        return bottle.static_file("identity.wadl",
                                  root=get_app_root(),
                                  mimetype="application/vnd.sun.wadl+xml")
    except Exception as e:
        return send_error(e)


@bottle.route('/v1.0/xsd/:xsd', method='GET')
def get_xsd_contract(xsd):
    try:
        return bottle.static_file("/xsd/" + xsd,
                                  root=get_app_root(),
                                  mimetype="application/xml")
    except Exception as e:
        return send_error(e)


@bottle.route('/v1.0/xsd/atom/:xsd', method='GET')
def get_xsd_atom_contract(xsd):
    try:
        return bottle.static_file("/xsd/atom/" + xsd,
                                  root=get_app_root(),
                                  mimetype="application/xml")
    except Exception as e:
        return send_error(e)

##
##  Token Operations
##


@bottle.route('/v1.0/token', method='POST')
def authenticate():
    try:
        creds = get_request(auth.PasswordCredentials)
        return send_result(200, service.authenticate(creds))
    except Exception as e:
        return send_error(e)


@bottle.route('/v1.0/token/:token_id', method='GET')
def validate_token(token_id):
    try:
        belongs_to = None
        if "belongsTo" in request.GET:
            belongs_to = request.GET["belongsTo"]
        rval = service.validate_token(get_auth_token(), token_id, belongs_to)
        return send_result(200, rval)
    except Exception as e:
        return send_error(e)


@bottle.route('/v1.0/token/:token_id', method='DELETE')
def delete_token(token_id):
    try:
        return send_result(204,
                           service.revoke_token(get_auth_token(), token_id))
    except Exception as e:
        return send_error(e)


##
##  Tenant Operations
##

@bottle.route('/v1.0/tenants', method='POST')
def create_tenant():
    try:
        tenant = get_request(tenants.Tenant)
        return send_result(201,
                           service.create_tenant(get_auth_token(), tenant))
    except Exception as e:
        return send_error(e)


@bottle.route('/v1.0/tenants', method='GET')
def get_tenants():
    try:
        marker = None
        if "marker" in request.GET:
            marker = request.GET["marker"]
        limit = None
        if "limit" in request.GET:
            limit = request.GET["limit"]
        tenants = service.get_tenants(get_auth_token(), marker, limit)
        return send_result(200, tenants)
    except Exception as e:
        return send_error(e)


@bottle.route('/v1.0/tenants/:tenant_id', method='GET')
def get_tenant(tenant_id):
    try:
        tenant = service.get_tenant(get_auth_token(), tenant_id)
        return send_result(200, tenant)
    except Exception as e:
        return send_error(e)


@bottle.route('/v1.0/tenants/:tenant_id', method='PUT')
def update_tenant(tenant_id):
    try:
        tenant = get_request(tenants.Tenant)
        rval = service.update_tenant(get_auth_token(), tenant_id, tenant)
        return send_result(200, rval)
    except Exception as e:
        return send_error(e)


@bottle.route('/v1.0/tenants/:tenant_id', method='DELETE')
def delete_tenant(tenant_id):
    try:
        rval = service.delete_tenant(get_auth_token(), tenant_id)
        return send_result(204, rval)
    except Exception as e:
        return send_error(e)


##
##  Extensions
##

@bottle.route('/v1.0/extensions', method='GET')
def get_extensions():
    try:
        if is_xml_response():
            resp_file = "content/extensions.xml"
            mimetype = "application/xml"
        else:
            resp_file = "content/extensions.json"
            mimetype = "application/json"
        return bottle.static_file(resp_file,
                                  root=get_app_root(),
                                  mimetype=mimetype)
    except Exception as e:
        return send_error(e)


@bottle.route('/v1.0/extensions/:ext_alias', method='GET')
def get_extension(ext_alias):
    try:
        #
        # Todo: Define some extensions :-)
        #
        raise fault.ItemNotFoundFault("The extension is not found")
    except Exception as e:
        return send_error(e)


if __name__ == "__main__":
    bottle.run(host='localhost', port=8080)
