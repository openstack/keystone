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
# Not Yet PEP8 standardized

import bottle
from bottle import route
from bottle import run
from bottle import request
from bottle import response
from bottle import abort
from bottle import error
from bottle import static_file

import keystone.logic.service as serv
import keystone.logic.types.auth as auth
import keystone.logic.types.tenant as tenants
import keystone.logic.types.fault as fault

from os import path

bottle.debug(True)

service = serv.IDMService()

##
## Override error pages
##
@error(400)
@error(401)
@error(403)
@error(404)
@error(409)
@error(415)
@error(500)
@error(503)
def error_handler(err):
    return err.output

def is_xml_response():
    if not "Accept" in request.header:
        return False
    return request.header["Accept"] == "application/xml"

def get_app_root():
    return path.abspath(path.dirname(__file__))

def send_result(result, code=500):
    if result != None:
        if is_xml_response():
            ret = result.to_xml()
            response.content_type = "application/xml"
        else:
            ret = result.to_json()
            response.content_type = "application/json"
    else:
        ret = None
        response.content_type = None
    response.status = code
    if code > 399:
        return abort (code, ret)
    return ret

def get_request(c):
    ctype = request.environ.get("CONTENT_TYPE")
    if ctype == "application/xml":
        ret = c.from_xml(request.body.read())
    elif ctype == "application/json":
        ret = c.from_json(request.body.read())
    else:
        raise fault.IDMFault("I don't understand the content type ",code=415)
    return ret

def get_auth_token():
    auth_token = None
    if "X-Auth-Token" in request.header:
        auth_token = request.header["X-Auth-Token"]
    return auth_token

def send_error(error):
    if isinstance(error, fault.IDMFault):
        send_result (error, error.code)
    else:
        send_result (fault.IDMFault("Unhandled error", error.__str__()))

@route('/v1.0/token', method='POST')
def authenticate():
    try:
        creds = get_request (auth.PasswordCredentials)
        return send_result (service.authenticate(creds), 200)
    except Exception as e:
        return send_error (e)

@route('/v1.0/token/:token_id', method='GET')
def validate_token(token_id):
    try:
        belongs_to = None
        if "belongsTo" in request.GET:
            belongs_to = request.GET["belongsTo"]
        return send_result (service.validate_token(get_auth_token(), token_id, belongs_to), 200)
    except Exception as e:
        return send_error (e)

@route('/v1.0/token/:token_id', method='DELETE')
def delete_token(token_id):
    try:
        return send_result (service.revoke_token(get_auth_token(), token_id), 204)
    except Exception as e:
        return send_error (e)

@route('/v1.0/tenants', method='POST')
def create_tenant():
    try:
        tenant = get_request(tenants.Tenant)
        return send_result (service.create_tenant(get_auth_token(), tenant), 201)
    except Exception as e:
        return send_error (e)

@route('/v1.0/tenants', method='GET')
def get_tenants():
    try:
        marker = None
        if "marker" in request.GET:
            marker = request.GET["marker"]
        limit = None
        if "limit" in request.GET:
            limit = request.GET["limit"]
        return send_result(service.get_tenants(get_auth_token(), marker, limit), 200)
    except Exception as e:
        return send_error (e)

@route('/v1.0/tenants/:tenant_id', method='GET')
def get_tenant(tenant_id):
    try:
        return send_result(service.get_tenant(get_auth_token(), tenant_id), 200)
    except Exception as e:
        return send_error (e)

@route('/v1.0/tenants/:tenant_id', method='PUT')
def update_tenant(tenant_id):
    try:
        tenant = get_request(tenants.Tenant)
        return send_result(service.update_tenant(get_auth_token(), tenant_id, tenant), 200)
    except Exception as e:
        return send_error(e)

@route('/v1.0/tenants/:tenant_id', method='DELETE')
def delete_tenant(tenant_id):
    try:
        return send_result(service.delete_tenant(get_auth_token(), tenant_id), 204)
    except Exception as e:
        return send_error (e)

@route('/v1.0/extensions', method='GET')
def get_extensions():
    try:
        if is_xml_response():
            resp_file = "content/extensions.xml"
            mimetype  = "application/xml"
        else:
            resp_file = "content/extensions.json"
            mimetype = "application/json"
        return static_file (resp_file,root=get_app_root(), mimetype=mimetype)
    except Exception as e:
        return send_error (e)

@route('/v1.0/extensions/:ext_alias', method='GET')
def get_extension(ext_alias):
    try:
        #
        # Todo: Define some extensions :-)
        #
        raise fault.ItemNotFoundFault("The extension is not found")
    except Exception as e:
        return send_error (e)

run(host='localhost', port=8080)
