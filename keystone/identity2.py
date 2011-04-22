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

import keystone.logic.service as serv
import keystone.logic.types.auth as auth
import keystone.logic.types.tenant as tenant
import keystone.logic.types.fault as fault

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
@error(500)
@error(503)
def error_handler(err):
    return err.output

def is_xml_response():
    if not "Accept" in request.header:
        return False
    return request.header["Accept"] == "application/xml"

def send_result(result, code=500):
    if is_xml_response():
        ret = result.to_xml()
        response.content_type = "application/xml"
    else:
        ret = result.to_json()
        response.content_type = "application/json"
    response.status = code
    if code > 399:
        return abort (code, ret)
    return ret

def send_error(error):
    if isinstance(error, fault.IDMFault):
        send_result (error, error.code)
    else:
        send_result (fault.IDMFault("Unhandled error", error.__str__()))

@route('/v1.0/token', method='POST')
def authenticate():
    return "Authenticate"

@route('/v1.0/token/:token_id', method='GET')
def validate_token(token_id):
    try:
        belongs_to = None
        if "belongsTo" in request.GET:
            belongs_to = request.GET["belongsTo"]
            auth_token = None
        if "X-Auth-Token" in request.header:
            auth_token = request.header["X-Auth-Token"]
        return send_result (service.validate_token(auth_token, token_id, belongs_to), 200)
    except Exception as e:
        return send_error (e)

@route('/v1.0/token/:token_id', method='DELETE')
def delete_token(token_id):
    return "Deleting "+token_id

run(host='localhost', port=8080)
