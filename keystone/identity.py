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
try:
    import simplejson as json
except ImportError:
    import json
import sqlite3

try:
    from bottle import route, run, request, debug, abort
except ImportError:
    import imp
    imp.load_source("bottle", "/Library/Python/2.6/site-packages/bottle-0.8.5-py2.6.egg/bottle.py")
    from bottle import route, run, request, debug, abort

import sqlite3

class Tenants:
    @route ('/tenants', method='POST')
    def create_tenant():
        '''
            Creating Tenants by doing a POST on /tenants
            Request Body:
            {"tenant":
                {
                    "id": "1234",
                        "description": "A description ...",
                        "enabled": true
                }
            }
        '''
        if 'CONTENT_TYPE' in request.environ:
            content_types = ['text/plain', 'application/json', 
                'application/xml', 'text/xml']
            content = request.environ['CONTENT_TYPE'];
            if content in content_types:
                if content == 'application/json':
                    body = json.loads(request.body.readline())
                    tenant_id = body['tenant']['id']
                    tenant_desc = body['tenant']['description']
                    tenant_enabled = body['tenant']['enabled']

                    dbpath = os.path.abspath(
                        os.path.join(os.path.dirname(__file__),
                            '../db/keystone.db'))
                    con = sqlite3.connect(dbpath)
                    cur = con.cursor()
                    cur.execute(
                        "INSERT INTO tenants VALUES ('%s', '%s', %d)" % 
                        (tenant_id, tenant_desc, tenant_enabled))
                    con.commit()
                    con.close()

                elif content == 'application/xml':
                    #TODO: Implement XML support
                    return "whatever, we don't have XML yet"

                accept_header = request.header.get('Accept')
                if accept_header in content_types:
                    if accept_header == 'application/json':
                        return body
                    elif accept_header == 'application/xml':
                        #TODO: Implement XML support
                        return "whatever, we don't have XML yet"
                else:
                    # If there is no Accept header, the default is JSON.
                    #TODO: Make sure that the body is actually JSON.
                    return body

        return 'it did NOT work\n'

    @route ('/tokens', method='POST')
    def create_token():
        '''
            Creating token by doing a POST on /tokens
        '''
        if 'CONTENT_TYPE' in request.environ:
            content_types = ['text/plain', 'application/json', 
                'application/xml', 'text/xml']
            content = request.environ['CONTENT_TYPE'];
            if content in content_types:
                if content == 'application/json':
                    body = json.loads(request.body.readline())
                    username = body['username']
                    password = body['password']

                    dbpath = os.path.abspath(
                        os.path.join(os.path.dirname(__file__),
                            '../db/keystone.db'))
                    con = sqlite3.connect(dbpath)
                    cur = con.cursor()
                    cur.execute(
                        "SELECT COUNT(*) FROM users WHERE username='%s' AND password='%s'" % 
                        (username, password))
                    con.commit()
                    con.close()

                elif content == 'application/xml':
                    #TODO: Implement XML support
                    return "whatever, we don't have XML yet"

                accept_header = request.header.get('Accept')
                if accept_header in content_types:
                    if accept_header == 'application/json':
                        return '{"token": "abcdefghijklmnopqrstuvwxyz"}'
                    elif accept_header == 'application/xml':
                        #TODO: Implement XML support
                        return "whatever, we don't have XML yet"
                else:
                    # If there is no Accept header, the default is JSON.
                    #TODO: Make sure that the body is actually JSON.
                    return '{"token": "abcdefghijklmnopqrstuvwxyz"}'

        return 'it did NOT work\n'

    @route('/token/:token_id', method='GET')
    def validate_token(token_id):
        '''
            Validating token by doing a GET on /token/token_id
        '''
        if 'CONTENT_TYPE' in request.environ:
            content_types = ['text/plain', 'application/json', 
                'application/xml', 'text/xml']
            content = request.environ['CONTENT_TYPE'];
            if content in content_types:
                if token_id == 'abcdefghijklmnopqrstuvwxyz':
                    return '{"auth" : { "token": {"id": "ab48a9efdfedb23ty3494", "expires": "2010-11-01T03:32:15-05:00"}, "user" :{"groups"{ "group": []}, "username": "jqsmith", "tenantId": "1234",}{"tenantId" : "1234", "name": "Admin"}}}'
                else:
                    abort(401, "Token not valid")

        return 'it did NOT work\n'

debug(True)
run(host='localhost', port=8080, reloader=True)
