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
import simplejson
import sqlite3

from bottle import route, run, request, debug

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
                    body = simplejson.loads(request.body.readline())
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


debug(True)
run(host='localhost', port=8080, reloader=True)
