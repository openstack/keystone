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

import os
import hashlib
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
import uuid
from datetime import datetime,timedelta

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
    
    
    @route ('/tenants/:tenantId', method='PUT')
    def update_tenant(tenantId):
        '''
            Updating Tenants by doing a PUT on /tenants
            Request Body:
            {"tenant":
                {
                    
                        "description": "A  New description ...",
                      
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
                    
                    tenant_desc = body['tenant']['description']
                    

                    dbpath = os.path.abspath(
                        os.path.join(os.path.dirname(__file__),
                            '../db/keystone.db'))
                    con = sqlite3.connect(dbpath)
                    cur = con.cursor()
                    cur.execute(
                        "UPDATE tenants SET tenant_desc='%s' WHERE tenant_id=%d" %
                        (tenant_desc, tenant_id))
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
                print content
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
                    a=cur.fetchone()
                    count=a[0]
                    
                    con.commit()
                    con.close() 
                    print count
                elif content == 'application/xml':
                    #TODO: Implement XML support
                    return "whatever, we don't have XML yet"
                if count:
                    
                    accept_header = request.header.get('Accept')
                    token=hashlib.sha224(str(username+password)).hexdigest()[:21]
                    expires=str(datetime.now()+timedelta(days=1))
                    
                    con = sqlite3.connect(dbpath,detect_types=sqlite3.PARSE_DECLTYPES)
                    cur = con.cursor()
                    cur.execute(
                       "INSERT INTO token VALUES ('%s',datetime('now','+1 day'))" % (token))
                    con.commit()
                    con.close() 
                    if accept_header in content_types:
                        if accept_header == 'application/json':
                            
                            return '{"token":'+token+',"expires": '+str(expires)+'}'
                        elif accept_header == 'application/xml':
                            #TODO: Implement XML support
                            return "whatever, we don't have XML yet"
                    else:
                        # If there is no Accept header, the default is JSON.
                        #TODO: Make sure that the body is actually JSON.
                        
                        return '{"token":'+token+',"expires": '+str(expires)+'}'
                else:
                   
                    return  abort(401, "User doesnot exists")

        return 'it did NOT work\n'
    
    
    """ 
        Created a simple create user functionality for testing..
        
        
    
        will be updated to after testing..
    """
    @route ('/users', method='POST')
    def create_user():
        '''
            Creating users by doing a POST on /users
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
                    
                    dbpath = os.path.abspath(os.path.join(os.path.dirname(__file__), '../db/keystone.db'))
                    
                    con = sqlite3.connect(dbpath)
                    cur = con.cursor()
                    cur.execute(
                       "INSERT INTO users VALUES ('%s','%s')" % 
                        (username,password))
                    con.commit()
                    con.close() 

                elif content == 'application/xml':
                    #TODO: Implement XML support
                    return "whatever, we don't have XML yet"
               
                accept_header = request.header.get('Accept')
                if accept_header in content_types:
                    if accept_header == 'application/json':
                        
                        return '{"User":"created successfully" }'
                    elif accept_header == 'application/xml':
                        #TODO: Implement XML support
                        return "whatever, we don't have  XML yet"
                else:
                    # If there is no Accept header, the default is JSON.
                    #TODO: Make sure that the body is actually JSON.
                   
                    return '{"User":"created successfully" }'
           
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
            count=0
            
            if content in content_types:
                    dbpath = os.path.abspath(
                        os.path.join(os.path.dirname(__file__),
                            '../db/keystone.db'))
                    con = sqlite3.connect(dbpath)
                    cur = con.cursor() 
                   
                    cur.execute(
                        "SELECT * FROM token WHERE token_id='%s' AND DATETIME(expires)>DATETIME('now')" % 
                        (token_id))
                    a=cur.fetchone()
                     
                    count=len(a)
                    con.commit() 
                    con.close() 
                    
            if count>0:
                #return '{ "token": {"id": "'+a[0]+'", "expires": "2010-11-01T03:32:15-05:00"}}'
                
                return '{"auth" : { "token": {"id": "'+a[0]+'", "expires": "'+a[1]+'"}, "user" :{"groups":{ "group": [{"tenantId" : "1234","name": "Admin"}]}, "username": "jqsmith", "tenantId": "1234",}{"tenantId" : "1234", "name": "Admin"}}}'
            else:
                abort(401, "Token not valid")

        return 'it did NOT work\n'
    
    
    
    
    
    @route('/tenant/:tenantId/groups', method='POST')
    def create_tenant_group(tenantId):
        '''
            Creating tenant by doing a POST on /tenant/:tenantId/groups
            {"group":
                        {
                        "id" : "Admin",
                        "description" : "A Description of the group..."
                        }
            }

        '''
        
        if 'CONTENT_TYPE' in request.environ:
            content_types = ['text/plain', 'application/json', 
                'application/xml', 'text/xml']
            content = request.environ['CONTENT_TYPE'];
            if content in content_types:
                
                #try:
                    if content == 'application/json':
                        if tenantId:
                            body = json.loads(request.body.readline())
                           
                            group_id = body['group']['id']
                            group_desc = body['group']['description']
        
                            dbpath = os.path.abspath(os.path.join(os.path.dirname(__file__),'../db/keystone.db'))
                            con = sqlite3.connect(dbpath)
                            cur = con.cursor()
                            cur.execute("SELECT * FROM tenants WHERE tenant_id='%s'" % (tenantId))
                            t=cur.fetchone()
                            # Finding Tenants Exists or not
                            if t is not None:
                                # Finding Tenant Exists or not
                                if not t[2]:
                                    return  abort(403, "Tenant Disabled")
                                
                            else:
                                return  abort(401, "unauthorized")
                            # Finding group Exists or not
                            cur.execute("SELECT count(*) FROM groups WHERE tenant_id='%s' AND group_id='%s' " % (tenantId,group_id))
                            a=cur.fetchone()
                            
                            count=a[0]
                            if count:
                                
                                    
                                    
                                return  abort(409, "Group already exists")
                                                                 
                            else:
                                    try:
                                        cur.execute("INSERT INTO groups ('group_id','tenant_id','group_desc') VALUES ('%s','%s', '%s')" % (group_id.strip(),tenantId,group_desc))
                                        con.commit()
                                    
                                        return '{"group":{"tenantId" : "%s","id" : "%s","description" : "%s"}}' % (group_id.strip(),tenantId,group_desc)
                                    except Exception,e:
                                        return abort(500,"IDM Fault Creation Failed")
                            con.close() 
                        else:
                            return  abort(400, "Bad Request")     
                    elif content == 'application/xml':
                        #TODO: Implement XML support
                        return "whatever, we don't have XML yet"
                    
                #except:
                 #   return  abort(500, "IDM Fault") 
        return 'it did NOT work\n'
    
    @route('/tenant/:tenantId/groups', method='GET')
    def get_tenant_groups(tenantId):
        '''
            Getting all Tenant Groups /tenant/tenantId/groups GET
           
           Response will be like 
           
            {"groups": {
                        "values" : [
                            {
                            "tenantId" : "1234",
                            "id" : "Admin",
                            "description" : "A description ..."
                            },
                            {
                            "tenantId" : "1234",
                            "id" : "Technical",
                            "description" : "Another description ..."
                            }
                                    ]
                        }
            }

        '''
        if 'CONTENT_TYPE' in request.environ:
            content_types = ['text/plain', 'application/json', 
                'application/xml', 'text/xml']
            content = request.environ['CONTENT_TYPE'];
            if content in content_types:
                
                #try:
                    if content == 'application/json':
                        if tenantId:
                            
        
                            dbpath = os.path.abspath(os.path.join(os.path.dirname(__file__),'../db/keystone.db'))
                            con = sqlite3.connect(dbpath)
                            cur = con.cursor()
                            # Finding group Exists or not
                            tenant=cur.execute("SELECT * FROM tenants WHERE tenant_id='%s'" % (tenantId))
                            t=cur.fetchone()
                            resp=''
                            count=tenant.rowcount
                            
                            
                            if count:
                                return t[2]
                                if not t[2]:
                                     # checking Tenant Enabled  or not
                                    return  abort(403, "Tenant disabled")
                                
                                groups=cur.execute("SELECT * FROM groups WHERE tenant_id='%s'" % (tenantId))
                                if groups.rowcount > 100:
                                    return abort(413,"Over Limit")
                                else:    
                                    resp+='{"groups": { "values" : ['
                                    gresp=''
                                    for group in groups:
                                        if gresp=='':
                                            gresp+='{"tenantId" : "%s","id" : "%s","description" : "%s"}' % (group[2],group[0],group[1])
                                        else:
                                            gresp+=',{"tenantId" : "%s","id" : "%s","description" : "%s"}' % (group[2],group[0],group[1])
                                    resp+=gresp+']}}'   
                                    
                                    return resp
                                
                                                                 
                            else:
                                return  abort(401, "unauthorized")     
                            con.close() 
                        else:
                            return  abort(400, "Bad Request")     
                    elif content == 'application/xml':
                        #TODO: Implement XML support
                        return "whatever, we don't have XML yet"
                #except:
                #    return  abort(500, "IDM Fault")
        return 'it did NOT work\n'
    
    @route('/tenant/:tenantId/groups/:groupId', method='GET')
    def get_tenant_group(tenantId,groupId):
        '''
            Getting Tenant Group /tenant/tenantId/groups/groupId
        '''
        if 'CONTENT_TYPE' in request.environ:
            content_types = ['text/plain', 'application/json', 
                'application/xml', 'text/xml']
            content = request.environ['CONTENT_TYPE'];
            if content in content_types:
                
                try:
                    if content == 'application/json':
                        if tenantId and groupId:
                            
        
                            dbpath = os.path.abspath(os.path.join(os.path.dirname(__file__),'../db/keystone.db'))
                            con = sqlite3.connect(dbpath)
                            cur = con.cursor()
                            # Finding group Exists or not
                            tenant=cur.execute("SELECT * FROM tenants WHERE tenant_id='%s'" % (tenantId))
                            t=cur.fetchone()
                            resp=''
                            count=tenant.rowcount
                            if count:
                                if not t[2]:
                                    # checking Tenant Enabled  or not
                                    return  abort(403, "Tenant disabled")
                                
                                cur.execute("SELECT * FROM groups WHERE tenant_id='%s' AND group_id='%s' " % (tenantId,groupId))
                                group=cur.fetchone
                                
                                if not group == None:    
                                    resp='{"group": { "tenantId" : "%s","id" : "%s","description" : "%s"}}' % (group[2],group[0],group[1])
                                    return resp      
                                else:
                                    
                                    return  abort(404, "Group Not Found")
                            else:
                                return  abort(401, "unauthorized")     
                            con.close() 
                        else:
                            return  abort(400, "Bad Request")     
                    elif content == 'application/xml':
                        #TODO: Implement XML support
                        return "whatever, we don't have XML yet"
                except:
                    return  abort(500, "IDM Fault")
        return 'it did NOT work\n'
    
debug(True)
run(host='localhost', port=8080, reloader=True)
